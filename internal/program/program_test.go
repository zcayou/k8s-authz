package program_test

import (
	"fmt"
	"math/rand/v2"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("SubjectAccessReview normalization", func() {
	It("normalizes a named resource request", func(ctx SpecContext) {
		request := normalize(ctx, resourceReview(authorizationv1.ResourceAttributes{
			Namespace: systemNamespace, Verb: "delete", Resource: "namespaces", Name: systemNamespace,
		}))

		Expect(request.Principal).To(Equal(model.Principal{
			User: aliceName, Groups: []string{developers, authenticatedGroup}, UID: "uid-1",
			Extra: map[string][]string{"scopes": {openidScope, profileScope}, "present-empty": {}},
		}))
		expectSingle(request.Query, model.APIGroup, model.Atom(""))
		expectSingle(request.Query, model.Resource, model.Atom("\x00namespaces"))
		expectSingle(request.Query, model.IngressNamespace, model.Atom(systemNamespace))
		expectSingle(request.Query, model.AffectedNamespace, model.Atom(systemNamespace))
		expectSingle(request.Query, model.Name, model.Atom(systemNamespace))
		Expect(request.Query.Regions[model.APIVersion]).To(Equal(model.PresentValues()))
	})

	It("normalizes empty namespace to named effects and the namespace-less witness", func(ctx SpecContext) {
		request := normalize(ctx, resourceReview(authorizationv1.ResourceAttributes{
			Verb: listVerb, Group: "*", Version: "*", Resource: secretsResource,
		}))

		expectSingle(request.Query, model.IngressNamespace, model.Atom(""))
		affected := request.Query.Regions[model.AffectedNamespace]
		Expect(affected.Contains(model.Atom(systemNamespace))).To(BeTrue())
		Expect(affected.Contains(utils.NamespaceWitness)).To(BeTrue())
		Expect(affected.Contains(model.Atom(""))).To(BeFalse())
		Expect(request.Query.Regions[model.APIGroup]).To(Equal(model.PresentValues()))
		Expect(request.Query.Regions[model.APIVersion]).To(Equal(model.PresentValues()))
	})

	It("reads namespace and subresource \"*\" literally, as RBAC does", func(ctx SpecContext) {
		request := normalize(ctx, resourceReview(authorizationv1.ResourceAttributes{
			Namespace: "*", Verb: getVerb, Group: appsNamespace, Version: "v1", Resource: deployments, Subresource: "*",
		}))

		expectSingle(request.Query, model.IngressNamespace, model.Atom("*"))
		expectSingle(request.Query, model.AffectedNamespace, model.Atom("*"))
		expectSingle(request.Query, model.Resource, model.Atom("*\x00deployments"))
	})

	It("keeps resource and subresource correlated", func(ctx SpecContext) {
		review := resourceReview(authorizationv1.ResourceAttributes{
			Namespace: appsNamespace, Verb: "update", Group: appsNamespace, Resource: deployments, Subresource: "scale",
		})
		expectSingle(normalize(ctx, review).Query, model.Resource, model.Atom("scale\x00deployments"))

		review.Spec.ResourceAttributes.Resource = "*"
		region := normalize(ctx, review).Query.Regions[model.Resource]
		Expect(region.Contains(model.Atom("scale\x00deployments"))).To(BeTrue())
		Expect(region.Contains(model.Atom("scale\x00statefulsets"))).To(BeTrue())
		Expect(region.Contains(model.Atom("status\x00deployments"))).To(BeFalse())

		review.Spec.ResourceAttributes.Subresource = ""
		Expect(normalize(ctx, review).Query.Regions[model.Resource]).To(Equal(model.PresentValues()))
	})

	It("normalizes non-resource requests independently from resource dimensions", func(ctx SpecContext) {
		review := baseReview()
		review.Spec.ResourceAttributes = nil
		review.Spec.NonResourceAttributes = &authorizationv1.NonResourceAttributes{Path: "/healthz", Verb: getVerb}
		request := normalize(ctx, review)

		Expect(request.Query.Regions).To(HaveLen(3))
		expectSingle(request.Query, model.Category, model.Atom("nonResource"))
		expectSingle(request.Query, model.URL, model.Atom("/healthz"))
	})

	It("gives conditions a resource request's principal and attributes", func(ctx SpecContext) {
		review := resourceReview(authorizationv1.ResourceAttributes{
			Namespace: teamNamespace, Verb: listVerb, Group: "apps", Version: "v1", Resource: deployments,
			LabelSelector: labelSelector([]metav1.LabelSelectorRequirement{{Key: teamLabel, Operator: metav1.LabelSelectorOpIn, Values: []string{redTeam}}}),
		})
		Expect(normalize(ctx, review).ConditionInput).To(MatchJSON(`{
			"principal": {"user": "alice", "groups": ["developers", "system:authenticated"], "uid": "uid-1", "extra": {"present-empty": [], "scopes": ["openid", "profile"]}},
			"request": {"resourceAttributes": {
				"namespace": "team-a", "verb": "list", "group": "apps", "version": "v1", "resource": "deployments", "subresource": "", "name": "",
				"fieldSelector": {},
				"labelSelector": {"requirements": [{"key": "team", "operator": "In", "values": ["red"]}]}
			}}
		}`))
	})

	It("gives conditions a non-resource request's attributes and an empty extra when it has none", func(ctx SpecContext) {
		review := baseReview()
		review.Spec.Extra = nil
		review.Spec.NonResourceAttributes = &authorizationv1.NonResourceAttributes{Path: "/healthz"}
		Expect(normalize(ctx, review).ConditionInput).To(MatchJSON(`{
			"principal": {"user": "alice", "groups": ["developers", "system:authenticated"], "uid": "uid-1", "extra": {}},
			"request": {"nonResourceAttributes": {"path": "/healthz", "verb": ""}}
		}`))
	})

	It("normalizes a principal without user, and groups as a set", func(ctx SpecContext) {
		review := baseReview()
		review.Spec.User = ""
		review.Spec.Groups = []string{"operators", "operators"}
		review.Spec.Extra = map[string]authorizationv1.ExtraValue{"present-empty": {}}
		review.Spec.ResourceAttributes = nil
		review.Spec.NonResourceAttributes = &authorizationv1.NonResourceAttributes{Path: "/healthz", Verb: getVerb}
		Expect(normalize(ctx, review).Principal).To(Equal(model.Principal{Groups: []string{"operators"}, UID: "uid-1", Extra: map[string][]string{"present-empty": {}}}))
	})

	It("uses parsed selectors and correlates metadata.name with the name dimension", func(ctx SpecContext) {
		request := normalize(ctx, resourceReview(authorizationv1.ResourceAttributes{
			Namespace: appsNamespace, Verb: listVerb, Group: appsNamespace, Version: "v1", Resource: deployments,
			LabelSelector: labelSelector([]metav1.LabelSelectorRequirement{
				{Key: teamLabel, Operator: metav1.LabelSelectorOpNotIn, Values: []string{redTeam}},
				{Key: "managed", Operator: metav1.LabelSelectorOpExists},
			}),
			FieldSelector: &authorizationv1.FieldSelectorAttributes{Requirements: []metav1.FieldSelectorRequirement{
				{Key: metadataName, Operator: metav1.FieldSelectorOpIn, Values: []string{apiName, "worker"}},
				{Key: "status.phase", Operator: metav1.FieldSelectorOpDoesNotExist},
			}},
		}))

		name := request.Query.Regions[model.Name]
		Expect(name.Contains(model.Atom(apiName))).To(BeTrue())
		Expect(name.Contains(model.Atom("worker"))).To(BeTrue())
		Expect(name.Contains(model.Atom(otherValue))).To(BeFalse())
		notRed := request.Query.Regions[model.LabelPrefix+teamLabel]
		Expect(notRed.Contains(model.Absent)).To(BeTrue())
		Expect(notRed.Contains(model.Atom(blueTeam))).To(BeTrue())
		Expect(notRed.Contains(model.Atom(redTeam))).To(BeFalse())
		Expect(request.Query.Regions[model.LabelPrefix+"managed"].Contains(model.Absent)).To(BeFalse())
		Expect(request.Query.Regions[model.FieldPrefix+"status.phase"]).To(Equal(model.Values(model.Absent)))
	})

	DescribeTable("normalizes each supported selector conjunction",
		func(ctx SpecContext, requirements []metav1.LabelSelectorRequirement, member, nonmember []string) {
			region := normalize(ctx, resourceReview(authorizationv1.ResourceAttributes{
				Namespace: appsNamespace, Verb: listVerb, Resource: podsResource, LabelSelector: labelSelector(requirements),
			})).Query.Regions[model.LabelPrefix+teamLabel]
			for _, value := range member {
				Expect(region.Contains(value)).To(BeTrue(), value)
			}
			for _, value := range nonmember {
				Expect(region.Contains(value)).To(BeFalse(), value)
			}
		},
		Entry("In", []metav1.LabelSelectorRequirement{{Key: teamLabel, Operator: metav1.LabelSelectorOpIn, Values: []string{"a", "b"}}}, []string{model.Atom("a"), model.Atom("b")}, []string{model.Atom("c"), model.Absent}),
		Entry("NotIn", []metav1.LabelSelectorRequirement{{Key: teamLabel, Operator: metav1.LabelSelectorOpNotIn, Values: []string{"a"}}}, []string{model.Atom("b"), model.Absent}, []string{model.Atom("a")}),
		Entry("Exists", []metav1.LabelSelectorRequirement{{Key: teamLabel, Operator: metav1.LabelSelectorOpExists}}, []string{model.Atom("a"), model.Atom("")}, []string{model.Absent}),
		Entry("DoesNotExist", []metav1.LabelSelectorRequirement{{Key: teamLabel, Operator: metav1.LabelSelectorOpDoesNotExist}}, []string{model.Absent}, []string{model.Atom("a")}),
		Entry("In and NotIn", []metav1.LabelSelectorRequirement{
			{Key: teamLabel, Operator: metav1.LabelSelectorOpIn, Values: []string{"a", "b"}},
			{Key: teamLabel, Operator: metav1.LabelSelectorOpNotIn, Values: []string{"b"}},
		}, []string{model.Atom("a")}, []string{model.Atom("b"), model.Absent}),
		Entry("Exists and NotIn", []metav1.LabelSelectorRequirement{
			{Key: teamLabel, Operator: metav1.LabelSelectorOpExists},
			{Key: teamLabel, Operator: metav1.LabelSelectorOpNotIn, Values: []string{"a"}},
		}, []string{model.Atom("b")}, []string{model.Atom("a"), model.Absent}),
		Entry("DoesNotExist and NotIn", []metav1.LabelSelectorRequirement{
			{Key: teamLabel, Operator: metav1.LabelSelectorOpDoesNotExist},
			{Key: teamLabel, Operator: metav1.LabelSelectorOpNotIn, Values: []string{"a"}},
		}, []string{model.Absent}, []string{model.Atom("a"), model.Atom("b")}),
	)

	It("distinguishes a present empty label value from an absent label", func(ctx SpecContext) {
		region := normalize(ctx, resourceReview(authorizationv1.ResourceAttributes{
			Namespace: appsNamespace, Verb: listVerb, Resource: podsResource,
			LabelSelector: labelSelector([]metav1.LabelSelectorRequirement{{Key: teamLabel, Operator: metav1.LabelSelectorOpIn, Values: []string{""}}}),
		})).Query.Regions[model.LabelPrefix+teamLabel]

		Expect(region.Contains(model.Atom(""))).To(BeTrue())
		Expect(region.Contains(model.Absent)).To(BeFalse())
	})

	It("does not reinterpret a raw collection selector", func(ctx SpecContext) {
		request := normalize(ctx, resourceReview(authorizationv1.ResourceAttributes{
			Namespace: appsNamespace, Verb: listVerb, Resource: podsResource,
			LabelSelector: &authorizationv1.LabelSelectorAttributes{RawSelector: teamLabel + "=" + redTeam},
		}))

		Expect(request.Query.Regions).NotTo(HaveKey(model.LabelPrefix + teamLabel))
	})

	It("ignores raw selectors and selector evidence on non-collection verbs", func(ctx SpecContext) {
		request := normalize(ctx, resourceReview(authorizationv1.ResourceAttributes{
			Namespace: appsNamespace, Verb: getVerb, Resource: podsResource, Name: apiName,
			LabelSelector: &authorizationv1.LabelSelectorAttributes{RawSelector: "team=red"},
			FieldSelector: &authorizationv1.FieldSelectorAttributes{Requirements: []metav1.FieldSelectorRequirement{
				{Key: metadataName, Operator: metav1.FieldSelectorOpIn, Values: []string{otherValue}},
			}},
		}))

		expectSingle(request.Query, model.Name, model.Atom(apiName))
		Expect(request.Query.Regions).NotTo(HaveKey(model.LabelPrefix + teamLabel))
	})

	It("broadens contradictory selector evidence instead of producing an empty query", func(ctx SpecContext) {
		for _, requirements := range [][]metav1.LabelSelectorRequirement{
			{
				{Key: teamLabel, Operator: metav1.LabelSelectorOpIn, Values: []string{redTeam}},
				{Key: teamLabel, Operator: metav1.LabelSelectorOpIn, Values: []string{blueTeam}},
			},
			{
				{Key: teamLabel, Operator: metav1.LabelSelectorOpExists},
				{Key: teamLabel, Operator: metav1.LabelSelectorOpDoesNotExist},
			},
		} {
			request := normalize(ctx, resourceReview(authorizationv1.ResourceAttributes{
				Namespace: appsNamespace, Verb: listVerb, Resource: podsResource, LabelSelector: labelSelector(requirements),
			}))
			Expect(request.Query.Regions).NotTo(HaveKey(model.LabelPrefix + teamLabel))
			Expect(request.Query.Regions[model.Name]).To(Equal(model.PresentValues()))
		}
	})

	It("drops all selector evidence when metadata.name contradicts a submitted name", func(ctx SpecContext) {
		request := normalize(ctx, resourceReview(authorizationv1.ResourceAttributes{
			Namespace: appsNamespace, Verb: listVerb, Resource: podsResource, Name: apiName,
			LabelSelector: labelSelector([]metav1.LabelSelectorRequirement{{Key: teamLabel, Operator: metav1.LabelSelectorOpIn, Values: []string{redTeam}}}),
			FieldSelector: &authorizationv1.FieldSelectorAttributes{Requirements: []metav1.FieldSelectorRequirement{
				{Key: metadataName, Operator: metav1.FieldSelectorOpIn, Values: []string{otherValue}},
			}},
		}))

		expectSingle(request.Query, model.Name, model.Atom(apiName))
		Expect(request.Query.Regions).NotTo(HaveKey(model.LabelPrefix + teamLabel))
	})

	It("rejects input normalization can't encode", func(ctx SpecContext) {
		for _, data := range malformedReviews {
			result := evaluate(ctx, []byte(data))
			Expect(result.Valid).To(BeFalse(), data)
			Expect(result.Error).To(Equal("invalid SubjectAccessReview"), data)
		}
	})

	It("ignores fields it doesn't read and treats explicit nulls as absent", func(ctx SpecContext) {
		expected := evaluate(ctx, []byte(`{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"alice","resourceAttributes":{"verb":"list","resource":"pods","namespace":"apps","labelSelector":{"requirements":[{"key":"team","operator":"In","values":["blue"]}]}}}}`))
		Expect(expected.Valid).To(BeTrue())
		for _, data := range openWorldReviews {
			actual := evaluate(ctx, []byte(data))
			Expect(actual.Principal).To(Equal(expected.Principal), data)
			Expect(actual.Query.Regions).To(Equal(expected.Query.Regions), data)
		}
	})
})

var _ = Describe("Generated request contracts", func() {
	It("accepts generated unknown fields at every nested level", func(ctx SpecContext) {
		additions := []func(int) string{
			func(index int) string {
				return fmt.Sprintf(`{"user":"alice","unknown-%d":true,"resourceAttributes":{"verb":"list","resource":"pods"}}`, index)
			},
			func(index int) string {
				return fmt.Sprintf(`{"user":"alice","resourceAttributes":{"verb":"list","resource":"pods","unknown-%d":{"nested":[1,2]}}}`, index)
			},
			func(index int) string {
				return fmt.Sprintf(`{"user":"alice","resourceAttributes":{"verb":"list","resource":"pods","labelSelector":{"requirements":[{"key":"team-%d","operator":"In","values":["blue"],"unknown":true}]}}}`, index)
			},
			func(index int) string {
				return fmt.Sprintf(`{"user":"alice","resourceAttributes":{"verb":"list","resource":"pods","fieldSelector":{"requirements":[{"key":"metadata.name","operator":"In","values":["api"]}],"tag":%d}}}`, index)
			},
		}

		for index := range generatedCases {
			spec := additions[index%len(additions)](index)
			raw := fmt.Sprintf(`{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","status":{"future-%d":true},"spec":%s}`, index, spec)
			Expect(evaluate(ctx, []byte(raw)).Valid).To(BeTrue(), "case=%d", index)
		}
	})

	It("normalizes principal sets independently of submitted ordering and duplication", func(ctx SpecContext) {
		random := rand.New(rand.NewPCG(requestSeedTwo, requestSeedOne))
		for index := range generatedCases {
			groups := []string{developers, authenticatedGroup, fmt.Sprintf("team-%02d", index%17), developers}
			scopes := []string{openidScope, profileScope, fmt.Sprintf("scope-%02d", index%13), profileScope}
			left := resourceReview(authorizationv1.ResourceAttributes{Verb: getVerb, Resource: podsResource, Name: fmt.Sprintf("pod-%03d", index)})
			right := left.DeepCopy()
			left.Spec.Groups = permuteStrings(random, groups)
			left.Spec.Extra["scopes"] = authorizationv1.ExtraValue(permuteStrings(random, scopes))
			right.Spec.Groups = permuteStrings(random, groups)
			right.Spec.Extra["scopes"] = authorizationv1.ExtraValue(permuteStrings(random, scopes))

			leftRequest := normalize(ctx, left)
			rightRequest := normalize(ctx, *right)
			Expect(leftRequest.Principal).To(Equal(rightRequest.Principal), "case=%d", index)
			Expect(leftRequest.Principal.Groups).To(HaveLen(3), "case=%d", index)
			Expect(leftRequest.Principal.Extra["scopes"]).To(HaveLen(3), "case=%d", index)
		}
	})

	It("keeps every accepted generated SAR footprint nonempty and broadens uncertain selectors", func(ctx SpecContext) {
		AddReportEntry("seed", fmt.Sprintf("%#x/%#x", requestSeedOne, requestSeedTwo))
		random := rand.New(rand.NewPCG(requestSeedOne, requestSeedTwo))
		namespaces := []string{"", defaultNamespace, systemNamespace, teamNamespace}
		verbs := []string{getVerb, "list", "watch", "deletecollection"}
		resources := []string{podsResource, "secrets", "deployments"}
		groups := []string{"", "apps", "*"}

		for index := range generatedCases {
			selectorCase := random.IntN(4)
			attributes := authorizationv1.ResourceAttributes{
				Namespace: namespaces[random.IntN(len(namespaces))], Verb: verbs[random.IntN(len(verbs))],
				Group: groups[random.IntN(len(groups))], Version: "v1", Resource: resources[random.IntN(len(resources))],
			}
			if random.IntN(2) == 0 {
				attributes.Name = fmt.Sprintf("object-%d", index)
			}
			uncertain := selectorCase != 0
			switch selectorCase {
			case 0:
				attributes.LabelSelector = labelSelector([]metav1.LabelSelectorRequirement{{Key: teamLabel, Operator: metav1.LabelSelectorOpIn, Values: []string{blueTeam}}})
			case 1:
				attributes.LabelSelector = labelSelector([]metav1.LabelSelectorRequirement{
					{Key: teamLabel, Operator: metav1.LabelSelectorOpIn, Values: []string{blueTeam}},
					{Key: teamLabel, Operator: metav1.LabelSelectorOpIn, Values: []string{"red"}},
				})
			case 2:
				attributes.LabelSelector = &authorizationv1.LabelSelectorAttributes{RawSelector: "team=blue"}
			case 3:
				attributes.Name = "submitted"
				attributes.LabelSelector = labelSelector([]metav1.LabelSelectorRequirement{{Key: teamLabel, Operator: metav1.LabelSelectorOpIn, Values: []string{blueTeam}}})
				attributes.FieldSelector = &authorizationv1.FieldSelectorAttributes{Requirements: []metav1.FieldSelectorRequirement{{Key: "metadata.name", Operator: metav1.FieldSelectorOpIn, Values: []string{"different"}}}}
			}

			request := normalize(ctx, resourceReview(attributes))
			Expect(request.Query.Regions).NotTo(BeEmpty(), "case=%d", index)
			for dimension, region := range request.Query.encoded {
				Expect(utils.ValidateRegion(region)).To(Succeed(), "case=%d dimension=%s", index, dimension)
				Expect(region.Empty()).To(BeFalse(), "case=%d dimension=%s", index, dimension)
			}
			assertNamespaceFootprint(request.Query, attributes.Namespace, index)
			if uncertain && (attributes.Verb == "list" || attributes.Verb == "watch" || attributes.Verb == "deletecollection") {
				Expect(request.Query.Regions).NotTo(HaveKey(model.LabelPrefix+teamLabel), "case=%d", index)
			}
		}
	})
})
