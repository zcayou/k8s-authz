package compiler_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/compiler"
	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("Contextual graph compilation", func() {
	var f *fixture
	BeforeEach(func() {
		f = newFixture()
		f.custom(model.KindPolicy, "all", `{"include":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]}`)
		f.custom(model.KindPolicyBinding, "admin", `{"policyRef":{"name":"all"},"subjects":[{"kind":"User","name":"admin"}]}`)
	})
	It("carries the endpoint's evaluation failure fallback into its program", func() {
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"}]}`)
		Expect(f.compile().Prepared.Endpoints["cluster"].WhenEvaluationFails).To(Equal(model.Result("Deny")))
		f.config.Endpoints[0].WhenEvaluationFails = "NoOpinion"
		Expect(f.compile().Prepared.Endpoints["cluster"].WhenEvaluationFails).To(Equal(model.Result("NoOpinion")))
	})
	It("reports a missing Allow-only reference and answers with whenNoPolicyAllows", func(ctx SpecContext) {
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"},{"name":"missing"}]}`)
		compiled := f.compile()
		program := compiled.Prepared
		Expect(program.Issues).To(BeEmpty())
		Expect(compiled.Diagnostics).To(ContainElement(SatisfyAll(HaveField("Reason", model.ReasonMissingReference), HaveField("Severity", api.IssueSeverityError))))
		Expect(decide(ctx, program, "get", "secrets", "kube-system", "admin").Result).To(Equal(model.Result("Allow")))
		result := decide(ctx, program, "get", "secrets", "kube-system", "user")
		Expect(result.Result).To(Equal(model.Result("NoOpinion")))
		Expect(result.EvaluationError).To(BeEmpty())
	})
	It("reports a missing Policy under a leaf entry binding as an Allow failure", func(ctx SpecContext) {
		f.custom(model.KindPolicyBinding, "entry", `{"policyRef":{"name":"missing"},"subjectMatch":{}}`)
		compiled := f.compile()
		program := compiled.Prepared
		Expect(program.Issues).To(BeEmpty())
		Expect(compiled.Diagnostics).To(ContainElement(HaveField("Reason", model.ReasonMissingReference)))
		result := decide(ctx, program, "get", "pods", "one", "admin")
		Expect(result.Result).To(Equal(model.Result("NoOpinion")))
		Expect(result.EvaluationError).To(BeEmpty())
	})
	It("reports an entry in an Inert source as unavailable, naming Inert", func(ctx SpecContext) {
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"}]}`)
		f.observation = model.SourceObservation{Instance: f.source, Failure: model.Failure{Reason: string(api.ContributionInert)}}
		compiled := f.compile()
		Expect(compiled.Prepared.Issues).To(ConsistOf(SatisfyAll(
			HaveField("Reason", model.ReasonSourceUnavailable),
			HaveField("Message", "source control/local is unavailable (Inert)"),
		)))
		Expect(decide(ctx, compiled.Prepared, "get", "pods", "one", "admin").Result).To(Equal(model.Result("Deny")))
	})
	It("neither reads nor requires a source outside the endpoint's sourceRefs, and keeps healthy siblings", func(ctx SpecContext) {
		excluded := model.SourceKey{Namespace: "control", Name: "excluded"}
		f.custom(model.KindPolicy, "allow", `{"include":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"],"namespaces":["team"]}]}`)
		f.custom(model.KindPolicyBinding, "good", `{"subjectMatch":{},"policyRef":{"name":"allow"}}`)
		f.custom(model.KindPolicyBinding, "bad", `{"subjectMatch":{},"policyRef":{"name":"never-read","namespace":"policies","sourceRef":{"namespace":"control","name":"excluded"}}}`)
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"good"},{"name":"bad"}]}`)
		compiled := f.compile()
		Expect(decide(ctx, compiled.Prepared, "get", "pods", "team", "alice").Result).To(Equal(model.Result("Allow")))
		Expect(compiled.References).NotTo(HaveKey(HaveField("Source", excluded)))
		Expect(compiled.References).To(HaveKey(HaveField("Source", f.source.Key)))
	})
	It("closes unknown prohibitions before independent platform access", func(ctx SpecContext) {
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"}],"prohibitionRefs":[{"name":"missing"}]}`)
		result := decide(ctx, f.compile().Prepared, "get", "secrets", "kube-system", "admin")
		Expect(result.Result).To(Equal(model.Result("Deny")))
		Expect(result.EvaluationError).NotTo(BeEmpty())
	})
	It("applies root prohibitions to the named effects of all-namespace requests", func(ctx SpecContext) {
		f.custom(model.KindPolicy, "secret-prohibition", `{"include":[{"apiGroups":[""],"resources":["secrets"],"verbs":["get","list","watch"],"namespaces":["kube-system"]}]}`)
		f.custom(model.KindPolicyBinding, "prohibit", `{"policyRef":{"name":"secret-prohibition"},"subjectMatch":{}}`)
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"}],"prohibitionRefs":[{"name":"prohibit"}]}`)
		program := f.compile().Prepared
		Expect(decide(ctx, program, "list", "secrets", "", "admin").Result).To(Equal(model.Result("Deny")))
		Expect(decide(ctx, program, "list", "secrets", "elastic-system", "admin").Result).To(Equal(model.Result("Allow")))
	})
	It("reuses a child through independent bounded paths and revokes only a removed path", func(ctx SpecContext) {
		f.custom(model.KindPolicyBinding, "team", `{"policyRef":{"name":"all"},"subjects":[{"kind":"User","name":"team"}]}`)
		f.custom(model.KindPolicySet, "child", `{"bindingRefs":[{"name":"team"}]}`)
		for _, namespace := range []string{"one", "two"} {
			f.custom(model.KindPolicy, namespace, fmt.Sprintf(`{"include":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"],"namespaces":[%q]}]}`, namespace))
			f.custom(model.KindPolicyBinding, namespace, fmt.Sprintf(`{"policyRef":{"kind":"PolicySet","name":"child"},"subjectMatch":{},"constraints":{"policyRef":{"name":%q}}}`, namespace))
		}
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"one"},{"name":"two"}]}`)
		program := f.compile().Prepared
		Expect(decide(ctx, program, "get", "pods", "one", "team").Result).To(Equal(model.Result("Allow")))
		Expect(decide(ctx, program, "get", "pods", "two", "team").Result).To(Equal(model.Result("Allow")))
		Expect(decide(ctx, program, "list", "pods", "", "team").Result).To(Equal(model.Result("NoOpinion")))
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"two"}]}`)
		program = f.compile().Prepared
		Expect(decide(ctx, program, "get", "pods", "one", "team").Result).To(Equal(model.Result("NoOpinion")))
		Expect(decide(ctx, program, "get", "pods", "two", "team").Result).To(Equal(model.Result("Allow")))
	})
	It("rejects descendant prohibitions without imposing them on independent root permissions", func(ctx SpecContext) {
		f.custom(model.KindPolicySet, "child", `{"prohibitionRefs":[{"name":"missing"}]}`)
		f.custom(model.KindPolicyBinding, "child", `{"policyRef":{"name":"child","kind":"PolicySet"},"constraints":{"policyRef":{"name":"all"}},"subjectMatch":{}}`)
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"},{"name":"child"}]}`)
		compiled := f.compile()
		program := compiled.Prepared
		Expect(decide(ctx, program, "get", "pods", "one", "admin").Result).To(Equal(model.Result("Allow")))
		result := decide(ctx, program, "get", "pods", "one", "team")
		Expect(result.Result).To(Equal(model.Result("NoOpinion")))
		Expect(result.EvaluationError).To(BeEmpty())
		Expect(compiled.Diagnostics).To(ContainElement(HaveField("Reason", model.ReasonDenyOutsideRoot)))
	})
	It("detects cycles on the current path without global graph visitation", func(ctx SpecContext) {
		f.custom(model.KindPolicyBinding, "loop", `{"policyRef":{"name":"root","kind":"PolicySet"},"constraints":{"policyRef":{"name":"all"},"maxDepth":4},"subjectMatch":{}}`)
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"},{"name":"loop"}]}`)
		compiled := f.compile()
		program := compiled.Prepared
		Expect(decide(ctx, program, "get", "pods", "one", "admin").Result).To(Equal(model.Result("Allow")))
		Expect(decide(ctx, program, "get", "pods", "one", "team").Result).To(Equal(model.Result("NoOpinion")))
		Expect(compiled.Diagnostics).To(ContainElement(HaveField("Reason", model.ReasonCycle)))
	})
	It("contains a branch overflow without suppressing independent root and sibling permissions", func(ctx SpecContext) {
		limits := compiler.DefaultLimits()
		limits.MaxBranchNodes = 48
		limits.MaxMergeNodes = 64
		limits.MaxDiagramNodes = 256
		f.limits = limits

		resourceRules := make([]map[string]any, 96)
		for i := range resourceRules {
			resourceRules[i] = map[string]any{
				"apiGroups": []string{""},
				"resources": []string{fmt.Sprintf("resource-%03d", i)},
				"verbs":     []string{"get"},
			}
		}
		noisyPolicy, err := json.Marshal(map[string]any{"include": resourceRules})
		Expect(err).NotTo(HaveOccurred())
		f.custom(model.KindPolicy, "noisy-policy", string(noisyPolicy))
		f.custom(model.KindPolicyBinding, "noisy-binding", `{"policyRef":{"name":"noisy-policy"},"subjects":[{"kind":"User","name":"noisy"}]}`)
		f.custom(model.KindPolicySet, "noisy-child", `{"bindingRefs":[{"name":"noisy-binding"}]}`)
		f.custom(model.KindPolicyBinding, "noisy", `{"policyRef":{"name":"noisy-child","kind":"PolicySet"},"constraints":{"policyRef":{"name":"all"}},"subjectMatch":{}}`)

		f.custom(model.KindPolicy, "sibling-policy", `{"include":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"],"namespaces":["one"]}]}`)
		f.custom(model.KindPolicyBinding, "sibling-binding", `{"policyRef":{"name":"sibling-policy"},"subjects":[{"kind":"User","name":"sibling"}]}`)
		f.custom(model.KindPolicySet, "sibling-child", `{"bindingRefs":[{"name":"sibling-binding"}]}`)
		f.custom(model.KindPolicyBinding, "sibling", `{"policyRef":{"name":"sibling-child","kind":"PolicySet"},"constraints":{"policyRef":{"name":"all"}},"subjectMatch":{}}`)
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"},{"name":"noisy"},{"name":"sibling"}]}`)

		compiled := f.compile()
		program := compiled.Prepared
		Expect(decide(ctx, program, "get", "secrets", "kube-system", "admin").Result).To(Equal(model.Result("Allow")))
		Expect(decide(ctx, program, "get", "pods", "one", "sibling").Result).To(Equal(model.Result("Allow")))
		noisy := decide(ctx, program, "get", "resource-000", "one", "noisy")
		Expect(noisy.Result).To(Equal(model.Result("NoOpinion")))
		Expect(noisy.EvaluationError).To(BeEmpty())
		Expect(compiled.Diagnostics).To(ContainElement(SatisfyAll(
			HaveField("Reason", model.ReasonResourceLimitExceeded),
			HaveField("Message", ContainSubstring("exceeds 48 nodes")),
		)))
		expectProgramWithinLimits(program, limits)
		for _, contribution := range program.Contributions {
			Expect(contribution.Path).NotTo(ContainElement(HaveField("Name", "noisy-policy")))
		}
		again := f.compile().Prepared
		Expect(again).To(Equal(program))
	})
	It("keeps a branch with many principals without dropping valid siblings", func(ctx SpecContext) {
		limits := compiler.DefaultLimits()
		limits.MaxBranchNodes = 512
		limits.MaxMergeNodes = 1024
		limits.MaxDiagramNodes = 4096
		f.limits = limits

		subjects := make([]map[string]string, 256)
		for i := range subjects {
			subjects[i] = map[string]string{"kind": "User", "name": fmt.Sprintf("noisy-principal-%03d", i)}
		}
		noisyBinding, err := json.Marshal(map[string]any{
			"policyRef": map[string]string{"name": "all"},
			"subjects":  subjects,
		})
		Expect(err).NotTo(HaveOccurred())
		f.custom(model.KindPolicyBinding, "noisy-binding", string(noisyBinding))
		f.custom(model.KindPolicySet, "noisy-child", `{"bindingRefs":[{"name":"noisy-binding"}]}`)
		f.custom(model.KindPolicyBinding, "noisy", `{"policyRef":{"name":"noisy-child","kind":"PolicySet"},"constraints":{"policyRef":{"name":"all"}},"subjectMatch":{}}`)

		f.custom(model.KindPolicyBinding, "sibling-binding", `{"policyRef":{"name":"all"},"subjects":[{"kind":"User","name":"sibling"}]}`)
		f.custom(model.KindPolicySet, "sibling-child", `{"bindingRefs":[{"name":"sibling-binding"}]}`)
		f.custom(model.KindPolicyBinding, "sibling", `{"policyRef":{"name":"sibling-child","kind":"PolicySet"},"constraints":{"policyRef":{"name":"all"}},"subjectMatch":{}}`)
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"},{"name":"noisy"},{"name":"sibling"}]}`)

		program := f.compile().Prepared
		Expect(decide(ctx, program, "get", "secrets", "kube-system", "admin").Result).To(Equal(model.Result("Allow")))
		Expect(decide(ctx, program, "get", "pods", "one", "sibling").Result).To(Equal(model.Result("Allow")))
		Expect(decide(ctx, program, "get", "pods", "one", "noisy-principal-000").Result).To(Equal(model.Result("Allow")))
		expectProgramWithinLimits(program, limits)
	})
	It("keeps an existing branch's decisions when authorities are added", func(ctx SpecContext) {
		limits := compiler.DefaultLimits()
		limits.MaxBranchNodes = 128
		f.limits = limits
		resourceRules := make([]map[string]any, 16)
		for i := range resourceRules {
			resourceRules[i] = map[string]any{"apiGroups": []string{""}, "resources": []string{fmt.Sprintf("resource-%03d", i)}, "verbs": []string{"get"}}
		}
		spec, err := json.Marshal(map[string]any{"include": resourceRules})
		Expect(err).NotTo(HaveOccurred())
		f.custom(model.KindPolicy, "wide", string(spec))
		f.custom(model.KindPolicyBinding, "wide", `{"policyRef":{"name":"wide"},"subjects":[{"kind":"User","name":"wide"}]}`)
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"},{"name":"wide"}]}`)

		compiled := f.compile()
		Expect(compiled.Diagnostics).To(BeEmpty())
		before := compiled.Prepared.Endpoints["cluster"].Authorities[0]
		Expect(decide(ctx, compiled.Prepared, "get", "resource-015", "one", "wide").Result).To(Equal(model.Result("Allow")))

		entry := f.config.Endpoints[0].Authorities[0]
		for index := range 7 {
			authority := entry
			authority.Binding.Name = fmt.Sprintf("entry-%d", index)
			f.custom(model.KindPolicyBinding, authority.Binding.Name, `{"policyRef":{"kind":"PolicySet","name":"root"},"subjects":[{"kind":"User","name":"nobody"}]}`)
			f.config.Endpoints[0].Authorities = append(f.config.Endpoints[0].Authorities, authority)
		}
		compiled = f.compile()
		Expect(compiled.Diagnostics).To(BeEmpty())
		Expect(compiled.Prepared.Endpoints["cluster"].Authorities[0]).To(Equal(before))
		Expect(decide(ctx, compiled.Prepared, "get", "resource-015", "one", "wide").Result).To(Equal(model.Result("Allow")))
	})
	DescribeTable("keeps a composed Allow within the traversal depth",
		func(ctx SpecContext, keys int, composed bool) {
			for _, name := range []string{"left", "right"} {
				rules := make([]map[string]any, 0, 1+keys)
				rules = append(rules, map[string]any{"apiGroups": []string{""}, "resources": []string{"pods"}, "verbs": []string{"get"}})
				for index := range keys {
					rules = append(rules, map[string]any{"apiGroups": []string{""}, "resources": []string{"pods"}, "verbs": []string{"list"},
						"labelSelector": map[string]any{"matchExpressions": []any{map[string]any{"key": fmt.Sprintf("%s.example/key-%03d", name, index), "operator": "DoesNotExist"}}}})
				}
				spec, err := json.Marshal(map[string]any{"include": rules})
				Expect(err).NotTo(HaveOccurred())
				f.custom(model.KindPolicy, name, string(spec))
				f.custom(model.KindPolicyBinding, name, fmt.Sprintf(`{"policyRef":{"name":%q},"subjects":[{"kind":"User","name":%q}]}`, name, name))
			}
			f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"left"},{"name":"right"}]}`)

			compiled := f.compile()
			authority := compiled.Prepared.Endpoints["cluster"].Authorities[0]
			if composed {
				Expect(compiled.Diagnostics).To(BeEmpty())
				Expect(authority.ComposedAllowDiagramID).NotTo(BeEmpty())
			} else {
				Expect(compiled.Diagnostics).To(ConsistOf(HaveField("Reason", model.ReasonGrantsNotComposed)))
				Expect(authority.ComposedAllowDiagramID).To(BeEmpty())
				Expect(authority.IndependentAllowDiagramIDs).To(HaveLen(2))
			}
			for _, user := range []string{"left", "right"} {
				Expect(decide(ctx, compiled.Prepared, "get", "pods", "one", user).Result).To(Equal(model.Result("Allow")))
				list := decide(ctx, compiled.Prepared, "list", "pods", "one", user)
				Expect(list.Result).To(Equal(model.Result("NoOpinion")))
				Expect(list.EvaluationError).To(BeEmpty())
			}
		},
		Entry("composing two 50-key bindings", 50, true),
		Entry("falling back from two 100-key bindings", 100, false),
	)
	DescribeTable("classifies a failed entry bound by the entry's target",
		func(ctx SpecContext, entry string, result model.Result, authoritative bool) {
			f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"}]}`)
			f.custom(model.KindPolicyBinding, "entry", entry)
			compiled := f.compile()
			decision := decide(ctx, compiled.Prepared, "get", "pods", "one", "admin")
			Expect(decision.Result).To(Equal(result))
			if authoritative {
				Expect(compiled.Prepared.Issues).To(ConsistOf(HaveField("Reason", model.ReasonMissingReference)))
				Expect(decision.EvaluationError).NotTo(BeEmpty())
			} else {
				Expect(compiled.Prepared.Issues).To(BeEmpty())
				Expect(compiled.Diagnostics).To(ContainElement(HaveField("Reason", model.ReasonMissingReference)))
				Expect(decision.EvaluationError).To(BeEmpty())
			}
		},
		Entry("answering whenNoPolicyAllows for a leaf Policy",
			`{"policyRef":{"name":"all"},"subjectMatch":{},"constraints":{"policyRef":{"name":"missing"}}}`, model.Result("NoOpinion"), false),
		Entry("answering whenEvaluationFails for a PolicySet",
			`{"policyRef":{"kind":"PolicySet","name":"root"},"subjectMatch":{},"constraints":{"policyRef":{"name":"missing"}}}`, model.Result("Deny"), true),
	)
	Context("when root bindings cover a broad request only together", func() {
		// tiers binds two Policies that list Pods in one namespace: one
		// in the frontend tier, the other outside it. Each adds extraKeys rules
		// on selector keys of its own.
		tiers := func(extraKeys int) {
			GinkgoHelper()
			for _, operator := range []string{"In", "NotIn"} {
				name := strings.ToLower(operator)
				rules := make([]map[string]any, 0, 1+extraKeys)
				rules = append(rules, map[string]any{"apiGroups": []string{""}, "resources": []string{"pods"}, "verbs": []string{"list"}, "namespaces": []string{"one"},
					"labelSelector": map[string]any{"matchExpressions": []any{map[string]any{"key": "tier", "operator": operator, "values": []string{"frontend"}}}}})
				for index := range extraKeys {
					rules = append(rules, map[string]any{"apiGroups": []string{""}, "resources": []string{"configmaps"}, "verbs": []string{"get"}, "namespaces": []string{"one"},
						"labelSelector": map[string]any{"matchExpressions": []any{map[string]any{"key": fmt.Sprintf("%s.example/key-%03d", name, index), "operator": "DoesNotExist"}}}})
				}
				spec, err := json.Marshal(map[string]any{"include": rules})
				Expect(err).NotTo(HaveOccurred())
				f.custom(model.KindPolicy, name, string(spec))
				f.custom(model.KindPolicyBinding, name, fmt.Sprintf(`{"policyRef":{"name":%q},"subjectMatch":{}}`, name))
			}
			f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"in"},{"name":"notin"}]}`)
		}
		expectComposed := func(ctx context.Context) {
			GinkgoHelper()
			compiled := f.compile()
			Expect(compiled.Diagnostics).To(BeEmpty())
			Expect(compiled.Prepared.Endpoints["cluster"].Authorities[0].ComposedAllowDiagramID).NotTo(BeEmpty())
			Expect(decide(ctx, compiled.Prepared, "list", "pods", "one", "alice").Result).To(Equal(model.Result("Allow")))
		}
		// expectNotComposed checks that the unfiltered list, which only both
		// bindings together cover, falls back, that each binding still grants
		// its own tier, and that the authority reports why.
		expectNotComposed := func(ctx context.Context, limit string) {
			GinkgoHelper()
			compiled := f.compile()
			authority := compiled.Prepared.Endpoints["cluster"].Authorities[0]
			Expect(authority.ComposedAllowDiagramID).To(BeEmpty())
			Expect(authority.IndependentAllowDiagramIDs).To(HaveLen(2))
			Expect(compiled.Diagnostics).To(ConsistOf(SatisfyAll(
				HaveField("Reason", model.ReasonGrantsNotComposed),
				HaveField("Severity", api.IssueSeverityError),
				HaveField("Authority", authority.Name),
				HaveField("Message", ContainSubstring(limit)),
			)))
			unfiltered := decide(ctx, compiled.Prepared, "list", "pods", "one", "alice")
			Expect(unfiltered.Result).To(Equal(model.Result("NoOpinion")))
			Expect(unfiltered.EvaluationError).To(BeEmpty())
			for _, operator := range []metav1.LabelSelectorOperator{metav1.LabelSelectorOpIn, metav1.LabelSelectorOpNotIn} {
				review := utils.SubjectAccessReview("alice", "list", "pods", "one")
				review.Spec.ResourceAttributes.LabelSelector = &authorizationv1.LabelSelectorAttributes{Requirements: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: operator, Values: []string{"frontend"}}}}
				result, err := utils.Evaluate(ctx, compiled.Prepared, "cluster", review)
				Expect(err).NotTo(HaveOccurred())
				Expect(result.Decision.Result).To(Equal(model.Result("Allow")), "tier %s frontend", operator)
			}
		}
		It("reports that it no longer grants it when the composition exceeds MaxMergeNodes", func(ctx SpecContext) {
			tiers(0)
			expectComposed(ctx)
			f.limits.MaxMergeNodes = 1
			expectNotComposed(ctx, "exceeds 1 nodes")
		})
		It("reports that it no longer grants it when the bindings together exceed MaxSelectorKeys at the default limits", func(ctx SpecContext) {
			tiers(0)
			expectComposed(ctx)
			tiers(compiler.MaxSelectorKeys / 2)
			expectNotComposed(ctx, "selector keys")
		})
	})
	Context("with a bounded entry binding", func() {
		var diagonal func(name, varied string, count int)
		BeforeEach(func() {
			f.custom(model.KindPolicy, "bound", `{"include":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}],"exclude":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"],"namespaces":["outside"]}]}`)
			f.custom(model.KindPolicyBinding, "entry", `{"policyRef":{"kind":"PolicySet","name":"root"},"subjectMatch":{},"constraints":{"policyRef":{"name":"bound"},"maxDepth":4}}`)
			f.custom(model.KindPolicySet, "broken", `{"bindingRefs":[{"name":"missing"}]}`)
			// diagonal pairs each value of one rule field with its own namespace. Each
			// diagram is linear in count, but a union of diagonals over different fields
			// grows with the product of their counts.
			diagonal = func(name, varied string, count int) {
				GinkgoHelper()
				rules := make([]map[string]any, count)
				for i := range rules {
					rules[i] = map[string]any{"apiGroups": []string{"*"}, "resources": []string{"*"}, "verbs": []string{"*"}, "namespaces": []string{fmt.Sprintf("%s-%02d", name, i)}}
					rules[i][varied] = []string{fmt.Sprintf("%s-%02d", strings.ToLower(varied), i)}
				}
				spec, err := json.Marshal(map[string]any{"include": rules})
				Expect(err).NotTo(HaveOccurred())
				f.custom(model.KindPolicy, name, string(spec))
			}
		})
		It("omits an overflowing composed Allow and keeps the independent diagrams", func(ctx SpecContext) {
			limits := compiler.DefaultLimits()
			limits.MaxMergeNodes = 8
			f.limits = limits
			f.custom(model.KindPolicyBinding, "team", `{"policyRef":{"name":"all"},"subjects":[{"kind":"User","name":"team"}]}`)
			f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"},{"name":"team"}]}`)

			compiled := f.compile()
			program := compiled.Prepared
			authority := program.Endpoints["cluster"].Authorities[0]
			Expect(authority.ComposedAllowDiagramID).To(BeEmpty())
			Expect(authority.IndependentAllowDiagramIDs).To(HaveLen(2))
			Expect(program.Issues).To(BeEmpty())
			Expect(compiled.Diagnostics).To(ContainElement(SatisfyAll(
				HaveField("Reason", model.ReasonGrantsNotComposed),
				HaveField("Authority", authority.Name),
				HaveField("Message", ContainSubstring("exceeds 8 nodes")),
			)))
			for _, user := range []string{"admin", "team"} {
				Expect(decide(ctx, program, "get", "pods", "one", user).Result).To(Equal(model.Result("Allow")))
				outside := decide(ctx, program, "get", "pods", "outside", user)
				Expect(outside.Result).To(Equal(model.Result("NoOpinion")))
				Expect(outside.EvaluationError).To(BeEmpty())
			}
			expectProgramWithinLimits(program, limits)
		})
		It("records an overflowing prohibition merge within the entry bound", func(ctx SpecContext) {
			limits := compiler.DefaultLimits()
			limits.MaxBranchNodes = 256
			limits.MaxMergeNodes = 256
			limits.MaxDiagramNodes = 2048
			f.limits = limits
			diagonal("by-resource", "resources", 24)
			diagonal("by-verb", "verbs", 24)
			f.custom(model.KindPolicyBinding, "prohibit-resource", `{"policyRef":{"name":"by-resource"},"subjectMatch":{}}`)
			f.custom(model.KindPolicyBinding, "prohibit-verb", `{"policyRef":{"name":"by-verb"},"subjectMatch":{}}`)
			f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"}],"prohibitionRefs":[{"name":"prohibit-resource"},{"name":"prohibit-verb"}]}`)

			program := f.compile().Prepared
			Expect(program.Issues).To(ConsistOf(SatisfyAll(
				HaveField("Reason", model.ReasonResourceLimitExceeded),
				HaveField("Message", ContainSubstring("merge prohibitions: permission diagram exceeds 256 nodes")),
				HaveField("Path", HaveLen(2)),
			)))
			inside := decide(ctx, program, "get", "pods", "one", "admin")
			Expect(inside.Result).To(Equal(model.Result("Deny")))
			Expect(inside.EvaluationError).NotTo(BeEmpty())
			outside := decide(ctx, program, "get", "pods", "outside", "admin")
			Expect(outside.Result).To(Equal(model.Result("NoOpinion")))
			Expect(outside.EvaluationError).To(BeEmpty())
			expectProgramWithinLimits(program, limits)
		})
		It("answers whenEvaluationFails inside an oversized prohibition's bound", func(ctx SpecContext) {
			limits := compiler.DefaultLimits()
			limits.MaxBranchNodes = 256
			f.limits = limits
			diagonal("oversized", "resources", 200)
			f.custom(model.KindPolicy, "scope", `{"include":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"],"namespaces":["one"]}]}`)
			f.custom(model.KindPolicyBinding, "prohibit", `{"policyRef":{"name":"oversized"},"subjectMatch":{},"constraints":{"policyRef":{"name":"scope"}}}`)
			f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"}],"prohibitionRefs":[{"name":"prohibit"}]}`)

			program := f.compile().Prepared
			Expect(program.Issues).To(ConsistOf(SatisfyAll(
				HaveField("Reason", model.ReasonResourceLimitExceeded),
				HaveField("Message", ContainSubstring("exceeds 256 nodes")),
			)))
			inside := decide(ctx, program, "get", "pods", "one", "admin")
			Expect(inside.Result).To(Equal(model.Result("Deny")))
			Expect(inside.EvaluationError).NotTo(BeEmpty())
			Expect(decide(ctx, program, "get", "pods", "two", "admin").Result).To(Equal(model.Result("Allow")))
			outside := decide(ctx, program, "get", "pods", "outside", "admin")
			Expect(outside.Result).To(Equal(model.Result("NoOpinion")))
			Expect(outside.EvaluationError).To(BeEmpty())
			expectProgramWithinLimits(program, limits)
		})
		DescribeTable("fails the compile only when failures or the program exceed MaxDiagramNodes",
			func(authorities, maxNodes, fieldCount, count int, expected string) {
				limits := compiler.DefaultLimits()
				limits.MaxDiagramNodes = maxNodes
				f.limits = limits
				for index := 1; index < authorities; index++ {
					name := fmt.Sprintf("%s-%d", "entry", index)
					f.custom(model.KindPolicyBinding, name, `{"policyRef":{"kind":"PolicySet","name":"root"},"subjectMatch":{},"constraints":{"policyRef":{"name":"bound"},"maxDepth":4}}`)
					authority := f.config.Endpoints[0].Authorities[0]
					authority.Binding.Name = name
					f.config.Endpoints[0].Authorities = append(f.config.Endpoints[0].Authorities, authority)
				}
				prohibitions := make([]string, 0, fieldCount)
				for _, varied := range []string{"resources", "verbs", "apiGroups", "resourceNames", "apiVersions"}[:fieldCount] {
					field := strings.ToLower(varied)
					diagonal("deny-"+field, varied, count)
					f.custom(model.KindPolicyBinding, "deny-"+field, fmt.Sprintf(`{"policyRef":{"name":"missing"},"subjectMatch":{},"constraints":{"policyRef":{"name":"deny-%s"}}}`, field))
					prohibitions = append(prohibitions, fmt.Sprintf(`{"name":"deny-%s"}`, field))
				}
				f.custom(model.KindPolicySet, "root", fmt.Sprintf(`{"bindingRefs":[{"name":"admin"}],"prohibitionRefs":[%s]}`, strings.Join(prohibitions, ",")))

				_, err := compiler.Compile(f.config, f.sources(), f.limits)
				Expect(err).To(MatchError(model.ErrLimit))
				Expect(err).To(MatchError(ContainSubstring(expected)))
			},
			Entry("across the complete program", 2, 2800, 5, 5, "policy program exceeds its 2800 diagram nodes"),
			Entry("within one authority's failures", 1, 2048, 5, 6, "failures of authority"),
		)
	})
})

var _ = Describe("Rego conditions", func() {
	const (
		podRules    = `[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]`
		secretRules = `[{"apiGroups":[""],"resources":["secrets"],"verbs":["get"]}]`
		inOne       = `allow if input.request.resourceAttributes.namespace == "one"`
		teamUser    = `allow if startswith(input.principal.user, "team")`
	)
	var f *fixture
	var tenant model.SourceKey
	// enter makes the entry binding delegate to the root with the sources
	// local, tenant and extra.
	enter := func(extra ...string) {
		sources := `{"namespace":"control","name":"local"},{"namespace":"control","name":"tenant"}`
		for _, name := range extra {
			sources += `,{"namespace":"control","name":"` + name + `"}`
		}
		f.custom(model.KindPolicyBinding, "entry", `{"policyRef":{"kind":"PolicySet","name":"root"},"subjectMatch":{},"constraints":{"maxDepth":4,"sourceRefs":[`+sources+`]}}`)
	}
	BeforeEach(func() {
		f = newFixture()
		tenant = f.addSource("tenant")
		enter()
		f.allowRego(f.source.Key, condition.DefaultBuiltins())
		f.allowRego(tenant, condition.DefaultBuiltins())
		f.custom(model.KindPolicy, "pods", `{"include":`+podRules+`}`)
		f.custom(model.KindPolicy, "all", `{"include":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]}`)
		f.custom(model.KindPolicyBinding, "admin", `{"policyRef":{"name":"all"},"subjects":[{"kind":"User","name":"admin"}]}`)
	})
	// conditionIDs returns the condition IDs of the program's contributions.
	conditionIDs := func(program model.PreparedRevision) [][]string {
		ids := make([][]string, 0, len(program.Contributions))
		for _, contribution := range program.Contributions {
			ids = append(ids, contribution.ConditionIDs)
		}
		return ids
	}

	It("carries a bound's condition into the PolicySet's descendants", func(ctx SpecContext) {
		f.custom(model.KindPolicy, "one-only", conditional(podRules, inOne))
		f.custom(model.KindPolicyBinding, "team", `{"policyRef":{"name":"pods"},"subjects":[{"kind":"User","name":"team"}]}`)
		f.custom(model.KindPolicySet, "child", `{"bindingRefs":[{"name":"team"}]}`)
		f.custom(model.KindPolicyBinding, "delegate", `{"policyRef":{"kind":"PolicySet","name":"child"},"subjectMatch":{},"constraints":{"policyRef":{"name":"one-only"}}}`)
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"delegate"}]}`)
		program := f.compile().Prepared
		Expect(program.Conditions).To(HaveLen(1))
		Expect(conditionIDs(program)).To(ConsistOf(ConsistOf(BeKeyOf(program.Conditions))))
		Expect(decide(ctx, program, "get", "pods", "one", "team").Result).To(Equal(model.Result("Allow")))
		Expect(decide(ctx, program, "get", "pods", "two", "team").Result).To(Equal(model.Result("NoOpinion")))
	})

	DescribeTable("fails a prohibition that would carry a condition over its bound",
		func(ctx SpecContext, setup func()) {
			f.custom(model.KindPolicy, "conditional-secrets", conditional(secretRules, `allow if true`))
			f.custom(model.KindPolicy, "secrets", `{"include":`+secretRules+`}`)
			setup()
			compiled := f.compile()
			Expect(compiled.Prepared.Issues).To(ContainElement(HaveField("Reason", model.ReasonConditionalProhibition)))
			result := decide(ctx, compiled.Prepared, "get", "secrets", "one", "admin")
			Expect(result.Result).To(Equal(model.Result("Deny")))
			Expect(result.EvaluationError).NotTo(BeEmpty())
		},
		Entry("through its target", func() {
			f.custom(model.KindPolicyBinding, "prohibit", `{"policyRef":{"name":"conditional-secrets"},"subjectMatch":{}}`)
			f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"}],"prohibitionRefs":[{"name":"prohibit"}]}`)
		}),
		Entry("through its bound", func() {
			f.custom(model.KindPolicyBinding, "prohibit", `{"policyRef":{"name":"secrets"},"subjectMatch":{},"constraints":{"policyRef":{"name":"conditional-secrets"}}}`)
			f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"}],"prohibitionRefs":[{"name":"prohibit"}]}`)
		}),
		Entry("through the entry's bound over a root with prohibitions", func() {
			f.custom(model.KindPolicy, "conditional-all", conditional(`[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]`, `allow if true`))
			f.custom(model.KindPolicyBinding, "entry", `{"policyRef":{"kind":"PolicySet","name":"root"},"subjectMatch":{},"constraints":{"maxDepth":4,"policyRef":{"name":"conditional-all"}}}`)
			f.custom(model.KindPolicyBinding, "prohibit", `{"policyRef":{"name":"secrets"},"subjectMatch":{}}`)
			f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"}],"prohibitionRefs":[{"name":"prohibit"}]}`)
		}),
	)

	It("keeps only the conditions its contributions carry", func() {
		f.custom(model.KindPolicy, "conditional-secrets", conditional(secretRules, `allow if true`))
		f.custom(model.KindPolicy, "secrets", `{"include":`+secretRules+`}`)
		f.custom(model.KindPolicyBinding, "prohibit", `{"policyRef":{"name":"secrets"},"subjectMatch":{},"constraints":{"policyRef":{"name":"conditional-secrets"}}}`)
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"admin"}],"prohibitionRefs":[{"name":"prohibit"}]}`)
		Expect(f.compile().Prepared.Conditions).To(BeEmpty())
	})

	DescribeTable("refuses a condition a source on its path doesn't allow, naming that source",
		func(setup func(), source string) {
			setup()
			compiled := f.compile()
			Expect(compiled.Diagnostics).To(ContainElement(SatisfyAll(
				HaveField("Reason", model.ReasonRegoNotAllowed),
				HaveField("Message", "source "+source+" doesn't allow Rego conditions"),
			)))
			Expect(compiled.Prepared.Conditions).To(BeEmpty())
		},
		Entry("in the Policy's own source", func() {
			f.observation.AllowedBuiltins = nil
			f.custom(model.KindPolicy, "one-only", conditional(podRules, inOne))
			f.custom(model.KindPolicyBinding, "team", `{"policyRef":{"name":"one-only"},"subjectMatch":{}}`)
			f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"team"}]}`)
		}, "control/local"),
		Entry("beneath bindings and a root PolicySet in a source without rego", func() {
			f.observation.AllowedBuiltins = nil
			f.customIn(tenant, model.KindPolicy, "one-only", conditional(podRules, inOne))
			f.custom(model.KindPolicyBinding, "team", `{"policyRef":{"name":"one-only","sourceRef":{"namespace":"control","name":"tenant"}},"subjectMatch":{}}`)
			f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"team"}]}`)
		}, "control/local"),
		Entry("beneath a child PolicySet in a source without rego", func() {
			plain := f.addSource("plain")
			enter("plain")
			f.customIn(tenant, model.KindPolicy, "one-only", conditional(podRules, inOne))
			f.customIn(plain, model.KindPolicyBinding, "team", `{"policyRef":{"name":"one-only","sourceRef":{"namespace":"control","name":"tenant"}},"subjectMatch":{}}`)
			f.customIn(plain, model.KindPolicySet, "child", `{"bindingRefs":[{"name":"team"}]}`)
			f.custom(model.KindPolicyBinding, "delegate", `{"policyRef":{"kind":"PolicySet","name":"child","sourceRef":{"namespace":"control","name":"plain"}},"subjectMatch":{},
				"constraints":{"sourceRefs":[{"namespace":"control","name":"plain"},{"namespace":"control","name":"tenant"}]}}`)
			f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"delegate"}]}`)
		}, "control/plain"),
	)

	It("keeps a condition on a Policy importing roles from a source without rego", func(ctx SpecContext) {
		rbac := f.addSource("rbac")
		enter("rbac")
		f.putIn(rbac, utils.NativeDocument(model.KindClusterRole, "", "pod-reader", `{"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]}`))
		rego, err := json.Marshal("package condition\n" + inOne + "\n")
		Expect(err).NotTo(HaveOccurred())
		f.custom(model.KindPolicy, "imported", `{"imports":[{"kind":"ClusterRole","name":"pod-reader","sourceRef":{"namespace":"control","name":"rbac"}}],"condition":{"rego":`+string(rego)+`}}`)
		f.custom(model.KindPolicyBinding, "team", `{"policyRef":{"name":"imported"},"subjectMatch":{}}`)
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"team"}]}`)
		compiled := f.compile()
		Expect(compiled.Diagnostics).To(BeEmpty())
		Expect(decide(ctx, compiled.Prepared, "get", "pods", "one", "team").Result).To(Equal(model.Result("Allow")))
		Expect(decide(ctx, compiled.Prepared, "get", "pods", "two", "team").Result).To(Equal(model.Result("NoOpinion")))
	})

	It("keeps a condition on a bound in a source other than the path's", func(ctx SpecContext) {
		f.customIn(tenant, model.KindPolicy, "one-only", conditional(podRules, inOne))
		f.custom(model.KindPolicyBinding, "team", `{"policyRef":{"name":"pods"},"subjectMatch":{},"constraints":{"policyRef":{"name":"one-only","sourceRef":{"namespace":"control","name":"tenant"}}}}`)
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"team"}]}`)
		program := f.compile().Prepared
		Expect(conditionIDs(program)).To(ConsistOf(HaveLen(1)))
		Expect(decide(ctx, program, "get", "pods", "one", "team").Result).To(Equal(model.Result("Allow")))
	})

	DescribeTable("refuses a condition calling builtins its path doesn't allow",
		func(setup func(), allow, missing string) {
			setup()
			f.customIn(tenant, model.KindPolicy, "conditional", conditional(podRules, allow))
			if _, found := f.observation.Documents[model.Reference{Source: f.source.Key, Group: api.GroupVersion.Group, Kind: model.KindPolicySet, Namespace: "policies", Name: "root"}]; !found {
				f.custom(model.KindPolicyBinding, "team", `{"policyRef":{"name":"conditional","sourceRef":{"namespace":"control","name":"tenant"}},"subjectMatch":{}}`)
				f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"team"}]}`)
			}
			compiled := f.compile()
			Expect(compiled.Diagnostics).To(ContainElement(SatisfyAll(
				HaveField("Reason", model.ReasonBuiltinNotAllowed),
				HaveField("Message", "condition calls builtins this path doesn't allow: "+missing),
			)))
		},
		Entry("against the default builtins", func() {}, `allow if count(numbers.range(1, 3)) == 3`, "numbers.range"),
		Entry("against its own source's list", func() {
			f.allowRego(tenant, model.BuiltinSet{"startswith"})
		}, `allow if endswith(input.principal.user, "a")`, "endswith"),
		Entry("against the intersection along its delegation", func() {
			f.allowRego(f.source.Key, model.BuiltinSet{"startswith"})
			f.allowRego(tenant, model.BuiltinSet{"endswith", "startswith"})
		}, `allow if endswith(input.principal.user, "a")`, "endswith"),
		Entry("against the service's ceiling", func() {
			f.config.BuiltinCeiling = &model.BuiltinSet{"startswith"}
		}, `allow if endswith(input.principal.user, "a")`, "endswith"),
	)

	It("keeps an ancestor's bound condition beneath a stricter delegated source", func(ctx SpecContext) {
		f.allowRego(tenant, model.BuiltinSet{})
		f.custom(model.KindPolicy, "teams", conditional(podRules, teamUser))
		f.customIn(tenant, model.KindPolicy, "pods", `{"include":`+podRules+`}`)
		f.customIn(tenant, model.KindPolicyBinding, "members", `{"policyRef":{"name":"pods"},"subjectMatch":{}}`)
		f.customIn(tenant, model.KindPolicySet, "child", `{"bindingRefs":[{"name":"members"}]}`)
		f.custom(model.KindPolicyBinding, "delegate", `{"policyRef":{"kind":"PolicySet","name":"child","sourceRef":{"namespace":"control","name":"tenant"}},"subjectMatch":{},"constraints":{"policyRef":{"name":"teams"}}}`)
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"delegate"}]}`)
		compiled := f.compile()
		Expect(compiled.Diagnostics).To(BeEmpty())
		Expect(conditionIDs(compiled.Prepared)).To(ConsistOf(HaveLen(1)))
		Expect(decide(ctx, compiled.Prepared, "get", "pods", "one", "team-a").Result).To(Equal(model.Result("Allow")))
		Expect(decide(ctx, compiled.Prepared, "get", "pods", "one", "alice").Result).To(Equal(model.Result("NoOpinion")))
	})
})
