package validation_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/validation"
	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("DecodeDocument", func() {
	It("takes the address from the object and the source from the caller", func() {
		object := customDocument("Policy", "reader", `{"include":[]}`)
		state := validation.DecodeDocument(tenantSource, object)
		Expect(state.Document).NotTo(BeNil(), issueMessage(state))
		Expect(state.Key).To(Equal(model.DocumentKey{Source: tenantSource, Group: api.GroupVersion.Group, Kind: "Policy", Namespace: "tenant", Name: "reader"}))
		Expect(state.UID).To(Equal("reader" + "-uid"))
		Expect(state.Document.Key).To(Equal(state.Key))
	})

	DescribeTable("rejects a field the Go types don't declare, at any depth",
		func(object *unstructured.Unstructured, field string) {
			state := validation.DecodeDocument(tenantSource, object)
			Expect(state.Document).To(BeNil())
			Expect(state.Issues).To(ConsistOf(SatisfyAll(
				HaveField("Severity", api.IssueSeverityError),
				HaveField("Reason", model.ReasonInvalid),
				HaveField("Message", ContainSubstring(fmt.Sprintf("unknown field %q", field))),
				HaveField("Document", &state.Key),
			)))
		},
		Entry("beside spec", withField(customDocument("Policy", "top", `{"include":[]}`), "status"), "status"),
		Entry("in metadata", withField(customDocument("Policy", "metadata", `{"include":[]}`), "metadata"), "metadata.unexpected"),
		Entry("in a Policy spec", customDocument("Policy", "spec", `{"include":[],"exlude":[]}`), "spec.exlude"),
		Entry("in an operation rule", customDocument("Policy", "rule", `{"include":[{"verbs":["get"],"apiGroups":[""],"resources":["pods"],"unknown":true}]}`), "spec.include[0].unknown"),
		Entry("in a label selector requirement", customDocument("Policy", "selector", `{"include":[{"verbs":["list"],"apiGroups":[""],"resources":["pods"],"labelSelector":{"matchExpressions":[{"key":"team","operator":"In","values":["blue"],"unknown":true}]}}]}`), "spec.include[0].labelSelector.matchExpressions[0].unknown"),
		Entry("in an import", customDocument("Policy", "import", `{"include":[],"imports":[{"kind":"ClusterRole","name":"view","unknown":true}]}`), "spec.imports[0].unknown"),
		Entry("in a policyRef", customDocument(model.KindPolicyBinding, "ref", `{"policyRef":{"name":"reader","unknown":true},"subjects":[{"kind":"User","name":"alice"}]}`), "spec.policyRef.unknown"),
		Entry("in a sourceRef", customDocument(model.KindPolicyBinding, "source", `{"policyRef":{"name":"reader","namespace":"tenant","sourceRef":{"namespace":"control","name":"remote","unknown":true}},"subjects":[{"kind":"User","name":"alice"}]}`), "spec.policyRef.sourceRef.unknown"),
		Entry("in a subject", customDocument(model.KindPolicyBinding, "subject", `{"policyRef":{"name":"reader"},"subjects":[{"kind":"User","name":"alice","unknown":true}]}`), "spec.subjects[0].unknown"),
		Entry("in a subject requirement", customDocument(model.KindPolicyBinding, "requirement", `{"policyRef":{"name":"reader"},"subjectMatch":{"requirements":[{"kind":"Group","operator":"Exists","unknown":true}]}}`), "spec.subjectMatch.requirements[0].unknown"),
		Entry("in constraints", customDocument(model.KindPolicyBinding, "constraints", `{"policyRef":{"kind":"PolicySet","name":"child"},"subjectMatch":{},"constraints":{"maxDepth":1,"unknown":true}}`), "spec.constraints.unknown"),
		Entry("in a PolicySet reference", customDocument("PolicySet", "set", `{"bindingRefs":[{"name":"reader","unknown":true}]}`), "spec.bindingRefs[0].unknown"),
		Entry("in a native Role rule", nativeDocument(model.KindRole, "role", `{"rules":[{"verbs":["get"],"apiGroups":[""],"resources":["pods"],"unknown":true}]}`), "rules[0].unknown"),
		Entry("in a native RoleBinding subject", nativeDocument(model.KindRoleBinding, "binding", `{"subjects":[{"kind":"Group","apiGroup":"rbac.authorization.k8s.io","name":"operators","unknown":true}],"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"reader"}}`), "subjects[0].unknown"),
		Entry("in a native roleRef", nativeDocument(model.KindRoleBinding, "role-ref", `{"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"reader","unknown":true}}`), "roleRef.unknown"),
		Entry("as an aggregation rule on a Role", nativeDocument(model.KindRole, "aggregated", `{"aggregationRule":{}}`), "aggregationRule"),
	)

	It("drops a field the Go types don't declare from a cached document", func() {
		object := customDocument("Policy", "cached", `{"include":[{"verbs":["get"],"apiGroups":[""],"resources":["pods"],"namespaces":["*"],"removed":true}],"retired":{}}`)
		cached := validation.DecodeCachedDocument(tenantSource, object)
		Expect(cached.Document).NotTo(BeNil(), issueMessage(cached))
		Expect(validation.DecodeDocument(tenantSource, object).Document).To(BeNil())
		current := validation.DecodeDocument(tenantSource, customDocument("Policy", "cached", `{"include":[{"verbs":["get"],"apiGroups":[""],"resources":["pods"],"namespaces":["*"]}]}`))
		Expect(cached.Digest).To(Equal(current.Digest))
	})

	DescribeTable("rejects a document the schema admits but the semantics don't",
		func(object *unstructured.Unstructured, fragment string) {
			state := validation.DecodeDocument(tenantSource, object)
			Expect(state.Document).To(BeNil())
			Expect(state.Issues).To(ConsistOf(SatisfyAll(
				HaveField("Reason", model.ReasonInvalid),
				HaveField("Message", ContainSubstring(fragment)),
			)))
		},
		Entry("an uppercase verb", customDocument("Policy", "verb", `{"include":[{"verbs":["GET"],"apiGroups":[""],"resources":["pods"]}]}`), `spec.include[0]: Invalid value: invalid verb "GET"`),
		Entry("a partial resource wildcard", customDocument("Policy", "resource", `{"exclude":[{"verbs":["get"],"apiGroups":[""],"resources":["pods/*"]}],"include":[]}`), `spec.exclude[0]: Invalid value: invalid resource "pods/*"`),
		Entry("a contradictory selector", customDocument("Policy", "selector", `{"include":[{"verbs":["list"],"apiGroups":[""],"resources":["pods"],"labelSelector":{"matchLabels":{"team":"a"},"matchExpressions":[{"key":"team","operator":"DoesNotExist"}]}}]}`), "contradictory selector"),
		Entry("a ServiceAccount subject that forges a user name", customDocument(model.KindPolicyBinding, "forged", `{"policyRef":{"name":"reader"},"subjects":[{"kind":"ServiceAccount","namespace":"tenant","name":"a:b"}]}`), "spec.subjects"),
		Entry("constraints.sourceRefs without the target's source", customDocument(model.KindPolicyBinding, "sources", `{"policyRef":{"kind":"PolicySet","name":"access","namespace":"elastic-system","sourceRef":{"namespace":"control","name":"elk"}},"subjectMatch":{},"constraints":{"sourceRefs":[{"namespace":"control","name":"platform"}]}}`), "spec.constraints.sourceRefs"),
		Entry("a native ServiceAccount subject name that forges a user name", nativeDocument(model.KindRoleBinding, "native", `{"subjects":[{"kind":"ServiceAccount","name":"a:b"}],"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"reader"}}`), "subjects[0]"),
		Entry("an unsupported kind", utils.NativeDocument("ConfigMap", "tenant", "other", `{}`), "kind: Unsupported value"),
	)

	It("checks a Policy's condition and keeps it with its builtins", func() {
		state := validation.DecodeDocument(tenantSource, customDocument("Policy", "conditional", `{
			"include":[{"verbs":["get"],"apiGroups":[""],"resources":["pods"],"namespaces":["tenant"]}],
			"condition":{"rego":"package condition\nallow if startswith(input.principal.user, \"alice\")\n"}
		}`))
		Expect(state.Document).NotTo(BeNil(), issueMessage(state))
		Expect(state.Issues).To(BeEmpty())
		Expect(state.Document.Policy.Include).To(HaveLen(1))
		Expect(state.Document.Policy.Condition).To(HaveValue(SatisfyAll(
			HaveField("ID", model.Digest("package condition\nallow if startswith(input.principal.user, \"alice\")\n")),
			HaveField("Builtins", model.BuiltinSet{"startswith"}),
		)))
	})

	It("reports a condition outside the language at spec.condition.rego", func() {
		state := validation.DecodeDocument(tenantSource, customDocument("Policy", "conditional", `{"include":[],"condition":{"rego":"package other\nallow if true\n"}}`))
		Expect(state.Document).To(BeNil())
		Expect(state.Issues).To(ConsistOf(SatisfyAll(
			HaveField("Reason", model.ReasonInvalid),
			HaveField("Message", ContainSubstring("spec.condition.rego: Invalid value: 1:1: package must be condition")),
		)))
	})

	It("gives a condition without include or imports the universal envelope, with a warning", func() {
		state := validation.DecodeDocument(tenantSource, customDocument("Policy", "universal", `{"condition":{"rego":"package condition\nallow if input.principal.user == \"alice\"\n"}}`))
		Expect(state.Document).NotTo(BeNil(), issueMessage(state))
		Expect(state.Document.Policy.Include).To(Equal([]model.Cube{{}}))
		Expect(state.Issues).To(ConsistOf(SatisfyAll(
			HaveField("Severity", api.IssueSeverityWarning),
			HaveField("Reason", model.ReasonUniversalEnvelope),
		)))
	})

	It("keeps an explicitly empty include with a condition empty", func() {
		state := validation.DecodeDocument(tenantSource, customDocument("Policy", "empty", `{"include":[],"condition":{"rego":"package condition\nallow if true\n"}}`))
		Expect(state.Document).NotTo(BeNil(), issueMessage(state))
		Expect(state.Document.Policy.Include).To(BeEmpty())
		Expect(state.Issues).To(BeEmpty())
	})

	It("merges repeated imports, set references and principals", func() {
		policy := validation.DecodeDocument(tenantSource, customDocument("Policy", "imports", `{"include":[],"imports":[
			{"kind":"ClusterRole","name":"view","namespaces":["b","a"]},
			{"kind":"ClusterRole","name":"view","apiGroup":"rbac.authorization.k8s.io","namespaces":["a","b"]}
		]}`))
		Expect(policy.Document).NotTo(BeNil(), issueMessage(policy))
		Expect(policy.Document.Policy.Imports).To(ConsistOf(HaveField("Namespaces", []string{"a", "b"})))

		set := validation.DecodeDocument(tenantSource, customDocument("PolicySet", "root", `{"bindingRefs":[{"name":"reader"},{"name":"reader","kind":"PolicyBinding"}],"prohibitionRefs":[{"name":"blocked"},{"name":"blocked"}]}`))
		Expect(set.Document).NotTo(BeNil(), issueMessage(set))
		Expect(set.Document.Set.Bindings).To(HaveLen(1))
		Expect(set.Document.Set.Prohibitions).To(HaveLen(1))

		binding := validation.DecodeDocument(tenantSource, customDocument(model.KindPolicyBinding, "principals", `{"policyRef":{"name":"reader"},"subjects":[{"kind":"User","name":"system:serviceaccount:tenant:web"},{"kind":"ServiceAccount","namespace":"tenant","name":"web"}]}`))
		Expect(binding.Document).NotTo(BeNil(), issueMessage(binding))
		Expect(binding.Document.Binding.Principal.Subjects).To(ConsistOf(model.PrincipalSubject{Kind: model.KindUser, Name: "system:serviceaccount:tenant:web"}))
	})

	It("warns about each exclusion that also affects empty-namespace requests", func() {
		state := validation.DecodeDocument(tenantSource, customDocument("Policy", "excluded", `{
			"include":[],
			"exclude":[
				{"verbs":["delete"],"apiGroups":["*"],"resources":["*"],"namespaces":["kube-system"]},
				{"verbs":["delete"],"apiGroups":["*"],"resources":["*"],"namespaces":[""]}
			]
		}`))
		Expect(state.Document).NotTo(BeNil(), issueMessage(state))
		Expect(state.Issues).To(ConsistOf(SatisfyAll(
			HaveField("Severity", api.IssueSeverityWarning),
			HaveField("Reason", model.ReasonNamespaceScopeConservative),
			HaveField("Scope", api.IssueScopeDocument),
			HaveField("Document", &state.Key),
		)))
	})

	DescribeTable("lints rules whose namespace scope differs from how they read",
		func(spec string, reason model.IssueReason) {
			state := validation.DecodeDocument(tenantSource, customDocument("Policy", "linted", spec))
			Expect(state.Document).NotTo(BeNil(), issueMessage(state))
			Expect(state.Issues).To(ConsistOf(SatisfyAll(HaveField("Severity", api.IssueSeverityWarning), HaveField("Reason", reason))))
		},
		Entry("a wildcard rule scoped to named namespaces, which widens a prohibition",
			`{"include":[{"verbs":["delete"],"apiGroups":["*"],"resources":["*"],"namespaces":["kube-system"]}]}`, model.ReasonNamespaceScopeConservative),
		Entry("a collection rule on every named namespace but not the empty one",
			`{"include":[{"verbs":["list"],"apiGroups":[""],"resources":["pods"],"namespaces":["*"]}]}`, model.ReasonAllNamespacesNotGranted),
	)

	It("doesn't lint resource-specific or empty-namespace rules", func() {
		for index, spec := range []string{
			`{"include":[],"exclude":[{"verbs":["delete"],"apiGroups":["apps"],"resources":["deployments"],"namespaces":["kube-system"]}]}`,
			`{"include":[],"exclude":[{"verbs":["delete"],"apiGroups":["*"],"resources":["*"],"namespaces":["kube-system",""]}]}`,
			`{"include":[{"verbs":["list"],"apiGroups":[""],"resources":["pods"],"namespaces":["*",""]}]}`,
		} {
			state := validation.DecodeDocument(tenantSource, customDocument("Policy", fmt.Sprintf("no-warning-%d", index), spec))
			Expect(state.Document).NotTo(BeNil(), issueMessage(state))
			Expect(state.Issues).To(BeEmpty())
		}
	})

	It("digests a document's warnings with its content", func() {
		warned := validation.DecodeDocument(tenantSource, customDocument("Policy", "digested", `{"include":[{"verbs":["list"],"apiGroups":[""],"resources":["pods"],"namespaces":["*"]}]}`))
		quiet := validation.DecodeDocument(tenantSource, customDocument("Policy", "digested", `{"include":[{"verbs":["get"],"apiGroups":[""],"resources":["pods"],"namespaces":["*"]}]}`))
		Expect(warned.Issues).To(HaveLen(1))
		Expect(quiet.Issues).To(BeEmpty())
		Expect(warned.Digest).NotTo(Equal(quiet.Digest))
		again := validation.DecodeDocument(tenantSource, customDocument("Policy", "digested", `{"include":[{"verbs":["list"],"apiGroups":[""],"resources":["pods"],"namespaces":["*"]}]}`))
		Expect(again.Digest).To(Equal(warned.Digest))
	})

	DescribeTable("resolves references relative to the referencing document",
		func(policyRef string, expected model.Reference) {
			state := validation.DecodeDocument(tenantSource, customDocument(model.KindPolicyBinding, "operators", `{"policyRef":`+policyRef+`,"subjects":[{"kind":"Group","name":"operators"}]}`))
			Expect(state.Document).NotTo(BeNil(), issueMessage(state))
			Expect(state.Document.Binding.Policy).To(Equal(expected))
		},
		Entry("a Policy in the same source and namespace", `{"name":"reader"}`,
			model.Reference{Source: tenantSource.Key, Group: api.GroupVersion.Group, Kind: "Policy", Namespace: "tenant", Name: "reader"}),
		Entry("a Role in another source", `{"kind":"Role","name":"reader","namespace":"workloads","sourceRef":{"namespace":"control","name":"remote"}}`,
			model.Reference{Source: model.SourceKey{Namespace: "control", Name: "remote"}, Group: rbacv1.GroupName, Kind: model.KindRole, Namespace: "workloads", Name: "reader"}),
		Entry("a ClusterRole in another source", `{"kind":"ClusterRole","name":"view","sourceRef":{"namespace":"control","name":"remote"}}`,
			model.Reference{Source: model.SourceKey{Namespace: "control", Name: "remote"}, Group: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"}),
	)

	It("keeps imports, namespace filters and exclusions as separate operands", func() {
		state := validation.DecodeDocument(tenantSource, customDocument("Policy", "access", `{
			"include":[{"verbs":["get"],"apiGroups":[""],"resources":["pods"],"namespaces":["tenant"]}],
			"imports":[{"kind":"ClusterRole","name":"view","namespaces":["safe","tenant"]}],
			"exclude":[{"verbs":["get"],"apiGroups":[""],"resources":["secrets"],"namespaces":["tenant"]}]
		}`))
		Expect(state.Document).NotTo(BeNil(), issueMessage(state))
		Expect(state.Document.Policy.Include).To(HaveLen(1))
		Expect(state.Document.Policy.Imports).To(ConsistOf(HaveField("Namespaces", []string{"safe", "tenant"})))
		Expect(state.Document.Policy.Exclude).To(HaveLen(1))
	})

	It("resolves a bound in the declaring source and namespace", func() {
		state := validation.DecodeDocument(tenantSource, customDocument(model.KindPolicyBinding, "to-elk", `{
			"policyRef":{"kind":"PolicySet","name":"access","namespace":"elastic-system","sourceRef":{"namespace":"control","name":"elk"}},
			"subjectMatch":{},"constraints":{"policyRef":{"name":"bound"},"maxDepth":0}
		}`))
		Expect(state.Document).NotTo(BeNil(), issueMessage(state))
		binding := state.Document.Binding
		Expect(binding.Bound.Source).To(Equal(tenantSource.Key))
		Expect(binding.Bound.Namespace).To(Equal("tenant"))
		Expect(binding.Policy.Source).To(Equal(model.SourceKey{Namespace: "control", Name: "elk"}))
		Expect(binding.Sources).To(BeNil())
		Expect(binding.MaxDepth).To(Equal(new(0)))
		Expect(binding.Principal).To(Equal(model.AllPrincipals()))
	})

	It("applies RoleBinding namespace semantics to native subjects", func() {
		state := validation.DecodeDocument(tenantSource, nativeDocument(model.KindRoleBinding, "operators", `{
			"subjects":[{"kind":"ServiceAccount","name":"controller"}],
			"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"view"}
		}`))
		Expect(state.Document).NotTo(BeNil(), issueMessage(state))
		Expect(state.Document.Binding.Namespace).To(Equal("tenant"))
		Expect(state.Document.Binding.Policy).To(Equal(model.Reference{Source: tenantSource.Key, Group: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"}))
		Expect(state.Document.Binding.Principal).To(Equal(model.Matcher{Kind: model.MatcherSubjects, Subjects: []model.PrincipalSubject{{Kind: model.KindUser, Name: "system:serviceaccount:tenant:controller"}}}))
	})

	It("restricts native Role rules to the Role's namespace", func() {
		state := validation.DecodeDocument(tenantSource, nativeDocument(model.KindRole, "reader", `{
			"rules":[{"verbs":["get"],"apiGroups":[""],"resources":["*"]}]
		}`))
		Expect(state.Document).NotTo(BeNil(), issueMessage(state))
		Expect(state.Document.Policy.Include).To(HaveLen(1))
		Expect(state.Document.Policy.Include[0][model.AffectedNamespace].Contains(model.Atom("tenant"))).To(BeTrue())
		Expect(state.Document.Policy.Include[0][model.AffectedNamespace].Contains(model.Atom("other"))).To(BeFalse())
		Expect(state.Issues).To(BeEmpty())
	})
})

func withField(object *unstructured.Unstructured, parent string) *unstructured.Unstructured {
	GinkgoHelper()
	Expect(unstructured.SetNestedField(object.Object, true, parent, "unexpected")).To(Succeed())
	return object
}
