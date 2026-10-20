//go:build integration

package integration

import (
	"context"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/test/utils"
)

const (
	grantRule    = `{"verbs":["get"],"apiGroups":[""],"resources":["pods"]}`
	groupSubject = `"subjects":[{"kind":"Group","name":"readers"}]`
	crossSource  = `"sourceRef":{"namespace":"control","name":"remote"}`
)

func rulePolicy(rule string) *unstructured.Unstructured {
	return ruleDocument(model.KindPolicy, "policy", `{"include":[`+rule+`]}`)
}

func ruleBinding(spec string) *unstructured.Unstructured {
	return ruleDocument(model.KindPolicyBinding, "binding", `{`+spec+`}`)
}

func importingPolicy(reference string) *unstructured.Unstructured {
	return ruleDocument(model.KindPolicy, "policy", `{"include":[`+grantRule+`],"imports":[`+reference+`]}`)
}

func bindingSet(reference string) *unstructured.Unstructured {
	return ruleDocument(model.KindPolicySet, "set", `{"bindingRefs":[`+reference+`]}`)
}

func collectingSource(keyRange string) *unstructured.Unstructured {
	return ruleDocument("PolicySource", "source", `{"provider":{"type":"Kubernetes"},"collection":[`+keyRange+`]}`)
}

// longSource returns a PolicySource whose name is one character longer than
// a label value can be.
func longSource() *unstructured.Unstructured {
	object := collectingSource(`{"kinds":["Policy"],"namespaces":["*"],"names":["*"]}`)
	object.SetName(strings.Repeat("a", 64))
	return object
}

func matchingBinding(requirement string) *unstructured.Unstructured {
	return ruleBinding(`"policyRef":{"name":"policy"},"subjectMatch":{"requirements":[` + requirement + `]}`)
}

func ruleService(mutate func(*api.AuthorizationService)) client.Object {
	object := utils.AuthorizationService(types.NamespacedName{Namespace: rulesNamespace, Name: "authz"})
	object.UID, object.Generation = "", 0
	mutate(object)
	return object
}

var _ = Describe("Validation rules", func() {
	BeforeEach(func(ctx context.Context) {
		ensureNamespace(ctx, rulesNamespace)
	})

	DescribeTable("reject what they guard",
		func(ctx context.Context, object client.Object, message string) {
			err := k8sClient.Create(ctx, object, strict)
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "%v", err)
			Expect(err.Error()).To(ContainSubstring(message))
		},
		Entry("a policy reference whose apiGroup does not match its kind",
			ruleBinding(groupSubject+`,"policyRef":{"kind":"ClusterRole","apiGroup":"authorization.zctx.io","name":"view"}`), "apiGroup must match kind"),
		Entry("a ClusterRole policy reference with a namespace",
			ruleBinding(groupSubject+`,"policyRef":{"kind":"ClusterRole","namespace":"team","name":"view"}`), "namespace is forbidden for ClusterRole"),
		Entry("a cross-source policy reference without a namespace",
			ruleBinding(groupSubject+`,"policyRef":{"name":"policy",`+crossSource+`}`), "a reference into another source requires namespace"),
		Entry("an import outside the RBAC group",
			importingPolicy(`{"kind":"Role","apiGroup":"authorization.zctx.io","name":"view"}`), "apiGroup must be rbac.authorization.k8s.io"),
		Entry("a ClusterRole import with a namespace",
			importingPolicy(`{"kind":"ClusterRole","namespace":"team","name":"view"}`), "namespace is forbidden for ClusterRole"),
		Entry("a cross-source Role import without a namespace",
			importingPolicy(`{"kind":"Role","name":"view",`+crossSource+`}`), "a reference into another source requires namespace"),
		Entry("a binding reference whose apiGroup does not match its kind",
			bindingSet(`{"kind":"RoleBinding","apiGroup":"authorization.zctx.io","name":"view"}`), "apiGroup must match kind"),
		Entry("a ClusterRoleBinding reference with a namespace",
			bindingSet(`{"kind":"ClusterRoleBinding","namespace":"team","name":"view"}`), "namespace is forbidden for ClusterRoleBinding"),
		Entry("a cross-source binding reference without a namespace",
			bindingSet(`{"name":"binding",`+crossSource+`}`), "a reference into another source requires namespace"),
		Entry("a key range mixing cluster-scoped and namespaced kinds",
			collectingSource(`{"kinds":["ClusterRole","Policy"],"namespaces":["team"],"names":["*"]}`), "kinds must be all cluster-scoped or all namespaced"),
		Entry("a namespaced key range without namespaces",
			collectingSource(`{"kinds":["Policy"],"names":["*"]}`), "namespaces is required for namespaced kinds and forbidden for cluster-scoped kinds"),
		Entry("a cluster-scoped key range with namespaces",
			collectingSource(`{"kinds":["ClusterRole"],"namespaces":["team"],"names":["*"]}`), "namespaces is required for namespaced kinds and forbidden for cluster-scoped kinds"),
		Entry("a namespaces wildcard beside a name",
			collectingSource(`{"kinds":["Policy"],"namespaces":["*","team"],"names":["*"]}`), "the namespaces wildcard must stand alone"),
		Entry("a names wildcard beside a name",
			collectingSource(`{"kinds":["Policy"],"namespaces":["team"],"names":["*","policy"]}`), "the names wildcard must stand alone"),
		Entry("a Group requirement with a namespace",
			matchingBinding(`{"kind":"Group","operator":"In","names":["readers"],"namespace":"team"}`), "namespace is required only for ServiceAccount"),
		Entry("an Extra requirement without a key",
			matchingBinding(`{"kind":"Extra","operator":"In","values":["a"]}`), "key is required only for Extra"),
		Entry("an identity requirement with values",
			matchingBinding(`{"kind":"User","operator":"In","values":["alice"]}`), "identity requirements use names and attributes use values"),
		Entry("a prefix operator on an attribute",
			matchingBinding(`{"kind":"Extra","key":"scope","operator":"StartsWith","values":["a"]}`), "prefix operators require identity names"),
		Entry("a membership requirement without operands",
			matchingBinding(`{"kind":"Group","operator":"In"}`), "presence operators forbid operands and the other operators require them"),
		Entry("a presence requirement with operands",
			matchingBinding(`{"kind":"Group","operator":"Exists","names":["readers"]}`), "presence operators forbid operands and the other operators require them"),
		Entry("an empty UID operand",
			matchingBinding(`{"kind":"UID","operator":"In","values":[""]}`), "UID values must not be empty"),
		Entry("an import namespace that isn't a DNS label",
			importingPolicy(`{"kind":"ClusterRole","name":"view","namespaces":["Team"]}`), "spec.imports[0].namespaces[0]"),
		Entry("a policy with neither include, imports nor a condition",
			ruleDocument(model.KindPolicy, "policy", `{"exclude":[`+grantRule+`]}`), "one of include, imports or condition is required"),
		Entry("a rule namespace that isn't a DNS label",
			rulePolicy(`{"verbs":["get"],"apiGroups":[""],"resources":["pods"],"namespaces":["Team"]}`), "spec.include[0].namespaces[0]"),
		Entry("a non-resource rule with resource fields",
			rulePolicy(`{"verbs":["get"],"nonResourceURLs":["/healthz"],"resources":["pods"]}`), "a non-resource rule forbids resource fields"),
		Entry("a resource rule without resources",
			rulePolicy(`{"verbs":["get"],"apiGroups":[""]}`), "a resource rule requires apiGroups and resources"),
		Entry("an apiVersions wildcard beside a version",
			rulePolicy(`{"verbs":["get"],"apiGroups":[""],"resources":["pods"],"apiVersions":["*","v1"]}`), "the apiVersions wildcard must stand alone"),
		Entry("a selector on a non-collection verb",
			rulePolicy(`{"verbs":["get"],"apiGroups":[""],"resources":["pods"],"labelSelector":{"matchLabels":{"team":"a"}}}`), "selectors require only collection verbs"),
		Entry("a binding with both subjects and subjectMatch",
			ruleBinding(groupSubject+`,"policyRef":{"name":"policy"},"subjectMatch":{"requirements":[{"kind":"Group","operator":"Exists"}]}`), "exactly one of subjects or subjectMatch is required"),
		Entry("a binding without subjects",
			ruleBinding(`"policyRef":{"name":"policy"}`), "exactly one of subjects or subjectMatch is required"),
		Entry("a binding with both a policyRef and a policySelector",
			ruleBinding(groupSubject+`,"policyRef":{"name":"policy"},"policySelector":{"namespaceSelector":{},"selector":{}}`), "exactly one of policyRef or policySelector is required"),
		Entry("a binding with neither a policyRef nor a policySelector",
			ruleBinding(groupSubject), "exactly one of policyRef or policySelector is required"),
		Entry("a policySelector without a selector",
			ruleBinding(groupSubject+`,"policySelector":{"namespaceSelector":{}}`), "spec.policySelector.selector: Required value"),
		Entry("a namespaceLabels setting other than Collect or Ignore",
			ruleDocument("PolicySource", "source", `{"provider":{"type":"Kubernetes"},"collection":[{"kinds":["PolicySet"],"namespaces":["*"],"names":["*"]}],"namespaceLabels":"Always"}`), "spec.namespaceLabels: Unsupported value"),
		Entry("traversal constraints on a leaf policy target",
			ruleBinding(groupSubject+`,"policyRef":{"name":"policy"},"constraints":{"maxDepth":2}`), "constraints.sourceRefs and constraints.maxDepth require a PolicySet target or a policySelector"),
		Entry("a constraint policy that is a PolicySet",
			ruleBinding(groupSubject+`,"policyRef":{"kind":"PolicySet","name":"set"},"constraints":{"policyRef":{"kind":"PolicySet","name":"other"}}`), "constraints.policyRef must target a leaf policy"),
		Entry("a subject of an unsupported kind",
			ruleBinding(`"policyRef":{"name":"policy"},"subjects":[{"kind":"Robot","name":"r2"}]`), "subject kind must be User, Group, or ServiceAccount"),
		Entry("a subject without a name",
			ruleBinding(`"policyRef":{"name":"policy"},"subjects":[{"kind":"Group","name":""}]`), "subject name must not be empty"),
		Entry("a ServiceAccount subject without a namespace",
			ruleBinding(`"policyRef":{"name":"policy"},"subjects":[{"kind":"ServiceAccount","name":"reader"}]`), "a ServiceAccount subject requires namespace and no apiGroup"),
		Entry("a Group subject with a namespace",
			ruleBinding(`"policyRef":{"name":"policy"},"subjects":[{"kind":"Group","name":"readers","namespace":"team"}]`), "User and Group subjects forbid namespace"),
		Entry("a runtime without a workload type",
			ruleService(func(object *api.AuthorizationService) { object.Spec.Runtime.Type = "" }), "spec.runtime.type"),
		Entry("more ready replicas than the Deployment runs",
			ruleService(func(object *api.AuthorizationService) { object.Spec.Runtime.MinReadyReplicas = 3 }), "minReadyReplicas must not exceed deployment.replicas"),
		Entry("an authority without a source",
			ruleService(func(object *api.AuthorizationService) {
				object.Spec.Endpoints[0].Authorities = []api.Authority{{BindingRef: api.BindingRef{Namespace: rulesNamespace, Name: "binding"}, WhenNoPolicyAllows: "Deny"}}
			}), "bindingRef.sourceRef is required for an authority"),
		Entry("a CA bundle reference naming both a Secret and a ConfigMap",
			ruleService(func(object *api.AuthorizationService) {
				object.Spec.TLS.Client.CARef.ConfigMapKeyRef = &api.ConfigMapKeyRef{Name: "client-ca", Key: "ca.crt"}
			}), "exactly one of secretKeyRef or configMapKeyRef is required"),
		Entry("a serving Secret reference without a name",
			ruleService(func(object *api.AuthorizationService) { object.Spec.TLS.Server.SecretRef.Name = "" }), "spec.tls.server.secretRef.name"),
		Entry("a CA bundle reference naming neither a Secret nor a ConfigMap",
			ruleService(func(object *api.AuthorizationService) { object.Spec.TLS.Server.CARef = api.CABundleRef{} }), "exactly one of secretKeyRef or configMapKeyRef is required"),
		Entry("a service name too long for its generated resources",
			ruleService(func(object *api.AuthorizationService) { object.Name = strings.Repeat("a", 58) }), "name must be a DNS label of at most 57 characters"),
		Entry("a source name too long for its cache Secrets' labels",
			longSource(), "name must be at most 63 characters"),
		Entry("a source reference whose name is longer than a source name can be",
			ruleService(func(object *api.AuthorizationService) {
				object.Spec.Endpoints[0].SourceRefs[0].Name = strings.Repeat("a", 64)
			}), "may not be more than 63"),
	)

	It("admits traversal constraints on a selecting binding, and defaults a source to ignore namespace labels", func(ctx context.Context) {
		Expect(createAndRemove(ctx, ruleBinding(`"subjectMatch":{},"policySelector":{"namespaceSelector":{"matchLabels":{"owner":"infra"}},"selector":{}},"constraints":{"maxDepth":2,"sourceRefs":[{"namespace":"rules","name":"local"}]}`))).To(Succeed())
		object := collectingSource(`{"kinds":["PolicySet"],"namespaces":["*"],"names":["*"]}`)
		Expect(createAndRemove(ctx, object)).To(Succeed())
		var stored api.PolicySource
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(object), &stored)).To(Succeed())
		Expect(stored.Spec.NamespaceLabels).To(Equal(api.NamespaceLabelsIgnore))
	})

	It("admits a DaemonSet service that sets only its required fields", func(ctx context.Context) {
		object := ruleDocument("AuthorizationService", "daemonset", `{
			"program":{"type":"Kubernetes"},
			"runtime":{"type":"DaemonSet","minReadyReplicas":3},
			"tls":{
				"server":{"secretRef":{"name":"server-tls"},"caRef":{"configMapKeyRef":{"name":"serving-ca","key":"ca.crt"}}},
				"client":{"caRef":{"secretKeyRef":{"name":"client-ca","key":"ca.crt"}}}
			},
			"endpoints":[{
				"name":"fleet",
				"callers":[{"commonName":"kube-apiserver"}],
				"sourceRefs":[{"namespace":"rules","name":"local"}],
				"authorities":[],
				"whenEvaluationFails":"Deny"
			}]
		}`)
		Expect(createAndRemove(ctx, object)).To(Succeed())
		var stored api.AuthorizationService
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(object), &stored)).To(Succeed())
		Expect(stored.Spec.Runtime.Type).To(Equal(api.RuntimeTypeDaemonSet))
		Expect(stored.Spec.Runtime.Deployment).To(Equal(&api.DeploymentRuntime{Replicas: 2}))
	})
})
