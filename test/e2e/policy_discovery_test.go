//go:build e2e

package e2e

import (
	"encoding/json"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Policy discovery", Label("discovery"), func() {
	BeforeEach(func(ctx SpecContext) {
		expectBaseline(ctx)
	})

	It("attaches the labeled PolicySets of labeled member namespaces, and only while the namespace stays labeled", func(ctx SpecContext) {
		By("publishing an application in a labeled and in an unlabeled member namespace")
		Expect(suite.member.apply(ctx, discoveryApplications)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			Expect(suite.member.kubectl(ctx, "delete", "namespace", discoveryNamespace, strayNamespace, "--ignore-not-found")).Error().NotTo(HaveOccurred())
			Expect(suite.member.kubectl(ctx, "delete", "clusterrole,clusterrolebinding", discoveryReaderName, "--ignore-not-found")).Error().NotTo(HaveOccurred())
			expectConverged(ctx, 2*time.Minute)
			expectMemberPodList(ctx, workloadNamespace, true)
		})
		Expect(apply(ctx, discoveryDocuments)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			Expect(kubectl(ctx, "-n", localPolicyNamespace, "delete", "policy,policybinding", "applications", "--ignore-not-found")).Error().NotTo(HaveOccurred())
		})

		By("collecting the member namespaces' documents and labels")
		var remote struct {
			Spec map[string]json.RawMessage `json:"spec"`
		}
		Expect(getJSON(ctx, &remote, "-n", controlNamespace, "policysource", "remote")).To(Succeed())
		original, err := json.Marshal(map[string]any{"spec": map[string]any{"collection": remote.Spec["collection"], "namespaceLabels": remote.Spec["namespaceLabels"]}})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func(ctx SpecContext) {
			Expect(kubectl(ctx, "-n", controlNamespace, "patch", "policysource", "remote", "--type=merge", "-p", string(original))).Error().NotTo(HaveOccurred())
		})
		Expect(kubectl(ctx, "-n", controlNamespace, "patch", "policysource", "remote", "--type=merge", "-p", `{"spec":{"namespaceLabels":"Collect","collection":[
			{"kinds":["Policy","PolicyBinding","PolicySet"],"namespaces":["e2e-remote"],"names":["*"]},
			{"kinds":["Policy","PolicyBinding","PolicySet"],"namespaces":["e2e-discovery","e2e-discovery-stray"],"names":["*"]}
		]}}`)).Error().NotTo(HaveOccurred())

		By("selecting the applications from the root PolicySet")
		DeferCleanup(func(ctx SpecContext) {
			Expect(kubectl(ctx, "-n", localPolicyNamespace, "patch", "policyset", "root", "--type=merge", "-p",
				`{"spec":{"bindingRefs":[{"name":"remote-team"}]}}`)).Error().NotTo(HaveOccurred())
		})
		Expect(kubectl(ctx, "-n", localPolicyNamespace, "patch", "policyset", "root", "--type=merge", "-p",
			`{"spec":{"bindingRefs":[{"name":"remote-team"},{"name":"applications"}]}}`)).Error().NotTo(HaveOccurred())
		expectMemberPodList(ctx, "default", true)
		expectMemberPodList(ctx, workloadNamespace, true)
		expectMemberPodList(ctx, "kube-public", false)

		By("detaching the application once its namespace loses the label")
		Expect(suite.member.kubectl(ctx, "label", "namespace", discoveryNamespace, discoveryOwnerLabel+"-")).Error().NotTo(HaveOccurred())
		expectMemberPodList(ctx, "default", false)
		expectMemberPodList(ctx, workloadNamespace, true)
	})
})

const (
	discoveryNamespace  = "e2e-discovery"
	strayNamespace      = "e2e-discovery-stray"
	discoveryReaderName = "remote-reader-namespaces"
	discoveryOwnerLabel = "e2e.zctx.io/policy-owner"
)

// discoveryApplications publish, in the member, an application granting the e2e
// admins pod lists in default from a namespace labeled as the platform's,
// and one granting them in kube-public from an unlabeled namespace. They let
// the remote reader read both namespaces' documents and the labels of every
// namespace the remote source collects.
const discoveryApplications = `apiVersion: v1
kind: Namespace
metadata:
  name: e2e-discovery
  labels:
    e2e.zctx.io/policy-owner: platform
---
apiVersion: v1
kind: Namespace
metadata:
  name: e2e-discovery-stray
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: remote-reader-namespaces
rules:
  - apiGroups: [""]
    resources: [namespaces]
    resourceNames: [e2e-remote, e2e-discovery, e2e-discovery-stray]
    verbs: [list, watch]
  - apiGroups: [authorization.zctx.io]
    resources: [policies, policybindings, policysets]
    verbs: [list, watch]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: remote-reader-namespaces
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: remote-reader-namespaces
subjects:
  - kind: ServiceAccount
    namespace: e2e-remote
    name: remote-reader
---
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicySet
metadata:
  namespace: e2e-discovery
  name: application
  labels:
    e2e.zctx.io/entrypoint: application
spec:
  bindingRefs:
    - name: admins
---
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata:
  namespace: e2e-discovery
  name: admins
spec:
  subjects:
    - kind: Group
      apiGroup: rbac.authorization.k8s.io
      name: oidc:e2e-admins
  policyRef:
    name: pods
---
apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata:
  namespace: e2e-discovery
  name: pods
spec:
  include:
    - apiGroups: [""]
      resources: [pods]
      verbs: [list]
      namespaces: [default]
---
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicySet
metadata:
  namespace: e2e-discovery-stray
  name: application
  labels:
    e2e.zctx.io/entrypoint: application
spec:
  bindingRefs:
    - name: admins
---
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata:
  namespace: e2e-discovery-stray
  name: admins
spec:
  subjects:
    - kind: Group
      apiGroup: rbac.authorization.k8s.io
      name: oidc:e2e-admins
  policyRef:
    name: pods
---
apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata:
  namespace: e2e-discovery-stray
  name: pods
spec:
  include:
    - apiGroups: [""]
      resources: [pods]
      verbs: [list]
      namespaces: [kube-public]
`

// discoveryDocuments select, from the remote source, the PolicySets labeled
// as application entry points in namespaces labeled as the platform's,
// bounded to pod lists in default and kube-public.
const discoveryDocuments = `apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata:
  namespace: e2e-local
  name: applications
spec:
  include:
    - apiGroups: [""]
      resources: [pods]
      verbs: [list]
      namespaces: [default, kube-public]
---
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata:
  namespace: e2e-local
  name: applications
spec:
  subjectMatch: {}
  policySelector:
    sourceRef:
      namespace: authz-system
      name: remote
    namespaceSelector:
      matchLabels:
        e2e.zctx.io/policy-owner: platform
    selector:
      matchLabels:
        e2e.zctx.io/entrypoint: application
  constraints:
    policyRef:
      name: applications
`
