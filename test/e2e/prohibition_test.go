//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
)

var _ = Describe("Root prohibition", Label("prohibition"), func() {
	const guardedUser, guardedGroup = "oidc:guarded-user", "oidc:guarded"

	// expectPodList waits until the API server lets guardedUser list pods
	// when allowed, or refuses it with the webhook's prohibition otherwise.
	expectPodList := func(ctx context.Context, allowed bool) {
		GinkgoHelper()
		Eventually(func(g Gomega) {
			output, err := listPods(ctx, guardedUser, guardedGroup)
			if allowed {
				g.Expect(err).NotTo(HaveOccurred())
				return
			}
			g.Expect(err).To(HaveOccurred())
			g.Expect(output).To(ContainSubstring("Forbidden"))
			g.Expect(output).To(ContainSubstring("code=RootProhibited"))
		}, 2*time.Minute).Should(Succeed())
	}

	BeforeEach(func(ctx SpecContext) {
		expectBaseline(ctx)
	})

	It("denies a request RBAC allows", func(ctx SpecContext) {
		Expect(apply(ctx, guardedDocuments)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			Expect(kubectl(ctx, "-n", localPolicyNamespace, "delete", "policyset,policybinding", "guarded",
				"--ignore-not-found")).Error().NotTo(HaveOccurred())
			Expect(kubectl(ctx, "-n", localPolicyNamespace, "delete", "policy,policybinding", "guarded-pods",
				"--ignore-not-found")).Error().NotTo(HaveOccurred())
		})
		service := authorizationService(ctx)
		original, err := json.Marshal(map[string]any{"spec": map[string]any{"endpoints": service.Spec.Endpoints}})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func(ctx SpecContext) {
			Expect(patchService(ctx, string(original))).To(Succeed())
			expectConverged(ctx, 2*time.Minute)
		})
		endpoint := &service.Spec.Endpoints[0]
		guarded := endpoint.Authorities[0]
		guarded.BindingRef.Name = "guarded"
		guarded.WhenNoPolicyAllows = "NoOpinion"
		endpoint.Authorities = append([]api.Authority{guarded}, endpoint.Authorities...)
		patch, err := json.Marshal(map[string]any{"spec": map[string]any{"endpoints": service.Spec.Endpoints}})
		Expect(err).NotTo(HaveOccurred())
		Expect(patchService(ctx, string(patch))).To(Succeed())
		expectConverged(ctx, 2*time.Minute)

		By("allowing the request through RBAC while the webhook has no opinion")
		Expect(apply(ctx, guardedReader)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			Expect(kubectl(ctx, "-n", workloadNamespace, "delete", "role,rolebinding", "guarded-reader",
				"--ignore-not-found")).Error().NotTo(HaveOccurred())
		})
		expectPodList(ctx, true)

		By("denying the request once the root PolicySet prohibits it")
		Expect(kubectl(ctx, "-n", localPolicyNamespace, "patch", "policyset", "guarded", "--type=merge", "-p",
			`{"spec":{"prohibitionRefs":[{"name":"guarded-pods"}]}}`)).Error().NotTo(HaveOccurred())
		expectPodList(ctx, false)

		By("allowing the request again once the prohibition is withdrawn")
		Expect(kubectl(ctx, "-n", localPolicyNamespace, "patch", "policyset", "guarded", "--type=merge", "-p",
			`{"spec":{"prohibitionRefs":null}}`)).Error().NotTo(HaveOccurred())
		expectPodList(ctx, true)
	})
})

// guardedDocuments select oidc:guarded- users into a root PolicySet granting
// nothing, and hold a prohibition on listing pods in team-one, which
// the PolicySet doesn't reference yet.
const guardedDocuments = `apiVersion: authorization.zctx.io/v1alpha1
kind: PolicySet
metadata:
  namespace: e2e-local
  name: guarded
spec: {}
---
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata:
  namespace: e2e-local
  name: guarded
spec:
  subjectMatch:
    requirements:
      - kind: User
        operator: StartsWith
        names: ["oidc:guarded-"]
  policyRef:
    kind: PolicySet
    name: guarded
---
apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata:
  namespace: e2e-local
  name: guarded-pods
spec:
  include:
    - apiGroups: [""]
      resources: [pods]
      verbs: [list]
      namespaces: [team-one]
---
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata:
  namespace: e2e-local
  name: guarded-pods
spec:
  subjectMatch: {}
  policyRef:
    name: guarded-pods
`

const guardedReader = `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: team-one
  name: guarded-reader
rules:
  - apiGroups: [""]
    resources: [pods]
    verbs: [get, list]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  namespace: team-one
  name: guarded-reader
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: oidc:guarded
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: guarded-reader
`
