//go:build e2e

package e2e

import (
	"encoding/json"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
)

var _ = Describe("Native RBAC fallback", Label("fallback"), func() {
	const nativeUser, nativeGroup = "oidc:native-user", "oidc:native"

	BeforeEach(func(ctx SpecContext) {
		expectBaseline(ctx)
	})

	It("passes a NoOpinion decision on to RBAC", func(ctx SpecContext) {
		service := authorizationService(ctx)
		original, err := json.Marshal(map[string]any{"spec": map[string]any{"endpoints": service.Spec.Endpoints}})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func(ctx SpecContext) {
			Expect(patchService(ctx, string(original))).To(Succeed())
			expectConverged(ctx, 2*time.Minute)
		})
		endpoint := &service.Spec.Endpoints[0]
		native := endpoint.Authorities[0]
		native.BindingRef.Name = "native"
		native.WhenNoPolicyAllows = "NoOpinion"
		endpoint.Authorities = append([]api.Authority{native}, endpoint.Authorities...)
		patch, err := json.Marshal(map[string]any{"spec": map[string]any{"endpoints": service.Spec.Endpoints}})
		Expect(err).NotTo(HaveOccurred())
		Expect(patchService(ctx, string(patch))).To(Succeed())
		expectConverged(ctx, 2*time.Minute)

		By("leaving the request to RBAC, which grants nothing")
		Eventually(func(g Gomega) {
			output, listErr := listPods(ctx, nativeUser, nativeGroup)
			g.Expect(listErr).To(HaveOccurred())
			g.Expect(output).To(ContainSubstring("Forbidden"))
		}, time.Minute).Should(Succeed())

		By("allowing the request once RBAC grants it")
		Expect(apply(ctx, nativeReader)).To(Succeed())
		DeferCleanup(func(ctx SpecContext) {
			Expect(kubectl(ctx, "-n", workloadNamespace, "delete", "role,rolebinding", "native-reader",
				"--ignore-not-found")).Error().NotTo(HaveOccurred())
		})
		Eventually(func() error {
			_, listErr := listPods(ctx, nativeUser, nativeGroup)
			return listErr
		}, time.Minute).Should(Succeed())
	})
})

const nativeReader = `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: team-one
  name: native-reader
rules:
  - apiGroups: [""]
    resources: [pods]
    verbs: [get, list]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  namespace: team-one
  name: native-reader
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: oidc:native
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: native-reader
`
