//go:build e2e

package e2e

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
)

var _ = Describe("Runtime kind", Label("runtime"), func() {
	BeforeEach(func(ctx SpecContext) {
		expectBaseline(ctx)
	})

	It("switches the engines from a Deployment to a DaemonSet", func(ctx SpecContext) {
		DeferCleanup(func(ctx SpecContext) {
			Expect(patchService(ctx, `{"spec":{"runtime":{"type":"Deployment"}}}`)).To(Succeed())
			Eventually(func() error {
				_, err := kubectl(ctx, "-n", controlNamespace, "get", "daemonset", listenerName)
				return err
			}, 3*time.Minute).Should(MatchError(ContainSubstring("NotFound")))
			expectBaseline(ctx)
		})

		Expect(patchService(ctx, `{"spec":{"runtime":{"type":"DaemonSet"}}}`)).To(Succeed())
		Eventually(func(g Gomega) {
			var daemonSet appsv1.DaemonSet
			g.Expect(getJSON(ctx, &daemonSet, "-n", controlNamespace, "daemonset", listenerName)).To(Succeed())
			g.Expect(daemonSet.Status.DesiredNumberScheduled).To(Equal(int32(2)))
			g.Expect(daemonSet.Status.NumberReady).To(Equal(int32(2)))
		}, 3*time.Minute).Should(Succeed())
		Eventually(func() error {
			_, err := kubectl(ctx, "-n", controlNamespace, "get", "deployment", listenerName)
			return err
		}, 3*time.Minute).Should(MatchError(ContainSubstring("NotFound")))
		expectConverged(ctx, 2*time.Minute)
		expectAllowed(ctx, time.Minute)
	})
})
