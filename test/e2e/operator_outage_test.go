//go:build e2e

package e2e

import (
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Operator outage", Label("outage"), func() {
	BeforeEach(func(ctx SpecContext) {
		expectBaseline(ctx)
	})

	It("keeps the engines serving while no operator runs", func(ctx SpecContext) {
		pods := podUIDs(enginePods(ctx))
		DeferCleanup(func(ctx SpecContext) {
			Expect(kubectl(ctx, "-n", operatorNamespace, "scale", "deployment", operatorDeployment,
				"--replicas=1")).Error().NotTo(HaveOccurred())
			expectBaseline(ctx)
		})

		Expect(kubectl(ctx, "-n", operatorNamespace, "scale", "deployment", operatorDeployment,
			"--replicas=0")).Error().NotTo(HaveOccurred())
		Eventually(func(g Gomega) {
			output, err := kubectl(ctx, "-n", operatorNamespace, "get", "pods", "-l", "control-plane=controller-manager", "-o", "name")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(output)).To(BeEmpty())
		}, 2*time.Minute).Should(Succeed())
		Consistently(func(g Gomega) {
			_, err := listPods(ctx, e2eUser, e2eAdminGroup)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(podUIDs(enginePods(ctx))).To(Equal(pods))
		}, 30*time.Second).Should(Succeed())
	})
})
