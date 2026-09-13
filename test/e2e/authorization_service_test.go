//go:build e2e

package e2e

import (
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apimeta "k8s.io/apimachinery/pkg/api/meta"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
)

var _ = Describe("Authorization service", Label("sources"), func() {
	BeforeEach(func(ctx SpecContext) {
		expectBaseline(ctx)
	})

	It("synchronizes the local source and the token-authenticated remote source", func(ctx SpecContext) {
		for _, name := range []string{"local", "remote"} {
			var source api.PolicySource
			Expect(getJSON(ctx, &source, "-n", controlNamespace, "policysource", name)).To(Succeed())
			Expect(source.Status.ObservedGeneration).To(Equal(source.Generation))
			Expect(apimeta.IsStatusConditionTrue(source.Status.Conditions, api.ConditionSynchronized)).To(BeTrue(), name)
		}
		output, err := kubectl(ctx, "-n", controlNamespace, "get", "deployment", listenerName, "-o", "name")
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.TrimSpace(output)).To(Equal("deployment.apps/" + listenerName))
	})

	It("authorizes API requests within the inherited delegation bound", func(ctx SpecContext) {
		expectAllowed(ctx, time.Minute)
	})

	It("denies API requests beyond the inherited delegation bound", func(ctx SpecContext) {
		output, err := kubectl(ctx, "get", "pods", "-n", "kube-system", "--as="+e2eUser, "--as-group="+e2eAdminGroup)
		Expect(err).To(HaveOccurred())
		Expect(output).To(ContainSubstring("Forbidden"))
	})
})
