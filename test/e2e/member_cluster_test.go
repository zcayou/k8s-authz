//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("Member cluster", Label("member-cluster"), func() {
	// expectMemberPodList waits until the member's API server lets the admin
	// list pods in namespace when allowed, or refuses it with the webhook's
	// fallback otherwise.
	expectMemberPodList := func(ctx context.Context, namespace string, allowed bool) {
		GinkgoHelper()
		Eventually(func(g Gomega) {
			output, err := suite.member.kubectl(ctx, "get", "pods", "-n", namespace,
				"--as="+e2eUser, "--as-group="+e2eAdminGroup)
			if allowed {
				g.Expect(err).NotTo(HaveOccurred())
				return
			}
			g.Expect(err).To(HaveOccurred())
			g.Expect(output).To(ContainSubstring("Forbidden"))
			g.Expect(output).To(ContainSubstring("code=AuthorityFallback"))
		}, 2*time.Minute).Should(Succeed())
	}

	BeforeEach(func(ctx SpecContext) {
		expectBaseline(ctx)
	})

	It("authorizes the member's requests within the bound its policy is delegated under", func(ctx SpecContext) {
		expectMemberPodList(ctx, workloadNamespace, true)
		expectMemberPodList(ctx, "kube-system", false)
	})

	It("pushes a policy edit made in the member cluster without rolling the engines", func(ctx SpecContext) {
		revision := authorizationService(ctx).Status.DesiredRevision
		digest := startupDigest(ctx)
		pods := podUIDs(enginePods(ctx))
		var policy struct {
			Spec json.RawMessage `json:"spec"`
		}
		Expect(suite.member.getJSON(ctx, &policy, "-n", remotePolicyNamespace, "policy", "namespace-admin")).To(Succeed())
		original, err := json.Marshal(map[string]json.RawMessage{"spec": policy.Spec})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func(ctx SpecContext) {
			Expect(suite.member.kubectl(ctx, "-n", remotePolicyNamespace, "patch", "policy", "namespace-admin",
				"--type=merge", "-p", string(original))).Error().NotTo(HaveOccurred())
			expectMemberPodList(ctx, workloadNamespace, true)
		})

		By("dropping the list verb from the member's policy")
		Expect(suite.member.kubectl(ctx, "-n", remotePolicyNamespace, "patch", "policy", "namespace-admin", "--type=merge", "-p",
			`{"spec":{"include":[{"apiGroups":["*"],"resources":["*"],"verbs":["get"]}]}}`)).Error().NotTo(HaveOccurred())
		expectMemberPodList(ctx, workloadNamespace, false)
		expectConverged(ctx, time.Minute)
		Expect(authorizationService(ctx).Status.DesiredRevision).NotTo(Equal(revision))
		Expect(startupDigest(ctx)).To(Equal(digest))
		Expect(podUIDs(enginePods(ctx))).To(Equal(pods))
	})

	It("admits each API server only to its own endpoint", func(ctx SpecContext) {
		checks := []struct {
			endpoint string
			caller   utils.Material
			status   int
		}{
			{memberEndpointName, suite.memberCaller, http.StatusOK},
			{endpointName, suite.memberCaller, http.StatusUnauthorized},
			{endpointName, suite.apiServerCaller, http.StatusOK},
			{memberEndpointName, suite.apiServerCaller, http.StatusUnauthorized},
		}
		for _, pod := range enginePods(ctx) {
			for _, check := range checks {
				Expect(review(ctx, pod.Name, check.endpoint, check.caller)).To(Equal(check.status),
					"caller %s on endpoint %s of Pod %s", check.caller.Certificate.Subject.CommonName, check.endpoint, pod.Name)
			}
		}
	})
})
