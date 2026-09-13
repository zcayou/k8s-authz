//go:build e2e

package e2e

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/resources"
	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("Policy delivery", Label("delivery"), func() {
	var digest string
	var pods []string

	BeforeEach(func(ctx SpecContext) {
		expectBaseline(ctx)
		digest = startupDigest(ctx)
		pods = podUIDs(enginePods(ctx))
		Expect(pods).To(HaveLen(2))
	})

	// expectSameEngines checks that the engines were neither rolled nor replaced.
	expectSameEngines := func(ctx context.Context) {
		GinkgoHelper()
		Expect(startupDigest(ctx)).To(Equal(digest))
		Expect(podUIDs(enginePods(ctx))).To(Equal(pods))
	}

	It("pushes a remote policy edit without rolling the engines", func(ctx SpecContext) {
		revision := authorizationService(ctx).Status.DesiredRevision
		var policy struct {
			Spec json.RawMessage `json:"spec"`
		}
		Expect(suite.member.getJSON(ctx, &policy, "-n", remotePolicyNamespace, "policy", "namespace-admin")).To(Succeed())
		original, err := json.Marshal(map[string]json.RawMessage{"spec": policy.Spec})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func(ctx SpecContext) {
			Expect(suite.member.kubectl(ctx, "-n", remotePolicyNamespace, "patch", "policy", "namespace-admin",
				"--type=merge", "-p", string(original))).Error().NotTo(HaveOccurred())
			expectAllowed(ctx, 2*time.Minute)
		})

		By("dropping the list verb from the remote policy")
		Expect(suite.member.kubectl(ctx, "-n", remotePolicyNamespace, "patch", "policy", "namespace-admin", "--type=merge", "-p",
			`{"spec":{"include":[{"apiGroups":["*"],"resources":["*"],"verbs":["get"]}]}}`)).Error().NotTo(HaveOccurred())
		expectForbidden(ctx, 2*time.Minute)
		expectConverged(ctx, time.Minute)
		Expect(authorizationService(ctx).Status.DesiredRevision).NotTo(Equal(revision))
		expectSameEngines(ctx)
	})

	It("pushes a caller edit without rolling the engines", func(ctx SpecContext) {
		DeferCleanup(func(ctx SpecContext) {
			Expect(patchCallers(ctx, suite.apiServerCaller.Certificate.Subject.CommonName)).To(Succeed())
			expectAllowed(ctx, 2*time.Minute)
		})

		By("admitting only a Common Name the API server doesn't present")
		Expect(patchCallers(ctx, "k8s-authz-e2e-other")).To(Succeed())
		Eventually(func(g Gomega) {
			output, err := listPods(ctx, e2eUser, e2eAdminGroup)
			g.Expect(err).To(HaveOccurred())
			// kube-apiserver reports the engine's 401 as an authorizer error.
			g.Expect(output).To(ContainSubstring("the server has asked for the client to provide credentials"))
		}, 2*time.Minute).Should(Succeed())
		expectSameEngines(ctx)

		By("admitting the API server again")
		Expect(patchCallers(ctx, suite.apiServerCaller.Certificate.Subject.CommonName)).To(Succeed())
		expectAllowed(ctx, 2*time.Minute)
		expectSameEngines(ctx)
	})

	It("rolls the engines when the management CA bundle changes", func(ctx SpecContext) {
		var secret corev1.Secret
		Expect(getJSON(ctx, &secret, "-n", operatorNamespace, "secret", "management-ca")).To(Succeed())
		original := secret.Data[caKey]
		extra, err := utils.NewAuthority(time.Now())
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func(ctx SpecContext) {
			Expect(applyManagementCA(ctx, original)).To(Succeed())
			Eventually(func() string { return startupDigest(ctx) }, 3*time.Minute).Should(Equal(digest))
			expectRolledOut(ctx)
			expectConverged(ctx, 2*time.Minute)
		})

		Expect(applyManagementCA(ctx, slices.Concat(original, extra.CertificatePEM))).To(Succeed())
		Eventually(func() string { return startupDigest(ctx) }, 3*time.Minute).ShouldNot(Equal(digest))
		expectRolledOut(ctx)
		Eventually(func(g Gomega) {
			current := podUIDs(enginePods(ctx))
			g.Expect(current).To(HaveLen(2))
			g.Expect(current).NotTo(ContainElement(BeElementOf(pods)))
		}, time.Minute).Should(Succeed())
		expectConverged(ctx, 2*time.Minute)
		expectAllowed(ctx, time.Minute)
	})

	It("reloads a client CA change without rolling the engines", func(ctx SpecContext) {
		extra, err := utils.NewAuthority(time.Now())
		Expect(err).NotTo(HaveOccurred())
		caller, err := extra.Issue(suite.apiServerCaller.Certificate.Subject.CommonName, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
		Expect(err).NotTo(HaveOccurred())
		engines := enginePods(ctx)
		DeferCleanup(func(ctx SpecContext) {
			Expect(applyClientCA(ctx, suite.callerAuthority.CertificatePEM)).To(Succeed())
			Eventually(func() string { return engineCABundle(ctx) }, 2*time.Minute).ShouldNot(ContainSubstring(string(extra.CertificatePEM)))
			expectConverged(ctx, time.Minute)
		})

		By("refusing a caller the new client CA issued before the engines trust it")
		for _, pod := range engines {
			Expect(review(ctx, pod.Name, endpointName, caller)).Error().To(HaveOccurred())
		}

		By("adding the new client CA to the bundle")
		Expect(applyClientCA(ctx, slices.Concat(suite.callerAuthority.CertificatePEM, extra.CertificatePEM))).To(Succeed())
		for _, pod := range engines {
			Eventually(func() (int, error) { return review(ctx, pod.Name, endpointName, caller) }).
				WithTimeout(3 * time.Minute).WithPolling(5 * time.Second).Should(Equal(http.StatusOK))
		}
		expectSameEngines(ctx)
		expectAllowed(ctx, time.Minute)
	})

	It("pushes state again to an engine whose OPA container restarted", func(ctx SpecContext) {
		pod := enginePods(ctx)[0]
		restarts := pod.Status.ContainerStatuses[0].RestartCount
		restartOPA(ctx, pod)
		Eventually(func(g Gomega) {
			var current corev1.Pod
			g.Expect(getJSON(ctx, &current, "-n", controlNamespace, "pod", pod.Name)).To(Succeed())
			g.Expect(current.UID).To(Equal(pod.UID))
			g.Expect(current.Status.ContainerStatuses[0].RestartCount).To(BeNumerically(">", restarts))
			g.Expect(resources.PodReady(&current)).To(BeTrue())
		}, 3*time.Minute).Should(Succeed())
		expectConverged(ctx, time.Minute)
		expectSameEngines(ctx)
	})
})

// patchCallers sets the fleet endpoint's only caller to commonName.
func patchCallers(ctx context.Context, commonName string) error {
	endpoints := authorizationService(ctx).Spec.Endpoints
	endpoints[0].Callers = []api.Caller{{CommonName: commonName}}
	patch, err := json.Marshal(map[string]any{"spec": map[string]any{"endpoints": endpoints}})
	if err != nil {
		return err
	}
	return patchService(ctx, string(patch))
}

func applyManagementCA(ctx context.Context, bundle []byte) error {
	return applySecret(ctx, corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: operatorNamespace, Name: "management-ca"},
		Data:       map[string][]byte{caKey: bundle},
	})
}

func applyClientCA(ctx context.Context, bundle []byte) error {
	return applySecret(ctx, corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: controlNamespace, Name: "client-ca"},
		Data:       map[string][]byte{caKey: bundle},
	})
}

// engineCABundle returns the CA bundle in the fleet service's engine ConfigMap.
func engineCABundle(ctx context.Context) string {
	GinkgoHelper()
	var config corev1.ConfigMap
	Expect(getJSON(ctx, &config, "-n", controlNamespace, "configmap", listenerName+"-engine")).To(Succeed())
	return config.Data[caKey]
}
