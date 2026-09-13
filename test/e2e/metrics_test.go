//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Operator metrics", Label("metrics"), func() {
	const scraper = "metrics-scraper"

	BeforeEach(func(ctx SpecContext) {
		expectBaseline(ctx)
	})

	It("serves metrics to a ServiceAccount bound to the metrics-reader role", func(ctx SpecContext) {
		Expect(kubectl(ctx, "-n", controlNamespace, "create", "serviceaccount", scraper)).Error().NotTo(HaveOccurred())
		DeferCleanup(func(ctx SpecContext) {
			Expect(kubectl(ctx, "-n", controlNamespace, "delete", "serviceaccount", scraper,
				"--ignore-not-found")).Error().NotTo(HaveOccurred())
			Expect(kubectl(ctx, "delete", "clusterrolebinding", scraper, "--ignore-not-found")).Error().NotTo(HaveOccurred())
		})
		token, err := kubectl(ctx, "-n", controlNamespace, "create", "token", scraper, "--duration=10m")
		Expect(err).NotTo(HaveOccurred())
		address := portForward(ctx, operatorNamespace, "service/"+operatorDeployment+"-metrics-service", 8443)
		// The scaffold's metrics server serves a self-signed certificate.
		client := &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // see above
			Timeout:   10 * time.Second,
		}
		DeferCleanup(client.CloseIdleConnections)
		scrape := func() (int, string, error) {
			return get(ctx, client, "https://"+address+"/metrics", strings.TrimSpace(token))
		}

		By("refusing the token before the role is bound")
		Eventually(func(g Gomega) {
			status, _, scrapeErr := scrape()
			g.Expect(scrapeErr).NotTo(HaveOccurred())
			g.Expect(status).To(Equal(http.StatusForbidden))
		}, time.Minute).Should(Succeed())

		By("serving the operator's metrics once the role is bound")
		Expect(kubectl(ctx, "create", "clusterrolebinding", scraper, "--clusterrole=k8s-authz-metrics-reader",
			"--serviceaccount="+controlNamespace+":"+scraper)).Error().NotTo(HaveOccurred())
		Eventually(func(g Gomega) {
			status, body, scrapeErr := scrape()
			g.Expect(scrapeErr).NotTo(HaveOccurred())
			g.Expect(status).To(Equal(http.StatusOK))
			g.Expect(body).To(ContainSubstring("controller_runtime_reconcile_total"))
			g.Expect(body).To(ContainSubstring(`k8s_authz_source_synchronized{name="remote",namespace="authz-system"} 1`))
		}, time.Minute).Should(Succeed())
	})
})

func get(ctx context.Context, client *http.Client, url, token string) (int, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	return response.StatusCode, string(body), err
}
