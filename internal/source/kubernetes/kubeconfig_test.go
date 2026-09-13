package kubernetes_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/rest"

	"github.com/zcayou/k8s-authz/internal/source/kubernetes"
)

func kubeconfig(token, server string) []byte {
	return fmt.Appendf(nil, `apiVersion: v1
kind: Config
current-context: source
clusters:
- name: source
  cluster:
    server: %s
users:
- name: source
  user:
    token: %s
contexts:
- name: source
  context:
    cluster: source
    user: source
`, server, token)
}

var _ = Describe("ParseKubeconfig", func() {
	It("loads an embedded credential", func() {
		config, err := kubernetes.ParseKubeconfig(kubeconfig("first-secret", "https://api.example.test:6443"))
		Expect(err).NotTo(HaveOccurred())
		Expect(config.BearerToken).To(Equal("first-secret"))
	})

	DescribeTable("rejects kubeconfigs that depend on ambient or unverified behavior",
		func(rewrite func(string) string, message string) {
			// The referenced files exist, so the rejection is ParseKubeconfig's own.
			directory := GinkgoT().TempDir()
			for _, name := range []string{"ca.crt", "token", "tls.crt", "tls.key"} {
				Expect(os.WriteFile(filepath.Join(directory, name), []byte("placeholder"), 0o600)).To(Succeed())
			}
			data := strings.ReplaceAll(rewrite(string(kubeconfig("secret", "https://api.example.test:6443"))), "/files", directory)
			_, err := kubernetes.ParseKubeconfig([]byte(data))
			Expect(err).To(MatchError(ContainSubstring(message)))
		},
		Entry("with insecure TLS", func(value string) string {
			return strings.Replace(value, "server: https://api.example.test:6443", "server: https://api.example.test:6443\n    insecure-skip-tls-verify: true", 1)
		}, "disables TLS verification"),
		Entry("with an external CA", func(value string) string {
			return strings.Replace(value, "server: https://api.example.test:6443", "server: https://api.example.test:6443\n    certificate-authority: /files/ca.crt", 1)
		}, "external files"),
		Entry("with an external token", func(value string) string {
			return strings.Replace(value, "token: secret", "tokenFile: /files/token", 1)
		}, "external files"),
		Entry("with an external client certificate", func(value string) string {
			return strings.Replace(value, "token: secret", "client-certificate: /files/tls.crt\n    client-key: /files/tls.key", 1)
		}, "external files"),
		Entry("with an exec plugin", func(value string) string {
			return strings.Replace(value, "token: secret", "exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: credential-helper\n      interactiveMode: Never", 1)
		}, "external authentication plugin"),
		Entry("with an auth provider", func(value string) string {
			return strings.Replace(value, "token: secret", "auth-provider:\n      name: oidc", 1)
		}, "external authentication plugin"),
		Entry("with an HTTP server", func(value string) string {
			return strings.Replace(value, "https://api.example.test:6443", "http://api.example.test:8080", 1)
		}, "must be an https URL"),
	)
})

var _ = Describe("Origin", func() {
	It("normalizes the API server URL and ignores credentials", func() {
		first, err := kubernetes.Origin(&rest.Config{Host: "https://API.example.test:6443/", BearerToken: "first"})
		Expect(err).NotTo(HaveOccurred())
		second, err := kubernetes.Origin(&rest.Config{Host: "https://api.example.test:6443", BearerToken: "second"})
		Expect(err).NotTo(HaveOccurred())
		Expect(first).To(Equal("https://api.example.test:6443"))
		Expect(second).To(Equal(first))
	})
})
