package resources_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/zcayou/k8s-authz/internal/resources"
)

var _ = Describe("Engine operand contract", func() {
	It("runs stock OPA with TLS, plaintext probes and only the policy and data directories", func() {
		Expect(resources.PodLayout.Arguments()).To(Equal([]string{
			"run", "--server",
			"--skip-version-check",
			"--addr=:8181",
			"--diagnostic-addr=http://:8182",
			"--authentication=tls",
			"--authorization=basic",
			"--tls-cert-file=/tls/tls.crt",
			"--tls-private-key-file=/tls/tls.key",
			"--tls-ca-cert-file=/engine/ca.crt",
			"--config-file=/engine/config.yaml",
			"/engine/policy",
			"/engine/data",
		}))
	})

	It("injects the addresses and directories of another layout", func() {
		layout := resources.Layout{Address: "127.0.0.1:1", DiagnosticAddress: "http://127.0.0.1:2", EngineDirectory: "/tmp/engine", TLSDirectory: "/tmp/tls"}
		Expect(layout.Arguments()).To(ContainElements("--addr=127.0.0.1:1", "--diagnostic-addr=http://127.0.0.1:2", "--tls-cert-file=/tmp/tls/tls.crt", "/tmp/engine/policy", "/tmp/engine/data"))
	})

	DescribeTable("projects each engine ConfigMap key into the layout",
		func(key, path string) {
			Expect(resources.ItemPath(key)).To(Equal(path))
		},
		Entry("the OPA configuration", resources.ConfigKey, "config.yaml"),
		Entry("the CA bundle", resources.CABundleKey, "ca.crt"),
		Entry("the bootstrap, under data.bootstrap", resources.BootstrapKey, "data/bootstrap/data.json"),
		Entry("a Rego module", "authz.rego", "policy/authz.rego"),
	)

	It("accepts an engine image pinned by digest", func() {
		Expect(resources.ValidateImage("docker.io/openpolicyagent/opa:1.20.2@sha256:7b15f9d96345dfa639322ad97f65a0b38260f95efcdd7f5c24e284228708f06c")).To(Succeed())
		Expect(resources.ValidateImage("registry.example.test:5000/opa@sha256:7b15f9d96345dfa639322ad97f65a0b38260f95efcdd7f5c24e284228708f06c")).To(Succeed())
	})

	DescribeTable("rejects an engine image that isn't pinned by digest",
		func(image, message string) {
			Expect(resources.ValidateImage(image)).To(MatchError(ContainSubstring(message)))
		},
		Entry("a tag alone", "openpolicyagent/opa:1.20.2", "must be pinned by digest"),
		Entry("a malformed digest", "openpolicyagent/opa@sha256:abc", "parse engine image"),
		Entry("an uppercase repository", "openpolicyagent/OPA@sha256:7b15f9d96345dfa639322ad97f65a0b38260f95efcdd7f5c24e284228708f06c", "parse engine image"),
	)
})
