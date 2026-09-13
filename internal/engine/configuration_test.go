package engine_test

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/zcayou/k8s-authz/internal/engine"
)

var _ = Describe("OPA runtime configuration", func() {
	It("bounds request bodies by the largest state document", func() {
		encoded, err := engine.Configuration(false)
		Expect(err).NotTo(HaveOccurred())
		Expect(decodeConfiguration(encoded)).To(Equal(map[string]any{"server": map[string]any{"decoding": map[string]any{"max_length": float64(engine.MaxContentBytes)}}}))
	})
})

var _ = Describe("OPA decision logging", func() {
	It("only configures console logging when enabled", func() {
		disabled, err := engine.Configuration(false)
		Expect(err).NotTo(HaveOccurred())
		Expect(decodeConfiguration(disabled)).NotTo(HaveKey("decision_logs"))
		enabled, err := engine.Configuration(true)
		Expect(err).NotTo(HaveOccurred())
		Expect(decodeConfiguration(enabled)).To(HaveKeyWithValue("decision_logs", map[string]any{"console": true}))
	})
})

func decodeConfiguration(data []byte) map[string]any {
	GinkgoHelper()
	var configuration map[string]any
	Expect(json.Unmarshal(data, &configuration)).To(Succeed())
	return configuration
}
