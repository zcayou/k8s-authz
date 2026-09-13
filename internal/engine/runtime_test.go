package engine_test

import (
	imagereference "github.com/distribution/reference"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/open-policy-agent/opa/v1/version"

	"github.com/zcayou/k8s-authz/internal/engine"
)

var _ = Describe("Engine runtime", func() {
	It("defaults to the stock OPA image of the runtime version, pinned by digest", func() {
		named, err := imagereference.ParseNormalizedNamed(engine.DefaultImage)
		Expect(err).NotTo(HaveOccurred())
		Expect(imagereference.FamiliarName(named)).To(Equal("openpolicyagent/opa"))
		tagged, ok := named.(imagereference.Tagged)
		Expect(ok).To(BeTrue())
		Expect(tagged.Tag()).To(Equal(engine.RuntimeVersion))
		_, pinned := named.(imagereference.Digested)
		Expect(pinned).To(BeTrue())
	})

	It("links the runtime version's OPA module", func() {
		Expect(engine.RuntimeVersion).To(Equal(version.Version))
	})
})
