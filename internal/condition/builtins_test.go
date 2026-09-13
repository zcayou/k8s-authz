package condition_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/zcayou/k8s-authz/internal/condition"
)

var _ = Describe("Builtins", func() {
	It("defines every default builtin", func() {
		Expect(condition.DefaultBuiltins()).NotTo(BeEmpty())
		for _, name := range condition.DefaultBuiltins() {
			Expect(condition.Defined(name)).To(BeTrue(), name)
		}
	})
	DescribeTable("defines the builtins an allowlist can name", func(name string, defined bool) {
		Expect(condition.Defined(name)).To(Equal(defined))
	},
		Entry("a default builtin", "startswith", true),
		Entry("a builtin outside the defaults", "http.send", true),
		Entry("print", "print", true),
		Entry("an operator", "eq", false),
		Entry("the membership operator", "internal.member_2", false),
		Entry("an internal builtin", "internal.print", false),
		Entry("a deprecated builtin", "re_match", false),
		Entry("an undefined name", "no.such.builtin", false),
	)
})
