package condition_test

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/model"
)

const teamNamespace = `package condition

default allow := false

allow if {
	some group in input.principal.groups
	team(group) == input.request.resourceAttributes.namespace
	every label in labels { startswith(label, "t") }
	count({key | some key in object.keys(input.principal.extra)}) < limit
	print("checked", group)
}

limit := 4

labels := ["team"]

team(group) := concat("-", ["team", trim_prefix(group, "team:")]) if {
	startswith(group, "team:")
} else := "none"
`

var _ = Describe("Check", func() {
	It("accepts a condition with helpers, a function, every, in and a comprehension", func() {
		checked, err := condition.Check(teamNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(checked.ID).To(Equal(model.Digest(teamNamespace)))
		Expect(checked.Rego).To(Equal(teamNamespace))
	})
	It("records the builtins it calls, including inside every, and no operators", func() {
		checked, err := condition.Check(teamNamespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(checked.Builtins).To(Equal(model.BuiltinSet{"concat", "count", "object.keys", "print", "startswith", "trim_prefix"}))
	})
	It("accepts rego.v1 and future.keywords imports", func() {
		Expect(condition.Check("package condition\nimport rego.v1\nimport future.keywords.in\nimport future.keywords\nallow if true\n")).Error().NotTo(HaveOccurred())
	})
	It("reports every violation with its position", func() {
		_, err := condition.Check("package other\nimport data.other\nallow := 1 if true\n")
		Expect(err).To(MatchError(ContainSubstring("1:1: package must be condition")))
		Expect(err).To(MatchError(ContainSubstring("2:1: import data.other isn't allowed")))
		Expect(err).To(MatchError(ContainSubstring("3:1: allow must be true")))
	})
	It("refuses more than MaxRules rules", func() {
		var source strings.Builder
		source.WriteString("package condition\nallow if true\n")
		for i := range condition.MaxRules {
			fmt.Fprintf(&source, "r%d := %d\n", i, i)
		}
		Expect(condition.Check(source.String())).Error().To(MatchError(ContainSubstring("more than 128")))
	})
	DescribeTable("refuses a module outside the language", func(source, fragment string) {
		Expect(condition.Check(source)).Error().To(MatchError(ContainSubstring(fragment)))
	},
		Entry("a parse error", "package condition\nallow if {", "rego_parse_error"),
		Entry("a compile error", "package condition\nallow if undefined_var\n", "rego_unsafe_var_error"),
		Entry("another package", "package authz\nallow if true\n", "package must be condition"),
		Entry("an import of data", "package condition\nimport data.authz\nallow if true\n", "import data.authz isn't allowed"),
		Entry("an import of input", "package condition\nimport input.request\nallow if true\n", "import input.request isn't allowed"),
		Entry("a with modifier", "package condition\nallow if { input.x with input as {\"x\": true} }\n", "with modifiers aren't allowed"),
		Entry("a reference head", "package condition\nallow if true\nhelpers.limit := 3\n", "rule helpers.limit has a reference head"),
		Entry("a partial object rule", "package condition\nallow if true\nobj[\"k\"] := 1\n", "has a reference head"),
		Entry("no allow rule", "package condition\ngrant if true\n", "defines no allow rule"),
		Entry("only a default allow", "package condition\ndefault allow := false\n", "defines no allow rule"),
		Entry("allow as a function", "package condition\nallow(x) if x\n", "allow must not be a function"),
		Entry("allow as a multi-value rule", "package condition\nallow contains 1 if true\n", "allow must not be a multi-value rule"),
		Entry("allow with another value", "package condition\nallow := \"yes\" if true\n", "allow must be true"),
		Entry("allow with an else branch", "package condition\nallow if input.x\nelse := false\n", "allow must not have an else branch"),
		Entry("a default allow of true", "package condition\ndefault allow := true\nallow if input.x\n", "default allow must be false"),
		Entry("a reference to another package", "package condition\nallow if data.authz.state\n", "reference data.authz.state isn't allowed"),
		Entry("a reference to the package itself", "package condition\nallow if { x := data.condition; x.limit }\nlimit := 1\n", "recursive"),
		Entry("a computed reference into the package", "package condition\nallow if { k := \"limit\"; data.condition[k] }\nlimit := 1\n", "recursive"),
	)
})
