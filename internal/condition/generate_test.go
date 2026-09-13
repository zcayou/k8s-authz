package condition_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/model"
)

var _ = Describe("Generate", func() {
	It("renders no conditions as the package and its digest", func() {
		module, err := condition.Generate(nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(module.Digest).To(Equal(bodyDigest("package authz.conditions\n")))
		Expect(string(module.Source)).To(Equal("package authz.conditions\n\ndigest := \"" + module.Digest + "\"\n"))
	})
	It("digests the module without its digest line", func() {
		module, err := condition.Generate(checked(teamNamespace))
		Expect(err).NotTo(HaveOccurred())
		body, found := strings.CutSuffix(string(module.Source), "\ndigest := \""+module.Digest+"\"\n")
		Expect(found).To(BeTrue())
		Expect(module.Digest).To(Equal(bodyDigest(body)))
	})
	It("produces the same module whatever the map's order", func() {
		conditions := checked(teamNamespace, "package condition\nallow if input.x\n", "package condition\nallow if input.y\n")
		first, err := condition.Generate(conditions)
		Expect(err).NotTo(HaveOccurred())
		for range 20 {
			Expect(condition.Generate(maps.Clone(conditions))).To(Equal(first))
		}
	})
	It("keeps each condition's rules together in ID order when their locations interleave", func() {
		conditions := checked(
			"package condition\nallow if a\na if input.a\n",
			"package condition\nallow if b\nb if input.b\n",
		)
		module, err := condition.Generate(conditions)
		Expect(err).NotTo(HaveOccurred())
		var owners []string
		for line := range strings.Lines(string(module.Source)) {
			if name, found := strings.CutPrefix(line, "c_"); found {
				id, _, _ := strings.Cut(name, "_")
				owners = append(owners, id)
			}
		}
		ids := slices.Sorted(maps.Keys(conditions))
		Expect(owners).To(Equal([]string{ids[0], ids[0], ids[1], ids[1]}))
	})
	It("renames rules that refer to each other, including functions and else chains", func(ctx SpecContext) {
		conditions := checked(teamNamespace)
		id := slices.Collect(maps.Keys(conditions))[0]
		module, err := condition.Generate(conditions)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(module.Source)).NotTo(ContainSubstring("data.condition"))
		allow := func(groups []string, namespace string) bool {
			input := map[string]any{
				"principal": map[string]any{"groups": groups, "extra": map[string]any{}},
				"request":   map[string]any{"resourceAttributes": map[string]any{"namespace": namespace}},
			}
			query := fmt.Sprintf("data.authz.conditions.c_%s_allow", id)
			results, err := rego.New(rego.Query(query), rego.Module(condition.PolicyID, string(module.Source)), rego.Input(input)).Eval(ctx)
			Expect(err).NotTo(HaveOccurred())
			return len(results) == 1 && results[0].Expressions[0].Value == true
		}
		Expect(allow([]string{"team:payments"}, "team-payments")).To(BeTrue())
		Expect(allow([]string{"team:payments"}, "team-billing")).To(BeFalse())
		Expect(allow([]string{"payments"}, "none")).To(BeTrue())
	})
	It("compiles with the engine's modules", func() {
		module, err := condition.Generate(checked(teamNamespace, "package condition\nallow if input.x\n"))
		Expect(err).NotTo(HaveOccurred())
		parsed := map[string]*ast.Module{}
		for name, text := range engine.Modules() {
			parsed[name], err = ast.ParseModuleWithOpts(name, text, ast.ParserOptions{RegoVersion: ast.RegoV1})
			Expect(err).NotTo(HaveOccurred())
		}
		parsed[condition.PolicyID], err = ast.ParseModuleWithOpts(condition.PolicyID, string(module.Source), ast.ParserOptions{RegoVersion: ast.RegoV1})
		Expect(err).NotTo(HaveOccurred())
		compiler := ast.NewCompiler()
		compiler.Compile(parsed)
		Expect(compiler.Errors).To(BeEmpty())
	})
})

func checked(sources ...string) map[string]model.Condition {
	GinkgoHelper()
	conditions := make(map[string]model.Condition, len(sources))
	for _, source := range sources {
		checked, err := condition.Check(source)
		Expect(err).NotTo(HaveOccurred())
		conditions[checked.ID] = checked
	}
	return conditions
}

func bodyDigest(body string) string {
	sum := sha256.Sum256([]byte(body))
	return "sha256:" + hex.EncodeToString(sum[:])
}
