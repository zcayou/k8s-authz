package condition

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/format"

	"github.com/zcayou/k8s-authz/internal/model"
)

const (
	// Package is the conditions module's package.
	Package = "authz.conditions"
	// PolicyID is the policy ID engines install the conditions module under.
	PolicyID = "k8s-authz/conditions"
)

var generatedPath = ast.MustParseRef("data." + Package)

// Module is a revision's generated conditions module.
type Module struct {
	Source []byte
	Digest string
}

// Generate renders conditions into one module. The same conditions always
// produce the same Source and Digest.
func Generate(conditions map[string]model.Condition) (Module, error) {
	header := []byte("package " + Package + "\n")
	body := bytes.Clone(header)
	for _, id := range slices.Sorted(maps.Keys(conditions)) {
		rules, err := render(conditions[id], header)
		if err != nil {
			return Module{}, fmt.Errorf("condition %s: %w", id, err)
		}
		body = append(body, rules...)
	}
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	return Module{
		Source: fmt.Appendf(body, "\ndigest := %q\n", digest),
		Digest: digest,
	}, nil
}

// render returns the condition's rules renamed into the conditions package,
// formatted on their own: the formatter orders rules by source location,
// and would interleave conditions formatted together.
func render(condition model.Condition, header []byte) ([]byte, error) {
	parsed, err := parse(condition.Rego)
	if err != nil {
		return nil, err
	}
	compiled, err := compile(parsed)
	if err != nil {
		return nil, err
	}
	module := compiled.Copy()
	rename := func(name string) string { return "c_" + condition.ID + "_" + name }
	for _, rule := range module.Rules {
		for branch := rule; branch != nil; branch = branch.Else {
			name := ast.Var(rename(ruleName(branch)))
			branch.Head.Name = name
			branch.Head.Reference = ast.Ref{ast.VarTerm(string(name))}
			branch.Annotations = nil
		}
	}
	transformed, err := ast.TransformRefs(module, func(ref ast.Ref) (ast.Value, error) {
		if len(ref) <= len(packagePath) || !ref.HasPrefix(packagePath) {
			return ref, nil
		}
		name, ok := ref[len(packagePath)].Value.(ast.String)
		if !ok {
			return ref, nil
		}
		renamed := generatedPath.Append(ast.StringTerm(rename(string(name))))
		return renamed.Concat(ref[len(packagePath)+1:]), nil
	})
	if err != nil {
		return nil, err
	}
	module, ok := transformed.(*ast.Module)
	if !ok {
		return nil, fmt.Errorf("transformed module is a %T", transformed)
	}
	module.Package = &ast.Package{Path: generatedPath}
	module.Imports = nil
	module.Annotations = nil
	module.Comments = nil
	formatted, err := format.AstWithOpts(module, format.Opts{RegoVersion: ast.RegoV1})
	if err != nil {
		return nil, err
	}
	rules, ok := bytes.CutPrefix(formatted, header)
	if !ok {
		return nil, fmt.Errorf("formatted module doesn't start with %q", header)
	}
	return rules, nil
}
