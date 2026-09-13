package condition

import (
	"errors"
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/zcayou/k8s-authz/internal/model"
)

// MaxRules bounds the rules of one condition module.
const MaxRules = 128

const entryPoint = "allow"

var (
	packagePath    = ast.MustParseRef("data.condition")
	regoV1Import   = ast.MustParseRef("rego.v1")
	futureKeywords = ast.MustParseRef("future.keywords")
)

// Check compiles source as a condition and returns it with its ID
// and the builtins it calls. The error lists every violation, each with its row
// and column when OPA reports one.
func Check(source string) (model.Condition, error) {
	parsed, err := parse(source)
	if err != nil {
		return model.Condition{}, err
	}
	violations := structure(parsed)
	compiled, err := compile(parsed)
	if err != nil {
		violations = append(violations, err)
	}
	if len(violations) > 0 {
		return model.Condition{}, errors.Join(violations...)
	}
	if err := errors.Join(references(compiled)...); err != nil {
		return model.Condition{}, err
	}
	return model.Condition{
		ID:       model.Digest(source),
		Rego:     source,
		Builtins: builtins(compiled),
	}, nil
}

func parse(source string) (*ast.Module, error) {
	return ast.ParseModuleWithOpts("condition", source, ast.ParserOptions{RegoVersion: ast.RegoV1})
}

// compile compiles a parsed condition alone and returns the compiled module,
// whose references are resolved. Print statements are enabled so the compiler
// keeps print calls, which it would otherwise erase.
func compile(parsed *ast.Module) (*ast.Module, error) {
	compiler := ast.NewCompiler().
		WithCapabilities(ast.CapabilitiesForThisVersion()).
		WithEnablePrintStatements(true)
	compiler.Compile(map[string]*ast.Module{"condition": parsed})
	if compiler.Failed() {
		return nil, compiler.Errors
	}
	return compiler.Modules["condition"], nil
}

// structure reports the violations visible on the parsed module.
func structure(module *ast.Module) []error {
	var violations []error
	if !module.Package.Path.Equal(packagePath) {
		violations = append(violations, violation(module.Package.Location, "package must be condition, not %s", module.Package.Path))
	}
	for _, imp := range module.Imports {
		if !allowedImport(imp) {
			violations = append(violations, violation(imp.Location, "import %s isn't allowed; only rego.v1 and future.keywords are", imp.Path))
		}
	}
	ast.WalkExprs(module, func(expr *ast.Expr) bool {
		if len(expr.With) > 0 {
			violations = append(violations, violation(expr.Location, "with modifiers aren't allowed"))
		}
		return false
	})
	if len(module.Rules) > MaxRules {
		violations = append(violations, fmt.Errorf("module has %d rules, more than %d", len(module.Rules), MaxRules))
	}
	entry := false
	for _, rule := range module.Rules {
		for branch := rule; branch != nil; branch = branch.Else {
			if len(branch.Head.Ref()) > 1 {
				violations = append(violations, violation(branch.Location, "rule %s has a reference head; rule names must be plain", branch.Head.Ref()))
			}
		}
		if ruleName(rule) != entryPoint {
			continue
		}
		if !rule.Default {
			entry = true
		}
		violations = append(violations, entryViolations(rule)...)
	}
	if !entry {
		violations = append(violations, errors.New("module defines no allow rule"))
	}
	return violations
}

func allowedImport(imp *ast.Import) bool {
	path, ok := imp.Path.Value.(ast.Ref)
	if !ok {
		return false
	}
	return path.Equal(regoV1Import) ||
		(path.HasPrefix(futureKeywords) && len(path) <= len(futureKeywords)+1)
}

// entryViolations reports an allow rule that isn't a plain boolean: allow
// holds exactly when one of its non-default rules succeeds.
func entryViolations(rule *ast.Rule) []error {
	var violations []error
	switch {
	case len(rule.Head.Args) > 0:
		violations = append(violations, violation(rule.Location, "allow must not be a function"))
	case rule.Head.RuleKind() == ast.MultiValue:
		violations = append(violations, violation(rule.Location, "allow must not be a multi-value rule"))
	case rule.Default:
		if !rule.Head.Value.Equal(ast.BooleanTerm(false)) {
			violations = append(violations, violation(rule.Location, "default allow must be false"))
		}
	default:
		if !rule.Head.Value.Equal(ast.BooleanTerm(true)) {
			violations = append(violations, violation(rule.Location, "allow must be true when it holds"))
		}
		if rule.Else != nil {
			violations = append(violations, violation(rule.Else.Location, "allow must not have an else branch"))
		}
	}
	return violations
}

// references reports each reference into data other than to one of the module's
// own rules by a constant name. The generator can rewrite only those
// to the renamed rules.
func references(module *ast.Module) []error {
	rules := make(map[ast.Value]bool, len(module.Rules))
	for _, rule := range module.Rules {
		rules[ast.String(ruleName(rule))] = true
	}
	var violations []error
	for _, rule := range module.Rules {
		ast.WalkRefs(rule, func(ref ast.Ref) bool {
			if !ref.HasPrefix(ast.DefaultRootRef) {
				return false
			}
			if len(ref) < len(packagePath)+1 || !ref.HasPrefix(packagePath) || !rules[ref[len(packagePath)].Value] {
				violations = append(violations, violation(ref[0].Location, "reference %s isn't allowed; data may only name this module's rules", ref))
			}
			return false
		})
	}
	return violations
}

// builtins returns the builtins the compiled module calls. It walks every call,
// because the compiler's own record misses calls inside every bodies. Operators
// aren't builtins an allowlist names, and template strings are syntax.
func builtins(module *ast.Module) model.BuiltinSet {
	var names []string
	record := func(operator ast.Ref) {
		name := operator.String()
		builtin, ok := ast.BuiltinMap[name]
		if !ok || builtin.Infix != "" || name == ast.InternalTemplateString.Name {
			return
		}
		if name == ast.InternalPrint.Name {
			name = ast.Print.Name
		}
		names = append(names, name)
	}
	for _, rule := range module.Rules {
		ast.WalkExprs(rule, func(expr *ast.Expr) bool {
			if expr.IsCall() {
				record(expr.Operator())
			}
			return false
		})
		ast.WalkTerms(rule, func(term *ast.Term) bool {
			if call, ok := term.Value.(ast.Call); ok {
				if operator, ok := call[0].Value.(ast.Ref); ok {
					record(operator)
				}
			}
			return false
		})
	}
	return model.NewBuiltinSet(names)
}

func ruleName(rule *ast.Rule) string {
	return rule.Head.Ref()[0].Value.String()
}

func violation(location *ast.Location, format string, args ...any) error {
	message := fmt.Sprintf(format, args...)
	if location == nil {
		return errors.New(message)
	}
	return fmt.Errorf("%d:%d: %s", location.Row, location.Col, message)
}
