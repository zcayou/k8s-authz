package engine

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"

	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/model"
)

// explainModule is loaded only to explain a snapshot, never into an engine.
//
//go:embed explain.rego
var explainModule string

// unexplainedBuiltins reach the network or describe the machine they run on.
// Explanation never runs them, so it never reaches out from its machine.
var unexplainedBuiltins = []string{"http.send", "net.lookup_ip_addr", "opa.runtime"}

// SnapshotEvaluation is the evaluator's decision on one request
// and the evidence behind it.
type SnapshotEvaluation struct {
	Decision model.Decision `json:"decision"`
	// Principal is the normalized principal, zero when the request is malformed.
	Principal model.Principal `json:"principal"`
	// Terminals maps each diagram the deciding authority reads to the terminals
	// the request reaches whose principal predicates match.
	Terminals map[string][]string `json:"terminals"`
	// Conditions maps the ID of each condition of every reached contribution
	// to whether it held.
	Conditions map[string]bool `json:"conditions"`
}

// EvaluateSnapshot evaluates the raw SubjectAccessReview rawRequest on endpoint
// of state, an installed state document, with the modules an engine serves
// it with, as the engine of state's service. It refuses state that another
// evaluator compiled, because only its own evaluator can explain it. state may
// come from any file, so its conditions are untrusted: it checks each again,
// refuses one that calls a builtin explanation doesn't run, and refuses state
// whose conditions don't regenerate its conditions digest. When ctx ends
// first, the error wraps its cause.
func EvaluateSnapshot(ctx context.Context, state model.ContentRevision, endpoint string, rawRequest []byte) (SnapshotEvaluation, error) {
	if evaluator := EvaluatorID(); state.EvaluatorID != evaluator {
		return SnapshotEvaluation{}, fmt.Errorf("state was compiled by evaluator %q, not this release's %q", state.EvaluatorID, evaluator)
	}
	if _, found := state.Endpoints[endpoint]; !found {
		return SnapshotEvaluation{}, fmt.Errorf("unknown endpoint %q", endpoint)
	}
	decoder := json.NewDecoder(bytes.NewReader(rawRequest))
	decoder.UseNumber()
	var request any
	if err := decoder.Decode(&request); err != nil {
		return SnapshotEvaluation{}, fmt.Errorf("decode SubjectAccessReview: %w", err)
	}
	if err := context.Cause(ctx); err != nil {
		return SnapshotEvaluation{}, fmt.Errorf("evaluate authorization snapshot: %w", err)
	}
	module, err := snapshotConditions(state)
	if err != nil {
		return SnapshotEvaluation{}, err
	}
	prepared, err := prepareExplanation(ctx, state, module)
	if err != nil {
		return SnapshotEvaluation{}, err
	}
	results, err := prepared.Eval(ctx, rego.EvalInput(map[string]any{"endpoint": endpoint, "request": request}))
	if err != nil {
		// OPA notices cancellation asynchronously, and a builtin that notices
		// it first reports its own error without wrapping the context's.
		if cause := context.Cause(ctx); cause != nil {
			err = cause
		}
		return SnapshotEvaluation{}, fmt.Errorf("evaluate authorization snapshot: %w", err)
	}
	if len(results) != 1 || len(results[0].Expressions) != 1 {
		return SnapshotEvaluation{}, errors.New("fixed evaluator returned no single decision")
	}
	encoded, err := json.Marshal(results[0].Expressions[0].Value)
	if err != nil {
		return SnapshotEvaluation{}, fmt.Errorf("encode evaluator decision: %w", err)
	}
	var evaluation SnapshotEvaluation
	if err = json.Unmarshal(encoded, &evaluation); err != nil {
		return SnapshotEvaluation{}, fmt.Errorf("decode evaluator decision: %w", err)
	}
	return evaluation, nil
}

// snapshotConditions checks state's conditions and regenerates their module.
func snapshotConditions(state model.ContentRevision) (condition.Module, error) {
	checked := make(map[string]model.Condition, len(state.Conditions))
	for _, id := range slices.Sorted(maps.Keys(state.Conditions)) {
		stated := state.Conditions[id]
		result, err := condition.Check(stated.Rego)
		if err != nil {
			return condition.Module{}, fmt.Errorf("state's condition %s: %w", id, err)
		}
		if result.ID != id || stated.ID != id {
			return condition.Module{}, fmt.Errorf("state's condition %s isn't the digest of its source, %s", id, result.ID)
		}
		if called := unexplainedCalls(result.Builtins); len(called) > 0 {
			return condition.Module{}, fmt.Errorf("state's condition %s calls %s, which explanation doesn't run", id, strings.Join(called, ", "))
		}
		checked[id] = result
	}
	module, err := condition.Generate(checked)
	if err != nil {
		return condition.Module{}, fmt.Errorf("generate conditions module: %w", err)
	}
	if module.Digest != state.ConditionsDigest {
		return condition.Module{}, fmt.Errorf("state's conditions digest %q doesn't match this release's %q", state.ConditionsDigest, module.Digest)
	}
	return module, nil
}

func unexplainedCalls(builtins model.BuiltinSet) []string {
	return slices.DeleteFunc(slices.Clone(unexplainedBuiltins), func(name string) bool {
		return !slices.Contains(builtins, name)
	})
}

// explanationCapabilities are the release's capabilities without the builtins
// explanation doesn't run. The fixed modules call none of them.
func explanationCapabilities() *ast.Capabilities {
	capabilities := ast.CapabilitiesForThisVersion()
	capabilities.Builtins = slices.DeleteFunc(capabilities.Builtins, func(builtin *ast.Builtin) bool {
		return slices.Contains(unexplainedBuiltins, builtin.Name)
	})
	return capabilities
}

func prepareExplanation(ctx context.Context, state model.ContentRevision, conditions condition.Module) (rego.PreparedEvalQuery, error) {
	modules := Modules()
	modules["explain.rego"] = explainModule
	modules[condition.PolicyID] = string(conditions.Source)
	options := make([]func(*rego.Rego), 0, len(modules)+3)
	options = append(options, rego.Query("data.authz.explain.explanation"), rego.Capabilities(explanationCapabilities()))
	for _, name := range slices.Sorted(maps.Keys(modules)) {
		options = append(options, rego.Module(name, modules[name]))
	}
	bootstrap := Bootstrap{ServiceUID: state.ServiceUID, EvaluatorID: state.EvaluatorID}
	options = append(options, rego.Store(inmem.NewFromObject(map[string]any{"bootstrap": bootstrap, "authz": map[string]any{"state": state}})))
	prepared, err := rego.New(options...).PrepareForEval(ctx)
	if err != nil {
		return rego.PreparedEvalQuery{}, fmt.Errorf("prepare fixed evaluator: %w", err)
	}
	return prepared, nil
}
