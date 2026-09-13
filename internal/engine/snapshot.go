package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"strconv"
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/model"
)

// MaxContentBytes bounds the encoded state document pushed to an engine.
const MaxContentBytes int64 = 32 * 1024 * 1024

// MaxConditionModuleBytes bounds the conditions module pushed to an engine.
// Installing it recompiles every module the engine holds, and the bound keeps
// that recompile well inside the management client's timeout on a CPU-limited
// engine.
const MaxConditionModuleBytes int64 = 1024 * 1024

// MaxExportBytes bounds an export of an installed state document: the document,
// which MaxContentBytes bounds, as an engine re-encodes it and wrapped
// with the export's metadata.
const MaxExportBytes = MaxContentBytes + 1024*1024

// FinalizeContent generates prepared's conditions module, binds prepared
// to service, this release's evaluator and the module's digest, and addresses
// the result by the digest of its encoding. It fails with model.ErrLimit when
// the module exceeds MaxConditionModuleBytes or the encoded state document,
// revision included, exceeds MaxContentBytes. Those are the only checks before
// the module and the document are pushed.
func FinalizeContent(prepared model.PreparedRevision, service model.ServiceUID) (model.ContentRevision, condition.Module, error) {
	module, err := conditionsModule(prepared.Conditions)
	if err != nil {
		return model.ContentRevision{}, condition.Module{}, err
	}
	content := model.ContentRevision{PreparedRevision: prepared, ServiceUID: service, EvaluatorID: EvaluatorID(), ConditionsDigest: module.Digest}
	hash := sha256.New()
	var size countingWriter
	if err := json.NewEncoder(io.MultiWriter(hash, &size)).Encode(content); err != nil {
		return model.ContentRevision{}, condition.Module{}, fmt.Errorf("encode state document: %w", err)
	}
	content.Revision = model.RevisionID("sha256:" + hex.EncodeToString(hash.Sum(nil)))
	// The pushed document is the digested one, less the encoder's trailing
	// newline, with the revision appended as its last field.
	pushed := int64(size) - 1 + int64(len(`,"revision":`)+len(strconv.Quote(string(content.Revision))))
	if pushed > MaxContentBytes {
		return model.ContentRevision{}, condition.Module{}, fmt.Errorf("state document of %d bytes exceeds %d bytes: %w", pushed, MaxContentBytes, model.ErrLimit)
	}
	return content, module, nil
}

// conditionsModule generates the module of conditions and compiles
// it with the release's modules, as an engine does when the module
// is installed. Each condition compiled on its own when it was checked, so
// a compile error here is the generator's fault.
func conditionsModule(conditions map[string]model.Condition) (condition.Module, error) {
	module, err := condition.Generate(conditions)
	if err != nil {
		return condition.Module{}, fmt.Errorf("generate conditions module: %w", err)
	}
	if size := int64(len(module.Source)); size > MaxConditionModuleBytes {
		return condition.Module{}, fmt.Errorf("conditions module of %d bytes exceeds %d bytes: %w", size, MaxConditionModuleBytes, model.ErrLimit)
	}
	fixed, err := parsedModules()
	if err != nil {
		return condition.Module{}, err
	}
	parsed, err := ast.ParseModuleWithOpts(condition.PolicyID, string(module.Source), ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return condition.Module{}, fmt.Errorf("parse conditions module: %w", err)
	}
	modules := maps.Clone(fixed)
	modules[condition.PolicyID] = parsed
	compiler := ast.NewCompiler()
	if compiler.Compile(modules); compiler.Failed() {
		return condition.Module{}, fmt.Errorf("compile conditions module: %w", compiler.Errors)
	}
	return module, nil
}

// parsedModules parses the release's modules once. The compiler copies
// the modules it compiles, so they're shared.
var parsedModules = sync.OnceValues(func() (map[string]*ast.Module, error) {
	parsed := map[string]*ast.Module{}
	for name, text := range modules() {
		module, err := ast.ParseModuleWithOpts(name, text, ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			return nil, fmt.Errorf("parse module %s: %w", name, err)
		}
		parsed[name] = module
	}
	return parsed, nil
})

type countingWriter int64

func (w *countingWriter) Write(data []byte) (int, error) {
	*w += countingWriter(len(data))
	return len(data), nil
}
