package engine

import (
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/zcayou/k8s-authz/internal/compiler"
	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/model"
)

// Program is a service's compilation, and the state document and conditions
// module it pushes to the service's engines.
type Program struct {
	Compilation compiler.Compilation
	Content     model.ContentRevision
	Conditions  condition.Module
}

// Prepare compiles config over sources and finalizes the program
// for the engines of the service whose UID is service.
func Prepare(service model.ServiceUID, config model.ServiceConfig, sources map[model.SourceKey]model.SourceObservation) (Program, error) {
	compilation, err := compiler.Compile(config, sources, compiler.DefaultLimits())
	if err != nil {
		return Program{}, fmt.Errorf("compile policy: %w", err)
	}
	content, conditions, err := FinalizeContent(compilation.Prepared, service)
	if err != nil {
		return Program{}, err
	}
	return Program{Compilation: compilation, Content: content, Conditions: conditions}, nil
}

// Cache holds one Program per service and reuses it while the service's UID,
// its configuration and the documents its compilation read are unchanged. It's
// safe for concurrent use. Callers must not modify a returned Program.
type Cache struct {
	mu      sync.Mutex
	entries map[serviceName]cachedProgram
}

type serviceName struct {
	namespace, name string
}

type cachedProgram struct {
	uid        model.ServiceUID
	config     string
	references []model.Reference
	inputs     string
	program    Program
}

func NewCache() *Cache {
	return &Cache{entries: map[serviceName]cachedProgram{}}
}

// Prepare returns the Program of service's configuration, reusing the cached
// one when only documents its compilation didn't read changed. It records
// the duration and outcome of each compilation it runs in the operator's
// metrics. A service recreated under the same name never reuses the program
// of its former incarnation.
func (c *Cache) Prepare(service model.Identity, config model.ServiceConfig, sources map[model.SourceKey]model.SourceObservation) (Program, error) {
	key := serviceName{service.Namespace, service.Name}
	uid := model.ServiceUID(service.UID)
	configDigest := model.Digest(config)
	c.mu.Lock()
	cached, found := c.entries[key]
	c.mu.Unlock()
	if found && cached.uid == uid && cached.config == configDigest && compilationInputs(sources, cached.references) == cached.inputs {
		return cached.program, nil
	}
	started := time.Now()
	program, err := Prepare(uid, config, sources)
	observeCompilation(time.Since(started), program, err)
	if err != nil {
		return Program{}, err
	}
	references := slices.Collect(maps.Keys(program.Compilation.References))
	model.SortReferences(references)
	inputs := compilationInputs(sources, references)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cachedProgram{uid: uid, config: configDigest, references: references, inputs: inputs, program: program}
	return program, nil
}

// Forget drops the Program of the service namespace/name.
func (c *Cache) Forget(namespace, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, serviceName{namespace, name})
}

type documentInput struct {
	Reference  model.Reference      `json:"reference"`
	Instance   model.SourceInstance `json:"instance"`
	Registered bool                 `json:"registered"`
	Complete   bool                 `json:"complete"`
	Failure    model.Failure        `json:"failure"`
	Present    bool                 `json:"present"`
	UID        string               `json:"uid"`
	Digest     string               `json:"digest"`
	// AllowedBuiltins are the source's, which decide whether the document's
	// conditions compile.
	AllowedBuiltins *model.BuiltinSet `json:"allowedBuiltins"`
}

// compilationInputs digests what a compilation read of each reference: its
// source's incarnation and allowed builtins, and its failure or the document's
// state.
func compilationInputs(sources map[model.SourceKey]model.SourceObservation, references []model.Reference) string {
	inputs := make([]documentInput, 0, len(references))
	for _, reference := range references {
		source, registered := sources[reference.Source]
		state, found := source.Documents[reference]
		inputs = append(inputs, documentInput{
			Reference: reference, Instance: source.Instance, Registered: registered, Complete: source.Complete, Failure: source.Failure,
			Present: found, UID: state.UID, Digest: state.Digest, AllowedBuiltins: source.AllowedBuiltins,
		})
	}
	return model.Digest(inputs)
}
