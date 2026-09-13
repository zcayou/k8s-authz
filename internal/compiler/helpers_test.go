package compiler_test

import (
	"context"
	"encoding/json"
	"maps"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/compiler"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/validation"
	"github.com/zcayou/k8s-authz/test/utils"
)

// fixture is one source whose entry binding targets the PolicySet root,
// and the other sources a spec adds.
type fixture struct {
	source      model.SourceInstance
	observation model.SourceObservation
	others      map[model.SourceKey]model.SourceObservation
	config      model.ServiceConfig
	limits      compiler.Limits
}

func newFixture() *fixture {
	source := model.SourceInstance{Key: model.SourceKey{Namespace: "control", Name: "local"}, UID: "source-1", Origin: "api-local"}
	root := model.Reference{Source: source.Key, Group: api.GroupVersion.Group, Kind: model.KindPolicyBinding, Namespace: "policies", Name: "entry"}
	result := &fixture{
		source:      source,
		observation: model.SourceObservation{Instance: source, Complete: true, Documents: map[model.Reference]model.DocumentState{}},
		others:      map[model.SourceKey]model.SourceObservation{},
		config: model.ServiceConfig{Endpoints: []model.EndpointConfig{{Name: "cluster", WhenEvaluationFails: "Deny", Sources: []model.SourceKey{source.Key}, Authorities: []model.AuthorityConfig{{
			Binding: root, Fallback: "NoOpinion",
		}}}}},
		limits: compiler.DefaultLimits(),
	}
	result.custom(model.KindPolicyBinding, "entry", `{"policyRef":{"kind":"PolicySet","name":"root"},"subjectMatch":{},"constraints":{"maxDepth":4}}`)
	return result
}

func (f *fixture) put(object *unstructured.Unstructured) {
	GinkgoHelper()
	state := validation.DecodeDocument(f.source, object)
	Expect(state.Document).NotTo(BeNil(), "%v", state.Issues)
	f.observation.Documents[state.Key.Reference()] = state
}

func (f *fixture) custom(kind, name, spec string) {
	f.put(utils.Document(kind, "policies", name, spec))
}

// addSource adds the complete source control/name that the endpoint reads.
func (f *fixture) addSource(name string) model.SourceKey {
	instance := model.SourceInstance{Key: model.SourceKey{Namespace: "control", Name: name}, UID: name + "-uid", Origin: "api-" + name}
	f.others[instance.Key] = model.SourceObservation{Instance: instance, Complete: true, Documents: map[model.Reference]model.DocumentState{}}
	f.config.Endpoints[0].Sources = append(f.config.Endpoints[0].Sources, instance.Key)
	return instance.Key
}

// customIn puts a product document into the added source key.
func (f *fixture) customIn(key model.SourceKey, kind, name, spec string) {
	f.putIn(key, utils.Document(kind, "policies", name, spec))
}

func (f *fixture) putIn(key model.SourceKey, object *unstructured.Unstructured) {
	GinkgoHelper()
	observation := f.others[key]
	state := validation.DecodeDocument(observation.Instance, object)
	Expect(state.Document).NotTo(BeNil(), "%v", state.Issues)
	observation.Documents[state.Key.Reference()] = state
}

// allowRego makes key's source allow Rego conditions calling builtins.
func (f *fixture) allowRego(key model.SourceKey, builtins model.BuiltinSet) {
	if key == f.source.Key {
		f.observation.AllowedBuiltins = &builtins
		return
	}
	observation := f.others[key]
	observation.AllowedBuiltins = &builtins
	f.others[key] = observation
}

func (f *fixture) sources() map[model.SourceKey]model.SourceObservation {
	sources := maps.Clone(f.others)
	sources[f.source.Key] = f.observation
	return sources
}

// conditional returns a Policy spec that includes rules and carries
// the condition whose allow rule is allow.
func conditional(rules, allow string) string {
	GinkgoHelper()
	rego, err := json.Marshal("package condition\n" + allow + "\n")
	Expect(err).NotTo(HaveOccurred())
	return `{"include":` + rules + `,"condition":{"rego":` + string(rego) + `}}`
}

// compile compiles the fixture's sources and checks every diagram's structure.
func (f *fixture) compile() compiler.Compilation {
	GinkgoHelper()
	result, err := compiler.Compile(f.config, f.sources(), f.limits)
	Expect(err).NotTo(HaveOccurred())
	for _, diagram := range result.Prepared.Diagrams {
		Expect(utils.ValidateDiagram(diagram, f.limits.MaxDiagramNodes)).To(Succeed())
	}
	return result
}

// decide evaluates user's verb on a core resource in namespace against
// the program's cluster endpoint.
func decide(ctx context.Context, program model.PreparedRevision, verb, resource, namespace, user string) model.Decision {
	GinkgoHelper()
	result, err := utils.Evaluate(ctx, program, "cluster", utils.SubjectAccessReview(user, verb, resource, namespace))
	Expect(err).NotTo(HaveOccurred())
	return result.Decision
}

func expectProgramWithinLimits(program model.PreparedRevision, limits compiler.Limits) {
	GinkgoHelper()
	nodes := 0
	for _, diagram := range program.Diagrams {
		nodes += len(diagram.Nodes)
		Expect(utils.ValidateDiagram(diagram, limits.MaxDiagramNodes)).To(Succeed())
	}
	Expect(nodes).To(BeNumerically("<=", limits.MaxDiagramNodes))
	Expect(engine.FinalizeContent(program, utils.ServiceUID)).Error().NotTo(HaveOccurred())
}
