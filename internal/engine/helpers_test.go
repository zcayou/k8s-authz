package engine_test

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/validation"
	"github.com/zcayou/k8s-authz/test/utils"
)

const (
	compileDurationMetric      = "k8s_authz_compile_duration_seconds"
	compileLimitFailuresMetric = "k8s_authz_compile_limit_failures_total"
)

// metricTotal reads the named metric from the operator's registry: a counter's
// value, or a histogram's observation count, summed over every label value.
func metricTotal(name string) float64 {
	GinkgoHelper()
	families, err := metrics.Registry.Gather()
	Expect(err).NotTo(HaveOccurred())
	total := 0.0
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			total += metric.GetCounter().GetValue() + float64(metric.GetHistogram().GetSampleCount())
		}
	}
	return total
}

type sourceFixture struct {
	source      model.SourceInstance
	observation model.SourceObservation
	config      model.ServiceConfig
}

func newSourceFixture() *sourceFixture {
	source := model.SourceInstance{Key: model.SourceKey{Namespace: "control", Name: "local"}, UID: "source-uid", Origin: "api-local"}
	entry := model.Reference{Source: source.Key, Group: api.GroupVersion.Group, Kind: model.KindPolicyBinding, Namespace: "policies", Name: "entry"}
	fixture := &sourceFixture{source: source, observation: model.SourceObservation{Instance: source, Complete: true, Documents: map[model.Reference]model.DocumentState{}},
		config: model.ServiceConfig{Endpoints: []model.EndpointConfig{{Name: "cluster", WhenEvaluationFails: "Deny", Sources: []model.SourceKey{source.Key}, Authorities: []model.AuthorityConfig{{Binding: entry, Fallback: "NoOpinion"}}}}}}
	fixture.put(model.KindPolicyBinding, "entry", map[string]any{"policyRef": map[string]any{"kind": model.KindPolicySet, "name": "root"}, "subjectMatch": map[string]any{}})
	return fixture
}

func (fixture *sourceFixture) put(kind, name string, spec any) {
	GinkgoHelper()
	encoded, err := json.Marshal(spec)
	Expect(err).NotTo(HaveOccurred())
	state := validation.DecodeDocument(fixture.source, utils.Document(kind, "policies", name, string(encoded)))
	Expect(state.Document).NotTo(BeNil(), "%s/%s: %v", kind, name, state.Issues)
	fixture.observation.Documents[state.Key.Reference()] = state
}

func (fixture *sourceFixture) ref(kind, name string) model.Reference {
	return model.Reference{Source: fixture.source.Key, Group: api.GroupVersion.Group, Kind: kind, Namespace: "policies", Name: name}
}

func operationRule(resource string) map[string]any {
	return map[string]any{"apiGroups": []string{""}, "resources": []string{resource}, "verbs": []string{"get"}, "namespaces": []string{"team"}}
}

func bindingSpec(policy string) map[string]any {
	return map[string]any{"policyRef": reference(policy), "subjects": []any{map[string]any{"kind": model.KindUser, "name": "admin"}}}
}

func reference(name string) map[string]any {
	return map[string]any{"name": name}
}
