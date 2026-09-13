package source_test

import (
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/source"
	"github.com/zcayou/k8s-authz/test/utils"
)

// emitter waits for reader to run and returns its emit function.
func emitter(reader *utils.FakeReader) func(model.SourceObservation) {
	GinkgoHelper()
	var emit func(model.SourceObservation)
	Eventually(reader.Emitters()).Should(Receive(&emit))
	return emit
}

func builds(reader source.Reader) func() (source.Reader, error) {
	return func() (source.Reader, error) { return reader, nil }
}

// startRegistry runs a registry until the spec ends and returns a function
// that stops it and waits for Start to return.
func startRegistry(registry *source.Registry) func() {
	stop := sync.OnceValue(utils.Start(registry))
	DeferCleanup(func() { Expect(stop()).To(Succeed()) })
	return func() { Expect(stop()).To(Succeed()) }
}

func instance(name, origin string) model.SourceInstance {
	return model.SourceInstance{Key: model.SourceKey{Namespace: "control", Name: name}, UID: name + "-uid", Origin: origin}
}

func registration(instance model.SourceInstance, digest string) source.Registration {
	return source.Registration{Instance: instance, Digest: digest}
}

func reference(key model.SourceKey, name string) model.Reference {
	return model.Reference{Source: key, Group: api.GroupVersion.Group, Kind: model.KindPolicy, Namespace: "policies", Name: name}
}

// complete returns a complete observation holding a valid document for each name.
func complete(instance model.SourceInstance, names ...string) model.SourceObservation {
	observation := model.SourceObservation{Instance: instance, Complete: true, Documents: map[model.Reference]model.DocumentState{}}
	for _, name := range names {
		observation.Documents[reference(instance.Key, name)] = model.DocumentState{Document: &model.Document{}, UID: name + "-uid", Digest: name}
	}
	return observation
}

func failing(instance model.SourceInstance, reason, message string) model.SourceObservation {
	return model.SourceObservation{Instance: instance, Failure: model.Failure{Reason: reason, Message: message}}
}

// notifications records the keys the registry notifies.
func notifications(registry *source.Registry) chan model.SourceKey {
	keys := make(chan model.SourceKey, 64)
	registry.Subscribe(func(key model.SourceKey) { keys <- key })
	return keys
}

// acquisitionFailures reads the source's acquisition failure counter.
func acquisitionFailures(key model.SourceKey) float64 {
	GinkgoHelper()
	families, err := metrics.Registry.Gather()
	Expect(err).NotTo(HaveOccurred())
	for _, family := range families {
		if family.GetName() != "k8s_authz_source_acquisition_failures_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			labels := map[string]string{}
			for _, label := range metric.GetLabel() {
				labels[label.GetName()] = label.GetValue()
			}
			if labels["namespace"] == key.Namespace && labels["name"] == key.Name {
				return metric.GetCounter().GetValue()
			}
		}
	}
	return 0
}
