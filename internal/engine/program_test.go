package engine_test

import (
	"encoding/json"
	"fmt"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/model"
)

var _ = Describe("Program preparation", func() {
	var fixture *sourceFixture
	var service model.Identity
	var config model.ServiceConfig
	var sources func() map[model.SourceKey]model.SourceObservation
	BeforeEach(func() {
		fixture = newSourceFixture()
		fixture.put(model.KindPolicySet, "root", map[string]any{"bindingRefs": []any{reference("reader")}})
		fixture.put(model.KindPolicyBinding, "reader", bindingSpec("pods"))
		fixture.put(model.KindPolicy, "pods", map[string]any{"include": []any{operationRule("pods")}})
		service = model.Identity{Namespace: "control", Name: "authz", UID: "service-1"}
		config = fixture.config
		sources = func() map[model.SourceKey]model.SourceObservation {
			return map[model.SourceKey]model.SourceObservation{fixture.source.Key: fixture.observation}
		}
	})

	It("compiles for this release's evaluator and binds the program to the service", func() {
		program, err := engine.Prepare("service-1", config, sources())
		Expect(err).NotTo(HaveOccurred())
		Expect(program.Content.EvaluatorID).To(Equal(engine.EvaluatorID()))
		Expect(program.Content.ServiceUID).To(Equal(model.ServiceUID("service-1")))
		Expect(program.Content.PreparedRevision).To(Equal(program.Compilation.Prepared))
		Expect(program.Compilation.References).To(HaveKey(fixture.ref(model.KindPolicy, "pods")))
	})

	Describe("the cache", func() {
		var cache *engine.Cache
		var baseline float64
		prepare := func() (engine.Program, bool) {
			GinkgoHelper()
			before := metricTotal(compileDurationMetric)
			program, err := cache.Prepare(service, config, sources())
			Expect(err).NotTo(HaveOccurred())
			return program, metricTotal(compileDurationMetric) == before
		}
		BeforeEach(func() {
			baseline = metricTotal(compileDurationMetric)
			cache = engine.NewCache()
		})

		It("reuses the finalized program through unrelated document edits", func() {
			first, reused := prepare()
			Expect(reused).To(BeFalse())
			fixture.put(model.KindPolicy, "unrelated", map[string]any{"include": []any{}})
			second, reused := prepare()
			Expect(reused).To(BeTrue())
			Expect(second).To(Equal(first))
		})
		It("prepares a changed builtin ceiling or source allowlist", func() {
			prepare()
			config.BuiltinCeiling = &model.BuiltinSet{"startswith"}
			_, reused := prepare()
			Expect(reused).To(BeFalse())
			_, reused = prepare()
			Expect(reused).To(BeTrue())
			fixture.observation.AllowedBuiltins = new(condition.DefaultBuiltins())
			_, reused = prepare()
			Expect(reused).To(BeFalse())
			fixture.observation.AllowedBuiltins = &model.BuiltinSet{"endswith"}
			_, reused = prepare()
			Expect(reused).To(BeFalse())
		})
		It("prepares changed callers and evaluation failure fallbacks into the endpoint program", func() {
			first, _ := prepare()
			Expect(first.Content.Endpoints["cluster"].Callers).To(BeEmpty())
			config.Endpoints[0].Callers = []string{"kube-apiserver-a", "kube-apiserver-b"}
			second, reused := prepare()
			Expect(reused).To(BeFalse())
			Expect(second.Content.Endpoints["cluster"].Callers).To(Equal([]string{"kube-apiserver-a", "kube-apiserver-b"}))
			config.Endpoints[0].WhenEvaluationFails = "NoOpinion"
			third, reused := prepare()
			Expect(reused).To(BeFalse())
			Expect(third.Content.Endpoints["cluster"].WhenEvaluationFails).To(Equal(model.Result("NoOpinion")))
			Expect(third.Content.Revision).NotTo(Equal(second.Content.Revision))
		})
		It("recompiles a service recreated under the same name", func() {
			first, _ := prepare()
			service.UID = "service-2"
			second, reused := prepare()
			Expect(reused).To(BeFalse())
			Expect(second.Content.ServiceUID).To(Equal(model.ServiceUID("service-2")))
			Expect(second.Content.Revision).NotTo(Equal(first.Content.Revision))
		})
		It("keeps one program per service", func() {
			prepare()
			other := model.Identity{Namespace: "control", Name: "other", UID: "other-service"}
			program, err := cache.Prepare(other, config, sources())
			Expect(err).NotTo(HaveOccurred())
			Expect(program.Content.ServiceUID).To(Equal(model.ServiceUID("other-service")))
			Expect(metricTotal(compileDurationMetric) - baseline).To(Equal(2.0))
			_, reused := prepare()
			Expect(reused).To(BeTrue())
		})
		It("prepares a changed or recreated reachable document", func() {
			first, _ := prepare()
			fixture.put(model.KindPolicy, "pods", map[string]any{"include": []any{operationRule("secrets")}})
			second, reused := prepare()
			Expect(reused).To(BeFalse())
			Expect(second.Content.Revision).NotTo(Equal(first.Content.Revision))
			reference := fixture.ref(model.KindPolicy, "pods")
			state := fixture.observation.Documents[reference]
			state.UID = "replacement-policy"
			fixture.observation.Documents[reference] = state
			_, reused = prepare()
			Expect(reused).To(BeFalse())
		})
		It("tracks unresolved references so their creation invalidates the program", func() {
			fixture.observation.Documents = map[model.Reference]model.DocumentState{}
			first, reused := prepare()
			Expect(reused).To(BeFalse())
			Expect(first.Content.Issues).NotTo(BeEmpty())
			fixture.put(model.KindPolicyBinding, "entry", map[string]any{"policyRef": map[string]any{"kind": model.KindPolicySet, "name": "root"}, "subjectMatch": map[string]any{}})
			fixture.put(model.KindPolicySet, "root", map[string]any{"bindingRefs": []any{}})
			second, reused := prepare()
			Expect(reused).To(BeFalse())
			Expect(second.Content.Issues).To(BeEmpty())
		})
		It("prepares a source that became incomplete or was replaced", func() {
			prepare()
			fixture.observation.Complete = false
			unavailable, reused := prepare()
			Expect(reused).To(BeFalse())
			Expect(unavailable.Content.Issues).NotTo(BeEmpty())
			fixture.observation.Complete = true
			fixture.observation.Instance.UID = "replacement-source"
			replacement, reused := prepare()
			Expect(reused).To(BeFalse())
			Expect(replacement.Content.Issues).To(BeEmpty())
		})
		It("counts a compilation with several resource limit failures once", func() {
			// Each rule adds its own selector key, so the prohibition's diagram
			// branches on more keys than the traversal can walk.
			rules := make([]map[string]any, 0, 129)
			for index := range cap(rules) {
				rules = append(rules, map[string]any{"apiGroups": []string{""}, "resources": []string{"pods"}, "verbs": []string{"get"},
					"labelSelector": map[string]any{"matchExpressions": []any{map[string]any{"key": fmt.Sprintf("example.com/key-%03d", index), "operator": "DoesNotExist"}}}})
			}
			spec, err := json.Marshal(map[string]any{"include": rules})
			Expect(err).NotTo(HaveOccurred())
			fixture.put(model.KindPolicy, "wide", json.RawMessage(spec))
			fixture.put(model.KindPolicyBinding, "prohibit", map[string]any{"policyRef": reference("wide"), "subjectMatch": map[string]any{}})
			fixture.put(model.KindPolicySet, "root", map[string]any{"bindingRefs": []any{reference("reader")}, "prohibitionRefs": []any{reference("prohibit")}})
			second := config.Endpoints[0].Authorities[0]
			second.Binding.Name = "second-entry"
			fixture.put(model.KindPolicyBinding, "second-entry", map[string]any{"policyRef": map[string]any{"kind": model.KindPolicySet, "name": "root"}, "subjectMatch": map[string]any{}})
			config.Endpoints[0].Authorities = append(config.Endpoints[0].Authorities, second)
			before := metricTotal(compileLimitFailuresMetric)

			program, reused := prepare()
			Expect(reused).To(BeFalse())
			Expect(program.Content.Issues).To(HaveLen(2))
			Expect(program.Content.Issues).To(HaveEach(HaveField("Reason", model.ReasonResourceLimitExceeded)))
			Expect(metricTotal(compileLimitFailuresMetric) - before).To(Equal(1.0))
		})
		It("drops a forgotten service's program", func() {
			prepare()
			cache.Forget("control", "authz")
			_, reused := prepare()
			Expect(reused).To(BeFalse())
		})
		It("serves concurrent callers for the same and different services", func() {
			expected, _ := prepare()
			observations := sources()
			var group sync.WaitGroup
			results := make([]engine.Program, 16)
			errs := make([]error, len(results))
			for index := range results {
				group.Go(func() {
					identity := service
					if index%2 == 1 {
						identity = model.Identity{Namespace: "control", Name: "concurrent", UID: "concurrent-service"}
					}
					results[index], errs[index] = cache.Prepare(identity, config, observations)
				})
			}
			group.Wait()
			for index, program := range results {
				Expect(errs[index]).NotTo(HaveOccurred())
				if index%2 == 0 {
					Expect(program).To(Equal(expected))
				} else {
					Expect(program.Content.ServiceUID).To(Equal(model.ServiceUID("concurrent-service")))
				}
			}
		})
	})
})
