package validation_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/validation/field"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/validation"
)

var _ = Describe("DecodeService", func() {
	It("returns each endpoint's callers as sorted Common Names", func() {
		spec := validServiceSpec()
		spec.Endpoints[0].Callers = []api.Caller{{CommonName: "kube-apiserver-b"}, {CommonName: "kube-apiserver-a"}}
		config, errs := validation.DecodeService(authorizationService(spec))
		Expect(errs).To(BeEmpty())
		Expect(config.Endpoints).To(ConsistOf(SatisfyAll(
			HaveField("Name", "fleet"),
			HaveField("Callers", []string{"kube-apiserver-a", "kube-apiserver-b"}),
			HaveField("Sources", []model.SourceKey{{Namespace: "control", Name: "platform"}}),
			HaveField("Authorities", BeEmpty()),
		)))
	})

	It("resolves ordered authorities with their fallbacks", func() {
		spec := validServiceSpec()
		spec.Endpoints[0].Authorities = []api.Authority{authority("platform", api.DecisionFallbackNoOpinion)}
		spec.Endpoints[0].WhenEvaluationFails = api.DecisionFallbackNoOpinion
		config, errs := validation.DecodeService(authorizationService(spec))
		Expect(errs).To(BeEmpty())
		Expect(config.Endpoints[0].WhenEvaluationFails).To(Equal(model.Result("NoOpinion")))
		Expect(config.Endpoints[0].Authorities).To(ConsistOf(model.AuthorityConfig{
			Binding:  model.Reference{Source: model.SourceKey{Namespace: "control", Name: "platform"}, Group: api.GroupVersion.Group, Kind: model.KindPolicyBinding, Namespace: "platform", Name: "root"},
			Fallback: "NoOpinion",
		}))
	})

	It("keeps the first of repeated authorities, which always decides first", func() {
		spec := validServiceSpec()
		second := authority("platform", api.DecisionFallbackNoOpinion)
		second.BindingRef.Kind = model.KindPolicyBinding
		spec.Endpoints[0].Authorities = []api.Authority{authority("platform", api.DecisionFallbackDeny), second}
		config, errs := validation.DecodeService(authorizationService(spec))
		Expect(errs).To(BeEmpty())
		Expect(config.Endpoints[0].Authorities).To(ConsistOf(HaveField("Fallback", model.Result("Deny"))))
	})

	It("imposes no builtin ceiling without rego", func() {
		config, errs := validation.DecodeService(authorizationService(validServiceSpec()))
		Expect(errs).To(BeEmpty())
		Expect(config.BuiltinCeiling).To(BeNil())
	})

	It("normalizes the builtin ceiling", func() {
		spec := validServiceSpec()
		spec.Rego = &api.AuthorizationServiceRego{AllowedBuiltins: []string{"startswith", "concat"}}
		config, errs := validation.DecodeService(authorizationService(spec))
		Expect(errs).To(BeEmpty())
		Expect(config.BuiltinCeiling).To(HaveValue(Equal(model.BuiltinSet{"concat", "startswith"})))
	})

	It("keeps an empty builtin ceiling, which admits no builtins", func() {
		spec := validServiceSpec()
		spec.Rego = &api.AuthorizationServiceRego{AllowedBuiltins: []string{}}
		config, errs := validation.DecodeService(authorizationService(spec))
		Expect(errs).To(BeEmpty())
		Expect(config.BuiltinCeiling).To(HaveValue(BeEmpty()))
	})

	It("rejects a ceiling naming a builtin this release doesn't define", func() {
		spec := validServiceSpec()
		spec.Rego = &api.AuthorizationServiceRego{AllowedBuiltins: []string{"concat", "no.such.builtin"}}
		_, errs := validation.DecodeService(authorizationService(spec))
		Expect(errs).To(ConsistOf(SatisfyAll(
			HaveField("Field", "spec.rego.allowedBuiltins[1]"),
			HaveField("Type", field.ErrorTypeNotSupported),
		)))
	})

	It("rejects an authority outside the endpoint's sources", func() {
		spec := validServiceSpec()
		spec.Endpoints[0].Authorities = []api.Authority{authority("other", api.DecisionFallbackDeny)}
		_, errs := validation.DecodeService(authorizationService(spec))
		Expect(errs).To(ConsistOf(SatisfyAll(
			HaveField("Field", "spec.endpoints[0].authorities[0].bindingRef.sourceRef"),
			HaveField("Type", field.ErrorTypeInvalid),
		)))
	})
})
