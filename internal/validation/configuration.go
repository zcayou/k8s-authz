package validation

import (
	"slices"

	"k8s.io/apimachinery/pkg/util/validation/field"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/model"
)

var specPath = field.NewPath("spec")

// DecodeService returns the configuration of an AuthorizationService the API
// server has admitted, normalized for the compiler. It rejects an authority
// whose bindingRef names a source outside its endpoint's sourceRefs, a rule
// the CRD's CEL cost budget can't hold, and a builtin ceiling naming a builtin
// this release doesn't define. A later duplicate of an authority is dropped:
// the first one always decides before it.
func DecodeService(service *api.AuthorizationService) (model.ServiceConfig, field.ErrorList) {
	var errs field.ErrorList
	config := model.ServiceConfig{Endpoints: make([]model.EndpointConfig, 0, len(service.Spec.Endpoints))}
	for index, endpoint := range service.Spec.Endpoints {
		result, endpointErrs := endpointConfig(endpoint, specPath.Child("endpoints").Index(index))
		errs = append(errs, endpointErrs...)
		config.Endpoints = append(config.Endpoints, result)
	}
	sortCanonical(config.Endpoints)
	if rego := service.Spec.Rego; rego != nil {
		for index, name := range rego.AllowedBuiltins {
			if !condition.Defined(name) {
				errs = append(errs, field.NotSupported[string](specPath.Child("rego", "allowedBuiltins").Index(index), name, nil))
			}
		}
		config.BuiltinCeiling = new(model.NewBuiltinSet(rego.AllowedBuiltins))
	}
	return config, errs
}

func endpointConfig(input api.Endpoint, path *field.Path) (model.EndpointConfig, field.ErrorList) {
	var errs field.ErrorList
	result := model.EndpointConfig{Name: input.Name, WhenEvaluationFails: model.Result(input.WhenEvaluationFails)}
	for _, caller := range input.Callers {
		result.Callers = append(result.Callers, caller.CommonName)
	}
	slices.Sort(result.Callers)
	for _, source := range input.SourceRefs {
		result.Sources = append(result.Sources, sourceKey(source))
	}
	sortCanonical(result.Sources)
	for index, authority := range input.Authorities {
		ref := bindingRef(authority.BindingRef, model.DocumentKey{})
		if !slices.Contains(result.Sources, ref.Source) {
			errs = append(errs, field.Invalid(path.Child("authorities").Index(index).Child("bindingRef", "sourceRef"), authority.BindingRef.SourceRef, "must be one of the endpoint's sourceRefs"))
			continue
		}
		if !slices.ContainsFunc(result.Authorities, func(existing model.AuthorityConfig) bool { return existing.Binding == ref }) {
			result.Authorities = append(result.Authorities, model.AuthorityConfig{Binding: ref, Fallback: model.Result(authority.WhenNoPolicyAllows)})
		}
	}
	return result, errs
}
