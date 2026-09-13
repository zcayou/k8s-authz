package validation

import (
	"cmp"
	"slices"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/model"
)

// DecodeDocument strictly decodes a document from source and normalizes it.
// The document's address comes from its own metadata: the API server served
// it for the source's collection.
func DecodeDocument(source model.SourceInstance, object *unstructured.Unstructured) model.DocumentState {
	return decodeState(source, object, true)
}

// DecodeCachedDocument decodes a document from source that the API server
// admitted earlier, and normalizes it. It drops fields the Go types don't
// declare, as the API server prunes them on read: in an admitted object they
// can only be fields a newer schema removed.
func DecodeCachedDocument(source model.SourceInstance, object *unstructured.Unstructured) model.DocumentState {
	return decodeState(source, object, false)
}

func decodeState(source model.SourceInstance, object *unstructured.Unstructured, strict bool) model.DocumentState {
	gvk := object.GroupVersionKind()
	key := model.DocumentKey{Source: source, Group: gvk.Group, Kind: gvk.Kind, Namespace: object.GetNamespace(), Name: object.GetName()}
	state := model.DocumentState{Key: key, UID: string(object.GetUID())}
	document, warnings, errs := decodeDocument(key, object, strict)
	if len(errs) == 0 {
		state.Document, state.Issues = &document, warnings
	} else {
		state.Issues = []model.Issue{{Severity: api.IssueSeverityError, Reason: model.ReasonInvalid, Message: errs.ToAggregate().Error(), Scope: api.IssueScopeDocument, Document: &key}}
	}
	state.Digest = model.Digest(struct {
		Document *model.Document `json:"document,omitempty"`
		Issues   []model.Issue   `json:"issues,omitempty"`
	}{state.Document, state.Issues})
	return state
}

func decodeDocument(key model.DocumentKey, object *unstructured.Unstructured, strict bool) (model.Document, []model.Issue, field.ErrorList) {
	doc := model.Document{Key: key}
	gvk := object.GroupVersionKind()
	switch gvk {
	case api.GroupVersion.WithKind(model.KindPolicy):
		var input api.Policy
		if errs := decodeInto(object, &input, strict); len(errs) != 0 {
			return doc, nil, errs
		}
		var errs field.ErrorList
		doc.Policy, errs = policy(input.Spec, key)
		return doc, policyWarnings(input.Spec, key), errs
	case api.GroupVersion.WithKind(model.KindPolicyBinding):
		var input api.PolicyBinding
		if errs := decodeInto(object, &input, strict); len(errs) != 0 {
			return doc, nil, errs
		}
		var errs field.ErrorList
		doc.Binding, errs = binding(input.Spec, key)
		return doc, nil, errs
	case api.GroupVersion.WithKind(model.KindPolicySet):
		var input api.PolicySet
		if errs := decodeInto(object, &input, strict); len(errs) != 0 {
			return doc, nil, errs
		}
		doc.Set = policySet(input.Spec, key)
		return doc, nil, nil
	case rbacv1.SchemeGroupVersion.WithKind(model.KindRole), rbacv1.SchemeGroupVersion.WithKind(model.KindClusterRole),
		rbacv1.SchemeGroupVersion.WithKind(model.KindRoleBinding), rbacv1.SchemeGroupVersion.WithKind(model.KindClusterRoleBinding):
		return decodeNative(key, object, strict)
	default:
		return doc, nil, field.ErrorList{field.NotSupported(field.NewPath("kind"), gvk.String(), []string{model.KindPolicy, model.KindPolicyBinding, model.KindPolicySet, model.KindRole, model.KindClusterRole, model.KindRoleBinding, model.KindClusterRoleBinding})}
	}
}

// DecodeStrict decodes object into a Go type and rejects fields the type
// doesn't declare, so a misspelled field fails instead of widening access.
func DecodeStrict(object *unstructured.Unstructured, into any) field.ErrorList {
	return decodeInto(object, into, true)
}

// decodeInto decodes object into a Go type. When strict, it rejects fields
// the type doesn't declare; otherwise it drops them.
func decodeInto(object *unstructured.Unstructured, into any, strict bool) field.ErrorList {
	if err := runtime.DefaultUnstructuredConverter.FromUnstructuredWithValidation(object.Object, into, strict); err != nil {
		return field.ErrorList{field.Invalid(field.NewPath(object.GetKind()), field.OmitValueType{}, err.Error())}
	}
	return nil
}

func policy(input api.PolicySpec, key model.DocumentKey) (*model.Policy, field.ErrorList) {
	var errs field.ErrorList
	result := &model.Policy{}
	for _, list := range []struct {
		name   string
		input  []api.OperationRule
		output *[]model.Cube
	}{{"include", input.Include, &result.Include}, {"exclude", input.Exclude, &result.Exclude}} {
		for index, rule := range list.input {
			cubes, err := operation(rule)
			if err != nil {
				errs = append(errs, field.Invalid(specPath.Child(list.name).Index(index), field.OmitValueType{}, err.Error()))
				continue
			}
			*list.output = append(*list.output, cubes...)
		}
	}
	for _, item := range input.Imports {
		imported := model.Import{Reference: reference(key, item.SourceRef, item.Kind, item.Namespace, item.Name), Namespaces: slices.Clone(item.Namespaces)}
		slices.Sort(imported.Namespaces)
		result.Imports = append(result.Imports, imported)
	}
	if input.Condition != nil {
		checked, err := condition.Check(input.Condition.Rego)
		if err != nil {
			errs = append(errs, field.Invalid(specPath.Child("condition", "rego"), field.OmitValueType{}, err.Error()))
		} else {
			result.Condition = &checked
		}
	}
	if universalEnvelope(input) {
		result.Include = []model.Cube{{}}
	}
	sortCanonical(result.Include)
	sortCanonical(result.Exclude)
	sortCanonical(result.Imports)
	result.Imports = slices.CompactFunc(result.Imports, func(a, b model.Import) bool {
		return a.Reference == b.Reference && slices.Equal(a.Namespaces, b.Namespaces)
	})
	return result, errs
}

// universalEnvelope reports whether a Policy's condition alone narrows it:
// without include or imports it allows every operation its condition allows.
func universalEnvelope(input api.PolicySpec) bool {
	return input.Include == nil && input.Imports == nil && input.Condition != nil
}

func binding(input api.PolicyBindingSpec, key model.DocumentKey) (*model.Binding, field.ErrorList) {
	result := &model.Binding{Policy: policyRef(input.PolicyRef, key)}
	var errs field.ErrorList
	matcher, err := principal(input.Subjects, input.SubjectMatch)
	if err != nil {
		location := specPath.Child("subjects")
		if input.SubjectMatch != nil {
			location = specPath.Child("subjectMatch")
		}
		errs = append(errs, field.Invalid(location, field.OmitValueType{}, err.Error()))
	}
	result.Principal = matcher
	if constraints := input.Constraints; constraints != nil {
		if constraints.PolicyRef != nil {
			result.Bound = new(policyRef(*constraints.PolicyRef, key))
		}
		if constraints.MaxDepth != nil {
			result.MaxDepth = new(int(*constraints.MaxDepth))
		}
		if constraints.SourceRefs != nil {
			for _, source := range constraints.SourceRefs {
				result.Sources = append(result.Sources, sourceKey(source))
			}
			if !slices.Contains(result.Sources, result.Policy.Source) {
				errs = append(errs, field.Invalid(specPath.Child("constraints", "sourceRefs"), field.OmitValueType{}, "must include the policyRef target's source"))
			}
			sortCanonical(result.Sources)
		}
	}
	return result, errs
}

// policyWarnings lints rules whose namespace scope behaves differently than
// it reads. A rule scoped to named namespaces also matches requests without
// a namespace whose effects may include them, which widens an exclusion
// or a prohibition. A collection rule on "*" alone lacks the empty-namespace
// witness an all-namespace request needs. A Policy whose condition alone
// narrows it is evaluated for every request inside its bound.
func policyWarnings(input api.PolicySpec, key model.DocumentKey) []model.Issue {
	var issues []model.Issue
	warn := func(reason model.IssueReason, message string) {
		if !slices.ContainsFunc(issues, func(issue model.Issue) bool { return issue.Reason == reason }) {
			issues = append(issues, model.Issue{Severity: api.IssueSeverityWarning, Reason: reason, Message: message, Scope: api.IssueScopeDocument, Document: &key})
		}
	}
	const clusterScoped = "also affects matching empty-namespace requests whose possible effects include the named namespace, including requests for cluster-scoped resources such as Nodes, CRDs, or PersistentVolumes"
	for _, rule := range input.Exclude {
		if wildcardResourceRule(rule) && namedNamespacesOnly(rule.Namespaces) {
			warn(model.ReasonNamespaceScopeConservative, "this exclusion "+clusterScoped)
		}
	}
	if universalEnvelope(input) {
		warn(model.ReasonUniversalEnvelope, "this policy has no include or imports, so its condition is evaluated for every request inside its bound")
	}
	for _, rule := range input.Include {
		if wildcardResourceRule(rule) && namedNamespacesOnly(rule.Namespaces) {
			warn(model.ReasonNamespaceScopeConservative, "used as a prohibition, this policy "+clusterScoped+"; an independent allow cannot override the prohibition")
		}
		if collectionRule(rule) && slices.Equal(rule.Namespaces, []string{"*"}) {
			warn(model.ReasonAllNamespacesNotGranted, "this collection permission covers every named namespace but lacks the empty-namespace witness required for an all-namespace request")
		}
	}
	return issues
}

func wildcardResourceRule(rule api.OperationRule) bool {
	return rule.NonResourceURLs == nil && (slices.Contains(rule.APIGroups, "*") || slices.Contains(rule.Resources, "*"))
}

func collectionRule(rule api.OperationRule) bool {
	return slices.ContainsFunc(rule.Verbs, func(verb string) bool {
		return verb == "*" || verb == "list" || verb == "watch" || verb == "deletecollection"
	})
}

func namedNamespacesOnly(namespaces []string) bool {
	return namespaces != nil && !slices.Contains(namespaces, "")
}
func policySet(input api.PolicySetSpec, key model.DocumentKey) *model.PolicySet {
	result := &model.PolicySet{}
	for _, list := range []struct {
		refs   []api.BindingRef
		output *[]model.Reference
	}{{input.BindingRefs, &result.Bindings}, {input.ProhibitionRefs, &result.Prohibitions}} {
		for _, binding := range list.refs {
			*list.output = append(*list.output, bindingRef(binding, key))
		}
		model.SortReferences(*list.output)
		*list.output = slices.Compact(*list.output)
	}
	return result
}

// bindingRef resolves a binding reference; omission of kind means PolicyBinding.
func bindingRef(input api.BindingRef, key model.DocumentKey) model.Reference {
	return reference(key, input.SourceRef, cmp.Or(input.Kind, model.KindPolicyBinding), input.Namespace, input.Name)
}

// policyRef resolves a permission reference; omission of kind means Policy.
func policyRef(input api.PolicyRef, key model.DocumentKey) model.Reference {
	return reference(key, input.SourceRef, cmp.Or(input.Kind, model.KindPolicy), input.Namespace, input.Name)
}

func sourceKey(input api.SourceRef) model.SourceKey {
	return model.SourceKey{Namespace: input.Namespace, Name: input.Name}
}

// reference resolves a reference relative to the referencing document: the same
// source unless one is named, and the document's namespace for a namespaced
// kind that names none.
func reference(key model.DocumentKey, source *api.SourceRef, kind, namespace, name string) model.Reference {
	documentKind := model.DocumentKinds[kind]
	result := model.Reference{Source: key.Source.Key, Group: documentKind.Resource.Group, Kind: kind, Namespace: namespace, Name: name}
	if source != nil {
		result.Source = sourceKey(*source)
	}
	if namespace == "" && documentKind.Namespaced {
		result.Namespace = key.Namespace
	}
	return result
}

// decodeNative normalizes a native RBAC document, which the API server has
// validated with RBAC's own rules.
func decodeNative(key model.DocumentKey, object *unstructured.Unstructured, strict bool) (model.Document, []model.Issue, field.ErrorList) {
	doc := model.Document{Key: key}
	switch key.Kind {
	case model.KindRole, model.KindClusterRole:
		var rules []rbacv1.PolicyRule
		if key.Kind == model.KindRole {
			var role rbacv1.Role
			if errs := decodeInto(object, &role, strict); len(errs) != 0 {
				return doc, nil, errs
			}
			rules = role.Rules
		} else {
			var role rbacv1.ClusterRole
			if errs := decodeInto(object, &role, strict); len(errs) != 0 {
				return doc, nil, errs
			}
			rules = role.Rules
		}
		policy, errs := nativePolicy(key, rules)
		doc.Policy = policy
		return doc, nil, errs
	default:
		var subjects []rbacv1.Subject
		var role rbacv1.RoleRef
		if key.Kind == model.KindRoleBinding {
			var binding rbacv1.RoleBinding
			if errs := decodeInto(object, &binding, strict); len(errs) != 0 {
				return doc, nil, errs
			}
			subjects, role = binding.Subjects, binding.RoleRef
		} else {
			var binding rbacv1.ClusterRoleBinding
			if errs := decodeInto(object, &binding, strict); len(errs) != 0 {
				return doc, nil, errs
			}
			subjects, role = binding.Subjects, binding.RoleRef
		}
		binding, errs := nativeBinding(key, subjects, role)
		doc.Binding = binding
		return doc, nil, errs
	}
}

func nativePolicy(key model.DocumentKey, rules []rbacv1.PolicyRule) (*model.Policy, field.ErrorList) {
	var errs field.ErrorList
	result := &model.Policy{}
	for index, rule := range rules {
		input := api.OperationRule{Verbs: rule.Verbs, APIGroups: rule.APIGroups, Resources: rule.Resources, ResourceNames: rule.ResourceNames, NonResourceURLs: rule.NonResourceURLs}
		if key.Kind == model.KindRole {
			input.Namespaces = []string{key.Namespace}
		}
		cubes, err := operation(input)
		if err != nil {
			errs = append(errs, field.Invalid(field.NewPath("rules").Index(index), field.OmitValueType{}, err.Error()))
			continue
		}
		result.Include = append(result.Include, cubes...)
	}
	sortCanonical(result.Include)
	return result, errs
}

func nativeBinding(key model.DocumentKey, subjects []rbacv1.Subject, role rbacv1.RoleRef) (*model.Binding, field.ErrorList) {
	var errs field.ErrorList
	principal := model.Matcher{Kind: model.MatcherSubjects}
	for index, subject := range subjects {
		if subject.Kind == model.KindServiceAccount && subject.Namespace == "" {
			subject.Namespace = key.Namespace
		}
		test, err := principalSubject(subject)
		if err != nil {
			errs = append(errs, field.Invalid(field.NewPath("subjects").Index(index), field.OmitValueType{}, err.Error()))
			continue
		}
		principal.Subjects = append(principal.Subjects, test)
	}
	sortCanonical(principal.Subjects)
	principal.Subjects = slices.Compact(principal.Subjects)
	return &model.Binding{Policy: reference(key, nil, role.Kind, "", role.Name), Principal: principal, Namespace: key.Namespace}, errs
}
