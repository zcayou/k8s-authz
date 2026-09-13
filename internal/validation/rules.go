package validation

import (
	"errors"
	"fmt"
	"maps"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
)

func validName(name string) error {
	if problems := utilvalidation.IsDNS1123Subdomain(name); len(problems) > 0 {
		return fmt.Errorf("invalid name %q: %s", name, strings.Join(problems, ", "))
	}
	return nil
}
func validNamespace(namespace string) error {
	if problems := utilvalidation.IsDNS1123Label(namespace); len(problems) > 0 {
		return fmt.Errorf("invalid namespace %q: %s", namespace, strings.Join(problems, ", "))
	}
	return nil
}

// checkLiterals accepts "*" and, when empty is set, the empty string; every
// other value is a nonempty literal without wildcards or NUL.
func checkLiterals(values []string, empty bool) error {
	for _, value := range values {
		if value == "*" || value == "" && empty {
			continue
		}
		if value == "" || strings.ContainsAny(value, "*\x00") {
			return fmt.Errorf("invalid literal %q", value)
		}
	}
	return nil
}
func literals(values []string) model.Region {
	result := model.EmptyRegion()
	for _, value := range values {
		if value == "*" {
			return model.PresentValues()
		}
		result = result.Union(model.Values(model.Atom(value)))
	}
	return result
}

func operation(rule api.OperationRule) ([]model.Cube, error) {
	if err := checkLiterals(rule.Verbs, false); err != nil {
		return nil, fmt.Errorf("verbs: %w", err)
	}
	for _, verb := range rule.Verbs {
		if verb != "*" && (strings.ToLower(verb) != verb || strings.ContainsAny(verb, " /\t\n")) {
			return nil, fmt.Errorf("invalid verb %q", verb)
		}
	}
	cube := model.Cube{model.Verb: literals(rule.Verbs)}
	if len(rule.NonResourceURLs) > 0 {
		return nonResource(rule, cube)
	}
	if err := checkLiterals(rule.APIGroups, true); err != nil {
		return nil, fmt.Errorf("apiGroups: %w", err)
	}
	resource, err := resourceRegion(rule.Resources)
	if err != nil {
		return nil, err
	}
	cube[model.Category] = model.Values(model.Atom("resource"))
	cube[model.APIGroup] = literals(rule.APIGroups)
	cube[model.Resource] = resource
	if rule.APIVersions != nil {
		if err = checkLiterals(rule.APIVersions, false); err != nil {
			return nil, fmt.Errorf("apiVersions: %w", err)
		}
		cube[model.APIVersion] = literals(rule.APIVersions)
	}
	if len(rule.ResourceNames) > 0 {
		for _, name := range rule.ResourceNames {
			if name == "" || strings.ContainsAny(name, "*\x00/") {
				return nil, fmt.Errorf("invalid resource name %q", name)
			}
		}
		cube[model.Name] = literals(rule.ResourceNames)
	}
	selectors, err := policySelectors(rule.LabelSelector, rule.FieldSelector)
	if err != nil {
		return nil, err
	}
	for dimension, region := range selectors {
		if existing, present := cube[dimension]; present {
			region = existing.Intersect(region)
		}
		cube[dimension] = region
	}
	scopes := model.NamespaceCubes(rule.Namespaces)
	result := make([]model.Cube, 0, len(scopes))
	for _, scope := range scopes {
		merged := maps.Clone(cube)
		maps.Copy(merged, scope)
		result = append(result, merged)
	}
	return result, nil
}
func nonResource(rule api.OperationRule, cube model.Cube) ([]model.Cube, error) {
	paths := model.EmptyRegion()
	for _, path := range rule.NonResourceURLs {
		if path == "*" {
			paths = paths.Union(model.PresentValues())
			continue
		}
		if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\x00") || strings.Count(path, "*") > 1 || strings.Contains(path, "*") && !strings.HasSuffix(path, "*") {
			return nil, fmt.Errorf("invalid non-resource URL %q", path)
		}
		if before, ok := strings.CutSuffix(path, "*"); ok {
			paths = paths.Union(model.Prefix(model.Atom(before)))
		} else {
			paths = paths.Union(model.Values(model.Atom(path)))
		}
	}
	cube[model.Category] = model.Values(model.Atom("nonResource"))
	cube[model.URL] = paths
	return []model.Cube{cube}, nil
}
func policySelectors(label *metav1.LabelSelector, field *api.FieldSelector) (model.Cube, error) {
	result := model.Cube{}
	if label != nil {
		if len(label.MatchLabels)+len(label.MatchExpressions) > 64 {
			return nil, errors.New("label selector exceeds 64 requirements")
		}
		for key, value := range label.MatchLabels {
			if err := labelKeyValue(key, []string{value}); err != nil {
				return nil, err
			}
			if err := addSelectorRequirement(result, model.LabelPrefix+key, model.OperatorIn, []string{value}); err != nil {
				return nil, err
			}
		}
		for _, r := range label.MatchExpressions {
			if err := labelKeyValue(r.Key, r.Values); err != nil {
				return nil, err
			}
			if err := addSelectorRequirement(result, model.LabelPrefix+r.Key, string(r.Operator), r.Values); err != nil {
				return nil, err
			}
		}
	}
	if field != nil {
		for _, r := range field.Requirements {
			if r.Key == "" || strings.ContainsRune(r.Key, '\x00') {
				return nil, errors.New("invalid field selector key")
			}
			dimension := model.FieldPrefix + r.Key
			if r.Key == "metadata.name" {
				dimension = model.Name
			}
			if err := addSelectorRequirement(result, dimension, string(r.Operator), r.Values); err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}
func labelKeyValue(key string, values []string) error {
	if len(utilvalidation.IsQualifiedName(key)) > 0 {
		return fmt.Errorf("invalid label key %q", key)
	}
	for _, value := range values {
		if len(utilvalidation.IsValidLabelValue(value)) > 0 {
			return fmt.Errorf("invalid label value %q", value)
		}
	}
	return nil
}

// addSelectorRequirement intersects a parsed selector requirement with a query cube.
func addSelectorRequirement(cube model.Cube, key, operator string, values []string) error {
	var region model.Region
	switch operator {
	case model.OperatorIn, model.OperatorNotIn:
		if len(values) == 0 {
			return fmt.Errorf("%s requires nonempty values", operator)
		}
		region = model.EmptyRegion()
		for _, value := range values {
			if strings.ContainsRune(value, '\x00') {
				return errors.New("invalid selector value")
			}
			region = region.Union(model.Values(model.Atom(value)))
		}
		if operator == model.OperatorNotIn {
			region = region.Complement()
		}
	case model.OperatorExists, model.OperatorDoesNotExist:
		if len(values) > 0 {
			return fmt.Errorf("%s forbids values", operator)
		}
		region = model.Values(model.Absent)
		if operator == model.OperatorExists {
			region = region.Complement()
		}
	default:
		return fmt.Errorf("unsupported selector operator %q", operator)
	}
	if previous, exists := cube[key]; exists {
		region = region.Intersect(previous)
	}
	if region.Empty() {
		return fmt.Errorf("contradictory selector for %s", key)
	}
	cube[key] = region
	return nil
}

func resourceRegion(resources []string) (model.Region, error) {
	resource := model.EmptyRegion()
	for _, value := range resources {
		if value == "*" {
			resource = model.PresentValues()
			continue
		}
		parts := strings.Split(value, "/")
		if len(parts) > 2 || parts[0] == "" || strings.ContainsAny(value, "\x00 \t\n") {
			return model.Region{}, fmt.Errorf("invalid resource %q", value)
		}
		if len(parts) == 1 {
			if strings.Contains(value, "*") {
				return model.Region{}, fmt.Errorf("invalid resource %q", value)
			}
			resource = resource.Union(model.Values(model.Atom("\x00" + value)))
			continue
		}
		// Native */subresource is the sole supported partial resource wildcard.
		if parts[1] == "" || strings.Contains(parts[1], "*") || strings.Contains(parts[0], "*") && parts[0] != "*" {
			return model.Region{}, fmt.Errorf("invalid resource %q", value)
		}
		if parts[0] == "*" {
			resource = resource.Union(model.Prefix(model.Atom(parts[1] + "\x00")))
		} else {
			resource = resource.Union(model.Values(model.Atom(parts[1] + "\x00" + parts[0])))
		}
	}
	return resource, nil
}
