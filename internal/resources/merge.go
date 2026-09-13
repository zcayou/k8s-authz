package resources

import (
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/util/strategicpatch"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
)

// mergePod merges a per-service Pod template override onto the generated Pod
// template.
func mergePod(base *corev1ac.PodTemplateSpecApplyConfiguration, override *api.PodTemplateOverride) (*corev1ac.PodTemplateSpecApplyConfiguration, error) {
	if override == nil {
		return base, nil
	}
	merged, err := merge(base, override)
	if err != nil {
		return nil, fmt.Errorf("merge spec.runtime.podTemplate: %w", err)
	}
	return merged, nil
}

// mergeService merges a per-service Service override onto the generated
// listener Service. Ports merge by name, so an override can change the https
// port's number.
func mergeService(base *corev1ac.ServiceApplyConfiguration, override *api.ServiceTemplateOverride) (*corev1ac.ServiceApplyConfiguration, error) {
	if override == nil {
		return base, nil
	}
	merged, err := merge(base, override)
	if err != nil {
		return nil, fmt.Errorf("merge spec.listener: %w", err)
	}
	return merged, nil
}

// merge applies override to base as a strategic merge patch whose merge keys
// come from the override type.
func merge[T, O any](base *T, override *O) (*T, error) {
	original, err := json.Marshal(base)
	if err != nil {
		return nil, fmt.Errorf("encode generated object: %w", err)
	}
	patch, err := json.Marshal(override)
	if err != nil {
		return nil, fmt.Errorf("encode override: %w", err)
	}
	schema, err := strategicpatch.NewPatchMetaFromStruct(*override)
	if err != nil {
		return nil, fmt.Errorf("read override merge keys: %w", err)
	}
	merged, err := strategicpatch.StrategicMergePatchUsingLookupPatchMeta(original, patch, schema)
	if err != nil {
		return nil, fmt.Errorf("apply override: %w", err)
	}
	result := new(T)
	if err := json.Unmarshal(merged, result); err != nil {
		return nil, fmt.Errorf("decode merged object: %w", err)
	}
	return result, nil
}
