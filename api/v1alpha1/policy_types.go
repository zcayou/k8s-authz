/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// PolicySpec defines a reusable permission set.
// +kubebuilder:validation:XValidation:rule="has(self.include) || has(self.imports) || has(self.condition)",message="one of include, imports or condition is required"
type PolicySpec struct {
	// include contains locally allowed operations. Omitted together with imports
	// on a Policy with a condition, it allows every operation the condition
	// allows.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=256
	Include []OperationRule `json:"include,omitzero"`

	// exclude contains operations removed from the local and imported union.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=256
	Exclude []OperationRule `json:"exclude,omitempty"`

	// imports contains native Role and ClusterRole permission definitions.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=64
	Imports []PolicyImport `json:"imports,omitempty"`

	// condition narrows the policy to the requests its Rego allows.
	// +optional
	Condition *PolicyCondition `json:"condition,omitempty"`
}

// PolicyCondition is a Rego module deciding whether a policy applies to a request.
type PolicyCondition struct {
	// rego is a Rego v1 module declaring package condition, whose rule allow
	// decides the condition.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=65536
	Rego string `json:"rego"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=azpol,categories=authz

// Policy defines permissions without subjects or endpoint selection.
type Policy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the policy permissions.
	// +required
	Spec PolicySpec `json:"spec"`
}

// +kubebuilder:object:root=true

// PolicyList contains a list of Policy objects.
type PolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []Policy `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &Policy{}, &PolicyList{})
		return nil
	})
}
