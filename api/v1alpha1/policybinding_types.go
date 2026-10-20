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

// PolicyBindingSpec attaches principals to one policy target, or to each
// PolicySet a selector matches.
// +kubebuilder:validation:XValidation:rule="has(self.subjects) != has(self.subjectMatch)",message="exactly one of subjects or subjectMatch is required"
// +kubebuilder:validation:XValidation:rule="has(self.policyRef) != has(self.policySelector)",message="exactly one of policyRef or policySelector is required"
// +kubebuilder:validation:XValidation:rule="!has(self.constraints) || !(has(self.constraints.sourceRefs) || has(self.constraints.maxDepth)) || has(self.policySelector) || (has(self.policyRef) && has(self.policyRef.kind) && self.policyRef.kind == 'PolicySet')",message="constraints.sourceRefs and constraints.maxDepth require a PolicySet target or a policySelector"
type PolicyBindingSpec struct {
	// policyRef identifies the permission definition.
	// +optional
	PolicyRef *PolicyRef `json:"policyRef,omitempty"`

	// policySelector selects PolicySets by their labels and their namespaces'
	// labels. Each match is delegated to as a policyRef to it would be.
	// +optional
	PolicySelector *PolicySelector `json:"policySelector,omitempty"`

	// subjects contains exact principals combined by OR.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:XValidation:rule="self.all(s, s.kind in ['User', 'Group', 'ServiceAccount'])",message="subject kind must be User, Group, or ServiceAccount"
	// +kubebuilder:validation:XValidation:rule="self.all(s, size(s.name) > 0)",message="subject name must not be empty"
	// +kubebuilder:validation:XValidation:rule="self.all(s, s.kind == 'ServiceAccount' ? (has(s.namespace) && size(s.namespace) > 0 && (!has(s.apiGroup) || s.apiGroup == '')) : (!has(s.namespace) || s.namespace == '') && (!has(s.apiGroup) || s.apiGroup == 'rbac.authorization.k8s.io'))",message="a ServiceAccount subject requires namespace and no apiGroup; User and Group subjects forbid namespace and use the rbac.authorization.k8s.io apiGroup"
	Subjects []Subject `json:"subjects,omitempty"`

	// subjectMatch selects principals with extended fixed-form predicates.
	// +optional
	SubjectMatch *SubjectMatch `json:"subjectMatch,omitempty"`

	// constraints narrows the target and its descendants.
	// +optional
	Constraints *BindingConstraints `json:"constraints,omitempty"`
}

// PolicySelector selects the PolicySets of one source.
type PolicySelector struct {
	// sourceRef selects another allowed PolicySource. Omission means the binding's
	// own source.
	// +optional
	SourceRef *SourceRef `json:"sourceRef,omitempty"`

	// namespaceSelector selects the namespaces whose PolicySets may match,
	// by the namespaces' labels in the source. An empty selector selects every
	// namespace; any other requires the source to collect namespace labels.
	// +required
	NamespaceSelector metav1.LabelSelector `json:"namespaceSelector"`

	// selector selects PolicySets by their own labels.
	// +required
	Selector metav1.LabelSelector `json:"selector"`
}

// SubjectMatch selects the principals that satisfy every requirement. Like
// an empty label selector, an empty subjectMatch selects every principal.
type SubjectMatch struct {
	// requirements are ANDed principal predicates.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=64
	Requirements []SubjectRequirement `json:"requirements,omitempty"`
}

// BindingConstraints restricts one policy association.
// +kubebuilder:validation:XValidation:rule="!has(self.policyRef) || !has(self.policyRef.kind) || self.policyRef.kind != 'PolicySet'",message="constraints.policyRef must target a leaf policy"
type BindingConstraints struct {
	// policyRef supplies a leaf permission bound.
	// +optional
	PolicyRef *PolicyRef `json:"policyRef,omitempty"`

	// sourceRefs narrows the incoming sources for a PolicySet target. It must
	// include the target's own source.
	// +optional
	// +listType=map
	// +listMapKey=namespace
	// +listMapKey=name
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	SourceRefs []SourceRef `json:"sourceRefs,omitempty"`

	// maxDepth caps further PolicySet edges below the target.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=64
	MaxDepth *int32 `json:"maxDepth,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=azpb,categories=authz

// PolicyBinding attaches principals to a Policy, PolicySet, or native role definition.
type PolicyBinding struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the principal binding.
	// +required
	Spec PolicyBindingSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// PolicyBindingList contains a list of PolicyBinding objects.
type PolicyBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PolicyBinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &PolicyBinding{}, &PolicyBindingList{})
		return nil
	})
}
