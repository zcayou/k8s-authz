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

// ProviderType identifies a PolicySource acquisition provider.
// +kubebuilder:validation:Enum=Kubernetes
type ProviderType string

// ProviderTypeKubernetes acquires documents from a Kubernetes API.
const ProviderTypeKubernetes ProviderType = "Kubernetes"

// PolicySourceProvider selects the provider and configures it.
type PolicySourceProvider struct {
	// type identifies the selected provider.
	// +required
	Type ProviderType `json:"type"`

	// kubernetes configures acquisition from a Kubernetes API.
	// +optional
	Kubernetes *KubernetesProvider `json:"kubernetes,omitempty"`
}

// KubernetesProvider configures acquisition from a Kubernetes API.
type KubernetesProvider struct {
	// kubeconfig selects an explicit kubeconfig credential. Omission reads
	// from the operator's own cluster with the operator's credentials.
	// +optional
	Kubeconfig *KubeconfigReference `json:"kubeconfig,omitempty"`
}

// KubeconfigReference identifies a kubeconfig stored in a Secret.
type KubeconfigReference struct {
	// secretRef identifies the Secret data containing the kubeconfig.
	// +required
	SecretRef SecretKeyRef `json:"secretRef"`
}

// Synchronization selects whether a PolicySource reads from its provider.
// Active reads continuously. Paused stops reading and keeps serving
// the source's last complete view.
// +kubebuilder:validation:Enum=Active;Paused
type Synchronization string

const (
	// SynchronizationActive reads from the provider continuously.
	SynchronizationActive Synchronization = "Active"
	// SynchronizationPaused stops reading and keeps the last complete view.
	SynchronizationPaused Synchronization = "Paused"
)

// Contribution selects whether a PolicySource's documents take part in compiled
// policy. Inert removes them: references into the source then fail
// as references into an unavailable source, whose issue names Inert.
// +kubebuilder:validation:Enum=Active;Inert
type Contribution string

const (
	// ContributionActive includes the source's documents in compiled policy.
	ContributionActive Contribution = "Active"
	// ContributionInert leaves the source's documents out of compiled policy.
	ContributionInert Contribution = "Inert"
)

// PolicySourceSpec defines acquisition, collection and lifecycle.
type PolicySourceSpec struct {
	// provider selects and configures the acquisition provider.
	// +required
	Provider PolicySourceProvider `json:"provider"`

	// collection contains the explicit ranges collected by this source.
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=64
	Collection []KeyRange `json:"collection"`

	// synchronization selects whether the source reads from its provider.
	// Paused stops reading and keeps serving the last complete view.
	// +optional
	// +kubebuilder:default=Active
	Synchronization Synchronization `json:"synchronization,omitempty"`

	// contribution selects whether the source's documents take part in compiled
	// policy. Toggling it never restarts acquisition.
	// +optional
	// +kubebuilder:default=Active
	Contribution Contribution `json:"contribution,omitempty"`

	// rego allows the source's documents to carry Rego conditions. Omission
	// forbids them, here and in every use beneath this source.
	// +optional
	Rego *PolicySourceRego `json:"rego,omitempty"`
}

// PolicySourceRego allows the source's documents to carry Rego conditions.
type PolicySourceRego struct {
	// allowedBuiltins are the builtins conditions may call. Omission means
	// the release's default builtins.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=128
	AllowedBuiltins []string `json:"allowedBuiltins,omitzero"`
}

// PolicySourceStatus reports acquisition health.
type PolicySourceStatus struct {
	// observedGeneration is the spec generation assessed by this status.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// lastAdmittedTime records when the source last admitted a complete view
	// whose documents changed, or which ended a period of failed acquisition.
	// +optional
	LastAdmittedTime *metav1.Time `json:"lastAdmittedTime,omitempty"`

	// conditions holds Synchronized, which reports whether the latest acquisition
	// is complete.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// issues contains bounded attributed diagnostics for the documents
	// in the source's view.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=128
	Issues []Issue `json:"issues,omitempty"`

	// issuesTruncated reports that additional diagnostics were omitted.
	// +optional
	IssuesTruncated bool `json:"issuesTruncated,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=azsrc,categories=authz
// +kubebuilder:printcolumn:name="Synchronized",type=string,JSONPath=`.status.conditions[?(@.type=="Synchronized")].status`
// +kubebuilder:printcolumn:name="LastAdmitted",type=date,JSONPath=`.status.lastAdmittedTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="size(self.metadata.name) <= 63",message="name must be at most 63 characters"

// PolicySource registers an acquired policy-document source.
type PolicySource struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines source acquisition.
	// +required
	Spec PolicySourceSpec `json:"spec"`

	// status reports observed acquisition state.
	// +optional
	Status PolicySourceStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PolicySourceList contains a list of PolicySource objects.
type PolicySourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PolicySource `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &PolicySource{}, &PolicySourceList{})
		return nil
	})
}
