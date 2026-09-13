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
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Subject is the native Kubernetes RBAC subject shape.
type Subject = rbacv1.Subject

// SourceRef identifies a PolicySource in the trusted control API.
type SourceRef struct {
	// namespace is the PolicySource namespace.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Namespace string `json:"namespace"`

	// name is the PolicySource name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name"`
}

// PolicyRef identifies a Policy, PolicySet, Role, or ClusterRole.
// +kubebuilder:validation:XValidation:rule="!has(self.apiGroup) || self.apiGroup == (has(self.kind) && self.kind in ['Role', 'ClusterRole'] ? 'rbac.authorization.k8s.io' : 'authorization.zctx.io')",message="apiGroup must match kind"
// +kubebuilder:validation:XValidation:rule="!(has(self.kind) && self.kind == 'ClusterRole') || !has(self.namespace)",message="namespace is forbidden for ClusterRole"
// +kubebuilder:validation:XValidation:rule="!has(self.sourceRef) || has(self.namespace) || (has(self.kind) && self.kind == 'ClusterRole')",message="a reference into another source requires namespace"
type PolicyRef struct {
	// apiGroup is the referenced kind's API group. It is derived from kind when
	// omitted.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	APIGroup string `json:"apiGroup,omitempty"`

	// kind is Policy, PolicySet, Role, or ClusterRole. Omission means Policy.
	// +optional
	// +kubebuilder:validation:Enum=Policy;PolicySet;Role;ClusterRole
	Kind string `json:"kind,omitempty"`

	// name is the referenced permission definition's name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// namespace is the logical namespace of a namespaced definition. Omission
	// means the referencing document's namespace.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Namespace string `json:"namespace,omitempty"`

	// sourceRef selects another allowed PolicySource.
	// +optional
	SourceRef *SourceRef `json:"sourceRef,omitempty"`
}

// PolicyImport identifies a native Role or ClusterRole and an optional namespace filter.
// +kubebuilder:validation:XValidation:rule="!has(self.apiGroup) || self.apiGroup == 'rbac.authorization.k8s.io'",message="apiGroup must be rbac.authorization.k8s.io"
// +kubebuilder:validation:XValidation:rule="self.kind != 'ClusterRole' || !has(self.namespace)",message="namespace is forbidden for ClusterRole"
// +kubebuilder:validation:XValidation:rule="!has(self.sourceRef) || has(self.namespace) || self.kind == 'ClusterRole'",message="a reference into another source requires namespace"
type PolicyImport struct {
	// apiGroup is the referenced native kind's API group.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	APIGroup string `json:"apiGroup,omitempty"`

	// kind is Role or ClusterRole.
	// +required
	// +kubebuilder:validation:Enum=Role;ClusterRole
	Kind string `json:"kind"`

	// name is the referenced native role name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// namespace is the logical namespace of a Role. Omission means the importing
	// document's namespace.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Namespace string `json:"namespace,omitempty"`

	// sourceRef selects another allowed PolicySource.
	// +optional
	SourceRef *SourceRef `json:"sourceRef,omitempty"`

	// namespaces restricts imported resource operations to matching namespaces,
	// as an operation rule's namespaces do.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:items:MaxLength=63
	// +kubebuilder:validation:items:Pattern=`^(\*|[a-z0-9]([-a-z0-9]*[a-z0-9])?)?$`
	Namespaces []string `json:"namespaces,omitempty"`
}

// BindingRef identifies a custom PolicyBinding or native RBAC binding.
// +kubebuilder:validation:XValidation:rule="!has(self.apiGroup) || self.apiGroup == (has(self.kind) && self.kind in ['RoleBinding', 'ClusterRoleBinding'] ? 'rbac.authorization.k8s.io' : 'authorization.zctx.io')",message="apiGroup must match kind"
// +kubebuilder:validation:XValidation:rule="!(has(self.kind) && self.kind == 'ClusterRoleBinding') || !has(self.namespace)",message="namespace is forbidden for ClusterRoleBinding"
// +kubebuilder:validation:XValidation:rule="!has(self.sourceRef) || has(self.namespace) || (has(self.kind) && self.kind == 'ClusterRoleBinding')",message="a reference into another source requires namespace"
type BindingRef struct {
	// apiGroup is the referenced kind's API group. It is derived from kind when
	// omitted.
	// +optional
	// +kubebuilder:validation:MaxLength=253
	APIGroup string `json:"apiGroup,omitempty"`

	// kind is PolicyBinding, RoleBinding, or ClusterRoleBinding. Omission means
	// PolicyBinding.
	// +optional
	// +kubebuilder:validation:Enum=PolicyBinding;RoleBinding;ClusterRoleBinding
	Kind string `json:"kind,omitempty"`

	// name is the binding name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// namespace is the logical namespace of a namespaced binding. Omission
	// means the referencing document's namespace.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Namespace string `json:"namespace,omitempty"`

	// sourceRef selects another allowed PolicySource.
	// +optional
	SourceRef *SourceRef `json:"sourceRef,omitempty"`
}

// SecretKeyRef identifies a key in a Secret in the containing control
// resource's namespace.
type SecretKeyRef struct {
	// name is the Secret name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name"`

	// key is the Secret data key.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[-._a-zA-Z0-9]+$`
	Key string `json:"key"`
}

// ConfigMapKeyRef identifies a key in a ConfigMap in the containing control
// resource's namespace.
type ConfigMapKeyRef struct {
	// name is the ConfigMap name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name"`

	// key is the ConfigMap data key.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[-._a-zA-Z0-9]+$`
	Key string `json:"key"`
}

// KeyRange selects policy documents to collect from a source. Cluster-scoped
// kinds omit namespaces; every other kind requires them.
// +kubebuilder:validation:XValidation:rule="self.kinds.all(k, k in ['ClusterRole', 'ClusterRoleBinding']) || self.kinds.all(k, !(k in ['ClusterRole', 'ClusterRoleBinding']))",message="kinds must be all cluster-scoped or all namespaced"
// +kubebuilder:validation:XValidation:rule="self.kinds.all(k, k in ['ClusterRole', 'ClusterRoleBinding']) != has(self.namespaces)",message="namespaces is required for namespaced kinds and forbidden for cluster-scoped kinds"
// +kubebuilder:validation:XValidation:rule="!has(self.namespaces) || !('*' in self.namespaces) || size(self.namespaces) == 1",message="the namespaces wildcard must stand alone"
// +kubebuilder:validation:XValidation:rule="!('*' in self.names) || size(self.names) == 1",message="the names wildcard must stand alone"
type KeyRange struct {
	// kinds are the canonical kinds included in the range.
	// +required
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:items:Enum=Policy;PolicyBinding;PolicySet;Role;ClusterRole;RoleBinding;ClusterRoleBinding
	Kinds []string `json:"kinds"`

	// namespaces are the logical namespaces included in the range. "*" selects
	// every namespace.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:items:MaxLength=63
	// +kubebuilder:validation:items:Pattern=`^(\*|[a-z0-9]([-a-z0-9]*[a-z0-9])?)$`
	Namespaces []string `json:"namespaces,omitempty"`

	// names are the document names included in the range. "*" selects every
	// name.
	// +required
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=253
	Names []string `json:"names"`
}

// SubjectRequirement tests one principal attribute. Requirements are ANDed.
// +kubebuilder:validation:XValidation:rule="self.kind == 'ServiceAccount' ? has(self.namespace) : !has(self.namespace)",message="namespace is required only for ServiceAccount"
// +kubebuilder:validation:XValidation:rule="self.kind == 'Extra' ? has(self.key) : !has(self.key)",message="key is required only for Extra"
// +kubebuilder:validation:XValidation:rule="self.kind in ['User', 'Group', 'ServiceAccount'] ? !has(self.values) : !has(self.names)",message="identity requirements use names and attributes use values"
// +kubebuilder:validation:XValidation:rule="!(self.operator in ['StartsWith', 'NotStartsWith']) || self.kind in ['User', 'Group', 'ServiceAccount']",message="prefix operators require identity names"
// +kubebuilder:validation:XValidation:rule="self.operator in ['Exists', 'DoesNotExist'] ? !has(self.names) && !has(self.values) : has(self.names) || has(self.values)",message="presence operators forbid operands and the other operators require them"
// +kubebuilder:validation:XValidation:rule="self.kind != 'UID' || !has(self.values) || self.values.all(v, size(v) > 0)",message="UID values must not be empty"
type SubjectRequirement struct {
	// kind selects the principal attribute.
	// +required
	// +kubebuilder:validation:Enum=User;Group;ServiceAccount;UID;Extra
	Kind string `json:"kind"`

	// operator compares the selected values or tests presence.
	// +required
	// +kubebuilder:validation:Enum=In;NotIn;Exists;DoesNotExist;StartsWith;NotStartsWith
	Operator string `json:"operator"`

	// names supplies operands for User, Group, or ServiceAccount.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:items:MinLength=1
	Names []string `json:"names,omitempty"`

	// namespace is required only for ServiceAccount.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Namespace string `json:"namespace,omitempty"`

	// key is required only for Extra.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Key string `json:"key,omitempty"`

	// values supplies operands for UID or Extra.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	Values []string `json:"values,omitempty"`
}

// FieldSelector restricts a collection operation with parsed field requirements.
type FieldSelector struct {
	// requirements are ANDed parsed field selector requirements.
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=64
	Requirements []metav1.FieldSelectorRequirement `json:"requirements,omitempty"`
}

// OperationRule describes a complete resource or non-resource operation set.
// +kubebuilder:validation:XValidation:rule="!has(self.nonResourceURLs) || !(has(self.apiGroups) || has(self.resources) || has(self.apiVersions) || has(self.resourceNames) || has(self.namespaces) || has(self.labelSelector) || has(self.fieldSelector))",message="a non-resource rule forbids resource fields"
// +kubebuilder:validation:XValidation:rule="has(self.nonResourceURLs) || (has(self.apiGroups) && has(self.resources))",message="a resource rule requires apiGroups and resources"
// +kubebuilder:validation:XValidation:rule="!has(self.apiVersions) || !('*' in self.apiVersions) || size(self.apiVersions) == 1",message="the apiVersions wildcard must stand alone"
// +kubebuilder:validation:XValidation:rule="!(has(self.labelSelector) || has(self.fieldSelector)) || self.verbs.all(v, v in ['list', 'watch', 'deletecollection'])",message="selectors require only collection verbs"
type OperationRule struct {
	// verbs are Kubernetes resource verbs or lowercase HTTP verbs.
	// +required
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	Verbs []string `json:"verbs"`

	// apiGroups are the resource API groups.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	APIGroups []string `json:"apiGroups,omitempty"`

	// resources are resource or resource/subresource names.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	Resources []string `json:"resources,omitempty"`

	// apiVersions are resource API versions. Omission means every version.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	APIVersions []string `json:"apiVersions,omitempty"`

	// resourceNames restrict resource operations to exact names.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=256
	ResourceNames []string `json:"resourceNames,omitempty"`

	// namespaces restrict resource operations by request effect namespace.
	// "*" matches every named namespace, and "" matches requests without one.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:items:MaxLength=63
	// +kubebuilder:validation:items:Pattern=`^(\*|[a-z0-9]([-a-z0-9]*[a-z0-9])?)?$`
	Namespaces []string `json:"namespaces,omitempty"`

	// nonResourceURLs are exact or suffix-wildcard absolute paths.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=256
	NonResourceURLs []string `json:"nonResourceURLs,omitempty"`

	// labelSelector restricts collection members with a native label selector.
	// +optional
	LabelSelector *metav1.LabelSelector `json:"labelSelector,omitempty"`

	// fieldSelector restricts collection members with parsed field requirements.
	// +optional
	FieldSelector *FieldSelector `json:"fieldSelector,omitempty"`
}

// IssueSeverity classifies a diagnostic as an error or warning.
// +kubebuilder:validation:Enum=Error;Warning
type IssueSeverity string

const (
	// IssueSeverityError identifies a diagnostic affecting validity or evaluation.
	IssueSeverityError IssueSeverity = "Error"
	// IssueSeverityWarning identifies an advisory diagnostic.
	IssueSeverityWarning IssueSeverity = "Warning"
)

// IssueScope identifies the level to which a diagnostic is attributed.
// +kubebuilder:validation:Enum=Document;Use
type IssueScope string

const (
	// IssueScopeDocument attributes a diagnostic to a canonical document.
	IssueScopeDocument IssueScope = "Document"
	// IssueScopeUse attributes a diagnostic to one contextual document use.
	IssueScopeUse IssueScope = "Use"
)

// QualifiedDocumentRef identifies a document in status diagnostics.
type QualifiedDocumentRef struct {
	// group is the canonical API group.
	Group string `json:"group"`
	// kind is the canonical kind.
	Kind string `json:"kind"`
	// namespace is present for namespaced document kinds.
	Namespace string `json:"namespace,omitempty"`
	// name is the document name.
	Name string `json:"name"`
}

// Issue is a bounded diagnostic projected into control-resource status.
type Issue struct {
	// severity is Error or Warning.
	Severity IssueSeverity `json:"severity"`
	// reason is a stable machine-readable reason.
	Reason string `json:"reason"`
	// message is a human-readable diagnostic.
	Message string `json:"message"`
	// scope identifies the diagnostic attribution level.
	Scope IssueScope `json:"scope"`
	// sourceRef identifies the source of the affected document when known.
	SourceRef *SourceRef `json:"sourceRef,omitempty"`
	// documentRef identifies an affected document when known.
	DocumentRef *QualifiedDocumentRef `json:"documentRef,omitempty"`
	// endpoint identifies an affected endpoint when known.
	Endpoint string `json:"endpoint,omitempty"`
	// authority identifies an affected authority when known.
	Authority string `json:"authority,omitempty"`
	// contextID identifies one contextual graph use when known.
	ContextID string `json:"contextID,omitempty"`
	// path is the ordered qualified ancestry for a contextual use.
	// +listType=atomic
	Path []QualifiedDocumentRef `json:"path,omitempty"`
}
