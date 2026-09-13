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

// DecisionFallback is the result returned when policy doesn't decide a request.
// Deny is an authoritative denial, and NoOpinion defers to the caller's next
// authorizer.
// +kubebuilder:validation:Enum=Deny;NoOpinion
type DecisionFallback string

const (
	// DecisionFallbackDeny denies the request authoritatively.
	DecisionFallbackDeny DecisionFallback = "Deny"
	// DecisionFallbackNoOpinion defers the request to the next authorizer.
	DecisionFallbackNoOpinion DecisionFallback = "NoOpinion"
)

// RuntimeType selects the engine workload kind. Deployment runs a fixed
// number of engines, and DaemonSet runs one on each node the Pod template can
// schedule on.
// +kubebuilder:validation:Enum=Deployment;DaemonSet
type RuntimeType string

const (
	// RuntimeTypeDeployment runs the engines as a Deployment.
	RuntimeTypeDeployment RuntimeType = "Deployment"
	// RuntimeTypeDaemonSet runs the engines as a DaemonSet.
	RuntimeTypeDaemonSet RuntimeType = "DaemonSet"
)

// AuthorizationServiceRuntime configures the managed serving workload.
// +kubebuilder:validation:XValidation:rule="self.type != 'Deployment' || !has(self.deployment) || !has(self.minReadyReplicas) || self.minReadyReplicas <= self.deployment.replicas",message="minReadyReplicas must not exceed deployment.replicas"
type AuthorizationServiceRuntime struct {
	// type selects the workload kind.
	// +required
	Type RuntimeType `json:"type"`

	// deployment configures the Deployment, used only when type is Deployment.
	// +optional
	// +kubebuilder:default={}
	Deployment *DeploymentRuntime `json:"deployment,omitempty"`

	// minReadyReplicas is the ready engine count the service keeps through
	// rollouts, voluntary disruptions and runtime-kind switches. Equal
	// to deployment.replicas, it lets no ready engine Pod be evicted, which blocks
	// node drains.
	// +optional
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	MinReadyReplicas int32 `json:"minReadyReplicas,omitempty"`

	// metadata customizes the Deployment or DaemonSet metadata.
	// +optional
	Metadata *ResourceMetadata `json:"metadata,omitempty"`

	// podTemplate customizes the generated engine Pods.
	// +optional
	PodTemplate *PodTemplateOverride `json:"podTemplate,omitempty"`
}

// DeploymentRuntime configures the engine Deployment.
type DeploymentRuntime struct {
	// replicas is the number of engine Pods.
	// +optional
	// +kubebuilder:default=2
	// +kubebuilder:validation:Minimum=1
	Replicas int32 `json:"replicas,omitempty"`
}

// AuthorizationServiceTLS configures the engines' serving identity and the CA
// that issues their webhook callers' certificates.
type AuthorizationServiceTLS struct {
	// server identifies the engines' serving certificate and its CA.
	// +required
	Server ServerTLS `json:"server"`

	// client identifies the CA that issues the certificates of every endpoint's
	// callers.
	// +required
	Client ClientTLS `json:"client"`
}

// ServerTLS configures the certificate the engines serve. It must be valid
// for the listener Service's DNS name, authz-<name>.<namespace>.svc, which
// is the TLS server name the operator and rendered caller configurations
// verify.
type ServerTLS struct {
	// secretRef identifies a kubernetes.io/tls Secret holding tls.crt and tls.key.
	// The engines reload it in place, so renewing the certificate never restarts
	// them.
	// +required
	SecretRef SecretReference `json:"secretRef"`

	// caRef identifies the CA bundle the operator verifies the serving certificate
	// with.
	// +required
	CARef CABundleRef `json:"caRef"`
}

// ClientTLS configures the CA the engines verify webhook callers' client
// certificates with. Each endpoint then admits its callers by Common Name,
// as kube-apiserver identifies x509 clients against one client CA.
type ClientTLS struct {
	// caRef identifies the CA bundle that issues the callers' client certificates.
	// The engines reload it in place, so changing its content never restarts
	// them.
	// +required
	CARef CABundleRef `json:"caRef"`
}

// SecretReference identifies a Secret in the AuthorizationService's namespace.
type SecretReference struct {
	// name is the Secret name.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name"`
}

// CABundleRef identifies a PEM CA bundle held in a key of a Secret
// or a ConfigMap in the AuthorizationService's namespace.
// +kubebuilder:validation:XValidation:rule="has(self.secretKeyRef) != has(self.configMapKeyRef)",message="exactly one of secretKeyRef or configMapKeyRef is required"
type CABundleRef struct {
	// secretKeyRef selects a Secret key.
	// +optional
	SecretKeyRef *SecretKeyRef `json:"secretKeyRef,omitempty"`

	// configMapKeyRef selects a ConfigMap key.
	// +optional
	ConfigMapKeyRef *ConfigMapKeyRef `json:"configMapKeyRef,omitempty"`
}

// Caller admits one webhook client by its certificate subject,
// as kube-apiserver identifies x509 clients.
type Caller struct {
	// commonName is the subject Common Name of the caller's client certificate.
	// Renewing or re-keying the certificate needs no change here.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=64
	CommonName string `json:"commonName"`
}

// Authority attaches a binding with an explicit uncovered-request fallback.
// +kubebuilder:validation:XValidation:rule="has(self.bindingRef.sourceRef)",message="bindingRef.sourceRef is required for an authority"
type Authority struct {
	// bindingRef identifies the principal-to-policy association. It names its
	// PolicySource explicitly.
	// +required
	BindingRef BindingRef `json:"bindingRef"`

	// whenNoPolicyAllows is the fallback after selecting this binding. It also
	// applies when an Allow can't be resolved, because a broken Allow grants
	// nothing; the problem is reported in status.
	// +required
	WhenNoPolicyAllows DecisionFallback `json:"whenNoPolicyAllows"`
}

// ProgramType identifies a request integration.
// +kubebuilder:validation:Enum=Kubernetes
type ProgramType string

// ProgramTypeKubernetes evaluates Kubernetes SubjectAccessReviews.
const ProgramTypeKubernetes ProgramType = "Kubernetes"

// AuthorizationProgram selects the built-in request integration.
type AuthorizationProgram struct {
	// type selects the request and response contract.
	// +required
	Type ProgramType `json:"type"`
}

// Endpoint defines an authenticated SubjectAccessReview decision route.
type Endpoint struct {
	// name is the DNS-1035 route key.
	// +required
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// callers contains clients admitted to this route, whose certificates
	// the service's client CA issues. Editing them takes effect without restarting
	// the engines.
	// +required
	// +listType=map
	// +listMapKey=commonName
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	Callers []Caller `json:"callers"`

	// sourceRefs is the complete source set available to authority roots.
	// +required
	// +listType=map
	// +listMapKey=namespace
	// +listMapKey=name
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	SourceRefs []SourceRef `json:"sourceRefs"`

	// authorities is evaluated in order and may be explicitly empty.
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=64
	Authorities []Authority `json:"authorities"`

	// whenEvaluationFails is the result when this endpoint can't evaluate
	// a request: the SubjectAccessReview is malformed, the engine has no policy
	// state, the selected entry binding can't be resolved, or a prohibition can't
	// be resolved. Deny responds with denied=true and NoOpinion with allowed=false
	// and denied=false; both carry evaluationError. The caller configuration
	// rendered by k8s-authz sets the webhook failurePolicy to the value it has
	// when rendered, so an engine that can't answer at all behaves the same way;
	// render the caller configuration again after changing it. kube-apiserver
	// caches these responses for unauthorizedTTL when it caches unauthorized
	// decisions.
	// +required
	WhenEvaluationFails DecisionFallback `json:"whenEvaluationFails"`
}

// AuthorizationServiceSpec defines one serving group and its endpoint contracts.
type AuthorizationServiceSpec struct {
	// program selects the request integration for every endpoint.
	// +required
	Program AuthorizationProgram `json:"program"`

	// runtime selects the managed serving workload and its capacity.
	// +required
	Runtime AuthorizationServiceRuntime `json:"runtime"`

	// listener customizes the generated listener Service.
	// +optional
	Listener *ServiceTemplateOverride `json:"listener,omitempty"`

	// tls configures the engines' serving identity and their callers' CA.
	// +required
	TLS AuthorizationServiceTLS `json:"tls"`

	// endpoints contains the service's authenticated decision routes.
	// +required
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	Endpoints []Endpoint `json:"endpoints"`

	// rego caps the builtins Rego conditions may call in this service's engines.
	// Omission imposes no limit beyond the sources'.
	// +optional
	Rego *AuthorizationServiceRego `json:"rego,omitempty"`
}

// AuthorizationServiceRego limits the builtins Rego conditions may call
// in the service's engines.
type AuthorizationServiceRego struct {
	// allowedBuiltins caps every source's allowed builtins.
	// +required
	// +listType=set
	// +kubebuilder:validation:MaxItems=256
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=128
	AllowedBuiltins []string `json:"allowedBuiltins"`
}

// AuthorizationServiceStatus reports preparation and serving state.
type AuthorizationServiceStatus struct {
	// observedGeneration is the spec generation this status reports on.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// desiredRevision is the content-addressed revision of the policy snapshot
	// prepared for the current spec and sources.
	// +optional
	DesiredRevision string `json:"desiredRevision,omitempty"`

	// desiredReplicas is the number of engine Pods the workload is expected
	// to run. It is absent while a DaemonSet has not reported its scheduled count.
	// +optional
	DesiredReplicas *int32 `json:"desiredReplicas,omitempty"`

	// readyReplicas is the number of ready engine Pods, each serving the state
	// installed on it.
	// +optional
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// currentReplicas is the number of engine Pods serving desiredRevision
	// that started from the current engine startup configuration.
	// +optional
	CurrentReplicas int32 `json:"currentReplicas,omitempty"`

	// conditions are Prepared, Ready and PolicyHealthy.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// issues contains bounded attributed diagnostics for the service
	// and the policy it compiles.
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
// +kubebuilder:resource:scope=Namespaced,shortName=azsvc,categories=authz
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Prepared",type=string,JSONPath=`.status.conditions[?(@.type=="Prepared")].status`
// +kubebuilder:printcolumn:name="ReadyReplicas",type=integer,JSONPath=`.status.readyReplicas`
// +kubebuilder:printcolumn:name="CurrentReplicas",type=integer,JSONPath=`.status.currentReplicas`
// +kubebuilder:printcolumn:name="DesiredRevision",type=string,JSONPath=`.status.desiredRevision`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="size(self.metadata.name) <= 57 && self.metadata.name.matches('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')",message="name must be a DNS label of at most 57 characters"

// AuthorizationService owns a serving group and its authorization endpoints.
type AuthorizationService struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the serving group and authorization roots.
	// +required
	Spec AuthorizationServiceSpec `json:"spec"`

	// status reports observed preparation and serving state.
	// +optional
	Status AuthorizationServiceStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// AuthorizationServiceList contains a list of AuthorizationService objects.
type AuthorizationServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []AuthorizationService `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &AuthorizationService{}, &AuthorizationServiceList{})
		return nil
	})
}
