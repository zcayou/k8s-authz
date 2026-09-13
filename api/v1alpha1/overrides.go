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
	corev1 "k8s.io/api/core/v1"
)

// ResourceMetadata customizes labels and annotations on a generated resource.
type ResourceMetadata struct {
	// labels are merged with the operator's labels. A label the operator also
	// sets takes the value given here.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// annotations are merged with the operator's annotations.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// PodTemplateOverride customizes the generated engine Pods. It is merged onto
// the operator's Pod template with strategic merge, and the values given here
// win. Overriding the opa container's image, command, args, ports or probe
// handlers, or the operator's volumes, mounts, labels and annotations,
// is unsupported. Probe timing can be customized.
type PodTemplateOverride struct {
	// metadata customizes Pod labels and annotations.
	// +optional
	Metadata *ResourceMetadata `json:"metadata,omitempty"`

	// spec customizes the Pod spec.
	// +optional
	Spec *PodSpecOverride `json:"spec,omitempty"`
}

// PodSpecOverride contains the Pod spec fields an AuthorizationService can
// customize. Named lists merge with the operator's entries by name.
type PodSpecOverride struct {
	// containers merge with the operator's containers by name. The engine
	// container is named opa.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +patchMergeKey=name
	// +patchStrategy=merge
	Containers []corev1.Container `json:"containers,omitempty" patchStrategy:"merge" patchMergeKey:"name"`

	// initContainers are added to the engine Pods.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +patchMergeKey=name
	// +patchStrategy=merge
	InitContainers []corev1.Container `json:"initContainers,omitempty" patchStrategy:"merge" patchMergeKey:"name"`

	// volumes merge with the operator's volumes by name.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +patchMergeKey=name
	// +patchStrategy=merge
	Volumes []corev1.Volume `json:"volumes,omitempty" patchStrategy:"merge" patchMergeKey:"name"`

	// imagePullSecrets are used to pull the engine and any added container images.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +patchMergeKey=name
	// +patchStrategy=merge
	ImagePullSecrets []corev1.LocalObjectReference `json:"imagePullSecrets,omitempty" patchStrategy:"merge" patchMergeKey:"name"`

	// nodeSelector constrains the nodes that run engine Pods.
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// serviceAccountName runs the engine Pods under this ServiceAccount instead
	// of the namespace's default one. The engines never mount its token.
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`

	// securityContext replaces fields of the operator's Pod security context.
	// +optional
	SecurityContext *corev1.PodSecurityContext `json:"securityContext,omitempty"`

	// affinity sets the Pods' scheduling affinity.
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// tolerations let engine Pods schedule onto tainted nodes.
	// +optional
	// +listType=atomic
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// priorityClassName sets the Pods' priority class.
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`

	// terminationGracePeriodSeconds sets the Pods' termination grace period.
	// +optional
	TerminationGracePeriodSeconds *int64 `json:"terminationGracePeriodSeconds,omitempty"`

	// hostNetwork runs the Pods in the host's network namespace.
	// +optional
	HostNetwork bool `json:"hostNetwork,omitempty"`

	// hostPID runs the Pods in the host's PID namespace.
	// +optional
	HostPID bool `json:"hostPID,omitempty"`

	// hostIPC runs the Pods in the host's IPC namespace.
	// +optional
	HostIPC bool `json:"hostIPC,omitempty"`

	// shareProcessNamespace shares one process namespace between containers.
	// +optional
	ShareProcessNamespace *bool `json:"shareProcessNamespace,omitempty"`

	// schedulerName selects the scheduler for the Pods.
	// +optional
	SchedulerName string `json:"schedulerName,omitempty"`

	// runtimeClassName selects the Pods' RuntimeClass.
	// +optional
	RuntimeClassName *string `json:"runtimeClassName,omitempty"`

	// dnsPolicy sets the Pods' DNS policy.
	// +optional
	DNSPolicy corev1.DNSPolicy `json:"dnsPolicy,omitempty"`

	// dnsConfig sets the Pods' DNS parameters.
	// +optional
	DNSConfig *corev1.PodDNSConfig `json:"dnsConfig,omitempty"`

	// hostAliases add entries to the Pods' hosts files.
	// +optional
	// +listType=atomic
	HostAliases []corev1.HostAlias `json:"hostAliases,omitempty"`

	// topologySpreadConstraints spread the Pods across topology domains.
	// +optional
	// +listType=atomic
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
}

// ServiceTemplateOverride customizes the generated listener Service.
// It is merged onto the operator's Service with strategic merge, and the values
// given here win.
type ServiceTemplateOverride struct {
	// metadata customizes Service labels and annotations.
	// +optional
	Metadata *ResourceMetadata `json:"metadata,omitempty"`

	// spec customizes the Service spec.
	// +optional
	Spec *ServiceSpecOverride `json:"spec,omitempty"`
}

// ServiceSpecOverride contains the Service spec fields an AuthorizationService
// can customize. The operator owns the selector and the engine's target port.
type ServiceSpecOverride struct {
	// ports merge with the operator's ports by name. The engine port is named
	// https.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +patchMergeKey=name
	// +patchStrategy=merge
	// +kubebuilder:validation:MaxItems=16
	Ports []ServicePortOverride `json:"ports,omitempty" patchStrategy:"merge" patchMergeKey:"name"`

	// clusterIP requests a specific cluster IP. It is immutable once allocated.
	// +optional
	ClusterIP string `json:"clusterIP,omitempty"`

	// clusterIPs requests specific cluster IPs. They are immutable once allocated.
	// +optional
	// +listType=atomic
	ClusterIPs []string `json:"clusterIPs,omitempty"`

	// type is ClusterIP, NodePort or LoadBalancer.
	// +optional
	Type corev1.ServiceType `json:"type,omitempty"`

	// externalIPs are additional IPs that route to the Service.
	// +optional
	// +listType=atomic
	ExternalIPs []string `json:"externalIPs,omitempty"`

	// sessionAffinity sets the Service's session affinity.
	// +optional
	SessionAffinity corev1.ServiceAffinity `json:"sessionAffinity,omitempty"`

	// loadBalancerIP requests a load balancer IP where the provider supports it.
	// +optional
	LoadBalancerIP string `json:"loadBalancerIP,omitempty"`

	// loadBalancerSourceRanges restrict the clients a load balancer admits.
	// +optional
	// +listType=atomic
	LoadBalancerSourceRanges []string `json:"loadBalancerSourceRanges,omitempty"`

	// externalTrafficPolicy routes external traffic cluster-wide or node-locally.
	// +optional
	ExternalTrafficPolicy corev1.ServiceExternalTrafficPolicy `json:"externalTrafficPolicy,omitempty"`

	// healthCheckNodePort sets the load balancer health-check node port.
	// +optional
	HealthCheckNodePort int32 `json:"healthCheckNodePort,omitempty"`

	// publishNotReadyAddresses publishes engines before they are ready.
	// +optional
	PublishNotReadyAddresses bool `json:"publishNotReadyAddresses,omitempty"`

	// sessionAffinityConfig configures session affinity.
	// +optional
	SessionAffinityConfig *corev1.SessionAffinityConfig `json:"sessionAffinityConfig,omitempty"`

	// ipFamilies selects the Service's IP families.
	// +optional
	// +listType=atomic
	IPFamilies []corev1.IPFamily `json:"ipFamilies,omitempty"`

	// ipFamilyPolicy selects single- or dual-stack addressing.
	// +optional
	IPFamilyPolicy *corev1.IPFamilyPolicy `json:"ipFamilyPolicy,omitempty"`

	// allocateLoadBalancerNodePorts controls node port allocation for load balancers.
	// +optional
	AllocateLoadBalancerNodePorts *bool `json:"allocateLoadBalancerNodePorts,omitempty"`

	// loadBalancerClass selects the load balancer implementation.
	// +optional
	LoadBalancerClass *string `json:"loadBalancerClass,omitempty"`

	// internalTrafficPolicy routes internal traffic cluster-wide or node-locally.
	// +optional
	InternalTrafficPolicy *corev1.ServiceInternalTrafficPolicy `json:"internalTrafficPolicy,omitempty"`

	// trafficDistribution expresses a preference for how traffic reaches engines.
	// +optional
	TrafficDistribution *string `json:"trafficDistribution,omitempty"`
}

// ServicePortOverride customizes one of the listener Service's ports.
type ServicePortOverride struct {
	// name identifies the port to customize.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=15
	Name string `json:"name"`

	// protocol is the port's IP protocol.
	// +optional
	Protocol corev1.Protocol `json:"protocol,omitempty"`

	// appProtocol is the port's application protocol.
	// +optional
	AppProtocol *string `json:"appProtocol,omitempty"`

	// port is the port the Service exposes.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`

	// nodePort requests a specific node port for NodePort and LoadBalancer
	// Services. Zero releases an allocated node port.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	NodePort *int32 `json:"nodePort,omitempty"`
}
