package resources

import (
	"slices"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
)

// FieldOwner is the field manager of every object the operator applies.
const FieldOwner = "k8s-authz-operator"

const (
	labelComponent = "app.kubernetes.io/component"
	// LabelInstance names the AuthorizationService that owns an object.
	LabelInstance  = "app.kubernetes.io/instance"
	labelManagedBy = "app.kubernetes.io/managed-by"
	labelName      = "app.kubernetes.io/name"
	// LabelServiceUID carries the UID of the AuthorizationService that owns
	// an object.
	LabelServiceUID = "authorization.zctx.io/service-uid"
	// labelRuntimeKind carries an engine pod's workload kind, Deployment
	// or DaemonSet.
	labelRuntimeKind = "authorization.zctx.io/runtime-kind"
	// AnnotationStartupDigest carries the digest of the engine ConfigMap an engine
	// pod starts from.
	AnnotationStartupDigest = "authorization.zctx.io/startup-digest"

	componentEngine   = "engine"
	componentListener = "listener"
)

// Name names the listener Service, workload and PodDisruptionBudget
// of the service named service.
func Name(service string) string {
	return "authz-" + service
}

// engineConfigName names the engine ConfigMap of the service named service.
func engineConfigName(service string) string {
	return Name(service) + "-engine"
}

// ServerName is the TLS server name the engines' serving certificate must
// cover: the DNS name of the listener Service of the service namespace/name.
func ServerName(namespace, name string) string {
	return Name(name) + "." + namespace + ".svc"
}

// ServiceUIDSelector selects the engine pods of the service whose UID is uid,
// whichever workload runs them.
func ServiceUIDSelector(uid types.UID) map[string]string {
	return map[string]string{LabelServiceUID: string(uid)}
}

// ServiceEngineSelector selects the engine pods of the AuthorizationService
// named service, among the pods of its namespace.
func ServiceEngineSelector(service string) map[string]string {
	return map[string]string{LabelInstance: service, labelComponent: componentEngine}
}

// EngineSelector selects the engine pods of every AuthorizationService.
func EngineSelector() labels.Selector {
	return labels.SelectorFromSet(labels.Set{labelManagedBy: FieldOwner, labelComponent: componentEngine})
}

// PodReady reports whether pod is Ready and not terminating.
func PodReady(pod *corev1.Pod) bool {
	return pod.DeletionTimestamp.IsZero() && slices.ContainsFunc(pod.Status.Conditions, func(condition corev1.PodCondition) bool {
		return condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue
	})
}

// workloadSelector selects the pods of the service's current workload kind,
// so the Deployment and DaemonSet never select each other's pods during
// a runtime-kind switch.
func workloadSelector(service *api.AuthorizationService) map[string]string {
	return map[string]string{LabelServiceUID: string(service.UID), labelRuntimeKind: string(service.Spec.Runtime.Type)}
}

func objectLabels(service *api.AuthorizationService, component string) map[string]string {
	return map[string]string{
		labelName:       "k8s-authz",
		LabelInstance:   service.Name,
		labelManagedBy:  FieldOwner,
		labelComponent:  component,
		LabelServiceUID: string(service.UID),
	}
}

func ownerReference(service *api.AuthorizationService) *metav1ac.OwnerReferenceApplyConfiguration {
	kind := api.GroupVersion.WithKind("AuthorizationService")
	return metav1ac.OwnerReference().WithAPIVersion(kind.GroupVersion().String()).WithKind(kind.Kind).
		WithName(service.Name).WithUID(service.UID).WithController(true).WithBlockOwnerDeletion(true)
}
