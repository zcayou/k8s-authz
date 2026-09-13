package resources

import (
	"k8s.io/apimachinery/pkg/runtime"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	policyv1ac "k8s.io/client-go/applyconfigurations/policy/v1"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/engine"
)

// BuildInput is the complete immutable input to Build.
type BuildInput struct {
	Service *api.AuthorizationService
	// EngineImage is the stock OPA image the engines run.
	EngineImage string
	// DecisionLogs has the engines log their decisions.
	DecisionLogs bool
	Bootstrap    engine.Bootstrap
	// CABundle is the PEM bundle the engines verify client certificates with:
	// the management roots and the service's client CA. It is nil while the client
	// CA can't be read.
	CABundle []byte
}

// Owned holds the native apply configurations of a service's owned objects.
type Owned struct {
	ConfigMap        *corev1ac.ConfigMapApplyConfiguration
	Service          *corev1ac.ServiceApplyConfiguration
	DisruptionBudget *policyv1ac.PodDisruptionBudgetApplyConfiguration
	Deployment       *appsv1ac.DeploymentApplyConfiguration
	DaemonSet        *appsv1ac.DaemonSetApplyConfiguration
	// StartupDigest is the digest of ConfigMap's data other than its CA bundle,
	// which the pod template carries in AnnotationStartupDigest.
	StartupDigest string
}

// Objects returns the desired objects in stable reconciliation order.
// The engine ConfigMap comes first, so new pods find it when they start.
func (o Owned) Objects() []runtime.ApplyConfiguration {
	objects := make([]runtime.ApplyConfiguration, 0, 4)
	if o.ConfigMap != nil {
		objects = append(objects, o.ConfigMap)
	}
	objects = append(objects, o.Service, o.DisruptionBudget)
	if o.Deployment != nil {
		objects = append(objects, o.Deployment)
	}
	if o.DaemonSet != nil {
		objects = append(objects, o.DaemonSet)
	}
	return objects
}
