package resources

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	policyv1ac "k8s.io/client-go/applyconfigurations/policy/v1"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/model"
)

const (
	httpsScheme = "https"

	engineVolume = "engine"
	tlsVolume    = "tls"

	// engineFSGroup lets the engine's non-root user read its serving Secret,
	// which is mounted group-readable only.
	engineFSGroup int64 = 65532
)

// Build returns native apply configurations for an AuthorizationService.
// Without input.CABundle it leaves out the engine ConfigMap and the workload
// that starts from it, and StartupDigest still identifies the pods started
// from them.
func Build(input BuildInput) (Owned, error) {
	service, err := buildService(input.Service)
	if err != nil {
		return Owned{}, err
	}
	data, err := startupData(input)
	if err != nil {
		return Owned{}, err
	}
	result := Owned{Service: service, DisruptionBudget: buildDisruptionBudget(input.Service), StartupDigest: model.Digest(data)}
	if input.CABundle == nil {
		return result, nil
	}
	data[CABundleKey] = string(input.CABundle)
	template, err := buildPodTemplate(input, data, result.StartupDigest)
	if err != nil {
		return Owned{}, err
	}
	result.ConfigMap = corev1ac.ConfigMap(engineConfigName(input.Service.Name), input.Service.Namespace).
		WithLabels(objectLabels(input.Service, componentEngine)).WithOwnerReferences(ownerReference(input.Service)).WithData(data)
	if input.Service.Spec.Runtime.Type == api.RuntimeTypeDeployment {
		result.Deployment = buildDeployment(input.Service, template)
	} else {
		result.DaemonSet = buildDaemonSet(input.Service, template)
	}
	return result, nil
}

// buildService leaves the addresses and node ports the API server allocates
// unset, and the API server keeps them when an apply omits them.
func buildService(service *api.AuthorizationService) (*corev1ac.ServiceApplyConfiguration, error) {
	spec := corev1ac.ServiceSpec().
		WithType(corev1.ServiceTypeClusterIP).
		WithSelector(ServiceUIDSelector(service.UID)).
		WithPorts(corev1ac.ServicePort().WithName(HTTPSPortName).WithProtocol(corev1.ProtocolTCP).WithPort(DefaultServicePort).
			WithTargetPort(intstr.FromInt32(EnginePort)).WithAppProtocol(httpsScheme)).
		WithInternalTrafficPolicy(corev1.ServiceInternalTrafficPolicyCluster).
		WithIPFamilyPolicy(corev1.IPFamilyPolicySingleStack)
	return mergeService(corev1ac.Service(Name(service.Name), service.Namespace).
		WithLabels(objectLabels(service, componentListener)).WithOwnerReferences(ownerReference(service)).WithSpec(spec), service.Spec.Listener)
}

// buildDisruptionBudget selects engine pods by service UID alone, so a single
// budget spans both workloads while the runtime kind switches. Unhealthy
// pods stay evictable so remediation can replace an engine that never became
// ready.
func buildDisruptionBudget(service *api.AuthorizationService) *policyv1ac.PodDisruptionBudgetApplyConfiguration {
	return policyv1ac.PodDisruptionBudget(Name(service.Name), service.Namespace).
		WithLabels(objectLabels(service, componentEngine)).WithOwnerReferences(ownerReference(service)).
		WithSpec(policyv1ac.PodDisruptionBudgetSpec().WithMinAvailable(intstr.FromInt32(service.Spec.Runtime.MinReadyReplicas)).
			WithSelector(metav1ac.LabelSelector().WithMatchLabels(ServiceUIDSelector(service.UID))).
			WithUnhealthyPodEvictionPolicy(policyv1.AlwaysAllow))
}

// startupData returns the engine ConfigMap's data other than its CA bundle,
// which is what the engines start from: OPA reloads the CA bundle in place.
func startupData(input BuildInput) (map[string]string, error) {
	configuration, err := engine.Configuration(input.DecisionLogs)
	if err != nil {
		return nil, fmt.Errorf("render engine configuration: %w", err)
	}
	bootstrap, err := json.Marshal(input.Bootstrap)
	if err != nil {
		return nil, fmt.Errorf("encode engine bootstrap: %w", err)
	}
	data := engine.Modules()
	data[ConfigKey] = string(configuration)
	data[BootstrapKey] = string(bootstrap)
	return data, nil
}

// buildPodTemplate runs stock OPA from the engine ConfigMap, whose keys
// are projected into PodLayout, and the serving Secret. The template carries
// the startup digest, so a startup change rolls the pods and each pod records
// the configuration it started with. The startup probe holds a pod's opa
// container unstarted until OPA serves, which the operator waits for before
// it pushes.
func buildPodTemplate(input BuildInput, data map[string]string, digest string) (*corev1ac.PodTemplateSpecApplyConfiguration, error) {
	items := make([]*corev1ac.KeyToPathApplyConfiguration, 0, len(data))
	for _, key := range slices.Sorted(maps.Keys(data)) {
		items = append(items, corev1ac.KeyToPath().WithKey(key).WithPath(ItemPath(key)))
	}
	volumes := []*corev1ac.VolumeApplyConfiguration{
		corev1ac.Volume().WithName(engineVolume).WithConfigMap(corev1ac.ConfigMapVolumeSource().
			WithName(engineConfigName(input.Service.Name)).WithItems(items...)),
		corev1ac.Volume().WithName(tlsVolume).WithSecret(corev1ac.SecretVolumeSource().
			WithSecretName(input.Service.Spec.TLS.Server.SecretRef.Name).WithDefaultMode(0o440).WithItems(
			corev1ac.KeyToPath().WithKey(corev1.TLSCertKey).WithPath(corev1.TLSCertKey),
			corev1ac.KeyToPath().WithKey(corev1.TLSPrivateKeyKey).WithPath(corev1.TLSPrivateKeyKey))),
	}
	container := corev1ac.Container().WithName(ContainerName).WithImage(input.EngineImage).
		WithImagePullPolicy(corev1.PullIfNotPresent).WithCommand(EnginePath).WithArgs(PodLayout.Arguments()...).
		WithPorts(corev1ac.ContainerPort().WithName(HTTPSPortName).WithContainerPort(EnginePort).WithProtocol(corev1.ProtocolTCP),
			corev1ac.ContainerPort().WithName(DiagnosticPortName).WithContainerPort(DiagnosticPort).WithProtocol(corev1.ProtocolTCP)).
		WithSecurityContext(corev1ac.SecurityContext().WithAllowPrivilegeEscalation(false).WithPrivileged(false).
			WithReadOnlyRootFilesystem(true).WithRunAsNonRoot(true).
			WithCapabilities(corev1ac.Capabilities().WithDrop("ALL")).
			WithSeccompProfile(corev1ac.SeccompProfile().WithType(corev1.SeccompProfileTypeRuntimeDefault))).
		WithStartupProbe(probe("/health/live", 1, 30)).WithReadinessProbe(probe("/health/ready", 2, 1)).
		WithLivenessProbe(probe("/health/live", 10, 3)).
		WithVolumeMounts(corev1ac.VolumeMount().WithName(engineVolume).WithMountPath(EngineDirectory).WithReadOnly(true),
			corev1ac.VolumeMount().WithName(tlsVolume).WithMountPath(TLSDirectory).WithReadOnly(true))
	spec := corev1ac.PodSpec().WithAutomountServiceAccountToken(false).
		WithHostNetwork(false).WithHostPID(false).WithHostIPC(false).WithTerminationGracePeriodSeconds(30).
		WithSecurityContext(corev1ac.PodSecurityContext().WithRunAsNonRoot(true).WithFSGroup(engineFSGroup).
			WithSeccompProfile(corev1ac.SeccompProfile().WithType(corev1.SeccompProfileTypeRuntimeDefault))).
		WithContainers(container).WithVolumes(volumes...)
	return mergePod(corev1ac.PodTemplateSpec().WithLabels(objectLabels(input.Service, componentEngine)).WithLabels(workloadSelector(input.Service)).
		WithAnnotations(map[string]string{AnnotationStartupDigest: digest}).WithSpec(spec), input.Service.Spec.Runtime.PodTemplate)
}

func probe(path string, period, failures int32) *corev1ac.ProbeApplyConfiguration {
	return corev1ac.Probe().WithHTTPGet(corev1ac.HTTPGetAction().WithPath(path).
		WithPort(intstr.FromString(DiagnosticPortName)).WithScheme(corev1.URISchemeHTTP)).
		WithPeriodSeconds(period).WithTimeoutSeconds(1).WithFailureThreshold(failures).WithSuccessThreshold(1)
}

func buildDeployment(service *api.AuthorizationService, template *corev1ac.PodTemplateSpecApplyConfiguration) *appsv1ac.DeploymentApplyConfiguration {
	runtime := service.Spec.Runtime
	labels, annotations := workloadMetadata(runtime)
	return appsv1ac.Deployment(Name(service.Name), service.Namespace).
		WithLabels(objectLabels(service, componentEngine)).WithLabels(labels).WithAnnotations(annotations).WithOwnerReferences(ownerReference(service)).
		WithSpec(appsv1ac.DeploymentSpec().WithReplicas(runtime.Deployment.Replicas).
			WithSelector(metav1ac.LabelSelector().WithMatchLabels(workloadSelector(service))).WithTemplate(template).
			WithStrategy(appsv1ac.DeploymentStrategy().WithType(appsv1.RollingUpdateDeploymentStrategyType).
				WithRollingUpdate(appsv1ac.RollingUpdateDeployment().WithMaxUnavailable(intstr.FromInt32(0)).WithMaxSurge(intstr.FromInt32(1)))))
}

func buildDaemonSet(service *api.AuthorizationService, template *corev1ac.PodTemplateSpecApplyConfiguration) *appsv1ac.DaemonSetApplyConfiguration {
	labels, annotations := workloadMetadata(service.Spec.Runtime)
	return appsv1ac.DaemonSet(Name(service.Name), service.Namespace).
		WithLabels(objectLabels(service, componentEngine)).WithLabels(labels).WithAnnotations(annotations).WithOwnerReferences(ownerReference(service)).
		WithSpec(appsv1ac.DaemonSetSpec().WithSelector(metav1ac.LabelSelector().WithMatchLabels(workloadSelector(service))).WithTemplate(template).
			WithUpdateStrategy(appsv1ac.DaemonSetUpdateStrategy().WithType(appsv1.RollingUpdateDaemonSetStrategyType).
				WithRollingUpdate(appsv1ac.RollingUpdateDaemonSet().WithMaxUnavailable(intstr.FromInt32(0)).WithMaxSurge(intstr.FromInt32(1)))))
}

// workloadMetadata returns the labels and annotations runtime.metadata adds
// to the Deployment or DaemonSet.
func workloadMetadata(runtime api.AuthorizationServiceRuntime) (map[string]string, map[string]string) {
	if runtime.Metadata == nil {
		return nil, nil
	}
	return runtime.Metadata.Labels, runtime.Metadata.Annotations
}
