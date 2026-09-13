package resources_test

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	gomegatypes "github.com/onsi/gomega/types"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/resources"
)

const (
	serviceName = "fleet-authz"
	serviceUID  = "4ef3b07d-7a98-4471-a754-880923b89e1f"
	nodePoolKey = "pool"
)

var _ = Describe("Build", func() {
	It("leaves the addresses and node ports the API server allocates unset", func() {
		desired, err := resources.Build(deploymentInput())
		Expect(err).NotTo(HaveOccurred())
		Expect(*desired.Service.Name).To(Equal("authz-" + serviceName))
		Expect(desired.Service.Spec.ClusterIP).To(BeNil())
		Expect(desired.Service.Spec.ClusterIPs).To(BeNil())
		Expect(desired.Service.Spec.IPFamilies).To(BeNil())
		Expect(desired.Service.Spec.HealthCheckNodePort).To(BeNil())
		Expect(*desired.Service.Spec.IPFamilyPolicy).To(Equal(corev1.IPFamilyPolicySingleStack))
		Expect(*desired.Service.Spec.InternalTrafficPolicy).To(Equal(corev1.ServiceInternalTrafficPolicyCluster))
		Expect(desired.Service.Spec.Selector).To(Equal(resources.ServiceUIDSelector(serviceUID)))
		Expect(desired.Service.Spec.Ports).To(ConsistOf(SatisfyAll(
			HaveField("Port", HaveValue(Equal(int32(443)))),
			HaveField("TargetPort", HaveValue(Equal(intstr.FromInt32(resources.EnginePort)))),
			HaveField("NodePort", BeNil()),
		)))
	})

	It("passes a requested address through for the API server to allocate or refuse", func() {
		input := deploymentInput()
		input.Service.Spec.Listener = serviceOverride(`{"spec":{"clusterIP":"2001:db8::11"}}`)
		desired, err := resources.Build(input)
		Expect(err).NotTo(HaveOccurred())
		Expect(desired.Service.Spec.ClusterIP).To(HaveValue(Equal("2001:db8::11")))
		Expect(desired.Service.Spec.ClusterIPs).To(BeNil())
		Expect(desired.Service.Spec.IPFamilies).To(BeNil())
	})

	It("keeps traffic distribution an optional soft preference", func() {
		input := deploymentInput()
		desired, err := resources.Build(input)
		Expect(err).NotTo(HaveOccurred())
		Expect(*desired.Service.Spec.TrafficDistribution).To(Equal("PreferSameNode"))
		Expect(*desired.Service.Spec.InternalTrafficPolicy).To(Equal(corev1.ServiceInternalTrafficPolicyCluster))

		input.Service.Spec.Listener = nil
		desired, err = resources.Build(input)
		Expect(err).NotTo(HaveOccurred())
		Expect(desired.Service.Spec.TrafficDistribution).To(BeNil())
		Expect(*desired.Service.Spec.InternalTrafficPolicy).To(Equal(corev1.ServiceInternalTrafficPolicyCluster))
	})

	It("keeps both runtime kinds on one listener with separate workload selectors", func() {
		deployment, err := resources.Build(deploymentInput())
		Expect(err).NotTo(HaveOccurred())
		daemon, err := resources.Build(daemonSetInput())
		Expect(err).NotTo(HaveOccurred())
		Expect(daemon.Service.Spec.Selector).To(Equal(deployment.Service.Spec.Selector))
		Expect(deployment.Deployment.Spec.Selector.MatchLabels).To(Equal(map[string]string{resources.LabelServiceUID: serviceUID, runtimeKindLabel: "Deployment"}))
		Expect(daemon.DaemonSet.Spec.Selector.MatchLabels).To(Equal(map[string]string{resources.LabelServiceUID: serviceUID, runtimeKindLabel: "DaemonSet"}))
		for key, value := range deployment.Deployment.Spec.Selector.MatchLabels {
			Expect(deployment.Deployment.Spec.Template.Labels).To(HaveKeyWithValue(key, value))
		}
		for key, value := range daemon.DaemonSet.Spec.Selector.MatchLabels {
			Expect(daemon.DaemonSet.Spec.Template.Labels).To(HaveKeyWithValue(key, value))
		}
		for key, value := range resources.ServiceEngineSelector(serviceName) {
			Expect(deployment.Deployment.Spec.Template.Labels).To(HaveKeyWithValue(key, value))
			Expect(daemon.DaemonSet.Spec.Template.Labels).To(HaveKeyWithValue(key, value))
		}
		for key, value := range deployment.Service.Spec.Selector {
			Expect(deployment.Deployment.Spec.Template.Labels).To(HaveKeyWithValue(key, value))
			Expect(daemon.DaemonSet.Spec.Template.Labels).To(HaveKeyWithValue(key, value))
		}
		Expect(deployment.Deployment.Spec.Strategy.RollingUpdate.MaxUnavailable.IntVal).To(BeZero())
		Expect(deployment.Deployment.Spec.Strategy.RollingUpdate.MaxSurge.IntVal).To(Equal(int32(1)))
		Expect(daemon.DaemonSet.Spec.UpdateStrategy.RollingUpdate.MaxUnavailable.IntVal).To(BeZero())
		Expect(daemon.DaemonSet.Spec.UpdateStrategy.RollingUpdate.MaxSurge.IntVal).To(Equal(int32(1)))
	})
	DescribeTable("rolls evaluator changes through the stable native workload",
		func(build func() resources.BuildInput) {
			input := build()
			previous, err := resources.Build(input)
			Expect(err).NotTo(HaveOccurred())
			input.Bootstrap.EvaluatorID = "next-evaluator"
			current, err := resources.Build(input)
			Expect(err).NotTo(HaveOccurred())
			Expect(current.StartupDigest).NotTo(Equal(previous.StartupDigest))
			Expect(current.Service).To(Equal(previous.Service))
			Expect(template(current).Annotations).To(HaveKeyWithValue(resources.AnnotationStartupDigest, current.StartupDigest))
			Expect(template(previous).Annotations).To(HaveKeyWithValue(resources.AnnotationStartupDigest, previous.StartupDigest))
			if current.DaemonSet != nil {
				Expect(current.DaemonSet.Name).To(Equal(previous.DaemonSet.Name))
				Expect(current.DaemonSet.Spec.Selector).To(Equal(previous.DaemonSet.Spec.Selector))
				Expect(current.DaemonSet.Spec.UpdateStrategy.RollingUpdate.MaxUnavailable.IntVal).To(BeZero())
			} else {
				Expect(current.Deployment.Name).To(Equal(previous.Deployment.Name))
				Expect(current.Deployment.Spec.Selector).To(Equal(previous.Deployment.Spec.Selector))
				Expect(current.Deployment.Spec.Strategy.RollingUpdate.MaxUnavailable.IntVal).To(BeZero())
			}
		},
		Entry("Deployment", deploymentInput), Entry("DaemonSet", daemonSetInput),
	)
	DescribeTable("builds the workload kind the runtime union selects",
		func(build func() resources.BuildInput, workloadType any) {
			desired, err := resources.Build(build())
			Expect(err).NotTo(HaveOccurred())
			Expect(desired.Objects()).To(ContainElement(BeAssignableToTypeOf(workloadType)))
			if desired.Deployment != nil {
				Expect(*desired.Deployment.Spec.Replicas).To(Equal(int32(3)))
				Expect(desired.DaemonSet).To(BeNil())
			} else {
				Expect(desired.DaemonSet).NotTo(BeNil())
			}
			pod := podSpec(desired)
			Expect(pod.HostNetwork).To(BeFalse())
			Expect(pod.TerminationGracePeriodSeconds).To(HaveValue(Equal(int64(30))))
			Expect(pod.Containers).To(HaveLen(1))
		},
		Entry("Deployment", deploymentInput, &appsv1ac.DeploymentApplyConfiguration{}),
		Entry("DaemonSet", daemonSetInput, &appsv1ac.DaemonSetApplyConfiguration{}),
	)

	DescribeTable("guards engine pods with a service-scoped disruption budget",
		func(build func() resources.BuildInput) {
			input := build()
			desired, err := resources.Build(input)
			Expect(err).NotTo(HaveOccurred())
			budget := desired.DisruptionBudget
			Expect(desired.Objects()).To(ContainElement(budget))
			Expect(*budget.Name).To(Equal("authz-" + serviceName))
			Expect(*budget.Namespace).To(Equal(input.Service.Namespace))
			Expect(*budget.Spec.MinAvailable).To(Equal(intstr.FromInt32(2)))
			Expect(*budget.Spec.UnhealthyPodEvictionPolicy).To(Equal(policyv1.AlwaysAllow))
			Expect(budget.Spec.Selector.MatchExpressions).To(BeEmpty())
			Expect(budget.Spec.Selector.MatchLabels).To(Equal(map[string]string{"authorization.zctx.io/service-uid": serviceUID}))
			var podLabels map[string]string
			if desired.Deployment != nil {
				podLabels = desired.Deployment.Spec.Template.Labels
			} else {
				podLabels = desired.DaemonSet.Spec.Template.Labels
			}
			for key, value := range budget.Spec.Selector.MatchLabels {
				Expect(podLabels).To(HaveKeyWithValue(key, value))
			}
		},
		Entry("Deployment", deploymentInput), Entry("DaemonSet", daemonSetInput),
	)

	It("runs stock OPA with the production arguments and independent health probes", func() {
		desired, err := resources.Build(deploymentInput())
		Expect(err).NotTo(HaveOccurred())
		container := podSpec(desired).Containers[0]
		Expect(container.Name).To(Equal(resources.ContainerName))
		Expect(container.Command).To(Equal([]string{resources.EnginePath}))
		Expect(container.Args).To(Equal(resources.PodLayout.Arguments()))
		Expect(container.Env).To(BeEmpty())
		Expect(container.Ports).To(ConsistOf(
			SatisfyAll(HaveField("Name", resources.HTTPSPortName), HaveField("ContainerPort", resources.EnginePort)),
			SatisfyAll(HaveField("Name", resources.DiagnosticPortName), HaveField("ContainerPort", resources.DiagnosticPort)),
		))
		Expect(container.ReadinessProbe.HTTPGet.Path).To(Equal("/health/ready"))
		Expect(container.ReadinessProbe.HTTPGet.Port.StrVal).To(Equal(resources.DiagnosticPortName))
		Expect(container.ReadinessProbe.HTTPGet.Scheme).To(Equal(corev1.URISchemeHTTP))
		Expect(container.ReadinessProbe.PeriodSeconds).To(Equal(int32(2)))
		Expect(container.ReadinessProbe.TimeoutSeconds).To(Equal(int32(1)))
		Expect(container.ReadinessProbe.FailureThreshold).To(Equal(int32(1)))
		Expect(container.ReadinessProbe.SuccessThreshold).To(Equal(int32(1)))
		Expect(container.LivenessProbe.HTTPGet.Path).To(Equal("/health/live"))
		Expect(container.LivenessProbe).NotTo(Equal(container.ReadinessProbe))
		Expect(container.StartupProbe.HTTPGet.Path).To(Equal("/health/live"))
		Expect(container.StartupProbe.HTTPGet.Port.StrVal).To(Equal(resources.DiagnosticPortName))
		Expect(container.StartupProbe.PeriodSeconds * container.StartupProbe.FailureThreshold).To(BeNumerically(">=",
			container.LivenessProbe.PeriodSeconds*container.LivenessProbe.FailureThreshold))
	})

	It("renders the engine ConfigMap and digests it into the pod template", func() {
		input := deploymentInput()
		desired, err := resources.Build(input)
		Expect(err).NotTo(HaveOccurred())
		config := desired.ConfigMap
		Expect(desired.Objects()[0]).To(BeIdenticalTo(config))
		Expect(*config.Name).To(Equal("authz-" + serviceName + "-engine"))
		Expect(*config.Namespace).To(Equal(input.Service.Namespace))
		bootstrap, err := json.Marshal(input.Bootstrap)
		Expect(err).NotTo(HaveOccurred())
		configuration, err := engine.Configuration(false)
		Expect(err).NotTo(HaveOccurred())
		modules := engine.Modules()
		Expect(config.Data).To(HaveKeyWithValue(resources.BootstrapKey, string(bootstrap)))
		Expect(config.Data).To(HaveKeyWithValue(resources.CABundleKey, string(input.CABundle)))
		Expect(config.Data).To(HaveKeyWithValue(resources.ConfigKey, string(configuration)))
		for name, module := range modules {
			Expect(config.Data).To(HaveKeyWithValue(name, module))
		}
		Expect(config.Data).To(HaveLen(len(modules) + 3))
		startup := maps.Clone(config.Data)
		delete(startup, resources.CABundleKey)
		digest := model.Digest(startup)
		Expect(desired.StartupDigest).To(Equal(digest))
		Expect(template(desired).Annotations).To(HaveKeyWithValue(resources.AnnotationStartupDigest, digest))
	})

	It("changes the CA bundle without rolling the engines, which reload it", func() {
		input := deploymentInput()
		first, err := resources.Build(input)
		Expect(err).NotTo(HaveOccurred())
		input.CABundle = []byte("management root\nrotated client CA\n")
		second, err := resources.Build(input)
		Expect(err).NotTo(HaveOccurred())
		Expect(second.ConfigMap.Data).To(HaveKeyWithValue(resources.CABundleKey, string(input.CABundle)))
		Expect(second.StartupDigest).To(Equal(first.StartupDigest))
		Expect(second.Deployment).To(Equal(first.Deployment))
	})

	It("leaves out the engine ConfigMap and the workload without a CA bundle", func() {
		input := deploymentInput()
		complete, err := resources.Build(input)
		Expect(err).NotTo(HaveOccurred())
		input.CABundle = nil
		desired, err := resources.Build(input)
		Expect(err).NotTo(HaveOccurred())
		Expect(desired.ConfigMap).To(BeNil())
		Expect(desired.Deployment).To(BeNil())
		Expect(desired.Objects()).To(Equal([]runtime.ApplyConfiguration{desired.Service, desired.DisruptionBudget}))
		Expect(desired.StartupDigest).To(Equal(complete.StartupDigest))
	})

	It("mounts the engine ConfigMap in the workload layout and the serving Secret, with no API token", func() {
		input := deploymentInput()
		desired, err := resources.Build(input)
		Expect(err).NotTo(HaveOccurred())
		pod := podSpec(desired)
		Expect(*pod.AutomountServiceAccountToken).To(BeFalse())
		Expect(pod.ServiceAccountName).To(BeEmpty())
		Expect(pod.Containers[0].VolumeMounts).To(ConsistOf(mountMatcher("engine", resources.EngineDirectory), mountMatcher("tls", resources.TLSDirectory)))
		config := volume(pod.Volumes, "engine").ConfigMap
		Expect(config.Name).To(Equal(*desired.ConfigMap.Name))
		Expect(config.Items).To(HaveLen(len(desired.ConfigMap.Data)))
		for _, item := range config.Items {
			Expect(desired.ConfigMap.Data).To(HaveKey(item.Key))
			Expect(item.Path).To(Equal(resources.ItemPath(item.Key)))
		}
		serving := volume(pod.Volumes, "tls").Secret
		Expect(serving.SecretName).To(Equal("fleet-authz-server-tls"))
		Expect(serving.Items).To(ConsistOf(
			corev1.KeyToPath{Key: corev1.TLSCertKey, Path: corev1.TLSCertKey},
			corev1.KeyToPath{Key: corev1.TLSPrivateKeyKey, Path: corev1.TLSPrivateKeyKey},
		))
		Expect(desired.Objects()).To(HaveLen(4))
	})
	It("applies restrictive security settings and leaves placement and resources to the service", func() {
		input := deploymentInput()
		desired, err := resources.Build(input)
		Expect(err).NotTo(HaveOccurred())
		pod := podSpec(desired)
		container := pod.Containers[0]
		Expect(container.Image).To(Equal(input.EngineImage))
		Expect(pod.NodeSelector).To(BeEmpty())
		Expect(pod.Tolerations).To(BeEmpty())
		Expect(pod.Affinity).To(BeNil())
		Expect(pod.ImagePullSecrets).To(BeEmpty())
		Expect(container.Resources).To(BeZero())
		Expect(*pod.SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(pod.SecurityContext.RunAsUser).To(BeNil())
		Expect(pod.SecurityContext.FSGroup).To(HaveValue(BeNumerically(">", 0)))
		Expect(*container.SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*container.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*container.SecurityContext.Privileged).To(BeFalse())
		Expect(*container.SecurityContext.ReadOnlyRootFilesystem).To(BeTrue())
		Expect(container.SecurityContext.Capabilities.Drop).To(Equal([]corev1.Capability{"ALL"}))
		Expect(container.SecurityContext.SeccompProfile.Type).To(Equal(corev1.SeccompProfileTypeRuntimeDefault))
	})

	It("keeps every derived name valid for its kind at the maximum service name length", func() {
		input := deploymentInput()
		input.Service.Name = strings.Repeat("a", 57)
		desired, err := resources.Build(input)
		Expect(err).NotTo(HaveOccurred())
		for _, configuration := range desired.Objects() {
			payload, err := runtime.DefaultUnstructuredConverter.ToUnstructured(configuration)
			Expect(err).NotTo(HaveOccurred())
			object := &unstructured.Unstructured{Object: payload}
			if object.GetKind() == "ConfigMap" {
				Expect(utilvalidation.IsDNS1123Subdomain(object.GetName())).To(BeEmpty())
				continue
			}
			Expect(utilvalidation.IsDNS1123Label(object.GetName())).To(BeEmpty())
		}
	})

	It("uses stable workload identity with changed startup templates", func() {
		input := deploymentInput()
		first, err := resources.Build(input)
		Expect(err).NotTo(HaveOccurred())
		input.Bootstrap.Management.Roots = append(input.Bootstrap.Management.Roots, "rotated management root")
		second, err := resources.Build(input)
		Expect(err).NotTo(HaveOccurred())
		Expect(second.Deployment.Name).To(Equal(first.Deployment.Name))
		Expect(second.Deployment.Spec.Selector).To(Equal(first.Deployment.Spec.Selector))
		Expect(second.Deployment.Spec.Template).NotTo(Equal(first.Deployment.Spec.Template))
	})
	It("changes the serving Secret through the native pod template", func() {
		input := deploymentInput()
		first, err := resources.Build(input)
		Expect(err).NotTo(HaveOccurred())
		input.Service.Spec.TLS.Server.SecretRef.Name = "fleet-authz-server-tls-rotated"
		second, err := resources.Build(input)
		Expect(err).NotTo(HaveOccurred())

		Expect(second.Deployment.Name).To(Equal(first.Deployment.Name))
		Expect(volume(podSpec(first).Volumes, "tls").Secret.SecretName).To(Equal("fleet-authz-server-tls"))
		Expect(volume(podSpec(second).Volumes, "tls").Secret.SecretName).To(Equal("fleet-authz-server-tls-rotated"))
		Expect(second.StartupDigest).To(Equal(first.StartupDigest))
	})

	It("sets native owner references on every desired object", func() {
		desired, err := resources.Build(deploymentInput())
		Expect(err).NotTo(HaveOccurred())
		for _, configuration := range desired.Objects() {
			payload, err := runtime.DefaultUnstructuredConverter.ToUnstructured(configuration)
			Expect(err).NotTo(HaveOccurred())
			object := &unstructured.Unstructured{Object: payload}
			Expect(object.GetOwnerReferences()).To(ContainElement(And(
				HaveField("Kind", "AuthorizationService"),
				HaveField("UID", types.UID(serviceUID)),
			)))
		}
	})
})

var _ = Describe("Native workload templates", func() {
	DescribeTable("customizes each generated resource while retaining runtime wiring",
		func(build func() resources.BuildInput) {
			input := build()
			input.Service.Spec.Runtime.Metadata = &api.ResourceMetadata{Labels: map[string]string{"team": "platform"}, Annotations: map[string]string{"example.test/workload": "custom"}}
			input.Service.Spec.Runtime.PodTemplate = podOverride(`{
				"metadata":{"labels":{"team":"platform"},"annotations":{"example.test/pod":"custom"}},
				"spec":{
					"priorityClassName":"authorization",
					"nodeSelector":{"pool":"dedicated"},
					"tolerations":[{"key":"dedicated","operator":"Exists","effect":"NoSchedule"}],
					"imagePullSecrets":[{"name":"private"}],
					"containers":[{"name":"opa","image":"example/engine@sha256:` + strings.Repeat("b", 64) + `",
						"imagePullPolicy":"Always","resources":{"requests":{"memory":"384Mi"}},
						"env":[{"name":"EXTRA","value":"value"}],
						"volumeMounts":[{"name":"extra","mountPath":"/etc/extra","readOnly":true}]},
						{"name":"helper","image":"example/helper:1"}],
					"initContainers":[{"name":"prepare","image":"example/prepare:1"}],
					"volumes":[{"name":"extra","configMap":{"name":"additional-config"}}]
				}}`)
			input.Service.Spec.Listener = serviceOverride(`{"metadata":{"labels":{"team":"platform"},"annotations":{"example.test/service":"custom"}},"spec":{"type":"LoadBalancer","allocateLoadBalancerNodePorts":false,"externalTrafficPolicy":"Local","loadBalancerClass":"example.test/lb","ports":[{"name":"https","port":8443}]}}`)

			desired, err := resources.Build(input)
			Expect(err).NotTo(HaveOccurred())
			pod := podSpec(desired)
			index := slices.IndexFunc(pod.Containers, func(container corev1.Container) bool { return container.Name == "opa" })
			Expect(index).To(BeNumerically(">=", 0))
			container := pod.Containers[index]
			Expect(container.Image).To(Equal("example/engine@sha256:" + strings.Repeat("b", 64)))
			Expect(container.ImagePullPolicy).To(Equal(corev1.PullAlways))
			Expect(container.Command).To(Equal([]string{resources.EnginePath}))
			Expect(container.Args).To(Equal(resources.PodLayout.Arguments()))
			Expect(container.Resources.Requests).To(Equal(corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("384Mi")}))
			Expect(container.Env).To(ConsistOf(corev1.EnvVar{Name: "EXTRA", Value: "value"}))
			Expect(container.VolumeMounts).To(ContainElement(mountMatcher("engine", resources.EngineDirectory)))
			Expect(container.VolumeMounts).To(ContainElement(mountMatcher("extra", "/etc/extra")))
			Expect(volume(pod.Volumes, "extra").ConfigMap.Name).To(Equal("additional-config"))
			Expect(volume(pod.Volumes, "tls").Secret.SecretName).To(Equal(input.Service.Spec.TLS.Server.SecretRef.Name))
			Expect(pod.Containers).To(HaveLen(2))
			Expect(pod.InitContainers).To(ConsistOf(HaveField("Name", "prepare")))
			Expect(pod.NodeSelector).To(Equal(map[string]string{nodePoolKey: "dedicated"}))
			Expect(pod.ImagePullSecrets).To(ConsistOf(corev1.LocalObjectReference{Name: "private"}))
			Expect(pod.PriorityClassName).To(Equal("authorization"))
			Expect(desired.Service.Spec.Type).To(HaveValue(Equal(corev1.ServiceTypeLoadBalancer)))
			Expect(desired.Service.Spec.AllocateLoadBalancerNodePorts).To(HaveValue(BeFalse()))
			Expect(desired.Service.Spec.LoadBalancerClass).To(HaveValue(Equal("example.test/lb")))
			Expect(desired.Service.Spec.Ports).To(HaveLen(1))
			Expect(desired.Service.Spec.Ports[0].Port).To(HaveValue(Equal(int32(8443))))
			Expect(desired.Service.Spec.Ports[0].TargetPort).To(HaveValue(Equal(intstr.FromInt32(8181))))
			Expect(desired.Service.Spec.Selector).To(Equal(resources.ServiceUIDSelector(serviceUID)))
			Expect(desired.Service.Annotations).To(HaveKeyWithValue("example.test/service", "custom"))
			var object runtime.ApplyConfiguration = desired.Deployment
			if desired.DaemonSet != nil {
				object = desired.DaemonSet
			}
			encoded, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
			Expect(err).NotTo(HaveOccurred())
			Expect(encoded).To(HaveKeyWithValue("metadata", And(
				HaveKeyWithValue("labels", HaveKeyWithValue("team", "platform")),
				HaveKeyWithValue("annotations", HaveKeyWithValue("example.test/workload", "custom")),
			)))
			Expect(encoded).To(HaveKeyWithValue("spec", HaveKeyWithValue("template", HaveKeyWithValue("metadata", And(
				HaveKeyWithValue("annotations", HaveKeyWithValue("example.test/pod", "custom")),
				HaveKeyWithValue("labels", HaveKeyWithValue("authorization.zctx.io/service-uid", serviceUID)),
			)))))
		}, Entry("Deployment", deploymentInput), Entry("DaemonSet", daemonSetInput),
	)

	It("replaces an overridden list that has no merge key", func() {
		input := deploymentInput()
		input.Service.Spec.Runtime.PodTemplate = podOverride(`{"spec":{"tolerations":[{"key":"dedicated","operator":"Exists","effect":"NoSchedule"}]}}`)
		desired, err := resources.Build(input)
		Expect(err).NotTo(HaveOccurred())
		Expect(podSpec(desired).Tolerations).To(ConsistOf(HaveField("Key", "dedicated")))
	})

	It("preserves explicit false and zero overrides", func() {
		input := deploymentInput()
		input.Service.Spec.Runtime.PodTemplate = podOverride(`{"spec":{"affinity":{},"terminationGracePeriodSeconds":0,"containers":[{"name":"opa","securityContext":{"readOnlyRootFilesystem":false},"readinessProbe":{"periodSeconds":5}}]}}`)
		desired, err := resources.Build(input)
		Expect(err).NotTo(HaveOccurred())
		pod := podSpec(desired)
		Expect(pod.Affinity).To(Equal(&corev1.Affinity{}))
		Expect(pod.TerminationGracePeriodSeconds).To(HaveValue(BeZero()))
		Expect(pod.Containers[0].SecurityContext.ReadOnlyRootFilesystem).To(HaveValue(BeFalse()))
		Expect(pod.Containers[0].ReadinessProbe.HTTPGet.Path).To(Equal("/health/ready"))
	})
})

var _ = Describe("Native Service templates", func() {
	It("keeps generated defaults for a metadata-only Service template", func() {
		input := deploymentInput()
		input.Service.Spec.Listener = serviceOverride(`{"metadata":{"annotations":{"example.test/owner":"platform"}}}`)
		desired, err := resources.Build(input)
		Expect(err).NotTo(HaveOccurred())
		Expect(desired.Service.Spec.Type).To(HaveValue(Equal(corev1.ServiceTypeClusterIP)))
		Expect(desired.Service.Spec.Ports[0].Port).To(HaveValue(Equal(int32(443))))
	})

	It("adds a port under a new name alongside the engine's", func() {
		input := deploymentInput()
		input.Service.Spec.Listener = serviceOverride(`{"spec":{"ports":[{"name":"metrics","port":9090}]}}`)
		desired, err := resources.Build(input)
		Expect(err).NotTo(HaveOccurred())
		Expect(desired.Service.Spec.Ports).To(ConsistOf(
			SatisfyAll(HaveField("Name", HaveValue(Equal(resources.HTTPSPortName))), HaveField("Port", HaveValue(Equal(resources.DefaultServicePort)))),
			SatisfyAll(HaveField("Name", HaveValue(Equal("metrics"))), HaveField("Port", HaveValue(Equal(int32(9090))))),
		))
	})

})

func deploymentInput() resources.BuildInput {
	return resources.BuildInput{
		Service: &api.AuthorizationService{
			ObjectMeta: metav1.ObjectMeta{Namespace: "authorization-system", Name: serviceName, UID: serviceUID},
			Spec: api.AuthorizationServiceSpec{
				Runtime:  api.AuthorizationServiceRuntime{Type: api.RuntimeTypeDeployment, Deployment: &api.DeploymentRuntime{Replicas: 3}, MinReadyReplicas: 2},
				Listener: serviceOverride(`{"spec":{"trafficDistribution":"PreferSameNode"}}`),
				TLS: api.AuthorizationServiceTLS{
					Server: api.ServerTLS{
						SecretRef: api.SecretReference{Name: "fleet-authz-server-tls"},
						CARef:     api.CABundleRef{SecretKeyRef: &api.SecretKeyRef{Name: "fleet-authz-serving-ca", Key: "ca.crt"}},
					},
					Client: api.ClientTLS{CARef: api.CABundleRef{SecretKeyRef: &api.SecretKeyRef{Name: "fleet-authz-client-ca", Key: "ca.crt"}}},
				},
			},
		},
		EngineImage: "registry.example.test/opa@sha256:" + strings.Repeat("a", 64),
		Bootstrap:   engine.Bootstrap{ServiceUID: serviceUID, EvaluatorID: "evaluator", Management: engine.Management{Roots: []string{"management root"}, Identity: "operator"}},
		CABundle:    []byte("management root\napiserver CA\n"),
	}
}

func daemonSetInput() resources.BuildInput {
	input := deploymentInput()
	input.Service.Spec.Runtime.Type = api.RuntimeTypeDaemonSet
	return input
}

func template(desired resources.Owned) *corev1ac.PodTemplateSpecApplyConfiguration {
	if desired.Deployment != nil {
		return desired.Deployment.Spec.Template
	}
	return desired.DaemonSet.Spec.Template
}

func podSpec(desired resources.Owned) corev1.PodSpec {
	GinkgoHelper()
	encoded, err := json.Marshal(template(desired).Spec)
	Expect(err).NotTo(HaveOccurred())
	var spec corev1.PodSpec
	Expect(json.Unmarshal(encoded, &spec)).To(Succeed())
	return spec
}

func volume(volumes []corev1.Volume, name string) corev1.VolumeSource {
	index := slices.IndexFunc(volumes, func(item corev1.Volume) bool { return item.Name == name })
	Expect(index).To(BeNumerically(">=", 0))
	return volumes[index].VolumeSource
}

func mountMatcher(name, path string) gomegatypes.GomegaMatcher {
	return MatchFields(IgnoreExtras, Fields{"Name": Equal(name), "MountPath": Equal(path), "SubPath": BeEmpty()})
}
