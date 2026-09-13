//go:build integration

package integration

import (
	"context"
	"crypto/x509"
	"os"
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/resources"
	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("AuthorizationService reconciliation", func() {
	var service *api.AuthorizationService
	BeforeEach(func(ctx SpecContext) {
		service = createService(ctx, newNamespace(ctx, "authorization-controller"), nil)
	})

	It("applies the listener at once, and the engine ConfigMap and workload once the client CA exists", func(ctx SpecContext) {
		expectCAReadFailed(ctx, service)
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, workloadKey(service), &corev1.Service{})).To(Succeed())
			g.Expect(k8sClient.Get(ctx, workloadKey(service), &policyv1.PodDisruptionBudget{})).To(Succeed())
		}).WithTimeout(convergence).Should(Succeed())
		Expect(apierrors.IsNotFound(k8sClient.Get(ctx, workloadKey(service), &appsv1.Deployment{}))).To(BeTrue())
		Expect(apierrors.IsNotFound(k8sClient.Get(ctx, engineConfigKey(service), &corev1.ConfigMap{}))).To(BeTrue())

		installTLS(ctx, service)
		var config corev1.ConfigMap
		Eventually(func() error {
			return k8sClient.Get(ctx, engineConfigKey(service), &config)
		}).WithTimeout(convergence).Should(Succeed())
		template := deployment(ctx, service).Spec.Template
		Expect(template.Annotations).To(HaveKeyWithValue(resources.AnnotationStartupDigest, Not(BeEmpty())))
		var listener corev1.Service
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: service.Namespace, Name: resources.Name(service.Name)}, &listener)).To(Succeed())
		Expect(listener.Spec.Selector).To(Equal(resources.ServiceUIDSelector(service.UID)))
		Expect(deployment(ctx, service).Spec.Selector.MatchLabels).To(Equal(map[string]string{resources.LabelServiceUID: string(service.UID), runtimeKindLabel: "Deployment"}))
		Eventually(func(g Gomega) {
			condition := apimeta.FindStatusCondition(serviceStatus(ctx, g, service).Conditions, api.ConditionReady)
			g.Expect(condition).To(HaveField("Status", metav1.ConditionFalse))
		}).WithTimeout(convergence).Should(Succeed())
	})

	It("updates the engine ConfigMap in place, without rolling the pod template, when the client CA changes", func(ctx SpecContext) {
		installTLS(ctx, service)
		before := deployment(ctx, service).Spec.Template
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: service.Namespace, Name: utils.ClientCASecret}, &secret)).To(Succeed())
		rotated := authority().CertificatePEM
		secret.Data[utils.CAKey] = rotated
		Expect(k8sClient.Update(ctx, &secret)).To(Succeed())
		Eventually(func(g Gomega) string {
			var config corev1.ConfigMap
			g.Expect(k8sClient.Get(ctx, engineConfigKey(service), &config)).To(Succeed())
			return config.Data[resources.CABundleKey]
		}).WithTimeout(convergence).Should(HaveSuffix(string(rotated)))
		var current appsv1.Deployment
		Expect(k8sClient.Get(ctx, workloadKey(service), &current)).To(Succeed())
		Expect(current.Spec.Template).To(Equal(before))
	})

	It("rolls the pod template when the management CA changes", Serial, func(ctx SpecContext) {
		installTLS(ctx, service)
		before := deployment(ctx, service).Spec.Template
		roots, err := os.ReadFile(managementCAPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(managementCAPath, slices.Concat(roots, authority().CertificatePEM), 0o600)).To(Succeed())
		DeferCleanup(func() { Expect(os.WriteFile(managementCAPath, roots, 0o600)).To(Succeed()) })
		Eventually(func(g Gomega) corev1.PodTemplateSpec {
			var current appsv1.Deployment
			g.Expect(k8sClient.Get(ctx, workloadKey(service), &current)).To(Succeed())
			return current.Spec.Template
		}).WithTimeout(convergence).ShouldNot(Equal(before))
	})

	It("leaves the pod template unchanged when the serving certificate is renewed", func(ctx SpecContext) {
		installTLS(ctx, service)
		before := deployment(ctx, service).Spec.Template
		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: service.Namespace, Name: utils.ServerTLSSecret}, &secret)).To(Succeed())
		renewed, err := authority().Issue("server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, resources.ServerName(service.Namespace, service.Name))
		Expect(err).NotTo(HaveOccurred())
		secret.Data = map[string][]byte{corev1.TLSCertKey: renewed.CertificatePEM, corev1.TLSPrivateKeyKey: renewed.KeyPEM}
		Expect(k8sClient.Update(ctx, &secret)).To(Succeed())
		Consistently(func(g Gomega) corev1.PodTemplateSpec {
			var current appsv1.Deployment
			g.Expect(k8sClient.Get(ctx, workloadKey(service), &current)).To(Succeed())
			return current.Spec.Template
		}).WithTimeout(2 * time.Second).Should(Equal(before))
	})

	It("recreates a deleted Deployment", func(ctx SpecContext) {
		installTLS(ctx, service)
		deleted := deployment(ctx, service)
		Expect(k8sClient.Delete(ctx, deleted)).To(Succeed())
		Eventually(func(g Gomega) types.UID {
			var current appsv1.Deployment
			g.Expect(k8sClient.Get(ctx, workloadKey(service), &current)).To(Succeed())
			return current.UID
		}).WithTimeout(convergence).ShouldNot(Equal(deleted.UID))
	})

	It("keeps the native workload unchanged when a client CA becomes unavailable", func(ctx SpecContext) {
		installTLS(ctx, service)
		before := deployment(ctx, service)
		Expect(k8sClient.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: service.Namespace, Name: utils.ClientCASecret}})).To(Succeed())
		expectCAReadFailed(ctx, service)
		var after appsv1.Deployment
		Expect(k8sClient.Get(ctx, workloadKey(service), &after)).To(Succeed())
		Expect(after.Spec).To(Equal(before.Spec))
	})

	It("applies per-service overrides and removes them when they're omitted", func(ctx SpecContext) {
		installTLS(ctx, service)
		deployment(ctx, service)
		updateService(ctx, service, func(service *api.AuthorizationService) {
			service.Spec.Runtime.Metadata = &api.ResourceMetadata{Labels: map[string]string{"team": "infrastructure"}}
			service.Spec.Runtime.PodTemplate = &api.PodTemplateOverride{
				Metadata: &api.ResourceMetadata{Annotations: map[string]string{"example.test/pod": "custom"}},
				Spec:     &api.PodSpecOverride{NodeSelector: map[string]string{"pool": "authorization"}},
			}
			service.Spec.Listener = &api.ServiceTemplateOverride{Spec: &api.ServiceSpecOverride{Type: corev1.ServiceTypeNodePort, Ports: []api.ServicePortOverride{{Name: "https", Port: 8443}}}}
		})
		Eventually(func(g Gomega) {
			var current appsv1.Deployment
			g.Expect(k8sClient.Get(ctx, workloadKey(service), &current)).To(Succeed())
			g.Expect(current.Labels).To(HaveKeyWithValue("team", "infrastructure"))
			g.Expect(current.Spec.Template.Annotations).To(HaveKeyWithValue("example.test/pod", "custom"))
			g.Expect(current.Spec.Template.Spec.NodeSelector).To(Equal(map[string]string{"pool": "authorization"}))
			g.Expect(current.Spec.Template.Spec.Containers[0].Image).To(Equal(engineImage))
			var listener corev1.Service
			g.Expect(k8sClient.Get(ctx, workloadKey(service), &listener)).To(Succeed())
			g.Expect(listener.Spec.Type).To(Equal(corev1.ServiceTypeNodePort))
			g.Expect(listener.Spec.Ports).To(ConsistOf(SatisfyAll(HaveField("Name", "https"), HaveField("Port", int32(8443)), HaveField("TargetPort.IntVal", resources.EnginePort))))
		}).WithTimeout(convergence).Should(Succeed())

		updateService(ctx, service, func(service *api.AuthorizationService) {
			service.Spec.Runtime.Metadata = nil
			service.Spec.Runtime.PodTemplate = nil
			service.Spec.Listener = nil
		})
		Eventually(func(g Gomega) {
			var current appsv1.Deployment
			g.Expect(k8sClient.Get(ctx, workloadKey(service), &current)).To(Succeed())
			g.Expect(current.Labels).NotTo(HaveKey("team"))
			g.Expect(current.Spec.Template.Annotations).NotTo(HaveKey("example.test/pod"))
			g.Expect(current.Spec.Template.Spec.NodeSelector).To(BeEmpty())
			var listener corev1.Service
			g.Expect(k8sClient.Get(ctx, workloadKey(service), &listener)).To(Succeed())
			g.Expect(listener.Spec.Type).To(Equal(corev1.ServiceTypeClusterIP))
			g.Expect(listener.Spec.Ports).To(ConsistOf(SatisfyAll(HaveField("Port", resources.DefaultServicePort), HaveField("NodePort", BeZero()))))
		}).WithTimeout(convergence).Should(Succeed())
	})

	It("repairs drift in the fields it applies and keeps fields another manager owns", func(ctx SpecContext) {
		installTLS(ctx, service)
		observed := deployment(ctx, service)
		before := observed.DeepCopy()
		observed.Spec.Template.Annotations = map[string]string{"external.example.test/injected": "true"}
		observed.Spec.Template.Spec.HostNetwork = true
		observed.Spec.Template.Spec.Containers[0].Image = "example/modified:latest"
		Expect(k8sClient.Patch(ctx, observed, client.MergeFrom(before), client.FieldOwner("external-controller"))).To(Succeed())
		Eventually(func(g Gomega) {
			var current appsv1.Deployment
			g.Expect(k8sClient.Get(ctx, workloadKey(service), &current)).To(Succeed())
			g.Expect(current.Spec.Template.Spec.HostNetwork).To(BeFalse())
			g.Expect(current.Spec.Template.Spec.Containers[0].Image).To(Equal(engineImage))
			g.Expect(current.Spec.Template.Annotations).To(HaveKeyWithValue("external.example.test/injected", "true"))
		}).WithTimeout(convergence).Should(Succeed())
	})

	It("reports ready capacity and the pushed revision without periodic status writes", func(ctx SpecContext) {
		installTLS(ctx, service)
		pod := createEnginePod(ctx, service.Namespace, "ready-engine", podAddress(3), deployment(ctx, service).Spec.Template, true)
		Eventually(func(g Gomega) {
			status := serviceStatus(ctx, g, service)
			g.Expect(status.CurrentReplicas).To(Equal(int32(1)))
			g.Expect(status.DesiredReplicas).To(HaveValue(Equal(int32(2))))
			g.Expect(status.DesiredRevision).To(Equal(string(pushed(g, pod).Revision)))
			g.Expect(apimeta.FindStatusCondition(status.Conditions, api.ConditionReady)).To(HaveField("Status", metav1.ConditionTrue))
		}).WithTimeout(convergence).Should(Succeed())
		var current api.AuthorizationService
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(service), &current)).To(Succeed())
		Consistently(func(g Gomega) string {
			var latest api.AuthorizationService
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(service), &latest)).To(Succeed())
			return latest.ResourceVersion
		}).WithTimeout(2 * time.Second).Should(Equal(current.ResourceVersion))
	})

	It("changes the desired revision when a referenced document changes", func(ctx SpecContext) {
		namespace := newNamespace(ctx, "document-edit")
		source := &api.PolicySource{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: utils.SourceName},
			Spec: api.PolicySourceSpec{
				Provider:   api.PolicySourceProvider{Type: "Kubernetes"},
				Collection: []api.KeyRange{{Kinds: []string{model.KindPolicy, model.KindPolicyBinding}, Namespaces: []string{namespace}, Names: []string{"*"}}},
			},
		}
		Expect(createAndRemove(ctx, source)).To(Succeed())
		Expect(k8sClient.Create(ctx, &api.PolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "entry"},
			Spec:       api.PolicyBindingSpec{SubjectMatch: &api.SubjectMatch{}, PolicyRef: api.PolicyRef{Name: "allow"}},
		})).To(Succeed())
		policy := &api.Policy{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "allow"},
			Spec:       api.PolicySpec{Include: []api.OperationRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}, Namespaces: []string{"*"}}}},
		}
		Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		reading := createService(ctx, namespace, func(service *api.AuthorizationService) {
			service.Spec.Endpoints[0].Authorities = []api.Authority{{
				BindingRef:         api.BindingRef{Name: "entry", Namespace: namespace, SourceRef: &api.SourceRef{Namespace: namespace, Name: utils.SourceName}},
				WhenNoPolicyAllows: "Deny",
			}}
		})
		installTLS(ctx, reading)
		desired := func(g Gomega) string {
			status := serviceStatus(ctx, g, reading)
			g.Expect(status.DesiredRevision).NotTo(BeEmpty())
			g.Expect(status.Issues).NotTo(ContainElement(HaveField("Reason", "MissingReference")))
			return status.DesiredRevision
		}
		var before string
		Eventually(func(g Gomega) { before = desired(g) }).WithTimeout(convergence).Should(Succeed())

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(policy), policy)).To(Succeed())
		policy.Spec.Include[0].Verbs = []string{"get", "list"}
		Expect(k8sClient.Update(ctx, policy)).To(Succeed())
		Eventually(desired).WithTimeout(convergence).ShouldNot(Equal(before))
	})

	It("applies a DaemonSet that selects its pods by service UID and runtime kind", func(ctx SpecContext) {
		daemon := createService(ctx, newNamespace(ctx, "daemonset-runtime"), func(service *api.AuthorizationService) {
			service.Spec.Runtime.Type = api.RuntimeTypeDaemonSet
		})
		installTLS(ctx, daemon)
		var current appsv1.DaemonSet
		Eventually(func() error { return k8sClient.Get(ctx, workloadKey(daemon), &current) }).WithTimeout(convergence).Should(Succeed())
		selector := map[string]string{resources.LabelServiceUID: string(daemon.UID), runtimeKindLabel: "DaemonSet"}
		Expect(current.Spec.Selector.MatchLabels).To(Equal(selector))
		for key, value := range selector {
			Expect(current.Spec.Template.Labels).To(HaveKeyWithValue(key, value))
		}
		Expect(current.Spec.Template.Annotations).To(HaveKeyWithValue(resources.AnnotationStartupDigest, Not(BeEmpty())))
		Expect(current.Spec.Template.Spec.AutomountServiceAccountToken).To(HaveValue(BeFalse()))
		Expect(metav1.IsControlledBy(&current, daemon)).To(BeTrue())
		Expect(apierrors.IsNotFound(k8sClient.Get(ctx, workloadKey(daemon), &appsv1.Deployment{}))).To(BeTrue())
	})

	It("adopts an orphaned listener Service with the same name", func(ctx SpecContext) {
		namespace := newNamespace(ctx, "orphan-listener")
		orphan := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: resources.Name("authz"), Labels: map[string]string{"example.test/orphan": "true"}},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "https", Port: 443}}},
		}
		Expect(k8sClient.Create(ctx, orphan)).To(Succeed())
		adopter := createService(ctx, namespace, nil)
		installTLS(ctx, adopter)
		Eventually(func(g Gomega) {
			var current corev1.Service
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(orphan), &current)).To(Succeed())
			g.Expect(current.UID).To(Equal(orphan.UID))
			g.Expect(metav1.IsControlledBy(&current, adopter)).To(BeTrue())
			g.Expect(current.Spec.Selector).To(Equal(resources.ServiceUIDSelector(adopter.UID)))
			g.Expect(current.Labels).To(HaveKeyWithValue("example.test/orphan", "true"))
		}).WithTimeout(convergence).Should(Succeed())
		deployment(ctx, adopter)
	})

	It("reports a listener Service another controller owns without taking it over, and applies the rest", func(ctx SpecContext) {
		namespace := newNamespace(ctx, "foreign-listener")
		owner := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "owner"}}
		Expect(k8sClient.Create(ctx, owner)).To(Succeed())
		foreign := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: resources.Name("authz"),
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: owner.Name, UID: owner.UID, Controller: new(true)}}},
			Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "https", Port: 443}}},
		}
		Expect(k8sClient.Create(ctx, foreign)).To(Succeed())
		claimant := createService(ctx, namespace, nil)
		installTLS(ctx, claimant)
		Eventually(func(g Gomega) []eventsv1.Event {
			return events(ctx, g, namespace)
		}).WithTimeout(convergence).Should(ContainElement(And(HaveField("Reason", "ApplyFailed"), HaveField("Regarding.UID", claimant.UID))))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(foreign), foreign)).To(Succeed())
		Expect(foreign.OwnerReferences).To(ConsistOf(HaveField("UID", owner.UID)))
		Expect(metav1.IsControlledBy(deployment(ctx, claimant), claimant)).To(BeTrue())
	})
})

// expectCAReadFailed waits for the Event reporting that service's client
// CA can't be read.
func expectCAReadFailed(ctx context.Context, service *api.AuthorizationService) {
	GinkgoHelper()
	Eventually(func(g Gomega) []eventsv1.Event {
		return events(ctx, g, service.Namespace)
	}).WithTimeout(convergence).Should(ContainElement(And(
		HaveField("Reason", "CAReadFailed"),
		HaveField("Regarding.UID", service.UID),
		HaveField("Note", ContainSubstring("client CA")),
	)))
}
