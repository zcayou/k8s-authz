package controller

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/resources"
	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("Owned objects", func() {
	var reconciler *AuthorizationServiceReconciler
	var recorder *events.FakeRecorder
	var control client.WithWatch
	var object *api.AuthorizationService
	var managementRoot, clientCA, servingCA utils.Material
	BeforeEach(func() {
		now := time.Now()
		var err error
		for _, authority := range []*utils.Material{&managementRoot, &clientCA, &servingCA} {
			*authority, err = utils.NewAuthority(now)
			Expect(err).NotTo(HaveOccurred())
		}
		object = utils.AuthorizationService(types.NamespacedName{Namespace: "control", Name: "authz"})
		control = fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(object,
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "control", Name: utils.ClientCASecret}, Data: map[string][]byte{utils.CAKey: clientCA.CertificatePEM}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "control", Name: utils.ServingCASecret}, Data: map[string][]byte{utils.CAKey: servingCA.CertificatePEM}},
		).Build()
		reconciler = newServiceReconciler(control)
		recorder = events.NewFakeRecorder(64)
		reconciler.Recorder = recorder
		reconciler.EngineImage = "example/opa@sha256:" + strings.Repeat("a", 64)
		files, err := utils.WriteTLSFiles(GinkgoT().TempDir())
		Expect(err).NotTo(HaveOccurred())
		certificate, err := certwatcher.New(files.Certificate, files.Key)
		Expect(err).NotTo(HaveOccurred())
		roots, err := dynamiccertificates.NewStaticCAContent("management", managementRoot.CertificatePEM)
		Expect(err).NotTo(HaveOccurred())
		reconciler.ManagementRoots, reconciler.ManagementCertificate = roots, certificate
	})
	engineConfig := func(ctx SpecContext) (*corev1.ConfigMap, error) {
		var config corev1.ConfigMap
		err := control.Get(ctx, types.NamespacedName{Namespace: "control", Name: resources.Name(object.Name) + "-engine"}, &config)
		return &config, err
	}
	workloadKey := types.NamespacedName{Namespace: "control", Name: resources.Name("authz")}

	It("starts the engines from the management identity and the union of the management roots and the client CA", func(ctx SpecContext) {
		digest, err := reconciler.applyOwned(ctx, object)
		Expect(err).NotTo(HaveOccurred())
		config, err := engineConfig(ctx)
		Expect(err).NotTo(HaveOccurred())
		var bootstrap engine.Bootstrap
		Expect(json.Unmarshal([]byte(config.Data[resources.BootstrapKey]), &bootstrap)).To(Succeed())
		Expect(bootstrap).To(Equal(engine.Bootstrap{ServiceUID: utils.ServiceUID, EvaluatorID: engine.EvaluatorID(), Management: engine.Management{
			Roots: []string{string(managementRoot.CertificatePEM)}, Identity: "tls",
		}}))
		Expect(config.Data).To(HaveKeyWithValue(resources.CABundleKey, string(managementRoot.CertificatePEM)+string(clientCA.CertificatePEM)))
		var deployment appsv1.Deployment
		Expect(control.Get(ctx, workloadKey, &deployment)).To(Succeed())
		Expect(deployment.Spec.Template.Annotations).To(HaveKeyWithValue(resources.AnnotationStartupDigest, digest))
	})

	It("adds a client CA that is also the management CA once", func(ctx SpecContext) {
		Expect(control.Update(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "control", Name: utils.ClientCASecret}, Data: map[string][]byte{utils.CAKey: managementRoot.CertificatePEM}})).To(Succeed())
		_, err := reconciler.applyOwned(ctx, object)
		Expect(err).NotTo(HaveOccurred())
		config, err := engineConfig(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(config.Data).To(HaveKeyWithValue(resources.CABundleKey, string(managementRoot.CertificatePEM)))
	})

	It("keeps the startup digest when only the client CA changes", func(ctx SpecContext) {
		before, err := reconciler.applyOwned(ctx, object)
		Expect(err).NotTo(HaveOccurred())
		Expect(control.Update(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "control", Name: utils.ClientCASecret}, Data: map[string][]byte{utils.CAKey: servingCA.CertificatePEM}})).To(Succeed())
		Expect(reconciler.applyOwned(ctx, object)).To(Equal(before))
		config, err := engineConfig(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(config.Data).To(HaveKeyWithValue(resources.CABundleKey, string(managementRoot.CertificatePEM)+string(servingCA.CertificatePEM)))
	})

	It("applies the rest and keeps the startup digest while the client CA can't be read", func(ctx SpecContext) {
		complete, err := reconciler.applyOwned(ctx, object)
		Expect(err).NotTo(HaveOccurred())
		Expect(control.DeleteAllOf(ctx, &corev1.ConfigMap{}, client.InNamespace("control"))).To(Succeed())
		Expect(control.DeleteAllOf(ctx, &appsv1.Deployment{}, client.InNamespace("control"))).To(Succeed())
		Expect(control.DeleteAllOf(ctx, &corev1.Service{}, client.InNamespace("control"))).To(Succeed())
		object.Spec.TLS.Client.CARef.SecretKeyRef = &api.SecretKeyRef{Name: "absent", Key: utils.CAKey}

		digest, err := reconciler.applyOwned(ctx, object)
		Expect(err).To(MatchError(apierrors.IsNotFound, "IsNotFound"))
		Expect(digest).To(Equal(complete))
		Expect(control.Get(ctx, workloadKey, &corev1.Service{})).To(Succeed())
		Expect(control.Get(ctx, workloadKey, &policyv1.PodDisruptionBudget{})).To(Succeed())
		_, err = engineConfig(ctx)
		Expect(apierrors.IsNotFound(err)).To(BeTrue())
		Expect(apierrors.IsNotFound(control.Get(ctx, workloadKey, &appsv1.Deployment{}))).To(BeTrue())
		Expect(recorder.Events).To(Receive(ContainSubstring("CAReadFailed")))
	})

	It("leaves the workload as it is while the engine ConfigMap can't be applied", func(ctx SpecContext) {
		refusing := interceptor.NewClient(control, interceptor.Funcs{Apply: func(ctx context.Context, writer client.WithWatch, configuration runtime.ApplyConfiguration, options ...client.ApplyOption) error {
			if _, ok := configuration.(*corev1ac.ConfigMapApplyConfiguration); ok {
				return errors.New("ConfigMap apply refused")
			}
			return writer.Apply(ctx, configuration, options...)
		}})
		reconciler.Client = client.WithFieldOwner(refusing, resources.FieldOwner)

		_, err := reconciler.applyOwned(ctx, object)
		Expect(err).To(MatchError(ContainSubstring("ConfigMap apply refused")))
		Expect(control.Get(ctx, workloadKey, &corev1.Service{})).To(Succeed())
		Expect(control.Get(ctx, workloadKey, &policyv1.PodDisruptionBudget{})).To(Succeed())
		Expect(apierrors.IsNotFound(control.Get(ctx, workloadKey, &appsv1.Deployment{}))).To(BeTrue())
	})

	It("reports a CA key the object lacks", func(ctx SpecContext) {
		object.Spec.TLS.Client.CARef.SecretKeyRef.Key = "missing.crt"
		_, err := reconciler.applyOwned(ctx, object)
		Expect(err).To(MatchError(ContainSubstring(`no key "missing.crt"`)))
	})

	It("verifies the engines against a serving CA bundle from a ConfigMap", func(ctx SpecContext) {
		Expect(control.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "control", Name: "serving-ca"}, Data: map[string]string{utils.CAKey: string(clientCA.CertificatePEM)}})).To(Succeed())
		object.Spec.TLS.Server.CARef = api.CABundleRef{ConfigMapKeyRef: &api.ConfigMapKeyRef{Name: "serving-ca", Key: utils.CAKey}}
		roots, err := reconciler.serverRoots(ctx, object)
		Expect(err).NotTo(HaveOccurred())
		Expect(roots.Equal(poolOf(clientCA))).To(BeTrue())
	})

	It("rejects a serving CA bundle without certificates", func(ctx SpecContext) {
		Expect(control.Update(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "control", Name: utils.ServingCASecret}, Data: map[string][]byte{utils.CAKey: []byte("not PEM")}})).To(Succeed())
		Expect(reconciler.serverRoots(ctx, object)).Error().To(MatchError(ContainSubstring("holds no PEM certificates")))
	})
})

var _ = Describe("Service decoding", func() {
	It("reports an invalid spec as Invalid", func() {
		object := utils.AuthorizationService(types.NamespacedName{Namespace: "control", Name: "authz"})
		entry := api.Authority{BindingRef: api.BindingRef{Name: "entry", SourceRef: &api.SourceRef{Namespace: "control", Name: "elsewhere"}}, WhenNoPolicyAllows: api.DecisionFallbackDeny}
		object.Spec.Endpoints[0].Authorities = []api.Authority{entry}
		_, err := decodeService(object)
		Expect(apierrors.IsInvalid(err)).To(BeTrue(), "%v", err)
	})
})
