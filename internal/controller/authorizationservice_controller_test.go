package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/resources"
	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("AuthorizationService watch mapping", func() {
	It("maps an engine pod to the service its instance label names", func(ctx SpecContext) {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "control", Name: "engine", Labels: map[string]string{resources.LabelInstance: "authz"}}}
		Expect(servicesForPod(ctx, pod)).To(Equal([]ctrl.Request{{NamespacedName: types.NamespacedName{Namespace: "control", Name: "authz"}}}))
		pod.Labels = nil
		Expect(servicesForPod(ctx, pod)).To(BeEmpty())
	})

	It("maps a source change to exactly the services whose endpoints read the source", func(ctx SpecContext) {
		reading := utils.AuthorizationService(types.NamespacedName{Namespace: "control", Name: "reading"})
		remote := utils.AuthorizationService(types.NamespacedName{Namespace: "other", Name: "remote"})
		remote.Spec.Endpoints[0].SourceRefs = []api.SourceRef{{Namespace: "control", Name: utils.SourceName}}
		unrelated := utils.AuthorizationService(types.NamespacedName{Namespace: "control", Name: "unrelated"})
		unrelated.Spec.Endpoints[0].SourceRefs = []api.SourceRef{{Namespace: "control", Name: "elsewhere"}}
		control := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(reading, remote, unrelated).
			WithIndex(&api.AuthorizationService{}, serviceSourceIndex, serviceSourceNames).Build()
		reconciler := newServiceReconciler(control)
		Expect(reconciler.servicesForSource(ctx, model.SourceKey{Namespace: "control", Name: utils.SourceName})).To(ConsistOf(
			ctrl.Request{NamespacedName: client.ObjectKeyFromObject(reading)},
			ctrl.Request{NamespacedName: client.ObjectKeyFromObject(remote)},
		))
		Expect(reconciler.servicesForSource(ctx, model.SourceKey{Namespace: "other", Name: utils.SourceName})).To(BeEmpty())
	})

	It("maps a CA Secret or ConfigMap to the services in its namespace that read it", func(ctx SpecContext) {
		service := utils.AuthorizationService(types.NamespacedName{Namespace: "control", Name: "authz"})
		service.Spec.TLS.Server.CARef = api.CABundleRef{ConfigMapKeyRef: &api.ConfigMapKeyRef{Name: "serving-ca", Key: "ca.crt"}}
		elsewhere := utils.AuthorizationService(types.NamespacedName{Namespace: "other", Name: "authz"})
		control := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(service, elsewhere).
			WithIndex(&api.AuthorizationService{}, serviceCAIndex, serviceCANames).Build()
		reconciler := newServiceReconciler(control)
		clientCA := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Namespace: "control", Name: utils.ClientCASecret}}
		Expect(reconciler.servicesForSecret(ctx, clientCA)).To(ConsistOf(ctrl.Request{NamespacedName: client.ObjectKeyFromObject(service)}))
		servingCA := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "control", Name: "serving-ca"}}
		Expect(reconciler.servicesForConfigMap(ctx, servingCA)).To(ConsistOf(ctrl.Request{NamespacedName: client.ObjectKeyFromObject(service)}))
		sameName := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Namespace: "control", Name: "serving-ca"}}
		Expect(reconciler.servicesForSecret(ctx, sameName)).To(BeEmpty())
		serving := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Namespace: "control", Name: utils.ServerTLSSecret}}
		Expect(reconciler.servicesForSecret(ctx, serving)).To(BeEmpty())
	})
})
