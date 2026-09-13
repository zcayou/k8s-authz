package controller

import (
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/resources"
	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("AuthorizationService status", func() {
	var reconciler *AuthorizationServiceReconciler
	var object *api.AuthorizationService
	var prepared engine.Program
	var control client.Client
	enginePod := func(ctx SpecContext, name string, ready bool) *corev1.Pod {
		GinkgoHelper()
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: object.Namespace, Name: name, Labels: resources.ServiceUIDSelector(object.UID)}}
		if ready {
			pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		}
		Expect(control.Create(ctx, pod)).To(Succeed())
		return pod
	}
	BeforeEach(func(ctx SpecContext) {
		object = utils.AuthorizationService(types.NamespacedName{Namespace: "control", Name: "authz"})
		object.Spec.Runtime.Deployment.Replicas = 1
		control = fake.NewClientBuilder().WithScheme(scheme.Scheme).WithStatusSubresource(object).WithObjects(object).Build()
		reconciler = newServiceReconciler(control)
		prepared = engine.Program{Content: model.ContentRevision{Revision: "content", PreparedRevision: model.PreparedRevision{Issues: map[string]model.ProgramIssue{}}}}
		enginePod(ctx, "ready", true)
	})
	writeStatus := func(ctx SpecContext, prepared *engine.Program, current int32, failure error) error {
		GinkgoHelper()
		var latest api.AuthorizationService
		Expect(reconciler.Get(ctx, client.ObjectKeyFromObject(object), &latest)).To(Succeed())
		return reconciler.writeStatus(ctx, &latest, prepared, current, failure)
	}
	status := func(ctx SpecContext) *api.AuthorizationServiceStatus {
		GinkgoHelper()
		var latest api.AuthorizationService
		Expect(reconciler.Client.Get(ctx, client.ObjectKeyFromObject(object), &latest)).To(Succeed())
		return &latest.Status
	}
	It("reports isolated policy errors without confusing them with serving", func(ctx SpecContext) {
		prepared.Content.Issues["missing"] = model.ProgramIssue{Issue: model.Issue{Severity: api.IssueSeverityError, Reason: "MissingReference", Message: "binding is absent", Endpoint: utils.EndpointName}}
		Expect(writeStatus(ctx, &prepared, 1, nil)).To(Succeed())
		result := status(ctx)
		Expect(result.ObservedGeneration).To(Equal(object.Generation))
		Expect(result.DesiredRevision).To(Equal("content"))
		Expect(apimeta.FindStatusCondition(result.Conditions, api.ConditionReady)).To(HaveField("Status", metav1.ConditionTrue))
		Expect(apimeta.FindStatusCondition(result.Conditions, api.ConditionPrepared)).To(HaveField("Status", metav1.ConditionTrue))
		Expect(apimeta.FindStatusCondition(result.Conditions, api.ConditionPolicyHealthy)).To(SatisfyAll(
			HaveField("Status", metav1.ConditionFalse),
			HaveField("Reason", api.ReasonPolicyErrors),
			HaveField("Message", "binding is absent"),
		))
	})
	It("reports ready capacity that serves no desired revision while the policy can't be prepared", func(ctx SpecContext) {
		Expect(writeStatus(ctx, nil, 0, errors.New("waiting for PolicySource control/local to be registered"))).To(Succeed())
		result := status(ctx)
		Expect(result.ObservedGeneration).To(Equal(object.Generation))
		Expect(result.ReadyReplicas).To(Equal(int32(1)))
		Expect(apimeta.FindStatusCondition(result.Conditions, api.ConditionReady)).To(SatisfyAll(
			HaveField("Status", metav1.ConditionFalse),
			HaveField("Reason", api.ReasonPreparationUnavailable),
		))
		Expect(apimeta.FindStatusCondition(result.Conditions, api.ConditionPrepared)).To(SatisfyAll(
			HaveField("Status", metav1.ConditionFalse),
			HaveField("Reason", api.ReasonPreparationUnavailable),
			HaveField("Message", "waiting for PolicySource control/local to be registered"),
		))
		Expect(apimeta.FindStatusCondition(result.Conditions, api.ConditionPolicyHealthy)).To(HaveField("Status", metav1.ConditionUnknown))
	})
	It("reports an invalid spec with the Invalid reason and every field error", func(ctx SpecContext) {
		invalid := apierrors.NewInvalid(api.GroupVersion.WithKind("AuthorizationService").GroupKind(), object.Name, field.ErrorList{
			field.Duplicate(field.NewPath("spec", "endpoints").Index(0).Child("authorities").Index(1).Child("bindingRef"), "entry"),
		})
		Expect(writeStatus(ctx, nil, 0, invalid)).To(Succeed())
		Expect(apimeta.FindStatusCondition(status(ctx).Conditions, api.ConditionPrepared)).To(SatisfyAll(
			HaveField("Status", metav1.ConditionFalse),
			HaveField("Reason", api.ReasonInvalid),
			HaveField("Message", ContainSubstring("spec.endpoints[0].authorities[1].bindingRef")),
		))
	})
	It("counts ready replicas and replicas serving the desired revision separately", func(ctx SpecContext) {
		enginePod(ctx, "former", true)
		enginePod(ctx, "starting", false)
		Expect(writeStatus(ctx, &prepared, 1, nil)).To(Succeed())
		result := status(ctx)
		Expect(result.DesiredReplicas).To(HaveValue(Equal(int32(1))))
		Expect(result.ReadyReplicas).To(Equal(int32(2)))
		Expect(result.CurrentReplicas).To(Equal(int32(1)))
	})
	It("is Ready only once minReadyReplicas engines serve the desired revision", func(ctx SpecContext) {
		Expect(writeStatus(ctx, &prepared, 0, nil)).To(Succeed())
		result := status(ctx)
		Expect(result.ReadyReplicas).To(Equal(int32(1)))
		Expect(apimeta.FindStatusCondition(result.Conditions, api.ConditionReady)).To(SatisfyAll(
			HaveField("Status", metav1.ConditionFalse),
			HaveField("Reason", api.ReasonInsufficientCapacity),
		))
	})
	It("applies status computed from an object older than the stored status", func(ctx SpecContext) {
		var stale api.AuthorizationService
		Expect(reconciler.Get(ctx, client.ObjectKeyFromObject(object), &stale)).To(Succeed())
		Expect(writeStatus(ctx, &prepared, 1, nil)).To(Succeed())
		Expect(reconciler.writeStatus(ctx, &stale, &prepared, 0, nil)).To(Succeed())
		result := status(ctx)
		Expect(result.CurrentReplicas).To(BeZero())
		Expect(apimeta.FindStatusCondition(result.Conditions, api.ConditionReady)).To(HaveField("Reason", api.ReasonInsufficientCapacity))
	})
	It("keeps a condition's transition time while its status holds", func(ctx SpecContext) {
		transitioned := metav1.NewTime(time.Now().Add(-time.Hour).Truncate(time.Second))
		var latest api.AuthorizationService
		Expect(reconciler.Get(ctx, client.ObjectKeyFromObject(object), &latest)).To(Succeed())
		latest.Status.Conditions = []metav1.Condition{
			{Type: api.ConditionReady, Status: metav1.ConditionTrue, Reason: api.ReasonServing, LastTransitionTime: transitioned},
			{Type: api.ConditionPrepared, Status: metav1.ConditionFalse, Reason: api.ReasonPreparationUnavailable, LastTransitionTime: transitioned},
		}
		Expect(control.Status().Update(ctx, &latest)).To(Succeed())
		Expect(writeStatus(ctx, &prepared, 1, nil)).To(Succeed())
		result := status(ctx)
		Expect(apimeta.FindStatusCondition(result.Conditions, api.ConditionReady).LastTransitionTime.Equal(&transitioned)).To(BeTrue())
		Expect(apimeta.FindStatusCondition(result.Conditions, api.ConditionPrepared).LastTransitionTime.After(transitioned.Time)).To(BeTrue())
	})
	It("does not count terminating capacity as ready", func(ctx SpecContext) {
		terminating := enginePod(ctx, "terminating", true)
		terminating.Finalizers = []string{"example.test/hold"}
		Expect(control.Update(ctx, terminating)).To(Succeed())
		Expect(control.Delete(ctx, terminating)).To(Succeed())
		Expect(writeStatus(ctx, &prepared, 1, nil)).To(Succeed())
		Expect(status(ctx).ReadyReplicas).To(Equal(int32(1)))
	})
})
