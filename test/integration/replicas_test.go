//go:build integration

package integration

import (
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/resources"
)

var _ = Describe("Replica reconciliation and disruption", func() {
	var service *api.AuthorizationService
	BeforeEach(func(ctx SpecContext) {
		service = createService(ctx, newNamespace(ctx, "replica-control"), nil)
		installTLS(ctx, service)
	})

	It("evicts an unready pod whose pushes keep failing", func(ctx SpecContext) {
		template := deployment(ctx, service).Spec.Template
		good := createEnginePod(ctx, service.Namespace, "good", podAddress(1), template, true)
		bad := createEnginePod(ctx, service.Namespace, "bad", podAddress(2), template, false)
		engines.Fail(engineAddress(bad), errors.New("unreachable"))
		Eventually(func() bool {
			return apierrors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(bad), &corev1.Pod{}))
		}).WithTimeout(3 * convergence).Should(BeTrue())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(good), &corev1.Pod{})).To(Succeed())
		Eventually(func(g Gomega) []eventsv1.Event {
			return events(ctx, g, service.Namespace)
		}).WithTimeout(convergence).Should(ContainElements(
			And(HaveField("Reason", "PushFailed"), HaveField("Regarding.Name", bad.Name)),
			And(HaveField("Reason", "Evicted"), HaveField("Regarding.Name", bad.Name)),
		))
	})

	It("pushes to a pod once its engine has started", func(ctx SpecContext) {
		template := deployment(ctx, service).Spec.Template
		pod := &corev1.Pod{ObjectMeta: *template.ObjectMeta.DeepCopy(), Spec: *template.Spec.DeepCopy()}
		pod.Namespace, pod.Name = service.Namespace, "starting"
		Expect(k8sClient.Create(ctx, pod)).To(Succeed())
		pod.Status = corev1.PodStatus{PodIP: podAddress(7), Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{Name: resources.ContainerName, Started: new(false)}}}
		Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())
		engines.Fail(engineAddress(pod), errors.New("connection refused"))
		Consistently(func(g Gomega) []eventsv1.Event {
			return events(ctx, g, service.Namespace)
		}).WithTimeout(3 * time.Second).ShouldNot(ContainElement(And(HaveField("Reason", "PushFailed"), HaveField("Regarding.Name", pod.Name))))
		Expect(pushed(Default, pod).Revision).To(BeEmpty())

		engines.Fail(engineAddress(pod), nil)
		pod.Status.ContainerStatuses[0].Started = new(true)
		Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())
		Eventually(func(g Gomega) {
			g.Expect(pushed(g, pod).Revision).To(Equal(model.RevisionID(serviceStatus(ctx, g, service).DesiredRevision)))
			g.Expect(serviceStatus(ctx, g, service).CurrentReplicas).To(Equal(int32(1)))
		}).WithTimeout(convergence).Should(Succeed())
	})

	It("keeps the former runtime kind's workload until the new workload reports minimum ready capacity", func(ctx SpecContext) {
		former := deployment(ctx, service)
		updateService(ctx, service, func(service *api.AuthorizationService) {
			service.Spec.Runtime.Type = api.RuntimeTypeDaemonSet
			service.Spec.Runtime.MinReadyReplicas = 2
		})
		// envtest runs no DaemonSet controller, so the spec reports the DaemonSet's
		// status itself.
		setDaemonSetStatus := func(status appsv1.DaemonSetStatus) {
			GinkgoHelper()
			Expect(retry.RetryOnConflict(retry.DefaultRetry, func() error {
				var daemonSet appsv1.DaemonSet
				if err := k8sClient.Get(ctx, workloadKey(service), &daemonSet); err != nil {
					return err
				}
				daemonSet.Status = status
				return k8sClient.Status().Update(ctx, &daemonSet)
			})).To(Succeed())
		}
		Eventually(func() error { return k8sClient.Get(ctx, workloadKey(service), &appsv1.DaemonSet{}) }).WithTimeout(convergence).Should(Succeed())
		setDaemonSetStatus(appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberReady: 1})
		// A prepared status with the scheduled count is written only after
		// a reconcile that saw the DaemonSet with one ready pod passed the switch.
		Eventually(func(g Gomega) {
			status := serviceStatus(ctx, g, service)
			g.Expect(status.DesiredReplicas).To(HaveValue(Equal(int32(3))))
			g.Expect(apimeta.FindStatusCondition(status.Conditions, api.ConditionPrepared)).To(HaveField("Status", metav1.ConditionTrue))
		}).WithTimeout(convergence).Should(Succeed())
		var current appsv1.Deployment
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(former), &current)).To(Succeed())
		Expect(current.DeletionTimestamp.IsZero()).To(BeTrue())

		setDaemonSetStatus(appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberReady: 2})
		Eventually(func(g Gomega) {
			var current appsv1.Deployment
			err := k8sClient.Get(ctx, client.ObjectKeyFromObject(former), &current)
			g.Expect(apierrors.IsNotFound(err) || err == nil && !current.DeletionTimestamp.IsZero()).To(BeTrue())
		}).WithTimeout(convergence).Should(Succeed())
	})
})
