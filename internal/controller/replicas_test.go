package controller

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	clocktesting "k8s.io/utils/clock/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/engineclient"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/resources"
	"github.com/zcayou/k8s-authz/test/utils"
)

const testStartupDigest = "current-startup"

var _ = Describe("Engine pod delivery", func() {
	var owner *api.AuthorizationService
	var engines *utils.FakeEngines
	var clock *clocktesting.FakePassiveClock
	var evictions []*policyv1.Eviction
	var reconciler *AuthorizationServiceReconciler
	var program engine.Program
	var addresses int
	enginePod := func(name, digest string) *corev1.Pod {
		addresses++
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "control", Name: name, UID: types.UID(name + "-uid"),
				Labels: resources.ServiceUIDSelector(owner.UID), Annotations: map[string]string{resources.AnnotationStartupDigest: digest}},
			Status: corev1.PodStatus{PodIP: "10.2.0." + strconv.Itoa(addresses), ContainerStatuses: []corev1.ContainerStatus{{Name: resources.ContainerName, Started: new(true)}}},
		}
	}
	address := func(pod *corev1.Pod) string {
		return net.JoinHostPort(pod.Status.PodIP, strconv.Itoa(int(resources.EnginePort)))
	}
	start := func(objects ...client.Object) {
		servingCA, err := utils.NewAuthority(clock.Now())
		Expect(err).NotTo(HaveOccurred())
		objects = append(objects, owner, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "control", Name: utils.ServingCASecret}, Data: map[string][]byte{utils.CAKey: servingCA.CertificatePEM}})
		control := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(objects...).
			WithInterceptorFuncs(interceptor.Funcs{SubResourceCreate: func(_ context.Context, _ client.Client, name string, _ client.Object, subResource client.Object, _ ...client.SubResourceCreateOption) error {
				Expect(name).To(Equal("eviction"))
				eviction, ok := subResource.(*policyv1.Eviction)
				Expect(ok).To(BeTrue())
				evictions = append(evictions, eviction)
				return nil
			}}).Build()
		reconciler = newServiceReconciler(control)
		reconciler.Clock, reconciler.Engines, reconciler.RemediationAfter = clock, engines, 2*time.Minute
	}
	push := func(ctx context.Context) (int32, error) {
		return reconciler.reconcilePods(ctx, owner, testStartupDigest, program)
	}
	pushFailure := func(ctx context.Context) error {
		_, err := push(ctx)
		return err
	}
	setStarted := func(ctx context.Context, pod *corev1.Pod, started bool) {
		GinkgoHelper()
		Expect(reconciler.Get(ctx, client.ObjectKeyFromObject(pod), pod)).To(Succeed())
		pod.Status.ContainerStatuses[0].Started = new(started)
		Expect(reconciler.Status().Update(ctx, pod)).To(Succeed())
	}
	BeforeEach(func() {
		owner = utils.AuthorizationService(types.NamespacedName{Namespace: "control", Name: "authz"})
		engines = utils.NewFakeEngines()
		clock = clocktesting.NewFakePassiveClock(time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC))
		evictions = nil
		content, conditions, err := engine.FinalizeContent(model.PreparedRevision{}, model.ServiceUID(owner.UID))
		Expect(err).NotTo(HaveOccurred())
		program = engine.Program{Content: content, Conditions: conditions}
	})

	It("pushes only to started pods on the current startup digest that lack the revision", func(ctx SpecContext) {
		stale, current, former := enginePod("stale", testStartupDigest), enginePod("current", testStartupDigest), enginePod("former", "previous-startup")
		unstarted, terminating := enginePod("unstarted", testStartupDigest), enginePod("terminating", testStartupDigest)
		unstarted.Status.ContainerStatuses[0].Started = new(false)
		terminating.DeletionTimestamp, terminating.Finalizers = new(metav1.NewTime(clock.Now())), []string{"example.test/hold"}
		installed := []byte(`{"revision":"` + string(program.Content.Revision) + `"}`)
		engines.Install(address(current), installed)
		start(stale, current, former, unstarted, terminating)
		Expect(push(ctx)).To(Equal(int32(2)))
		Expect(engines.Targets()).To(HaveEach(HaveField("Address", BeElementOf(address(stale), address(current)))))
		Expect(engines.Installed(ctx, engineclient.Target{Address: address(stale)})).To(HaveField("Revision", program.Content.Revision))
		Expect(engines.State(address(current))).To(Equal(installed))
	})

	It("pushes the conditions module before the state to a pod without either", func(ctx SpecContext) {
		empty := enginePod("empty", testStartupDigest)
		start(empty)
		Expect(push(ctx)).To(Equal(int32(1)))
		Expect(engines.Writes(address(empty))).To(Equal([]string{utils.WriteConditions, utils.WriteState}))
		Expect(engines.Installed(ctx, engineclient.Target{Address: address(empty)})).To(Equal(engineclient.Installed{
			Revision: program.Content.Revision, ConditionsDigest: program.Conditions.Digest,
		}))
	})

	It("repairs only the module of a pod serving the revision under another module", func(ctx SpecContext) {
		repaired := enginePod("repaired", testStartupDigest)
		engines.Install(address(repaired), []byte(`{"revision":"`+string(program.Content.Revision)+`"}`))
		engines.InstallModule(address(repaired), "sha256:newer")
		start(repaired)
		Expect(push(ctx)).To(Equal(int32(1)))
		Expect(engines.Writes(address(repaired))).To(Equal([]string{utils.WriteConditions}))
		Expect(engines.Module(address(repaired))).To(Equal(program.Conditions.Digest))
	})

	It("writes nothing to a pod serving the revision and its module", func(ctx SpecContext) {
		current := enginePod("current", testStartupDigest)
		engines.Install(address(current), []byte(`{"revision":"`+string(program.Content.Revision)+`"}`))
		engines.InstallModule(address(current), program.Conditions.Digest)
		start(current)
		Expect(push(ctx)).To(Equal(int32(1)))
		Expect(engines.Writes(address(current))).To(BeEmpty())
	})

	It("counts a failed module write as a failed push and doesn't write the state", func(ctx SpecContext) {
		failing := enginePod("failing", testStartupDigest)
		engines.FailConditions(address(failing), errors.New("rego_compile_error"))
		start(failing)
		current, err := push(ctx)
		Expect(current).To(BeZero())
		Expect(err).To(MatchError(ContainSubstring("push to Pod failing: rego_compile_error")))
		Expect(engines.Writes(address(failing))).To(BeEmpty())
		Expect(engines.State(address(failing))).To(BeNil())
	})

	It("reports failed pushes for retry without evicting before the remediation delay", func(ctx SpecContext) {
		failing := enginePod("failing", testStartupDigest)
		engines.Fail(address(failing), errors.New("unreachable"))
		start(failing)
		current, err := push(ctx)
		Expect(current).To(BeZero())
		Expect(err).To(MatchError(ContainSubstring("push to Pod failing: unreachable")))
		clock.SetTime(clock.Now().Add(90 * time.Second))
		Expect(pushFailure(ctx)).To(HaveOccurred())
		Expect(evictions).To(BeEmpty())
	})

	It("evicts a pod whose pushes kept failing for the remediation delay, by UID", func(ctx SpecContext) {
		failing, healthy := enginePod("failing", testStartupDigest), enginePod("healthy", testStartupDigest)
		engines.Fail(address(failing), errors.New("unreachable"))
		start(failing, healthy)
		Expect(pushFailure(ctx)).To(HaveOccurred())
		clock.SetTime(clock.Now().Add(2 * time.Minute))
		Expect(pushFailure(ctx)).To(HaveOccurred())
		Expect(evictions).To(ConsistOf(SatisfyAll(
			HaveField("Name", failing.Name),
			HaveField("DeleteOptions.Preconditions.UID", HaveValue(Equal(failing.UID))),
		)))
	})

	It("restarts the clock after a successful push", func(ctx SpecContext) {
		failing := enginePod("failing", testStartupDigest)
		engines.Fail(address(failing), errors.New("unreachable"))
		start(failing)
		Expect(pushFailure(ctx)).To(HaveOccurred())
		clock.SetTime(clock.Now().Add(time.Minute))
		engines.Fail(address(failing), nil)
		Expect(push(ctx)).To(Equal(int32(1)))
		engines.Fail(address(failing), errors.New("unreachable"))
		Expect(pushFailure(ctx)).To(HaveOccurred())
		clock.SetTime(clock.Now().Add(90 * time.Second))
		Expect(pushFailure(ctx)).To(HaveOccurred())
		Expect(evictions).To(BeEmpty())
	})

	It("neither pushes to nor evicts a pod that hasn't started, and restarts its clock", func(ctx SpecContext) {
		failing := enginePod("failing", testStartupDigest)
		engines.Fail(address(failing), errors.New("unreachable"))
		start(failing)
		Expect(pushFailure(ctx)).To(HaveOccurred())
		clock.SetTime(clock.Now().Add(time.Minute))
		setStarted(ctx, failing, false)
		for range 3 {
			Expect(push(ctx)).To(BeZero())
			clock.SetTime(clock.Now().Add(time.Minute))
		}
		setStarted(ctx, failing, true)
		Expect(pushFailure(ctx)).To(HaveOccurred())
		clock.SetTime(clock.Now().Add(90 * time.Second))
		Expect(pushFailure(ctx)).To(HaveOccurred())
		Expect(evictions).To(BeEmpty())
	})
})

var _ = Describe("Runtime-kind switch", func() {
	var owner *api.AuthorizationService
	var reconciler *AuthorizationServiceReconciler
	var former *appsv1.Deployment
	BeforeEach(func() {
		owner = utils.AuthorizationService(types.NamespacedName{Namespace: "control", Name: "authz"})
		owner.Spec.Runtime = api.AuthorizationServiceRuntime{Type: api.RuntimeTypeDaemonSet, MinReadyReplicas: 2}
		key := types.NamespacedName{Namespace: "control", Name: resources.Name(owner.Name)}
		controller := metav1.OwnerReference{APIVersion: api.GroupVersion.String(), Kind: "AuthorizationService", Name: owner.Name, UID: owner.UID, Controller: new(true)}
		former = &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name, UID: "deployment-uid", OwnerReferences: []metav1.OwnerReference{controller}}}
		current := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name, UID: "daemonset-uid", OwnerReferences: []metav1.OwnerReference{controller}}, Status: appsv1.DaemonSetStatus{NumberReady: 1}}
		control := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(owner, former, current).WithStatusSubresource(current).Build()
		reconciler = newServiceReconciler(control)
	})
	formerExists := func(ctx context.Context) bool {
		GinkgoHelper()
		err := reconciler.Get(ctx, client.ObjectKeyFromObject(former), &appsv1.Deployment{})
		if apierrors.IsNotFound(err) {
			return false
		}
		Expect(err).NotTo(HaveOccurred())
		return true
	}

	It("keeps the former workload until the new one reports minReadyReplicas ready pods", func(ctx SpecContext) {
		Expect(reconciler.finishRuntimeKindSwitch(ctx, owner)).To(Succeed())
		Expect(formerExists(ctx)).To(BeTrue())
		var current appsv1.DaemonSet
		Expect(reconciler.Get(ctx, client.ObjectKeyFromObject(former), &current)).To(Succeed())
		current.Status.NumberReady = 2
		Expect(reconciler.Status().Update(ctx, &current)).To(Succeed())
		Expect(reconciler.finishRuntimeKindSwitch(ctx, owner)).To(Succeed())
		Expect(formerExists(ctx)).To(BeFalse())
	})

	It("keeps the former workload while the current one is being deleted", func(ctx SpecContext) {
		var current appsv1.DaemonSet
		Expect(reconciler.Get(ctx, client.ObjectKeyFromObject(former), &current)).To(Succeed())
		current.Status.NumberReady = 2
		Expect(reconciler.Status().Update(ctx, &current)).To(Succeed())
		current.Finalizers = []string{"example.test/hold"}
		Expect(reconciler.Update(ctx, &current)).To(Succeed())
		Expect(reconciler.Delete(ctx, &current)).To(Succeed())
		Expect(reconciler.finishRuntimeKindSwitch(ctx, owner)).To(Succeed())
		Expect(formerExists(ctx)).To(BeTrue())
	})

	It("keeps the former workload while the current one belongs to another controller", func(ctx SpecContext) {
		var current appsv1.DaemonSet
		Expect(reconciler.Get(ctx, client.ObjectKeyFromObject(former), &current)).To(Succeed())
		current.OwnerReferences[0].UID = "another-owner"
		Expect(reconciler.Update(ctx, &current)).To(Succeed())
		current.Status.NumberReady = 2
		Expect(reconciler.Status().Update(ctx, &current)).To(Succeed())
		Expect(reconciler.finishRuntimeKindSwitch(ctx, owner)).To(Succeed())
		Expect(formerExists(ctx)).To(BeTrue())
	})

	It("leaves a former workload another controller owns", func(ctx SpecContext) {
		former.OwnerReferences[0].UID = "another-owner"
		Expect(reconciler.Update(ctx, former)).To(Succeed())
		owner.Spec.Runtime.MinReadyReplicas = 1
		Expect(reconciler.finishRuntimeKindSwitch(ctx, owner)).To(Succeed())
		Expect(formerExists(ctx)).To(BeTrue())
	})
})
