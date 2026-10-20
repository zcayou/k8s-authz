//go:build integration

package integration

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/compiler"
	"github.com/zcayou/k8s-authz/internal/model"
)

var _ = Describe("PolicySource registration", func() {
	It("keeps serving the view across a token rotation", func(ctx SpecContext) {
		fixture := newSourceFixture(ctx, "workloads", "operators")
		replica := startReplica(k8sClient)
		replica.reconcile(ctx, fixture)
		initial := synchronizedView(replica.registry, fixture.key())
		Expect(initial.Documents).To(HaveLen(2))
		fixture.expectRegisteredOnlyWithView(replica.registry)

		fixture.secret.Data["kubeconfig"] = fixture.kubeconfig(ctx)
		Expect(k8sClient.Update(ctx, fixture.secret)).To(Succeed())
		// Reconciling the rotated kubeconfig replaces the reader before it returns.
		replica.reconcile(ctx, fixture)
		view := replica.registry.Snapshot()[fixture.key()]
		Expect(view.Complete).To(BeTrue())
		Expect(view.Documents).To(Equal(initial.Documents))

		Expect(k8sClient.Create(ctx, &api.Policy{
			ObjectMeta: metav1.ObjectMeta{Namespace: fixture.namespace, Name: "added"},
			Spec:       api.PolicySpec{Include: []api.OperationRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}, Namespaces: []string{"*"}}}},
		})).To(Succeed())
		Eventually(func() map[model.Reference]model.DocumentState {
			return replica.registry.Snapshot()[fixture.key()].Documents
		}).WithTimeout(convergence).Should(HaveLen(3))
	}, SpecTimeout(time.Minute))

	It("narrows the view when the collection narrows", func(ctx SpecContext) {
		fixture := newSourceFixture(ctx, "workloads", "operators")
		fixture.synchronized(ctx)
		fixture.cachedEventually(ctx, "workloads", "operators")

		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(fixture.object), fixture.object)).To(Succeed())
		fixture.object.Spec.Collection[0].Names = []string{"workloads"}
		Expect(k8sClient.Update(ctx, fixture.object)).To(Succeed())
		fixture.synchronized(ctx)
		fixture.cachedEventually(ctx, "workloads")
	}, SpecTimeout(time.Minute))

	It("keeps the view while its kubeconfig Secret is deleted and recovers when it's restored", func(ctx SpecContext) {
		fixture := newSourceFixture(ctx, "workloads")
		fixture.synchronized(ctx)
		fixture.cachedEventually(ctx, "workloads")
		data := fixture.secret.Data

		Expect(k8sClient.Delete(ctx, fixture.secret)).To(Succeed())
		Eventually(func() *metav1.Condition { return fixture.condition(ctx) }).WithTimeout(convergence).Should(HaveField("Reason", api.ReasonInvalidCredential))
		Expect(fixture.cached(ctx)).To(ConsistOf("workloads"))

		fixture.secret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: fixture.secret.Namespace, Name: fixture.secret.Name}, Data: data}
		Expect(k8sClient.Create(ctx, fixture.secret)).To(Succeed())
		fixture.synchronized(ctx)
		Expect(fixture.cached(ctx)).To(ConsistOf("workloads"))
	}, SpecTimeout(time.Minute))

	It("rewrites its cache Secrets when they're deleted or edited out of band", func(ctx SpecContext) {
		fixture := newSourceFixture(ctx, "workloads")
		fixture.synchronized(ctx)
		fixture.cachedEventually(ctx, "workloads")

		Expect(k8sClient.DeleteAllOf(ctx, &corev1.Secret{}, client.InNamespace(fixture.namespace), fixture.cacheLabels())).To(Succeed())
		fixture.cachedEventually(ctx, "workloads")

		var secrets corev1.SecretList
		Expect(k8sClient.List(ctx, &secrets, client.InNamespace(fixture.namespace), fixture.cacheLabels())).To(Succeed())
		Expect(secrets.Items).NotTo(BeEmpty())
		for _, secret := range secrets.Items {
			secret.Annotations["authorization.zctx.io/cache-digest"] = "edited"
			Expect(k8sClient.Update(ctx, &secret)).To(Succeed())
		}
		fixture.cachedEventually(ctx, "workloads")
	}, SpecTimeout(time.Minute))

	It("persists its namespace labels while namespaceLabels is Collect, follows label-only changes, drops them once it's Ignore and reads them again once it's Collect", func(ctx SpecContext) {
		fixture := newSelectionFixture(ctx)
		fixture.synchronized(ctx)
		cachedOwner := func(g Gomega) string {
			collects, labels := fixture.cachedNamespaceLabels(ctx)
			g.Expect(collects).To(BeTrue())
			g.Expect(labels).To(HaveKey(fixture.namespace))
			return labels[fixture.namespace]["owner"]
		}
		Eventually(cachedOwner).WithTimeout(convergence).Should(Equal("infra"))

		labelNamespace(ctx, fixture.namespace, map[string]string{"owner": "netsec"})
		Eventually(cachedOwner).WithTimeout(convergence).Should(Equal("netsec"))

		fixture.update(ctx, func(spec *api.PolicySourceSpec) { spec.NamespaceLabels = api.NamespaceLabelsIgnore })
		Eventually(func(g Gomega) {
			collects, labels := fixture.cachedNamespaceLabels(ctx)
			g.Expect(collects).To(BeFalse())
			g.Expect(labels).To(BeEmpty())
		}).WithTimeout(convergence).Should(Succeed())
		fixture.synchronized(ctx)

		fixture.update(ctx, func(spec *api.PolicySourceSpec) { spec.NamespaceLabels = api.NamespaceLabelsCollect })
		Eventually(cachedOwner).WithTimeout(convergence).Should(Equal("netsec"))
		fixture.synchronized(ctx)
	}, SpecTimeout(time.Minute))

	It("serves a selection's matches from the persisted view on a replica that has just started while its source is unreachable", func(ctx SpecContext) {
		fixture := newSelectionFixture(ctx)
		fixture.synchronized(ctx)
		Eventually(func(g Gomega) {
			_, labels := fixture.cachedNamespaceLabels(ctx)
			g.Expect(labels).To(HaveKey(fixture.namespace))
		}).WithTimeout(convergence).Should(Succeed())

		Expect(k8sClient.Delete(ctx, fixture.secret)).To(Succeed())
		replica := startReplica(k8sClient)
		replica.reconcile(ctx, fixture)
		Expect(replica.registry.Health(fixture.key()).Reason).To(Equal(api.ReasonInvalidCredential))
		selected := compiler.Select(selection(fixture.key()), replica.registry.Snapshot(), compiler.DefaultLimits().MaxSelectionMatches)
		Expect(selected.Reason).To(BeEmpty(), selected.Message)
		Expect(selected.Matches).To(ConsistOf(HaveField("Name", "access")))
	}, SpecTimeout(time.Minute))

	Context("on a replica that has just started", func() {
		var fixture *sourceFixture
		BeforeEach(func(ctx SpecContext) {
			fixture = newSourceFixture(ctx, "workloads")
			fixture.synchronized(ctx)
			fixture.cachedEventually(ctx, "workloads")
		})

		It("restores the view when the kubeconfig Secret is missing", func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, fixture.secret)).To(Succeed())
			replica := startReplica(k8sClient)
			fixture.expectRegisteredOnlyWithView(replica.registry)

			replica.reconcile(ctx, fixture)
			fixture.expectRestored(replica.registry, api.ReasonInvalidCredential)
		}, SpecTimeout(time.Minute))

		It("restores a Paused source's view without reading its kubeconfig Secret, and keeps it when unpaused", func(ctx SpecContext) {
			fixture.update(ctx, func(spec *api.PolicySourceSpec) { spec.Synchronization = api.SynchronizationPaused })
			replica := startReplica(secretGetRefused{k8sClient})
			fixture.expectRegisteredOnlyWithView(replica.registry)

			replica.reconcile(ctx, fixture)
			fixture.expectRestored(replica.registry, api.ReasonPaused)

			fixture.update(ctx, func(spec *api.PolicySourceSpec) { spec.Synchronization = "Active" })
			replica.supervisor.APIReader = k8sClient
			replica.reconcile(ctx, fixture)
			Expect(replica.registry.Snapshot()[fixture.key()].Documents).To(HaveLen(1))
			Eventually(func() bool { return replica.registry.Health(fixture.key()).Complete }).WithTimeout(convergence).Should(BeTrue())
			Expect(replica.registry.Snapshot()[fixture.key()].Documents).To(HaveLen(1))
		}, SpecTimeout(time.Minute))
	})
})
