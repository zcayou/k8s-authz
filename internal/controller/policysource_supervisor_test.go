package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/source"
)

var _ = Describe("PolicySource supervisor", func() {
	var registry *source.Registry

	BeforeEach(func() {
		registry = startedRegistry()
	})

	// secretsFail makes reader's Secret reads fail with err.
	secretsFail := func(reader client.WithWatch, err error) client.Reader {
		return interceptor.NewClient(reader, interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, isSecret := obj.(*corev1.Secret); isSecret {
					return err
				}
				return c.Get(ctx, key, obj, opts...)
			},
		})
	}

	expectRestored := func(object *api.PolicySource, reason string) {
		GinkgoHelper()
		uid, registered := registry.Registered(sourceKeyOf(object))
		Expect(registered).To(BeTrue())
		Expect(uid).To(Equal(string(object.UID)))
		view := registry.Snapshot()[sourceKeyOf(object)]
		Expect(view.Complete).To(BeTrue())
		Expect(view.Instance).To(Equal(sourceInstance(object)))
		Expect(view.Documents).To(HaveKey(policyDocument(view.Instance, "workloads").Key.Reference()))
		Expect(registry.Health(sourceKeyOf(object)).Reason).To(Equal(reason))
	}

	DescribeTable("resolves a source's settings", func(rego *api.PolicySourceRego, builtins types.GomegaMatcher) {
		settings := sourceSettings(api.PolicySourceSpec{Contribution: api.ContributionInert, Rego: rego})
		Expect(settings.Contribution).To(Equal(api.ContributionInert))
		Expect(settings.AllowedBuiltins).To(builtins)
	},
		Entry("without rego", nil, BeNil()),
		Entry("with the default builtins", &api.PolicySourceRego{}, HaveValue(Equal(condition.DefaultBuiltins()))),
		Entry("with listed builtins, kept even when undefined", &api.PolicySourceRego{AllowedBuiltins: []string{"startswith", "no.such.builtin", "concat"}},
			HaveValue(Equal(model.BuiltinSet{"concat", "no.such.builtin", "startswith"}))),
		Entry("with no builtins", &api.PolicySourceRego{AllowedBuiltins: []string{}}, HaveValue(BeEmpty())),
	)

	It("maps metadata-only Secret events to sources that select the Secret", func(ctx SpecContext) {
		selected := remotePolicySource("selected", "source-selected", "source-config")
		unrelated := remotePolicySource("unrelated", "source-unrelated", "another-config")
		supervisor := newPolicySourceSupervisor(newPolicySourceFakeClient(selected, unrelated), registry)
		metadata := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "source-config"}}

		Expect(supervisor.policySourcesForSecret(ctx, metadata)).To(ConsistOf(
			reconcile.Request{NamespacedName: client.ObjectKeyFromObject(selected)},
		))
	})

	It("restores the cached view under its recorded origin when the kubeconfig Secret is missing", func(ctx SpecContext) {
		object := remotePolicySource("restarted", "source-restarted", "source-config")
		controlClient := newPolicySourceFakeClient(object)
		cacheView(ctx, controlClient, object, completeView(sourceInstance(object), "workloads"))

		_, err := newPolicySourceSupervisor(controlClient, registry).Reconcile(ctx, policySourceRequestFor(object))
		Expect(err).NotTo(HaveOccurred())
		expectRestored(object, api.ReasonInvalidCredential)
	})

	It("restores a Paused source's cached view without reading its kubeconfig Secret", func(ctx SpecContext) {
		object := remotePolicySource("paused", "source-paused", "source-config")
		object.Spec.Synchronization = api.SynchronizationPaused
		controlClient := newPolicySourceFakeClient(object)
		cacheView(ctx, controlClient, object, completeView(sourceInstance(object), "workloads"))
		supervisor := newPolicySourceSupervisor(controlClient, registry)
		supervisor.APIReader = secretsFail(controlClient, errors.New("the kubeconfig Secret was read"))

		_, err := supervisor.Reconcile(ctx, policySourceRequestFor(object))
		Expect(err).NotTo(HaveOccurred())
		expectRestored(object, api.ReasonPaused)
	})

	It("reports a kubeconfig it can't use without its credential", func(ctx SpecContext) {
		object := remotePolicySource("unusable", "source-unusable", "source-config")
		kubeconfig := bytes.Replace(testKubeconfig("private-token"), []byte("token: private-token"), []byte("token: private-token\n    tokenFile: /var/run/token"), 1)
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: object.Namespace, Name: "source-config", UID: "secret-uid"},
			Data:       map[string][]byte{"kubeconfig": kubeconfig},
		}
		controlClient := newPolicySourceFakeClient(object, secret)
		_, err := newPolicySourceSupervisor(controlClient, registry).Reconcile(ctx, policySourceRequestFor(object))
		Expect(err).NotTo(HaveOccurred())
		_, err = newPolicySourceReconciler(controlClient, registry).Reconcile(ctx, policySourceRequestFor(object))
		Expect(err).NotTo(HaveOccurred())

		status := observedPolicySourceStatus(ctx, controlClient, object)
		Expect(synchronizedCondition(status)).To(HaveField("Reason", api.ReasonInvalidCredential))
		encoded, err := json.Marshal(status)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(encoded)).NotTo(ContainSubstring("private-token"))
	})

	It("leaves the registration alone when the kubeconfig Secret can't be read", func(ctx SpecContext) {
		object := remotePolicySource("unreadable", "source-unreadable", "source-config")
		controlClient := newPolicySourceFakeClient(object)
		reader, emit := runReader(registry, object)
		emit(completeView(sourceInstance(object), "workloads"))
		before := registry.Health(sourceKeyOf(object))
		errUnreadable := errors.New("credential unreadable")
		supervisor := newPolicySourceSupervisor(controlClient, registry)
		supervisor.APIReader = secretsFail(controlClient, errUnreadable)

		_, err := supervisor.Reconcile(ctx, policySourceRequestFor(object))
		Expect(err).To(MatchError(errUnreadable))
		Expect(registry.Health(sourceKeyOf(object))).To(Equal(before))
		Expect(registry.Snapshot()[sourceKeyOf(object)].Documents).To(HaveLen(1))
		Expect(reader.Stopped()).NotTo(BeClosed())
	})

	It("removes a deleted source from the registry", func(ctx SpecContext) {
		object := localPolicySource("deleted", "source-deleted")
		controlClient := newPolicySourceFakeClient(object)
		reader, _ := runReader(registry, object)
		Expect(controlClient.Delete(ctx, object)).To(Succeed())

		_, err := newPolicySourceSupervisor(controlClient, registry).Reconcile(ctx, policySourceRequestFor(object))
		Expect(err).NotTo(HaveOccurred())
		Expect(reader.Stopped()).To(BeClosed())
		_, registered := registry.Registered(sourceKeyOf(object))
		Expect(registered).To(BeFalse())
		Expect(registry.Snapshot()).NotTo(HaveKey(sourceKeyOf(object)))
	})
})
