package source_test

import (
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/source"
	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("Registry", func() {
	var (
		registry *source.Registry
		local    model.SourceInstance
	)

	BeforeEach(func() {
		registry = source.NewRegistry()
		local = instance("local", "https://control.example")
	})

	It("starts a reader applied before Start once Start runs", func() {
		reader := utils.NewFakeReader()
		Expect(registry.Apply(registration(local, "one"), builds(reader))).To(Succeed())
		Consistently(reader.Emitters()).ShouldNot(Receive())
		startRegistry(registry)
		emit := emitter(reader)
		before := time.Now()
		emit(complete(local, "a"))
		Expect(registry.Snapshot()[local.Key].Documents).To(HaveKey(reference(local.Key, "a")))
		Expect(registry.Health(local.Key)).To(SatisfyAll(
			HaveField("Complete", BeTrue()),
			HaveField("LastAdmitted", SatisfyAll(BeTemporally(">=", before), BeTemporally("<=", time.Now()))),
		))
	})

	It("stops every reader when Start's context ends and refuses later registrations", func() {
		stop := startRegistry(registry)
		reader := utils.NewFakeReader()
		Expect(registry.Apply(registration(local, "one"), builds(reader))).To(Succeed())
		emitter(reader)
		stop()
		Expect(reader.Stopped()).To(BeClosed())
		Expect(registry.Apply(registration(local, "two"), builds(utils.NewFakeReader()))).To(MatchError("source registry is stopped"))
	})

	It("keeps a reader whose registration is current", func() {
		startRegistry(registry)
		reader := utils.NewFakeReader()
		Expect(registry.Apply(registration(local, "one"), builds(reader))).To(Succeed())
		emitter(reader)
		Expect(registry.Apply(registration(local, "one"), func() (source.Reader, error) {
			Fail("a current registration must not build a reader")
			return nil, nil
		})).To(Succeed())
		Expect(reader.Stopped()).NotTo(BeClosed())
	})

	It("narrows the view to a narrowed collection and serves it until the replacement reader completes", func() {
		startRegistry(registry)
		first := utils.NewFakeReader()
		Expect(registry.Apply(registration(local, "one"), builds(first))).To(Succeed())
		emitter(first)(complete(local, "kept", "dropped"))

		second := utils.NewFakeReader()
		withoutDropped := utils.Coverage{Documents: func(reference model.Reference) bool { return reference.Name != "dropped" }}
		Expect(registry.Apply(covered(local, "two", withoutDropped), builds(second))).To(Succeed())
		Expect(first.Stopped()).To(BeClosed())
		emit := emitter(second)
		view := registry.Effective(local.Key)
		Expect(view.Complete).To(BeTrue())
		Expect(view.Documents).To(ConsistOf(HaveField("Digest", "kept")))

		emit(complete(local, "kept", "added"))
		view = registry.Effective(local.Key)
		Expect(view.Documents).To(HaveLen(2))
	})

	It("discards the view when a built reader reads another origin", func() {
		startRegistry(registry)
		first := utils.NewFakeReader()
		Expect(registry.Apply(registration(local, "one"), builds(first))).To(Succeed())
		emitter(first)(complete(local, "a"))

		moved := instance("local", "https://elsewhere.example")
		Expect(registry.Apply(registration(moved, "one"), builds(utils.NewFakeReader()))).To(Succeed())
		view := registry.Effective(local.Key)
		Expect(view.Complete).To(BeFalse())
		Expect(view.Documents).To(BeEmpty())
		health := registry.Health(local.Key)
		Expect(health.Reason).To(Equal(api.ReasonPending))
	})

	It("records a build failure as a credential issue and keeps the running reader", func() {
		startRegistry(registry)
		reader := utils.NewFakeReader()
		Expect(registry.Apply(registration(local, "one"), builds(reader))).To(Succeed())
		emitter(reader)(complete(local, "a"))

		Expect(registry.Apply(registration(local, "two"), func() (source.Reader, error) {
			return nil, errors.New("kubeconfig Secret is missing")
		})).To(Succeed())
		Expect(reader.Stopped()).NotTo(BeClosed())
		health := registry.Health(local.Key)
		Expect(health).To(SatisfyAll(
			HaveField("Complete", BeFalse()),
			HaveField("Reason", api.ReasonInvalidCredential),
			HaveField("Message", "kubeconfig Secret is missing"),
		))
		Expect(registry.Snapshot()[local.Key].Documents).To(HaveLen(1))

		Expect(registry.Apply(registration(local, "one"), builds(utils.NewFakeReader()))).To(Succeed())
		health = registry.Health(local.Key)
		Expect(health.Complete).To(BeTrue())
	})

	It("narrows the view at once to a narrowed collection whose reader fails to build, and narrows what the running reader still observes", func() {
		startRegistry(registry)
		reader := utils.NewFakeReader()
		Expect(registry.Apply(covered(local, "one", everyNamespace), builds(reader))).To(Succeed())
		emit := emitter(reader)
		emit(labeled(complete(local, "kept", "dropped"), map[string]map[string]string{"apps": {"owner": "infra"}}))

		Expect(registry.Apply(covered(local, "two", keptOnly), func() (source.Reader, error) {
			return nil, errors.New("kubeconfig Secret is missing")
		})).To(Succeed())
		Expect(reader.Stopped()).NotTo(BeClosed())
		Expect(registry.Health(local.Key).Reason).To(Equal(api.ReasonInvalidCredential))
		view := registry.Snapshot()[local.Key]
		Expect(view.Documents).To(ConsistOf(HaveField("Digest", "kept")))
		Expect(view.CollectsNamespaceLabels).To(BeFalse())
		Expect(view.NamespaceLabels).To(BeNil())

		emit(labeled(complete(local, "kept", "dropped", "added"), map[string]map[string]string{"apps": {"owner": "netsec"}}))
		view = registry.Snapshot()[local.Key]
		Expect(view.Documents).To(ConsistOf(HaveField("Digest", "kept")))
		Expect(view.CollectsNamespaceLabels).To(BeFalse())
	})

	It("retains the view while acquisition fails and admits the recovery", func() {
		startRegistry(registry)
		reader := utils.NewFakeReader()
		Expect(registry.Apply(registration(local, "one"), builds(reader))).To(Succeed())
		emit := emitter(reader)
		emit(complete(local, "a"))
		admitted := registry.Health(local.Key).LastAdmitted
		emit(failing(local, api.ReasonWatchFailing, "list or watch policies: forbidden"))
		health := registry.Health(local.Key)
		Expect(health).To(Equal(source.Health{Reason: api.ReasonWatchFailing, Message: "list or watch policies: forbidden", LastAdmitted: admitted}))
		Expect(registry.Snapshot()[local.Key].Documents).To(HaveLen(1))

		emit(complete(local, "a"))
		health = registry.Health(local.Key)
		Expect(health.Complete).To(BeTrue())
	})

	It("notifies only observations that change documents or health", func() {
		startRegistry(registry)
		keys := notifications(registry)
		reader := utils.NewFakeReader()
		Expect(registry.Apply(registration(local, "one"), builds(reader))).To(Succeed())
		Eventually(keys).Should(Receive(Equal(local.Key)))
		emit := emitter(reader)
		emit(complete(local, "a"))
		Expect(keys).To(Receive(Equal(local.Key)))
		emit(complete(local, "a"))
		Expect(keys).NotTo(Receive())
		emit(failing(local, api.ReasonWatchFailing, "forbidden"))
		Expect(keys).To(Receive(Equal(local.Key)))
		emit(failing(local, api.ReasonWatchFailing, "forbidden"))
		Expect(keys).NotTo(Receive())
	})

	It("notifies label-only changes to documents", func() {
		startRegistry(registry)
		keys := notifications(registry)
		reader := utils.NewFakeReader()
		Expect(registry.Apply(registration(local, "one"), builds(reader))).To(Succeed())
		Eventually(keys).Should(Receive(Equal(local.Key)))
		emit := emitter(reader)
		observation := complete(local, "a")
		emit(observation)
		Expect(keys).To(Receive(Equal(local.Key)))
		relabeled := complete(local, "a")
		state := relabeled.Documents[reference(local.Key, "a")]
		state.Labels = map[string]string{"entry": "app"}
		relabeled.Documents[reference(local.Key, "a")] = state
		emit(relabeled)
		Expect(keys).To(Receive(Equal(local.Key)))
		Expect(registry.Snapshot()[local.Key].Documents[reference(local.Key, "a")].Labels).To(Equal(map[string]string{"entry": "app"}))
		emit(observation)
		Expect(keys).To(Receive(Equal(local.Key)))
	})

	It("notifies changes to namespace labels and to whether they're collected", func() {
		startRegistry(registry)
		keys := notifications(registry)
		reader := utils.NewFakeReader()
		Expect(registry.Apply(covered(local, "one", everyNamespace), builds(reader))).To(Succeed())
		Eventually(keys).Should(Receive(Equal(local.Key)))
		emit := emitter(reader)
		emit(labeled(complete(local, "a"), map[string]map[string]string{"apps": {"owner": "infra"}}))
		Expect(keys).To(Receive(Equal(local.Key)))
		emit(labeled(complete(local, "a"), map[string]map[string]string{"apps": {"owner": "infra"}}))
		Expect(keys).NotTo(Receive())
		emit(labeled(complete(local, "a"), map[string]map[string]string{"apps": {"owner": "netsec"}}))
		Expect(keys).To(Receive(Equal(local.Key)))
		Expect(registry.Snapshot()[local.Key].NamespaceLabels).To(Equal(map[string]map[string]string{"apps": {"owner": "netsec"}}))
		emit(labeled(complete(local, "a"), map[string]map[string]string{}))
		Expect(keys).To(Receive(Equal(local.Key)))
		emit(complete(local, "a"))
		Expect(keys).To(Receive(Equal(local.Key)))
		Expect(registry.Snapshot()[local.Key].CollectsNamespaceLabels).To(BeFalse())
	})

	It("narrows namespace labels to a narrowed collection, and drops them for one that reads none", func() {
		startRegistry(registry)
		first := utils.NewFakeReader()
		Expect(registry.Apply(covered(local, "one", everyNamespace), builds(first))).To(Succeed())
		emitter(first)(labeled(complete(local, "a"), map[string]map[string]string{"kept": {"owner": "infra"}, "dropped": {"owner": "infra"}}))

		second := utils.NewFakeReader()
		keptNamespace := utils.Coverage{Namespaces: func(namespace string) bool { return namespace == "kept" }}
		Expect(registry.Apply(covered(local, "two", keptNamespace), builds(second))).To(Succeed())
		emitter(second)
		view := registry.Effective(local.Key)
		Expect(view.CollectsNamespaceLabels).To(BeTrue())
		Expect(view.NamespaceLabels).To(Equal(map[string]map[string]string{"kept": {"owner": "infra"}}))

		third := utils.NewFakeReader()
		Expect(registry.Apply(registration(local, "three"), builds(third))).To(Succeed())
		emitter(third)
		view = registry.Effective(local.Key)
		Expect(view.Complete).To(BeTrue())
		Expect(view.CollectsNamespaceLabels).To(BeFalse())
		Expect(view.NamespaceLabels).To(BeNil())
	})

	It("toggles contribution without replacing the reader", func() {
		startRegistry(registry)
		keys := notifications(registry)
		reader := utils.NewFakeReader()
		Expect(registry.Apply(registration(local, "one"), builds(reader))).To(Succeed())
		emitter(reader)(complete(local, "a"))
		Eventually(keys).Should(HaveLen(2))
		for range 2 {
			Expect(keys).To(Receive(Equal(local.Key)))
		}

		inert := registration(local, "one")
		inert.Settings.Contribution = api.ContributionInert
		Expect(registry.Apply(inert, builds(utils.NewFakeReader()))).To(Succeed())
		Expect(keys).To(Receive(Equal(local.Key)))
		snapshot := registry.Snapshot()[local.Key]
		Expect(snapshot.Complete).To(BeFalse())
		Expect(snapshot.Documents).To(BeEmpty())
		Expect(snapshot.Failure.Reason).To(Equal(string(api.ContributionInert)))
		view := registry.Effective(local.Key)
		Expect(view.Documents).To(HaveLen(1))

		Expect(registry.Apply(registration(local, "one"), builds(utils.NewFakeReader()))).To(Succeed())
		Expect(registry.Snapshot()[local.Key].Documents).To(HaveLen(1))
		Expect(reader.Stopped()).NotTo(BeClosed())
	})

	It("carries allowed builtins on a complete view without replacing the reader", func() {
		startRegistry(registry)
		keys := notifications(registry)
		reader := utils.NewFakeReader()
		Expect(registry.Apply(registration(local, "one"), builds(reader))).To(Succeed())
		emitter(reader)(complete(local, "a"))
		Eventually(keys).Should(HaveLen(2))
		for range 2 {
			Expect(keys).To(Receive(Equal(local.Key)))
		}
		Expect(registry.Snapshot()[local.Key].AllowedBuiltins).To(BeNil())

		rego := registration(local, "one")
		rego.Settings.AllowedBuiltins = new(model.NewBuiltinSet([]string{"startswith"}))
		Expect(registry.Apply(rego, builds(utils.NewFakeReader()))).To(Succeed())
		Expect(keys).To(Receive(Equal(local.Key)))
		Expect(registry.Snapshot()[local.Key].AllowedBuiltins).To(HaveValue(Equal(model.BuiltinSet{"startswith"})))
		Expect(registry.Effective(local.Key).AllowedBuiltins).To(BeNil())

		same := registration(local, "one")
		same.Settings.AllowedBuiltins = new(model.NewBuiltinSet([]string{"startswith"}))
		Expect(registry.Apply(same, builds(utils.NewFakeReader()))).To(Succeed())
		Expect(keys).NotTo(Receive())

		same.Settings.Contribution = api.ContributionInert
		Expect(registry.Apply(same, builds(utils.NewFakeReader()))).To(Succeed())
		Expect(keys).To(Receive(Equal(local.Key)))
		Expect(registry.Snapshot()[local.Key].AllowedBuiltins).To(BeNil())
		Expect(reader.Stopped()).NotTo(BeClosed())
	})

	It("restores a view only while the source has none", func() {
		startRegistry(registry)
		registry.Restore(complete(local, "cached"))
		Expect(registry.Snapshot()).NotTo(HaveKey(local.Key), "a restored source contributes once registered")
		reader := utils.NewFakeReader()
		Expect(registry.Apply(registration(local, "one"), builds(reader))).To(Succeed())
		emit := emitter(reader)
		Expect(registry.Snapshot()[local.Key].Documents).To(HaveKey(reference(local.Key, "cached")))
		health := registry.Health(local.Key)
		Expect(health.Reason).To(Equal(api.ReasonPending))

		registry.Restore(complete(local, "stale"))
		Expect(registry.Snapshot()[local.Key].Documents).To(HaveKey(reference(local.Key, "cached")))
		emit(complete(local, "fresh"))
		Expect(registry.Snapshot()[local.Key].Documents).To(HaveKey(reference(local.Key, "fresh")))
	})

	It("pauses a reader and keeps its view until synchronization resumes", func() {
		startRegistry(registry)
		reader := utils.NewFakeReader()
		Expect(registry.Apply(registration(local, "one"), builds(reader))).To(Succeed())
		emitter(reader)(complete(local, "a"))

		registry.Pause(local.Key, local.UID, source.Settings{}, utils.Coverage{})
		Expect(reader.Stopped()).To(BeClosed())
		health := registry.Health(local.Key)
		Expect(health.Reason).To(Equal(api.ReasonPaused))
		Expect(registry.Snapshot()[local.Key].Documents).To(HaveLen(1))

		resumed := utils.NewFakeReader()
		Expect(registry.Apply(registration(local, "one"), builds(resumed))).To(Succeed())
		emitter(resumed)
		Expect(registry.Snapshot()[local.Key].Documents).To(HaveLen(1))
	})

	It("removes a source with its reader and view", func() {
		startRegistry(registry)
		reader := utils.NewFakeReader()
		Expect(registry.Apply(registration(local, "one"), builds(reader))).To(Succeed())
		emit := emitter(reader)
		registry.Remove(local.Key)
		Expect(reader.Stopped()).To(BeClosed())
		emit(complete(local, "late"))
		Expect(registry.Effective(local.Key).Documents).To(BeEmpty())
		_, registered := registry.Registered(local.Key)
		Expect(registered).To(BeFalse())
		Expect(registry.Snapshot()).To(BeEmpty())
	})

	It("snapshots a source without a complete view with only the reason that keeps it incomplete", func() {
		startRegistry(registry)
		reader := utils.NewFakeReader()
		Expect(registry.Apply(registration(local, "one"), builds(reader))).To(Succeed())
		Expect(registry.Snapshot()[local.Key]).To(SatisfyAll(
			HaveField("Complete", BeFalse()),
			HaveField("Failure", model.Failure{Reason: api.ReasonPending}),
		))
		emit := emitter(reader)
		emit(failing(local, api.ReasonWatchFailing, "Get \"https://remote.example.test/api?timeoutSeconds=301\": connection refused"))
		snapshot := registry.Snapshot()
		Expect(snapshot[local.Key].Failure).To(Equal(model.Failure{Reason: api.ReasonWatchFailing}))
		emit(failing(local, api.ReasonWatchFailing, "Get \"https://remote.example.test/api?timeoutSeconds=417\": connection refused"))
		Expect(registry.Health(local.Key).Message).To(ContainSubstring("timeoutSeconds=417"))
		Expect(registry.Snapshot()).To(Equal(snapshot))
	})

	It("counts each time acquisition starts failing", func() {
		startRegistry(registry)
		reader := utils.NewFakeReader()
		Expect(registry.Apply(registration(local, "one"), builds(reader))).To(Succeed())
		emit := emitter(reader)
		before := acquisitionFailures(local.Key)
		emit(failing(local, api.ReasonWatchFailing, "connection refused"))
		emit(failing(local, api.ReasonWatchFailing, "forbidden"))
		emit(failing(local, api.ReasonIncompatibleSchema, "CRD policies.authorization.zctx.io is not installed"))
		Expect(acquisitionFailures(local.Key) - before).To(Equal(1.0))
		emit(complete(local, "a"))
		emit(failing(local, api.ReasonWatchFailing, "forbidden"))
		Expect(acquisitionFailures(local.Key) - before).To(Equal(2.0))
	})

	Context("registration", func() {
		It("reports an unknown source as unregistered, pending and empty", func() {
			_, registered := registry.Registered(local.Key)
			Expect(registered).To(BeFalse())
			Expect(registry.Health(local.Key).Reason).To(Equal(api.ReasonPending))
			Expect(registry.Effective(local.Key).Documents).To(BeEmpty())
		})

		It("records the UID before building a reader and notifies once it's visible", func() {
			startRegistry(registry)
			keys := make(chan string, 4)
			registry.Subscribe(func(key model.SourceKey) {
				uid, _ := registry.Registered(key)
				keys <- uid
			})
			Expect(registry.Apply(registration(local, "one"), func() (source.Reader, error) {
				uid, registered := registry.Registered(local.Key)
				Expect(registered).To(BeTrue())
				Expect(uid).To(Equal(local.UID))
				return nil, errors.New("kubeconfig Secret is missing")
			})).To(Succeed())
			Expect(keys).To(Receive(Equal(local.UID)))
			Expect(keys).NotTo(Receive())
			Expect(registry.Snapshot()).To(HaveKey(local.Key))
		})

		It("stops the old reader and discards the view when the UID changes, even when the build fails", func() {
			startRegistry(registry)
			reader := utils.NewFakeReader()
			Expect(registry.Apply(registration(local, "one"), builds(reader))).To(Succeed())
			emitter(reader)(complete(local, "a"))

			recreated := local
			recreated.UID = "recreated-uid"
			Expect(registry.Apply(registration(recreated, "one"), func() (source.Reader, error) {
				return nil, errors.New("kubeconfig Secret is missing")
			})).To(Succeed())
			Expect(reader.Stopped()).To(BeClosed())
			uid, _ := registry.Registered(local.Key)
			Expect(uid).To(Equal(recreated.UID))
			view := registry.Snapshot()[local.Key]
			Expect(view.Complete).To(BeFalse())
			Expect(view.Documents).To(BeEmpty())
			Expect(registry.Health(local.Key).Reason).To(Equal(api.ReasonInvalidCredential))
		})

		It("keeps a restored view's origin when the build fails, and discards it for a reader of another origin", func() {
			startRegistry(registry)
			registry.Restore(complete(local, "cached"))
			unknown := local
			unknown.Origin = ""
			Expect(registry.Apply(registration(unknown, "broken"), func() (source.Reader, error) {
				return nil, errors.New("kubeconfig Secret is missing")
			})).To(Succeed())
			view := registry.Snapshot()[local.Key]
			Expect(view.Instance).To(Equal(local))
			Expect(view.Documents).To(HaveKey(reference(local.Key, "cached")))

			moved := instance("local", "https://elsewhere.example")
			reader := utils.NewFakeReader()
			Expect(registry.Apply(registration(moved, "fixed"), builds(reader))).To(Succeed())
			emitter(reader)
			view = registry.Snapshot()[local.Key]
			Expect(view.Instance).To(Equal(moved))
			Expect(view.Documents).To(BeEmpty())
		})

		It("keeps a view restored for a UID that replaces the registered one", func() {
			startRegistry(registry)
			Expect(registry.Apply(registration(local, "one"), func() (source.Reader, error) {
				return nil, errors.New("kubeconfig Secret is missing")
			})).To(Succeed())
			recreated := local
			recreated.UID = "recreated-uid"
			registry.Restore(complete(recreated, "cached"))
			uid, _ := registry.Registered(local.Key)
			Expect(uid).To(Equal(local.UID))

			registry.Pause(local.Key, recreated.UID, source.Settings{}, utils.Coverage{})
			Expect(registry.Snapshot()[local.Key].Documents).To(HaveKey(reference(local.Key, "cached")))
		})

		It("discards a view the replaced UID's reader admits after a restore for the new UID", func() {
			startRegistry(registry)
			reader := utils.NewFakeReader()
			Expect(registry.Apply(registration(local, "one"), builds(reader))).To(Succeed())
			emit := emitter(reader)
			recreated := local
			recreated.UID = "recreated-uid"
			registry.Restore(complete(recreated, "cached"))
			emit(complete(local, "former"))

			registry.Pause(local.Key, recreated.UID, source.Settings{}, utils.Coverage{})
			Expect(registry.Snapshot()[local.Key].Documents).To(BeEmpty())
		})

		It("narrows a paused view to a narrowed collection and discards it for another UID", func() {
			startRegistry(registry)
			registry.Restore(complete(local, "kept", "dropped"))
			registry.Pause(local.Key, local.UID, source.Settings{}, keptOnly)
			view := registry.Snapshot()[local.Key]
			Expect(view.Complete).To(BeTrue())
			Expect(view.Documents).To(ConsistOf(HaveField("Digest", "kept")))
			Expect(registry.Health(local.Key).Reason).To(Equal(api.ReasonPaused))

			registry.Pause(local.Key, "recreated-uid", source.Settings{}, utils.Coverage{})
			Expect(registry.Snapshot()[local.Key].Documents).To(BeEmpty())
		})

		It("drops a paused view's namespace labels for a collection that reads none", func() {
			startRegistry(registry)
			registry.Restore(labeled(complete(local, "kept"), map[string]map[string]string{"apps": {"owner": "infra"}}))
			registry.Pause(local.Key, local.UID, source.Settings{}, utils.Coverage{})
			view := registry.Snapshot()[local.Key]
			Expect(view.Documents).To(HaveLen(1))
			Expect(view.CollectsNamespaceLabels).To(BeFalse())
			Expect(view.NamespaceLabels).To(BeNil())
		})

		It("keeps a paused view when synchronization resumes", func() {
			startRegistry(registry)
			registry.Restore(complete(local, "cached"))
			registry.Pause(local.Key, local.UID, source.Settings{}, utils.Coverage{})
			reader := utils.NewFakeReader()
			Expect(registry.Apply(registration(local, "one"), builds(reader))).To(Succeed())
			emitter(reader)
			Expect(registry.Snapshot()[local.Key].Documents).To(HaveKey(reference(local.Key, "cached")))
			Expect(registry.Health(local.Key).Reason).To(Equal(api.ReasonPending))
		})
	})
})
