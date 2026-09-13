package storage_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"slices"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/source/storage"
	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("Source cache", func() {
	var (
		owner    *api.PolicySource
		instance model.SourceInstance
		secrets  client.Client
	)

	BeforeEach(func() {
		owner = &api.PolicySource{ObjectMeta: metav1.ObjectMeta{Namespace: "control", Name: "platform", UID: "platform-uid"}}
		instance = model.SourceInstance{Key: model.SourceKey{Namespace: owner.Namespace, Name: owner.Name}, UID: string(owner.UID), Origin: "https://platform.example"}
		scheme := runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(api.AddToScheme(scheme)).To(Succeed())
		secrets = fake.NewClientBuilder().WithScheme(scheme).Build()
	})

	// view returns a complete view of one Policy per note, each annotated
	// with its note.
	view := func(notes ...string) model.SourceObservation {
		observation := model.SourceObservation{Instance: instance, Complete: true, Documents: map[model.Reference]model.DocumentState{}}
		for index, note := range notes {
			object := utils.Document(model.KindPolicy, "policies", fmt.Sprintf("policy-%d", index), `{"include":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"],"namespaces":["*"]}]}`)
			object.SetAnnotations(map[string]string{"note": note})
			state, err := utils.AcquiredDocument(instance, object)
			Expect(err).NotTo(HaveOccurred())
			Expect(state.Document).NotTo(BeNil(), "%v", state.Issues)
			observation.Documents[state.Key.Reference()] = state
		}
		return observation
	}

	write := func(ctx context.Context, observation model.SourceObservation) {
		GinkgoHelper()
		Expect(storage.Write(ctx, client.WithFieldOwner(secrets, "k8s-authz-test"), secrets, owner, observation)).To(Succeed())
	}

	cached := func(ctx context.Context) []corev1.Secret {
		GinkgoHelper()
		var list corev1.SecretList
		Expect(secrets.List(ctx, &list, client.InNamespace(owner.Namespace))).To(Succeed())
		return list.Items
	}

	// versions returns the resourceVersion of each cache Secret by name.
	versions := func(ctx context.Context) map[string]string {
		GinkgoHelper()
		result := map[string]string{}
		for _, secret := range cached(ctx) {
			result[secret.Name] = secret.ResourceVersion
		}
		return result
	}

	expectRestored := func(ctx context.Context, expected model.SourceObservation) {
		GinkgoHelper()
		restored, found, err := storage.Read(ctx, secrets, instance)
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(restored.Complete).To(BeTrue())
		Expect(restored.Instance).To(Equal(instance))
		Expect(restored.Documents).To(HaveLen(len(expected.Documents)))
		for reference, state := range expected.Documents {
			Expect(restored.Documents).To(HaveKey(reference))
			Expect(restored.Documents[reference].Digest).To(Equal(state.Digest))
			Expect(restored.Documents[reference].Object).To(MatchJSON(state.Object))
		}
		written := versions(ctx)
		write(ctx, restored)
		Expect(versions(ctx)).To(Equal(written), "writing the restored view changes the cache")
	}

	expectDiscarded := func(ctx context.Context) {
		GinkgoHelper()
		_, found, err := storage.Read(ctx, secrets, instance)
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeFalse())
	}

	It("restores what it wrote into Secrets the PolicySource controls", func(ctx SpecContext) {
		written := view("one", "two")
		write(ctx, written)
		Expect(cached(ctx)).To(ConsistOf(SatisfyAll(
			HaveField("Type", corev1.SecretType("authorization.zctx.io/source-cache")),
			HaveField("ObjectMeta.OwnerReferences", ConsistOf(HaveField("UID", owner.UID))),
		)))
		expectRestored(ctx, written)
	})

	It("reports no cache for a source that has none", func(ctx SpecContext) {
		expectDiscarded(ctx)
	})

	It("leaves a cache that holds the view unchanged", func(ctx SpecContext) {
		written := view("one")
		write(ctx, written)
		unchanged := versions(ctx)
		write(ctx, written)
		Expect(versions(ctx)).To(Equal(unchanged))
	})

	It("rewrites a chunk deleted out of band", func(ctx SpecContext) {
		written := view("one")
		write(ctx, written)
		Expect(secrets.Delete(ctx, &cached(ctx)[0])).To(Succeed())
		write(ctx, written)
		expectRestored(ctx, written)
	})

	It("rewrites a chunk whose digest was edited out of band", func(ctx SpecContext) {
		written := view("one")
		write(ctx, written)
		secret := cached(ctx)[0]
		secret.Annotations["authorization.zctx.io/cache-digest"] = "other"
		Expect(secrets.Update(ctx, &secret)).To(Succeed())
		expectDiscarded(ctx)
		write(ctx, written)
		expectRestored(ctx, written)
	})

	It("rewrites a view whose documents are unchanged under its new origin", func(ctx SpecContext) {
		write(ctx, view("one"))
		instance.Origin = "https://moved.example"
		moved := view("one")
		write(ctx, moved)
		expectRestored(ctx, moved)
	})

	Context("with a view larger than one Secret", func() {
		var large model.SourceObservation
		BeforeEach(func(ctx SpecContext) {
			notes := make([]string, 4)
			for index := range notes {
				random := make([]byte, 192<<10)
				_, err := rand.Read(random)
				Expect(err).NotTo(HaveOccurred())
				notes[index] = base64.StdEncoding.EncodeToString(random)
			}
			large = view(notes...)
			write(ctx, large)
		})

		It("splits the view across chunks", func(ctx SpecContext) {
			Expect(len(cached(ctx))).To(BeNumerically(">", 1))
			expectRestored(ctx, large)
		})

		It("deletes the chunks a smaller view no longer needs", func(ctx SpecContext) {
			small := view("small")
			write(ctx, small)
			Expect(cached(ctx)).To(HaveLen(1))
			expectRestored(ctx, small)
		})

		It("rewrites a view missing its last chunk", func(ctx SpecContext) {
			chunks := cached(ctx)
			last := slices.IndexFunc(chunks, func(secret corev1.Secret) bool {
				return secret.Labels["authorization.zctx.io/cache-chunk"] == strconv.Itoa(len(chunks)-1)
			})
			Expect(last).NotTo(Equal(-1))
			Expect(secrets.Delete(ctx, &chunks[last])).To(Succeed())
			expectDiscarded(ctx)
			write(ctx, large)
			Expect(cached(ctx)).To(HaveLen(len(chunks)))
			expectRestored(ctx, large)
		})
	})

	It("discards a cache collected from another origin", func(ctx SpecContext) {
		write(ctx, view("one"))
		instance.Origin = "https://elsewhere.example"
		expectDiscarded(ctx)
	})

	It("restores a cache under the origin it recorded when no origin is expected", func(ctx SpecContext) {
		written := view("one")
		write(ctx, written)
		restored, found, err := storage.Read(ctx, secrets, model.SourceInstance{Key: instance.Key, UID: instance.UID})
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(restored.Instance).To(Equal(instance))
		Expect(restored.Documents).To(HaveLen(1))
		for _, state := range restored.Documents {
			Expect(state.Key.Source).To(Equal(instance))
		}
	})

	It("restores a document holding a field the current schema removed as Valid", func(ctx SpecContext) {
		state, err := utils.AcquiredDocument(instance, utils.Document(model.KindPolicy, "policies", "retired", `{"include":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"],"namespaces":["*"],"retired":true}]}`))
		Expect(err).NotTo(HaveOccurred())
		Expect(state.Document).To(BeNil(), "a live document is decoded strictly")
		write(ctx, model.SourceObservation{Instance: instance, Complete: true, Documents: map[model.Reference]model.DocumentState{state.Key.Reference(): state}})
		restored, found, err := storage.Read(ctx, secrets, instance)
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(restored.Documents).To(HaveKeyWithValue(state.Key.Reference(), SatisfyAll(
			HaveField("Document", Not(BeNil())),
			HaveField("Object", MatchJSON(state.Object)),
		)))
	})

	It("discards chunks that disagree on the digest", func(ctx SpecContext) {
		write(ctx, view("one"))
		secret := cached(ctx)[0]
		secret.Annotations["authorization.zctx.io/cache-digest"] = "other"
		Expect(secrets.Update(ctx, &secret)).To(Succeed())
		expectDiscarded(ctx)
	})

	It("ignores Secrets a replaced PolicySource controls", func(ctx SpecContext) {
		write(ctx, view("one"))
		instance.UID = "replacement-uid"
		expectDiscarded(ctx)
	})

	It("marks each chunk controlled by its PolicySource, blocking the owner's deletion", func(ctx SpecContext) {
		write(ctx, view("one"))
		Expect(cached(ctx)).To(ConsistOf(HaveField("ObjectMeta.OwnerReferences", ConsistOf(SatisfyAll(
			HaveField("UID", owner.UID),
			HaveField("Controller", HaveValue(BeTrue())),
			HaveField("BlockOwnerDeletion", HaveValue(BeTrue())),
		)))))
	})
})
