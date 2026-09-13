package kubernetes_test

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/source/kubernetes"
)

var everyPolicy = []api.KeyRange{{Kinds: []string{model.KindPolicy}, Namespaces: []string{teamNamespace}, Names: []string{"*"}}}

var _ = Describe("Reader", func() {
	It("keeps an invalid document as an issue without failing the view", func(ctx SpecContext) {
		invalid := allowPods()
		invalid["surprise"] = true
		client := fakeClient(policyCRD(true), policy("valid", allowPods()), policy("invalid", invalid))
		reader := kubernetes.NewReader(client, source, everyPolicy)
		var observation model.SourceObservation
		Eventually(run(ctx, reader)).Should(Receive(&observation))
		Expect(observation.Complete).To(BeTrue())
		Expect(observation.Documents).To(HaveLen(2))
		for reference, state := range observation.Documents {
			Expect(state.Key.Source).To(Equal(source))
			if reference.Name == "valid" {
				Expect(state.Document).NotTo(BeNil())
				continue
			}
			Expect(state.Document).To(BeNil())
			Expect(state.Issues).To(ConsistOf(HaveField("Reason", model.ReasonInvalid)))
		}
	})

	It("keeps each document's canonical object without server-managed field history", func(ctx SpecContext) {
		applied := policy("applied", allowPods())
		applied.SetManagedFields([]metav1.ManagedFieldsEntry{{Manager: "kubectl", Operation: metav1.ManagedFieldsOperationApply}})
		applied.SetAnnotations(map[string]string{corev1.LastAppliedConfigAnnotation: "{}", "team": "platform"})
		reader := kubernetes.NewReader(fakeClient(policyCRD(true), applied), source, everyPolicy)
		var observation model.SourceObservation
		Eventually(run(ctx, reader)).Should(Receive(&observation))
		Expect(observation.Documents).To(HaveLen(1))
		for _, state := range observation.Documents {
			var object map[string]any
			Expect(json.Unmarshal(state.Object, &object)).To(Succeed())
			Expect(object["metadata"]).NotTo(HaveKey("managedFields"))
			Expect(object["metadata"]).To(HaveKeyWithValue("annotations", map[string]any{"team": "platform"}))
		}
	})

	DescribeTable("reports IncompatibleSchema without admitting a view",
		func(ctx SpecContext, crds ...runtime.Object) {
			client := fakeClient(append(crds, policy("valid", allowPods()))...)
			reader := kubernetes.NewReader(client, source, everyPolicy)
			var observation model.SourceObservation
			Eventually(run(ctx, reader)).Should(Receive(&observation))
			Expect(observation.Complete).To(BeFalse())
			Expect(observation.Documents).To(BeEmpty())
			Expect(observation.Failure.Reason).To(Equal(api.ReasonIncompatibleSchema))
		},
		Entry("when the CRD doesn't serve v1alpha1", policyCRD(false)),
		Entry("when the CRD is missing"),
	)
})
