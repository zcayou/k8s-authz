package kubernetes_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	clienttesting "k8s.io/client-go/testing"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/source/kubernetes"
)

// listed runs a reader for collection and returns the resource, namespace
// and field selector of each list request it made.
func listed(ctx context.Context, collection kubernetes.Collection) []string {
	GinkgoHelper()
	client := fakeClient(documentCRD("policies", true))
	reader := kubernetes.NewReader(client, source, collection)
	Eventually(run(ctx, reader)).Should(Receive())
	var requests []string
	for _, action := range client.Actions() {
		if list, ok := action.(clienttesting.ListAction); ok {
			requests = append(requests, list.GetResource().Resource+" "+list.GetNamespace()+" "+list.GetListRestrictions().Fields.String())
		}
	}
	return requests
}

var _ = Describe("Query planning", func() {
	It("lists each named object through its own field selector", func(ctx SpecContext) {
		Expect(listed(ctx, collects(collection([]string{model.KindPolicy}, []string{teamNamespace}, "a", "b")))).To(ConsistOf(
			"policies team metadata.name=a",
			"policies team metadata.name=b",
			"customresourcedefinitions  metadata.name=policies."+api.GroupVersion.Group,
		))
	})

	It("drops queries a broader query covers", func(ctx SpecContext) {
		Expect(listed(ctx, collects(
			collection([]string{model.KindPolicy}, []string{teamNamespace}, "a", "*"),
			collection([]string{model.KindPolicy}, []string{"*"}, "b"),
			collection([]string{model.KindPolicy}, []string{teamNamespace}, "b"),
		))).To(ConsistOf(
			"policies team ",
			"policies  metadata.name=b",
			"customresourcedefinitions  metadata.name=policies."+api.GroupVersion.Group,
		))
	})

	It("lists cluster-scoped kinds without a namespace and checks no CRD for native kinds", func(ctx SpecContext) {
		Expect(listed(ctx, collects(collection([]string{"ClusterRole"}, nil, "view")))).To(ConsistOf("clusterroles  metadata.name=view"))
	})

	It("lists each named namespace whose labels it reads through its own field selector", func(ctx SpecContext) {
		collection := collects(
			collection([]string{"Role"}, []string{teamNamespace, "other"}, "*"),
			collection([]string{"Role"}, []string{teamNamespace}, "view"),
			collection([]string{"ClusterRole"}, nil, "view"),
		)
		collection.NamespaceLabels = true
		Expect(listed(ctx, collection)).To(ConsistOf(
			"roles team ",
			"roles other ",
			"clusterroles  metadata.name=view",
			"namespaces  metadata.name=team",
			"namespaces  metadata.name=other",
		))
	})

	It("lists every namespace when a range selects every namespace", func(ctx SpecContext) {
		collection := collects(collection([]string{"Role"}, []string{teamNamespace}, "*"), collection([]string{"Role"}, []string{"*"}, "view"))
		collection.NamespaceLabels = true
		Expect(listed(ctx, collection)).To(ConsistOf("roles team ", "roles  metadata.name=view", "namespaces  "))
	})
})
