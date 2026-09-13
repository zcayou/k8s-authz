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
func listed(ctx context.Context, collection ...api.KeyRange) []string {
	GinkgoHelper()
	client := fakeClient(policyCRD(true))
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
		Expect(listed(ctx, collection([]string{model.KindPolicy}, []string{teamNamespace}, "a", "b"))).To(ConsistOf(
			"policies team metadata.name=a",
			"policies team metadata.name=b",
			"customresourcedefinitions  metadata.name=policies."+api.GroupVersion.Group,
		))
	})

	It("drops queries a broader query covers", func(ctx SpecContext) {
		Expect(listed(ctx,
			collection([]string{model.KindPolicy}, []string{teamNamespace}, "a", "*"),
			collection([]string{model.KindPolicy}, []string{"*"}, "b"),
			collection([]string{model.KindPolicy}, []string{teamNamespace}, "b"),
		)).To(ConsistOf(
			"policies team ",
			"policies  metadata.name=b",
			"customresourcedefinitions  metadata.name=policies."+api.GroupVersion.Group,
		))
	})

	It("lists cluster-scoped kinds without a namespace and checks no CRD for native kinds", func(ctx SpecContext) {
		Expect(listed(ctx, collection([]string{"ClusterRole"}, nil, "view"))).To(ConsistOf("clusterroles  metadata.name=view"))
	})
})
