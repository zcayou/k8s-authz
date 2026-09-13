package kubernetes_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/internal/source/kubernetes"
)

var _ = Describe("Collection", func() {
	It("sorts each range and the ranges, and drops duplicate ranges", func() {
		Expect(kubernetes.NewCollection([]api.KeyRange{
			{Kinds: []string{model.KindPolicySet, model.KindPolicy}, Namespaces: []string{"team-b", "team-a"}, Names: []string{"*"}},
			{Kinds: []string{"ClusterRoleBinding", "ClusterRole"}, Names: []string{"view"}},
			{Kinds: []string{model.KindPolicy, model.KindPolicySet}, Namespaces: []string{"team-a", "team-b"}, Names: []string{"*"}},
		})).To(Equal(kubernetes.Collection{
			collection([]string{"ClusterRole", "ClusterRoleBinding"}, nil, "view"),
			collection([]string{model.KindPolicy, model.KindPolicySet}, []string{"team-a", "team-b"}, "*"),
		}))
		Expect(kubernetes.NewCollection(nil)).To(BeEmpty())
	})

	It("reports the references it covers", func() {
		covered := kubernetes.Collection{
			collection([]string{model.KindPolicy}, []string{teamNamespace}, "*"),
			collection([]string{"ClusterRole"}, nil, "view"),
		}
		reference := func(group, kind, namespace, name string) model.Reference {
			return model.Reference{Source: source.Key, Group: group, Kind: kind, Namespace: namespace, Name: name}
		}
		Expect(covered.Collects(reference(api.GroupVersion.Group, model.KindPolicy, teamNamespace, "any"))).To(BeTrue())
		Expect(covered.Collects(reference(api.GroupVersion.Group, model.KindPolicy, "other", "any"))).To(BeFalse())
		Expect(covered.Collects(reference(api.GroupVersion.Group, model.KindPolicySet, teamNamespace, "any"))).To(BeFalse())
		Expect(covered.Collects(reference(rbacv1.GroupName, model.KindPolicy, teamNamespace, "any"))).To(BeFalse())
		Expect(covered.Collects(reference(rbacv1.GroupName, "ClusterRole", "", "view"))).To(BeTrue())
		Expect(covered.Collects(reference(rbacv1.GroupName, "ClusterRole", "", "edit"))).To(BeFalse())
	})
})
