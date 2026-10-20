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
		Expect(kubernetes.NewCollection(api.PolicySourceSpec{Collection: []api.KeyRange{
			{Kinds: []string{model.KindPolicySet, model.KindPolicy}, Namespaces: []string{"team-b", "team-a"}, Names: []string{"*"}},
			{Kinds: []string{"ClusterRoleBinding", "ClusterRole"}, Names: []string{"view"}},
			{Kinds: []string{model.KindPolicy, model.KindPolicySet}, Namespaces: []string{"team-a", "team-b"}, Names: []string{"*"}},
		}, NamespaceLabels: api.NamespaceLabelsCollect})).To(Equal(kubernetes.Collection{Ranges: []api.KeyRange{
			collection([]string{"ClusterRole", "ClusterRoleBinding"}, nil, "view"),
			collection([]string{model.KindPolicy, model.KindPolicySet}, []string{"team-a", "team-b"}, "*"),
		}, NamespaceLabels: true}))
		Expect(kubernetes.NewCollection(api.PolicySourceSpec{NamespaceLabels: api.NamespaceLabelsIgnore})).To(Equal(kubernetes.Collection{Ranges: []api.KeyRange{}}))
	})

	It("reports the references it covers", func() {
		covered := collects(
			collection([]string{model.KindPolicy}, []string{teamNamespace}, "*"),
			collection([]string{"ClusterRole"}, nil, "view"),
		)
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

	It("reports the namespaces whose labels it reads", func() {
		named := collects(collection([]string{model.KindPolicySet}, []string{teamNamespace}, "*"), collection([]string{"ClusterRole"}, nil, "view"))
		Expect(named.CollectsNamespaceLabels()).To(BeFalse())
		Expect(named.CollectsNamespace(teamNamespace)).To(BeFalse())
		named.NamespaceLabels = true
		Expect(named.CollectsNamespaceLabels()).To(BeTrue())
		Expect(named.CollectsNamespace(teamNamespace)).To(BeTrue())
		Expect(named.CollectsNamespace("other")).To(BeFalse())
		every := collects(collection([]string{model.KindPolicySet}, []string{"*"}, "access"))
		every.NamespaceLabels = true
		Expect(every.CollectsNamespace("other")).To(BeTrue())
	})
})
