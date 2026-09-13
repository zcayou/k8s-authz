package validation_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("Permission-rule normalization", func() {
	It("retains the conservative namespace footprint", func() {
		named, err := policyInclude(api.OperationRule{Verbs: []string{"list"}, APIGroups: []string{""}, Resources: []string{"secrets"}, Namespaces: []string{"elastic-system"}})
		Expect(err).NotTo(HaveOccurred())
		Expect(named).To(HaveLen(1))
		Expect(named[0]).NotTo(HaveKey(model.IngressNamespace))
		Expect(named[0][model.AffectedNamespace].Contains(model.Atom("elastic-system"))).To(BeTrue())
		Expect(named[0][model.AffectedNamespace].Contains(utils.NamespaceWitness)).To(BeFalse())

		allNamed, err := policyInclude(api.OperationRule{Verbs: []string{"list"}, APIGroups: []string{""}, Resources: []string{"secrets"}, Namespaces: []string{"*"}})
		Expect(err).NotTo(HaveOccurred())
		Expect(allNamed[0][model.AffectedNamespace].Contains(model.Atom("other"))).To(BeTrue())
		Expect(allNamed[0][model.AffectedNamespace].Contains(utils.NamespaceWitness)).To(BeFalse())

		allNamespaceRequest, err := policyInclude(api.OperationRule{Verbs: []string{"list"}, APIGroups: []string{""}, Resources: []string{"secrets"}, Namespaces: []string{""}})
		Expect(err).NotTo(HaveOccurred())
		Expect(allNamespaceRequest[0][model.IngressNamespace].Contains(model.Atom(""))).To(BeTrue())
		Expect(allNamespaceRequest[0]).NotTo(HaveKey(model.AffectedNamespace))
	})

	It("keeps resource and subresource pairs distinct", func() {
		cubes, err := policyInclude(api.OperationRule{Verbs: []string{"get"}, APIGroups: []string{"apps"}, Resources: []string{"deployments", "*/scale"}})
		Expect(err).NotTo(HaveOccurred())
		resources := cubes[0][model.Resource]
		Expect(resources.Contains(model.Atom("\x00deployments"))).To(BeTrue())
		Expect(resources.Contains(model.Atom("scale\x00deployments"))).To(BeTrue())
		Expect(resources.Contains(model.Atom("log\x00pods"))).To(BeFalse())
		_, err = policyInclude(api.OperationRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods/*"}})
		Expect(err).To(MatchError(ContainSubstring("invalid resource")))
	})

	It("intersects repeated selector requirements and rejects contradictions", func() {
		cubes, err := policyInclude(api.OperationRule{
			Verbs:     []string{"list"},
			APIGroups: []string{""},
			Resources: []string{"pods"},
			LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "elk"}, MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key: "team", Operator: metav1.LabelSelectorOpIn, Values: []string{"elk", "netsec"},
			}}},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(cubes[0][model.LabelPrefix+"team"].Contains(model.Atom("elk"))).To(BeTrue())
		Expect(cubes[0][model.LabelPrefix+"team"].Contains(model.Atom("netsec"))).To(BeFalse())

		_, err = policyInclude(api.OperationRule{
			Verbs:     []string{"list"},
			APIGroups: []string{""},
			Resources: []string{"pods"},
			LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "elk"}, MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key: "team", Operator: metav1.LabelSelectorOpDoesNotExist,
			}}},
		})
		Expect(err).To(MatchError(ContainSubstring("contradictory selector")))
	})

	It("normalizes repeated selector values", func() {
		cubes, err := policyInclude(api.OperationRule{
			Verbs:     []string{"list"},
			APIGroups: []string{""},
			Resources: []string{"pods"},
			LabelSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key: "team", Operator: metav1.LabelSelectorOpIn, Values: []string{"elk", "elk"},
			}}},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(cubes[0][model.LabelPrefix+"team"].Key()).To(Equal(model.Values(model.Atom("elk")).Key()))
	})

	DescribeTable("rejects malformed operation shapes",
		func(rule api.OperationRule, fragment string) {
			_, err := policyInclude(rule)
			Expect(err).To(MatchError(ContainSubstring(fragment)))
		},
		Entry("uppercase verb", api.OperationRule{Verbs: []string{"GET"}, APIGroups: []string{""}, Resources: []string{"pods"}}, "invalid verb"),
		Entry("partial wildcard group", api.OperationRule{Verbs: []string{"get"}, APIGroups: []string{"apps*"}, Resources: []string{"pods"}}, "apiGroups"),
		Entry("wildcard resource name", api.OperationRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{"web-*"}}, "invalid resource name"),
		Entry("query string in URL", api.OperationRule{Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz?full=true"}}, "invalid non-resource URL"),
		Entry("inner URL wildcard", api.OperationRule{Verbs: []string{"get"}, NonResourceURLs: []string{"/api/*/pods"}}, "invalid non-resource URL"),
	)
})
