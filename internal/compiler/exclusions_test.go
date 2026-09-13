package compiler_test

import (
	"context"
	"slices"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/test/utils"
)

// matchingExclusions returns the exclusion proofs alice's list of resource
// in namespace reaches under the deciding authority, and the decision.
func matchingExclusions(ctx context.Context, program model.PreparedRevision, namespace, resource string) ([]model.ExclusionProof, model.Decision) {
	GinkgoHelper()
	evaluation, err := utils.Evaluate(ctx, program, "cluster", utils.SubjectAccessReview("alice", "list", resource, namespace))
	Expect(err).NotTo(HaveOccurred())
	var result []model.ExclusionProof
	for id, proof := range program.Exclusions {
		if slices.Contains(evaluation.Terminals[proof.DiagramID], id) {
			result = append(result, proof)
		}
	}
	return result, evaluation.Decision
}

var _ = Describe("Contextual exclusion provenance", func() {
	var f *fixture
	BeforeEach(func() {
		f = newFixture()
	})
	It("retains removed regions and qualified paths alongside an independent Allow", func(ctx SpecContext) {
		f.custom(model.KindPolicy, "limited", `{"include":[{"verbs":["list"],"apiGroups":[""],"resources":["pods","secrets"]}],"exclude":[{"verbs":["list"],"apiGroups":[""],"resources":["secrets"],"namespaces":["kube-system"]}]}`)
		f.custom(model.KindPolicy, "all", `{"include":[{"verbs":["*"],"apiGroups":["*"],"resources":["*"]}]}`)
		f.custom(model.KindPolicyBinding, "limited", `{"policyRef":{"name":"limited"},"subjects":[{"kind":"User","name":"alice"}]}`)
		f.custom(model.KindPolicyBinding, "independent", `{"policyRef":{"name":"all"},"subjects":[{"kind":"User","name":"alice"}]}`)
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"limited"},{"name":"independent"}]}`)
		program := f.compile().Prepared
		proofs, decision := matchingExclusions(ctx, program, "", "secrets")
		Expect(decision.Result).To(Equal(model.Result("Allow")))
		Expect(proofs).To(HaveLen(1))
		Expect(proofs[0].Path).To(HaveExactElements(HaveField("Name", "entry"), HaveField("Name", "root"), HaveField("Name", "limited"), HaveField("Name", "limited")))
		for _, key := range proofs[0].Path {
			Expect(key.Source).To(Equal(f.source))
		}
		for _, request := range [][2]string{{"tenant", "secrets"}, {"", "pods"}, {"kube-system", "configmaps"}} {
			proofs, _ = matchingExclusions(ctx, program, request[0], request[1])
			Expect(proofs).To(BeEmpty(), "%v", request)
		}
	})
	It("narrows an imported permission's exclusion through delegation bounds", func(ctx SpecContext) {
		f.put(utils.NativeDocument(model.KindClusterRole, "", "imported", `{"rules":[{"verbs":["list"],"apiGroups":[""],"resources":["secrets"]}]}`))
		f.custom(model.KindPolicy, "limited", `{"include":[],"imports":[{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":"imported","namespaces":["tenant","other"]}],"exclude":[{"verbs":["list"],"apiGroups":[""],"resources":["secrets"]}]}`)
		f.custom(model.KindPolicy, "bound", `{"include":[{"verbs":["*"],"apiGroups":["*"],"resources":["*"],"namespaces":["tenant"]}]}`)
		f.custom(model.KindPolicyBinding, "reader", `{"policyRef":{"name":"limited"},"subjects":[{"kind":"User","name":"alice"}]}`)
		f.custom(model.KindPolicySet, "child", `{"bindingRefs":[{"name":"reader"}]}`)
		f.custom(model.KindPolicyBinding, "edge", `{"policyRef":{"name":"child","kind":"PolicySet"},"constraints":{"policyRef":{"name":"bound"}},"subjectMatch":{}}`)
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"edge"}]}`)
		program := f.compile().Prepared
		proofs, _ := matchingExclusions(ctx, program, "tenant", "secrets")
		Expect(proofs).To(HaveLen(1))
		for _, request := range [][2]string{{"other", "secrets"}, {"tenant", "pods"}} {
			proofs, _ = matchingExclusions(ctx, program, request[0], request[1])
			Expect(proofs).To(BeEmpty(), "%v", request)
		}
	})
})
