package compiler_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
)

var _ = Describe("Compilation diagnostics", func() {
	It("reports a document's warnings for the uses that read it", func() {
		f := newFixture()
		f.custom(model.KindPolicy, "collections", `{"include":[{"verbs":["list"],"apiGroups":[""],"resources":["pods"],"namespaces":["*"]}]}`)
		f.custom(model.KindPolicyBinding, "bound", `{"policyRef":{"name":"collections"},"subjects":[{"kind":"Group","name":"operators"}]}`)
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"bound"}]}`)
		Expect(f.compile().Diagnostics).To(ConsistOf(SatisfyAll(
			HaveField("Severity", api.IssueSeverityWarning),
			HaveField("Reason", model.ReasonAllNamespacesNotGranted),
			HaveField("Document.Name", "collections"),
		)))
	})

	It("keeps diagnostics outside evaluator content and retains a deterministic bounded selection, errors first", func() {
		f := newFixture()
		f.custom(model.KindPolicy, "policy", `{"include":[{"verbs":["get"],"apiGroups":[""],"resources":["pods"]}]}`)
		policyRef := model.Reference{Source: f.source.Key, Group: api.GroupVersion.Group, Kind: model.KindPolicy, Namespace: "policies", Name: "policy"}
		state := f.observation.Documents[policyRef]
		for index := range 129 {
			state.Issues = append(state.Issues, model.Issue{Severity: api.IssueSeverityWarning, Reason: model.IssueReason(fmt.Sprintf("Advisory%03d", index)), Scope: api.IssueScopeDocument, Document: &state.Key})
		}
		f.observation.Documents[policyRef] = state
		f.custom(model.KindPolicyBinding, "bound", `{"policyRef":{"name":"policy"},"subjects":[{"kind":"User","name":"alice"}]}`)
		f.custom(model.KindPolicySet, "root", `{"bindingRefs":[{"name":"bound"},{"name":"missing"}]}`)
		first := f.compile()
		second := f.compile()
		Expect(first.DiagnosticsTruncated).To(BeTrue())
		Expect(first.Diagnostics).To(HaveLen(128))
		Expect(first.Diagnostics[0]).To(SatisfyAll(HaveField("Severity", api.IssueSeverityError), HaveField("Reason", model.ReasonMissingReference)))
		Expect(second.Diagnostics).To(Equal(first.Diagnostics))
		Expect(first.Prepared.Issues).To(BeEmpty())
		Expect(first.Prepared).To(Equal(second.Prepared))
	})
})
