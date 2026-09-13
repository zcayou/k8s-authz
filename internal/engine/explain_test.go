package engine_test

import (
	"context"
	"maps"
	"slices"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/test/utils"
)

var _ = Describe("Offline fixed-evaluator execution", func() {
	It("evaluates installed policy on the raw request", func(ctx SpecContext) {
		state := explanationFixture()
		actual, err := engine.EvaluateSnapshot(ctx, state, "cluster", mustJSON(utils.SubjectAccessReview("alice", "get", "pods", "team-one")))
		Expect(err).NotTo(HaveOccurred())
		Expect(actual.Decision.Result).To(Equal(model.Result("Allow")))
		Expect(actual.Decision.Code).To(Equal("PolicyAllowed"))
		Expect(actual.Principal.User).To(Equal("alice"))
		Expect(actual.Decision.Revision).To(Equal(state.Revision))
	})

	It("reports the terminals the request reaches in the deciding authority's diagrams", func(ctx SpecContext) {
		state := explanationFixture()
		authority := state.Endpoints["cluster"].Authorities[0]
		prohibited, err := engine.EvaluateSnapshot(ctx, state, "cluster", mustJSON(utils.SubjectAccessReview("alice", "get", "secrets", "kube-system")))
		Expect(err).NotTo(HaveOccurred())
		Expect(prohibited.Decision.Result).To(Equal(model.Result("Deny")))
		Expect(prohibited.Terminals).To(HaveKeyWithValue(authority.ProhibitionDiagramID, []string{"deny"}))
		allowed, err := engine.EvaluateSnapshot(ctx, state, "cluster", mustJSON(utils.SubjectAccessReview("alice", "get", "pods", "team-one")))
		Expect(err).NotTo(HaveOccurred())
		Expect(allowed.Terminals).To(HaveKeyWithValue(authority.ComposedAllowDiagramID, []string{"allow-a", "allow-b"}))
		Expect(allowed.Terminals).To(HaveKeyWithValue(authority.ProhibitionDiagramID, BeEmpty()))
	})

	It("reads request keys exactly as live serving does", func(ctx SpecContext) {
		raw := []byte(`{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"User":"alice","resourceAttributes":{"verb":"get","version":"v1","resource":"pods","namespace":"team-one"}}}`)
		actual, err := engine.EvaluateSnapshot(ctx, explanationFixture(), "cluster", raw)
		Expect(err).NotTo(HaveOccurred())
		Expect(actual.Principal.User).To(BeEmpty())
		Expect(actual.Decision.Authority).To(Equal("second"))
	})

	It("rejects state compiled by another evaluator, malformed JSON and cancellation", func(ctx SpecContext) {
		state := explanationFixture()
		raw := mustJSON(utils.SubjectAccessReview("alice", "get", "pods", "team-one"))
		other := state
		other.EvaluatorID = "another-evaluator"
		Expect(engine.EvaluateSnapshot(ctx, other, "cluster", raw)).Error().To(MatchError(ContainSubstring(`compiled by evaluator "another-evaluator"`)))
		Expect(engine.EvaluateSnapshot(ctx, state, "cluster", []byte("{"))).Error().To(MatchError(ContainSubstring("decode SubjectAccessReview")))
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		Expect(engine.EvaluateSnapshot(canceled, state, "cluster", raw)).Error().To(MatchError(context.Canceled))
	})
})

var _ = Describe("Offline condition evaluation", func() {
	// conditionalContent is state whose Policy pods carries the condition
	// whose allow rule is allow.
	conditionalContent := func(allow string) model.ContentRevision {
		GinkgoHelper()
		fixture := newSourceFixture()
		fixture.observation.AllowedBuiltins = new(condition.DefaultBuiltins())
		fixture.put(model.KindPolicySet, "root", map[string]any{"bindingRefs": []any{reference("reader")}})
		fixture.put(model.KindPolicyBinding, "reader", bindingSpec("pods"))
		fixture.put(model.KindPolicy, "pods", map[string]any{"include": []any{operationRule("pods")}, "condition": map[string]any{"rego": "package condition\n" + allow + "\n"}})
		program, err := engine.Prepare("service-1", fixture.config, map[model.SourceKey]model.SourceObservation{fixture.source.Key: fixture.observation})
		Expect(err).NotTo(HaveOccurred())
		Expect(program.Content.Conditions).To(HaveLen(1))
		return program.Content
	}
	review := mustJSON(utils.SubjectAccessReview("admin", "get", "pods", "team"))
	onlyID := func(content model.ContentRevision) string {
		return slices.Collect(maps.Keys(content.Conditions))[0]
	}
	// replaced returns content whose one condition has source.
	replaced := func(content model.ContentRevision, source string) model.ContentRevision {
		id := onlyID(content)
		content.Conditions = map[string]model.Condition{id: {ID: id, Rego: source}}
		return content
	}

	It("reports whether each reached condition held", func(ctx SpecContext) {
		held := conditionalContent(`allow if input.request.resourceAttributes.verb == "get"`)
		evaluation, err := engine.EvaluateSnapshot(ctx, held, "cluster", review)
		Expect(err).NotTo(HaveOccurred())
		Expect(evaluation.Decision.Result).To(Equal(model.Result("Allow")))
		Expect(evaluation.Conditions).To(Equal(map[string]bool{onlyID(held): true}))

		failed := conditionalContent(`allow if input.request.resourceAttributes.verb == "list"`)
		evaluation, err = engine.EvaluateSnapshot(ctx, failed, "cluster", review)
		Expect(err).NotTo(HaveOccurred())
		Expect(evaluation.Decision.Result).To(Equal(model.Result("NoOpinion")))
		Expect(evaluation.Conditions).To(Equal(map[string]bool{onlyID(failed): false}))
	})

	DescribeTable("refuses state whose conditions it can't trust", func(ctx SpecContext, tamper func(model.ContentRevision) model.ContentRevision, message string) {
		content := tamper(conditionalContent(`allow if input.request.resourceAttributes.verb == "get"`))
		Expect(engine.EvaluateSnapshot(ctx, content, "cluster", review)).Error().To(MatchError(ContainSubstring(message)))
	},
		Entry("a digest another module has", func(content model.ContentRevision) model.ContentRevision {
			content.ConditionsDigest = "sha256:other"
			return content
		}, `state's conditions digest "sha256:other" doesn't match`),
		Entry("a condition failing the check", func(content model.ContentRevision) model.ContentRevision {
			return replaced(content, "package other\nallow if true\n")
		}, "package must be condition"),
		Entry("an ID that isn't its source's digest", func(content model.ContentRevision) model.ContentRevision {
			return replaced(content, "package condition\nallow if true\n")
		}, "isn't the digest of its source"),
		Entry("a condition calling the network", func(content model.ContentRevision) model.ContentRevision {
			checked, err := condition.Check("package condition\nallow if http.send({\"method\": \"get\", \"url\": \"http://example.test\"}).status_code == 200\n")
			Expect(err).NotTo(HaveOccurred())
			content.Conditions = map[string]model.Condition{checked.ID: checked}
			return content
		}, "calls http.send"),
	)
})

func explanationFixture() model.ContentRevision {
	GinkgoHelper()
	content, _, err := engine.FinalizeContent(decisionProgram("Deny").PreparedRevision, "service-1")
	Expect(err).NotTo(HaveOccurred())
	return content
}
