package engine_test

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	authorizationv1 "k8s.io/api/authorization/v1"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/test/utils"
)

type evaluatorOutput struct {
	Decision model.Decision                      `json:"decision"`
	Response authorizationv1.SubjectAccessReview `json:"response"`
}

var _ = Describe("Engine bootstrap", func() {
	It("names the service, the evaluator and each management root", func() {
		first, err := utils.NewAuthority(time.Now())
		Expect(err).NotTo(HaveOccurred())
		second, err := utils.NewAuthority(time.Now())
		Expect(err).NotTo(HaveOccurred())
		bundle := append(append([]byte("# management roots\n"), first.CertificatePEM...), second.CertificatePEM...)
		bootstrap, err := engine.NewBootstrap("service-1", bundle, "operator")
		Expect(err).NotTo(HaveOccurred())
		Expect(bootstrap).To(Equal(engine.Bootstrap{ServiceUID: "service-1", EvaluatorID: engine.EvaluatorID(), Management: engine.Management{
			Roots: []string{string(first.CertificatePEM), string(second.CertificatePEM)}, Identity: "operator",
		}}))
	})

	It("requires a management root and identity", func() {
		root, err := utils.NewAuthority(time.Now())
		Expect(err).NotTo(HaveOccurred())
		Expect(engine.NewBootstrap("service-1", []byte("not PEM"), "operator")).Error().To(MatchError(ContainSubstring("no certificates")))
		Expect(engine.NewBootstrap("service-1", root.CertificatePEM, "")).Error().To(MatchError(ContainSubstring("Common Name")))
	})

	It("loads the evaluator's and the program's modules", func() {
		modules := engine.Modules()
		Expect(modules).To(HaveKey("authz.rego"))
		Expect(modules).To(HaveKey("traversal_base.rego"))
		Expect(modules).To(HaveKey("kubernetes.rego"))
		Expect(modules).To(HaveKey("endpoints.rego"))
	})

	It("compiles the modules strictly", func() {
		parsed := map[string]*ast.Module{}
		for name, text := range engine.Modules() {
			module, err := ast.ParseModuleWithOpts(name, text, ast.ParserOptions{RegoVersion: ast.RegoV1})
			Expect(err).NotTo(HaveOccurred())
			parsed[name] = module
		}
		compiler := ast.NewCompiler().WithStrict(true)
		compiler.Compile(parsed)
		Expect(compiler.Errors).To(BeEmpty())
	})
})

var _ = Describe("Evaluator decisions", func() {
	It("selects the first authority whose matcher selects the principal and decides by its composed diagram", func(ctx SpecContext) {
		output := evaluateDecision(ctx, decisionProgram("Deny"), utils.SubjectAccessReview("alice", "get", "pods", "team-one"))
		Expect(output.Decision.Result).To(Equal(model.Result("Allow")))
		Expect(output.Decision.Authority).To(Equal("first"))
		Expect(output.Decision.ContributionIDs).To(Equal([]string{"allow-a", "allow-b"}))
		Expect(output.Response.Status.Reason).To(ContainSubstring("code=PolicyAllowed"))
	})

	It("ignores the independent diagrams while the composed diagram is pushed", func(ctx SpecContext) {
		content := decisionProgram("Deny")
		setFirstAuthority(&content, func(authority *model.AuthorityProgram) { authority.ComposedAllowDiagramID = "empty" })
		output := evaluateDecision(ctx, content, utils.SubjectAccessReview("alice", "get", "pods", "team-one"))
		Expect(output.Decision.Result).To(Equal(model.Result("NoOpinion")))
		Expect(output.Response.Status.Reason).To(ContainSubstring("code=AuthorityFallback"))
	})

	It("grants through the first covering independent diagram when the composed diagram was omitted", func(ctx SpecContext) {
		content := decisionProgram("Deny")
		setFirstAuthority(&content, func(authority *model.AuthorityProgram) { authority.ComposedAllowDiagramID = "" })
		output := evaluateDecision(ctx, content, utils.SubjectAccessReview("alice", "get", "pods", "team-one"))
		Expect(output.Decision.Result).To(Equal(model.Result("Allow")))
		Expect(output.Decision.ContributionIDs).To(Equal([]string{"allow-a"}))
	})

	It("grants nothing through an Allow diagram the traversal can't evaluate", func(ctx SpecContext) {
		content := decisionProgram("Deny")
		setFirstAuthority(&content, func(authority *model.AuthorityProgram) {
			authority.ComposedAllowDiagramID = ""
			authority.IndependentAllowDiagramIDs = append([]string{"missing"}, authority.IndependentAllowDiagramIDs...)
		})
		output := evaluateDecision(ctx, content, utils.SubjectAccessReview("alice", "get", "pods", "team-one"))
		Expect(output.Decision.Result).To(Equal(model.Result("Allow")))
		Expect(output.Decision.ContributionIDs).To(Equal([]string{"allow-a"}))

		setFirstAuthority(&content, func(authority *model.AuthorityProgram) { authority.IndependentAllowDiagramIDs = []string{"missing"} })
		output = evaluateDecision(ctx, content, utils.SubjectAccessReview("alice", "get", "pods", "team-one"))
		Expect(output.Decision.Result).To(Equal(model.Result("NoOpinion")))
		Expect(output.Response.Status.Reason).To(ContainSubstring("code=AuthorityFallback"))
	})

	It("returns whenNoPolicyAllows without an error when no Allow covers the request", func(ctx SpecContext) {
		output := evaluateDecision(ctx, decisionProgram("Deny"), utils.SubjectAccessReview("alice", "get", "configmaps", "team-one"))
		Expect(output.Decision.Result).To(Equal(model.Result("NoOpinion")))
		Expect(output.Decision.EvaluationError).To(BeEmpty())
		Expect(output.Response.Status.Reason).To(ContainSubstring("code=AuthorityFallback"))
		Expect(output.Response.Status.Allowed).To(BeFalse())
		Expect(output.Response.Status.Denied).To(BeFalse())
	})

	It("returns the fallback when an authority has no Allow diagrams", func(ctx SpecContext) {
		content := decisionProgram("Deny")
		setFirstAuthority(&content, func(authority *model.AuthorityProgram) {
			authority.IndependentAllowDiagramIDs = nil
			authority.ComposedAllowDiagramID = ""
		})
		output := evaluateDecision(ctx, content, utils.SubjectAccessReview("alice", "get", "pods", "team-one"))
		Expect(output.Decision.Result).To(Equal(model.Result("NoOpinion")))
		Expect(output.Decision.EvaluationError).To(BeEmpty())
		Expect(output.Response.Status.Reason).To(ContainSubstring("code=AuthorityFallback"))
	})

	It("returns NoOpinion only after no authority matcher selects the principal", func(ctx SpecContext) {
		content := decisionProgram("Deny")
		endpoint := content.Endpoints["cluster"]
		endpoint.Authorities = endpoint.Authorities[:1]
		content.Endpoints["cluster"] = endpoint
		output := evaluateDecision(ctx, content, utils.SubjectAccessReview("nobody", "get", "pods", "team-one"))
		Expect(output.Decision.Result).To(Equal(model.Result("NoOpinion")))
		Expect(output.Response.Status.Allowed).To(BeFalse())
		Expect(output.Response.Status.Denied).To(BeFalse())
		Expect(output.Response.Status.Reason).To(ContainSubstring("code=NoMatchingAuthority"))
	})

	It("denies a request a root prohibition covers before any Allow", func(ctx SpecContext) {
		output := evaluateDecision(ctx, decisionProgram("NoOpinion"), utils.SubjectAccessReview("alice", "get", "secrets", "kube-system"))
		Expect(output.Decision.Result).To(Equal(model.Result("Deny")))
		Expect(output.Decision.ContributionIDs).To(Equal([]string{"deny"}))
		Expect(output.Response.Status.Reason).To(ContainSubstring("code=RootProhibited"))
	})

	DescribeTable("answers an authoritative failure the request reaches with the endpoint's whenEvaluationFails",
		func(ctx SpecContext, fallback model.Result, denied bool) {
			content := decisionProgram(fallback)
			setFirstAuthority(&content, func(authority *model.AuthorityProgram) {
				authority.AuthoritativeFailureDiagramID = addIssueDiagram(&content.PreparedRevision, "prohibition-invalid", requestRegions("secrets", "kube-system"))
			})

			output := evaluateDecision(ctx, content, utils.SubjectAccessReview("alice", "get", "secrets", "kube-system"))
			Expect(output.Decision.Result).To(Equal(fallback))
			Expect(output.Decision.EvaluationError).To(Equal("authoritative policy unavailable"))
			Expect(output.Decision.IssueIDs).To(Equal([]string{"prohibition-invalid"}))
			expectEvaluationError(output.Response, denied)
			Expect(output.Response.Status.Reason).NotTo(ContainSubstring("alice"))

			Expect(evaluateDecision(ctx, content, utils.SubjectAccessReview("alice", "get", "pods", "team-one")).Decision.Result).To(Equal(model.Result("Allow")))
		},
		Entry("Deny", model.Result("Deny"), true),
		Entry("NoOpinion", model.Result("NoOpinion"), false),
	)

	DescribeTable("answers an unselectable entry binding with the endpoint's whenEvaluationFails",
		func(ctx SpecContext, fallback model.Result, denied bool) {
			content := decisionProgram(fallback)
			setFirstAuthority(&content, func(authority *model.AuthorityProgram) {
				authority.SelectionErrorIDs = []string{addIssueDiagram(&content.PreparedRevision, "entry-invalid", requestRegions("pods", "team-one"))}
			})
			output := evaluateDecision(ctx, content, utils.SubjectAccessReview("alice", "get", "pods", "team-one"))
			Expect(output.Decision.Result).To(Equal(fallback))
			Expect(output.Decision.EvaluationError).To(Equal("entry binding unavailable"))
			expectEvaluationError(output.Response, denied)
		},
		Entry("Deny", model.Result("Deny"), true),
		Entry("NoOpinion", model.Result("NoOpinion"), false),
	)

	It("applies a compiled kube-system Secret prohibition to all-namespace list", func(ctx SpecContext) {
		program, err := utils.SecretProhibitionProgram()
		Expect(err).NotTo(HaveOccurred())
		content := model.ContentRevision{PreparedRevision: program, ServiceUID: "service-1", Revision: "compiled-revision"}
		output := evaluateDecision(ctx, content, utils.SubjectAccessReview("admin", "list", "secrets", ""))
		Expect(output.Decision.Result).To(Equal(model.Result("Deny")))
		Expect(output.Decision.Reason).To(Equal("Prohibited"))
		Expect(output.Response.Status.Reason).To(ContainSubstring("code=RootProhibited"))
	})

	DescribeTable("answers a malformed SAR with a SubjectAccessReview under the endpoint's whenEvaluationFails",
		func(ctx SpecContext, fallback model.Result, denied bool) {
			prepared := prepareEvaluator(ctx, decisionProgram(fallback))
			for _, review := range []any{
				nil,
				"not a review",
				map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview", "spec": nil},
				map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview", "spec": map[string]any{"user": "alice"}},
			} {
				value := evaluateQuery(ctx, prepared, map[string]any{"endpoint": "cluster", "review": review})
				encoded, err := json.Marshal(value)
				Expect(err).NotTo(HaveOccurred())
				var output evaluatorOutput
				Expect(json.Unmarshal(encoded, &output)).To(Succeed())
				Expect(output.Decision.Result).To(Equal(fallback))
				Expect(output.Decision.EvaluationError).To(Equal("invalid SubjectAccessReview"))
				Expect(output.Response.APIVersion).To(Equal("authorization.k8s.io/v1"))
				Expect(output.Response.Kind).To(Equal("SubjectAccessReview"))
				expectEvaluationError(output.Response, denied)
			}
		},
		Entry("Deny", model.Result("Deny"), true),
		Entry("NoOpinion", model.Result("NoOpinion"), false),
	)

	DescribeTable("leaves the decision undefined without installed state, so the caller's failurePolicy applies",
		func(ctx SpecContext, fallback model.Result) {
			prepared := prepareStatelessEvaluator(ctx, decisionProgram(fallback))
			for _, review := range []any{
				utils.SubjectAccessReview("alice", "get", "pods", "team-one"),
				map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview", "spec": nil},
			} {
				results, err := prepared.Eval(ctx, rego.EvalInput(map[string]any{"endpoint": "cluster", "review": review}))
				Expect(err).NotTo(HaveOccurred())
				Expect(results).To(BeEmpty())
			}
		},
		Entry("Deny", model.Result("Deny")),
		Entry("NoOpinion", model.Result("NoOpinion")),
	)

	It("evaluates a SAR carrying unknown fields normally and does not reflect caller metadata or status", func(ctx SpecContext) {
		prepared := prepareEvaluator(ctx, decisionProgram("Deny"))
		review := utils.SubjectAccessReview("alice", "get", "pods", "team-one")
		review.Name = "caller-value"
		review.Status.Allowed = true
		review.Status.Reason = "caller-status"
		var raw map[string]any
		Expect(json.Unmarshal(mustJSON(review), &raw)).To(Succeed())
		raw["future"] = map[string]any{"field": true}
		spec, ok := raw["spec"].(map[string]any)
		Expect(ok).To(BeTrue())
		spec["future"] = []any{1}
		attributes, ok := spec["resourceAttributes"].(map[string]any)
		Expect(ok).To(BeTrue())
		attributes["future"] = "value"

		value := evaluateQuery(ctx, prepared, map[string]any{"endpoint": "cluster", "review": raw})
		encoded, err := json.Marshal(value)
		Expect(err).NotTo(HaveOccurred())
		var output evaluatorOutput
		Expect(json.Unmarshal(encoded, &output)).To(Succeed())
		Expect(output.Decision.Result).To(Equal(model.Result("Allow")))
		Expect(output.Response.Name).To(BeEmpty())
		Expect(output.Response.Status.Reason).NotTo(ContainSubstring("caller"))
		Expect(output.Response.Status.Allowed).To(BeTrue())
		Expect(output.Response.Status.Denied).To(BeFalse())
		Expect(output.Response.Status.EvaluationError).To(BeEmpty())
	})

})

// decisionProgram has two authorities. The first selects alice, allows pods
// in team-one through two contributions, and prohibits Secrets in kube-system.
// The second selects everyone and allows through the second contribution only.
func decisionProgram(whenEvaluationFails model.Result) model.ContentRevision {
	GinkgoHelper()
	program := model.PreparedRevision{
		Endpoints: map[string]model.EndpointProgram{}, Predicates: map[string]model.Matcher{},
		Contributions: map[string]model.Contribution{}, Diagrams: map[string]model.Diagram{}, Issues: map[string]model.ProgramIssue{},
	}
	program.Predicates["alice"] = model.Matcher{Kind: model.MatcherSubjects, Subjects: []model.PrincipalSubject{{Kind: model.KindUser, Name: "alice"}}}
	program.Predicates["all"] = model.AllPrincipals()
	program.Contributions["allow-a"] = model.Contribution{ID: "allow-a", Effect: model.EffectAllow, PrincipalIDs: []string{"alice"}}
	program.Contributions["allow-b"] = model.Contribution{ID: "allow-b", Effect: model.EffectAllow, PrincipalIDs: []string{"all"}}
	program.Contributions["deny"] = model.Contribution{ID: "deny", Effect: model.EffectDeny, PrincipalIDs: []string{"all"}}
	allowA := addContributionDiagram(&program, "allow-a", requestRegions("pods", "team-one"))
	allowB := addContributionDiagram(&program, "allow-b", requestRegions("pods", "team-one"))
	deny := addContributionDiagram(&program, "deny", requestRegions("secrets", "kube-system"))
	program.Diagrams["empty"] = model.NewArena(2).Snapshot(0)
	arena := model.NewArena(1000)
	left, err := arena.Import(program.Diagrams[allowA])
	Expect(err).NotTo(HaveOccurred())
	right, err := arena.Import(program.Diagrams[allowB])
	Expect(err).NotTo(HaveOccurred())
	root, err := arena.Union(left, right)
	Expect(err).NotTo(HaveOccurred())
	program.Diagrams["composed"] = arena.Snapshot(root)
	first := model.AuthorityProgram{Name: "first", MatcherID: "alice", Fallback: "NoOpinion", ProhibitionDiagramID: deny, IndependentAllowDiagramIDs: []string{allowA, allowB}, ComposedAllowDiagramID: "composed", AuthoritativeFailureDiagramID: "empty"}
	second := model.AuthorityProgram{Name: "second", MatcherID: "all", Fallback: "Deny", ProhibitionDiagramID: "empty", ComposedAllowDiagramID: allowB, AuthoritativeFailureDiagramID: "empty"}
	program.Endpoints["cluster"] = model.EndpointProgram{Name: "cluster", WhenEvaluationFails: whenEvaluationFails, Authorities: []model.AuthorityProgram{first, second}}
	content := model.ContentRevision{PreparedRevision: program, ServiceUID: "service-1", EvaluatorID: "evaluator-1", Revision: "revision-1"}
	return content
}

// setFirstAuthority edits the first authority of content's endpoint.
func setFirstAuthority(content *model.ContentRevision, edit func(*model.AuthorityProgram)) {
	endpoint := content.Endpoints["cluster"]
	endpoint.Authorities = slices.Clone(endpoint.Authorities)
	edit(&endpoint.Authorities[0])
	content.Endpoints["cluster"] = endpoint
}

func addContributionDiagram(program *model.PreparedRevision, label string, regions map[string]model.Region) string {
	GinkgoHelper()
	arena := model.NewArena(1000)
	root, err := arena.Cube(regions)
	Expect(err).NotTo(HaveOccurred())
	root, err = arena.Label(root, label)
	Expect(err).NotTo(HaveOccurred())
	id := "diagram-" + label
	program.Diagrams[id] = arena.Snapshot(root)
	return id
}

func addIssueDiagram(program *model.PreparedRevision, id string, regions map[string]model.Region) string {
	program.Issues[id] = model.ProgramIssue{Issue: model.Issue{Severity: api.IssueSeverityError, Reason: model.ReasonMissingReference}, PrincipalIDs: []string{"all"}}
	return addContributionDiagram(program, id, regions)
}

func expectEvaluationError(response authorizationv1.SubjectAccessReview, denied bool) {
	GinkgoHelper()
	Expect(response.Status.Allowed).To(BeFalse())
	Expect(response.Status.Denied).To(Equal(denied))
	Expect(response.Status.EvaluationError).NotTo(BeEmpty())
	Expect(response.Status.Reason).To(ContainSubstring("code=EvaluationError"))
}

func requestRegions(resource, namespace string) map[string]model.Region {
	affected := model.Values(model.Atom(namespace))
	if namespace == "" {
		affected = model.NamedNamespaces().Union(model.Values(utils.NamespaceWitness))
	}
	return map[string]model.Region{
		model.Category: model.Values(model.Atom("resource")), model.APIGroup: model.Values(model.Atom("")), model.APIVersion: model.Values(model.Atom("v1")),
		model.Resource: model.Values(model.Atom("\x00" + resource)), model.Verb: model.Values(model.Atom("get")), model.IngressNamespace: model.Values(model.Atom(namespace)),
		model.AffectedNamespace: affected, model.Name: model.PresentValues(),
	}
}

const evaluatorQuery = `{"decision": data.authz.program.kubernetes.decision(input.endpoint, input.review), "response": data.authz.program.kubernetes.response(input.endpoint, input.review)}`

func prepareEvaluator(ctx context.Context, content model.ContentRevision) rego.PreparedEvalQuery {
	return prepareQuery(ctx, content, evaluatorQuery)
}

// prepareStatelessEvaluator prepares the evaluator of a pod started for content
// that has no state installed yet.
func prepareStatelessEvaluator(ctx context.Context, content model.ContentRevision) rego.PreparedEvalQuery {
	return prepareQueryWithData(ctx, content, evaluatorQuery, map[string]any{})
}

func prepareQuery(ctx context.Context, content model.ContentRevision, query string) rego.PreparedEvalQuery {
	return prepareQueryWithData(ctx, content, query, map[string]any{"state": content})
}

func prepareQueryWithData(ctx context.Context, content model.ContentRevision, query string, authz map[string]any) rego.PreparedEvalQuery {
	GinkgoHelper()
	bootstrap := engine.Bootstrap{ServiceUID: content.ServiceUID, EvaluatorID: content.EvaluatorID}
	modules := engine.Modules()
	options := make([]func(*rego.Rego), 0, len(modules)+2)
	options = append(options, rego.Query(query))
	for name, text := range modules {
		options = append(options, rego.Module(name, text))
	}
	options = append(options, rego.Store(inmem.NewFromObject(map[string]any{"bootstrap": bootstrap, "authz": authz})))
	prepared, err := rego.New(options...).PrepareForEval(ctx)
	Expect(err).NotTo(HaveOccurred())
	return prepared
}

func evaluateDecision(ctx context.Context, content model.ContentRevision, review authorizationv1.SubjectAccessReview) evaluatorOutput {
	return evaluateDecisionPrepared(ctx, prepareEvaluator(ctx, content), review)
}

func evaluateDecisionPrepared(ctx context.Context, prepared rego.PreparedEvalQuery, review authorizationv1.SubjectAccessReview) evaluatorOutput {
	GinkgoHelper()
	value := evaluateQuery(ctx, prepared, map[string]any{"endpoint": "cluster", "review": review})
	encoded, err := json.Marshal(value)
	Expect(err).NotTo(HaveOccurred())
	var output evaluatorOutput
	Expect(json.Unmarshal(encoded, &output)).To(Succeed())
	return output
}

func evaluateQuery(ctx context.Context, prepared rego.PreparedEvalQuery, input any) any {
	GinkgoHelper()
	results, err := prepared.Eval(ctx, rego.EvalInput(input))
	Expect(err).NotTo(HaveOccurred())
	Expect(results).To(HaveLen(1))
	return results[0].Expressions[0].Value
}

func mustJSON(value any) []byte {
	encoded, err := json.Marshal(value)
	Expect(err).NotTo(HaveOccurred())
	return encoded
}
