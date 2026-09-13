package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	rbacv1 "k8s.io/api/rbac/v1"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/compiler"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/model"
	"github.com/zcayou/k8s-authz/test/utils"
)

// query is a traversal input: a region per constrained dimension.
type query map[string]model.Region

var _ = Describe("Generated Rego permission traversal", func() {
	It("reaches every path of broad, correlated and skipped dimensions", func(ctx SpecContext) {
		diagrams := map[string]model.Diagram{}

		arena := model.NewArena(1000)
		getOne := labeledCube(arena, "get-one", map[string]model.Region{
			model.Verb:              model.Values("get"),
			model.AffectedNamespace: model.Values(model.Atom("one")),
		})
		updateTwo := labeledCube(arena, "update-two", map[string]model.Region{
			model.Verb:              model.Values("update"),
			model.AffectedNamespace: model.Values(model.Atom("two")),
		})
		root, err := arena.Union(getOne, updateTwo)
		Expect(err).NotTo(HaveOccurred())
		diagrams["verbs"] = arena.Snapshot(root)

		arena = model.NewArena(1000)
		root = labeledCube(arena, "core-get", map[string]model.Region{
			model.APIGroup: model.Values(model.Atom("")),
			model.Verb:     model.Values(model.Atom("get")),
		})
		diagrams["skipped"] = arena.Snapshot(root)

		prepared := prepareTraversal(ctx, diagrams)
		broad := evaluateTraversal(ctx, prepared, "verbs", query{model.Verb: model.AnyRegion(), model.AffectedNamespace: model.NamedNamespaces()})
		Expect(broad).To(ConsistOf([]string{}, []string{"get-one"}, []string{"update-two"}))

		point := evaluateTraversal(ctx, prepared, "verbs", query{model.Verb: model.Values("get"), model.AffectedNamespace: model.Values(model.Atom("one"))})
		Expect(point).To(Equal([][]string{{"get-one"}}))

		skipped := evaluateTraversal(ctx, prepared, "skipped", query{model.Verb: model.Values(model.Atom("get"))})
		Expect(skipped).To(ConsistOf([]string{}, []string{"core-get"}))
	})

	It("retains empty terminal paths and namespace-less witnesses", func(ctx SpecContext) {
		arena := model.NewArena(1000)
		named := labeledCube(arena, "named", map[string]model.Region{model.AffectedNamespace: model.NamedNamespaces()})
		result := evaluateTraversal(ctx, prepareTraversal(ctx, map[string]model.Diagram{"namespace": arena.Snapshot(named)}), "namespace", query{
			model.IngressNamespace:  model.Values(model.Atom("")),
			model.AffectedNamespace: model.NamedNamespaces().Union(model.Values(utils.NamespaceWitness)),
		})
		Expect(result).To(ConsistOf([]string{}, []string{"named"}))
	})

	It("preserves unknown names and URL prefix holes", func(ctx SpecContext) {
		diagrams := map[string]model.Diagram{}
		queries := map[string]query{}

		arena := model.NewArena(1000)
		root := labeledCube(arena, "ordinary-name", map[string]model.Region{
			model.Name: model.PresentValues().Subtract(model.Values(model.Atom("secret"))),
		})
		diagrams["name"] = arena.Snapshot(root)
		queries["name"] = query{model.Name: model.PresentValues()}

		arena = model.NewArena(1000)
		root = labeledCube(arena, "public-url", map[string]model.Region{
			model.URL: model.Prefix(model.Atom("/api/")).Subtract(model.Prefix(model.Atom("/api/private/"))),
		})
		diagrams["url"] = arena.Snapshot(root)
		queries["url"] = query{model.URL: model.Prefix(model.Atom("/api/"))}

		arena = model.NewArena(1000)
		root = labeledCube(arena, "nested-prefix", map[string]model.Region{
			model.URL: model.Prefix("a").Subtract(model.Prefix("ab")).Union(model.Values("abc")),
		})
		diagrams["nested"] = arena.Snapshot(root)
		queries["nested"] = query{model.URL: model.Prefix("a")}

		prepared := prepareTraversal(ctx, diagrams)
		for id, input := range queries {
			result := evaluateTraversal(ctx, prepared, id, input)
			Expect(result).To(ContainElement(BeEmpty()), id)
			Expect(result).To(ContainElement(HaveLen(1)), id)
		}
	})

	It("does not invent overlap through an excluded Secret resource", func(ctx SpecContext) {
		arena := model.NewArena(1000)
		root := labeledCube(arena, "without-secrets", map[string]model.Region{
			model.Resource: model.PresentValues().Subtract(model.Values(model.Atom("\x00secrets"))),
		})
		result := evaluateTraversal(ctx, prepareTraversal(ctx, map[string]model.Diagram{"secrets": arena.Snapshot(root)}), "secrets", query{model.Resource: model.Values(model.Atom("\x00secrets"))})
		Expect(result).To(Equal([][]string{{}}))
	})

	It("follows exact indexes to a single leaf", func(ctx SpecContext) {
		arena := model.NewArena(1000)
		regions := map[string]model.Region{
			model.APIGroup:   model.Values(model.Atom("apps")),
			model.APIVersion: model.Values(model.Atom("v1")),
			model.Resource:   model.Values(model.Atom("\x00deployments")),
			model.Verb:       model.Values(model.Atom("get")),
		}
		root := labeledCube(arena, "exact", regions)
		result := evaluateTraversal(ctx, prepareTraversal(ctx, map[string]model.Diagram{"exact": arena.Snapshot(root)}), "exact", regions)
		Expect(result).To(Equal([][]string{{"exact"}}))
	})

	It("uses the longest prefix and complement indexes for point queries", func(ctx SpecContext) {
		arena := model.NewArena(1000)
		all := labeledCube(arena, "all", map[string]model.Region{model.URL: model.AnyRegion()})
		api := labeledCube(arena, "api", map[string]model.Region{model.URL: model.Prefix(model.Atom("/api/"))})
		private := labeledCube(arena, "private", map[string]model.Region{model.URL: model.Prefix(model.Atom("/api/private/"))})
		root, err := arena.Union(all, api)
		Expect(err).NotTo(HaveOccurred())
		root, err = arena.Union(root, private)
		Expect(err).NotTo(HaveOccurred())
		prepared := prepareTraversal(ctx, map[string]model.Diagram{"url": arena.Snapshot(root)})

		for value, terminals := range map[string][]string{
			"/api/private/item": {"all", "api", "private"},
			"/api/public/item":  {"all", "api"},
			"/health/ready":     {"all"},
		} {
			Expect(evaluateTraversal(ctx, prepared, "url", query{model.URL: model.Values(model.Atom(value))})).To(Equal([][]string{terminals}), value)
		}
	})

	It("answers absent and explicit selector dimensions", func(ctx SpecContext) {
		arena := model.NewArena(1000)
		root := labeledCube(arena, "red", map[string]model.Region{
			model.Verb:                 model.Values(model.Atom("list")),
			model.LabelPrefix + "team": model.Values(model.Atom("red")),
		})
		prepared := prepareTraversal(ctx, map[string]model.Diagram{"selector": arena.Snapshot(root)})

		unselected := evaluateTraversal(ctx, prepared, "selector", query{model.Verb: model.Values(model.Atom("list"))})
		Expect(unselected).To(ConsistOf([]string{}, []string{"red"}))

		selected := evaluateTraversal(ctx, prepared, "selector", query{model.Verb: model.Values(model.Atom("list")), model.LabelPrefix + "team": model.Values(model.Atom("red"))})
		Expect(selected).To(Equal([][]string{{"red"}}))
	})

	It("walks the maximum path, is undefined past it, and visits a shared node once", func(ctx SpecContext) {
		maximum, maximumQuery := exactChain(136)
		tooDeep, tooDeepQuery := exactChain(137)
		wide := model.Diagram{Root: 0, Nodes: []model.Node{
			{
				Dimension: model.Verb,
				Edges: []model.Edge{
					{Region: model.Values("a"), Next: 1},
					{Region: model.Values("b"), Next: 1},
					{Region: model.Values("c"), Next: 1},
					{Region: model.AnyRegion().Subtract(model.Values("a", "b", "c")), Next: 1},
				},
				Exact:      map[string]model.NodeID{"a": 1, "b": 1, "c": 1},
				Complement: new(model.NodeID(1)),
			},
			{Terminals: []string{"wide"}},
		}}
		prepared := prepareTraversal(ctx, map[string]model.Diagram{"maximum": maximum, "deep": tooDeep, "wide": wide})

		Expect(evaluateTraversal(ctx, prepared, "maximum", maximumQuery)).To(Equal([][]string{{"terminal"}}))
		deep, err := prepared.Eval(ctx, traversalInput("deep", tooDeepQuery))
		Expect(err).NotTo(HaveOccurred())
		Expect(deep).To(BeEmpty())
		Expect(evaluateTraversal(ctx, prepared, "wide", query{model.Verb: model.AnyRegion()})).To(Equal([][]string{{"wide"}}))
	})
})

func labeledCube(arena *model.Arena, label string, regions map[string]model.Region) model.NodeID {
	GinkgoHelper()
	root, err := arena.Cube(regions)
	Expect(err).NotTo(HaveOccurred())
	root, err = arena.Label(root, label)
	Expect(err).NotTo(HaveOccurred())
	return root
}

func prepareTraversal(ctx context.Context, diagrams map[string]model.Diagram) rego.PreparedEvalQuery {
	GinkgoHelper()
	regionsModule, err := os.ReadFile("assets/regions.rego")
	Expect(err).NotTo(HaveOccurred())
	traversalModule, err := os.ReadFile("assets/traversal.rego")
	Expect(err).NotTo(HaveOccurred())
	baseModule, err := os.ReadFile("assets/traversal_base.rego")
	Expect(err).NotTo(HaveOccurred())
	prepared, err := rego.New(
		rego.Query("data.authz.evaluator.traversal.evaluate(input.diagramID, input.query)"),
		rego.Module("regions.rego", string(regionsModule)),
		rego.Module("traversal.rego", string(traversalModule)),
		rego.Module("traversal_base.rego", string(baseModule)),
		rego.Store(inmem.NewFromObject(map[string]any{"authz": map[string]any{"state": map[string]any{"diagrams": diagrams}}})),
	).PrepareForEval(ctx)
	Expect(err).NotTo(HaveOccurred())
	return prepared
}

// evaluateTraversal returns the terminals the traversal of diagramID reaches
// for regions, which must be defined.
func evaluateTraversal(ctx context.Context, prepared rego.PreparedEvalQuery, diagramID string, regions query) [][]string {
	GinkgoHelper()
	results, err := prepared.Eval(ctx, traversalInput(diagramID, regions))
	Expect(err).NotTo(HaveOccurred())
	Expect(results).To(HaveLen(1))
	encoded, err := json.Marshal(results[0].Expressions[0].Value)
	Expect(err).NotTo(HaveOccurred())
	var terminals [][]string
	Expect(json.Unmarshal(encoded, &terminals)).To(Succeed())
	return terminals
}

func traversalInput(diagramID string, regions query) rego.EvalOption {
	return rego.EvalInput(map[string]any{"diagramID": diagramID, "query": map[string]any{"regions": regions}})
}

func exactChain(branches int) (model.Diagram, query) {
	nodes := make([]model.Node, branches+2)
	regions := make(query, branches)
	empty := model.NodeID(branches + 1) //nolint:gosec // Fixtures use a handful of branches.
	for index := range branches {
		dimension := model.LabelPrefix + string(rune(0x100+index))
		regions[dimension] = model.Values("x")
		next := model.NodeID(index + 1)
		nodes[index] = model.Node{
			Dimension:  dimension,
			Edges:      []model.Edge{{Region: model.Values("x"), Next: next}, {Region: model.Values("x").Complement(), Next: empty}},
			Exact:      map[string]model.NodeID{"x": next},
			Complement: new(empty),
		}
	}
	nodes[branches] = model.Node{Terminals: []string{"terminal"}}
	return model.Diagram{Nodes: nodes}, regions
}

type oracleOperation struct {
	resource, subresource, verb, ingress, affected, name string
}

type oracleRule struct {
	resources, verbs, namespaces, names []string
}

type oraclePolicy struct {
	include, exclude []oracleRule
}

type oracleEdge struct {
	from, to int
	bound    oraclePolicy
}

type oracleGraph struct {
	policies    []oraclePolicy
	edges       []oracleEdge
	prohibition oraclePolicy
}

var _ = Describe("Independent finite authorization oracle", func() {
	It("checks compiled OPA decisions against tuple sets through shared paths, subtraction and edge removal", func(ctx SpecContext) {

		results := map[model.Result]int{}
		for seed := range uint64(6) {
			graph := generatedOracleGraph(seed)
			for removed := -1; removed < 2; removed++ {
				fixture := graph.fixture(removed)
				compilation, err := compiler.Compile(fixture.config, map[model.SourceKey]model.SourceObservation{fixture.source.Key: fixture.observation}, compiler.DefaultLimits())
				Expect(err).NotTo(HaveOccurred())
				Expect(compilation.Prepared.Issues).To(BeEmpty())
				content, _, err := engine.FinalizeContent(compilation.Prepared, "service-1")
				Expect(err).NotTo(HaveOccurred())
				prepared := prepareEvaluator(ctx, content)
				for _, request := range oracleRequests() {
					review := utils.SubjectAccessReview("admin", request.verb, request.resource, request.ingress)
					review.Spec.ResourceAttributes.Subresource = request.subresource
					review.Spec.ResourceAttributes.Name = request.name
					expected := graph.decision(request, removed)
					results[expected]++
					actual := evaluateDecisionPrepared(ctx, prepared, review)
					Expect(actual.Decision.Result).To(Equal(expected), "seed=%d removedEdge=%d request=%+v graph=%+v", seed, removed, request, graph)
					Expect(actual.Decision.EvaluationError).To(BeEmpty())
				}
			}
		}
		for _, result := range []model.Result{"Allow", "Deny", "NoOpinion"} {
			Expect(results[result]).To(BeNumerically(">", 0), "oracle never exercised %s", result)
		}
		AddReportEntry("finite-oracle-results", results)
	}, SpecTimeout(3*time.Minute))
})

func (r oracleRule) matches(operation oracleOperation) bool {
	resource := operation.resource
	if operation.subresource != "" {
		resource += "/" + operation.subresource
	}
	if !oracleMember(r.resources, resource) || !oracleMember(r.verbs, operation.verb) || len(r.names) != 0 && !slices.Contains(r.names, operation.name) {
		return false
	}
	if len(r.namespaces) == 0 {
		return true
	}
	for _, namespace := range r.namespaces {
		if namespace == "" && operation.ingress == "" || namespace == "*" && operation.affected != "<namespace-less-witness>" || namespace != "" && namespace != "*" && namespace == operation.affected {
			return true
		}
	}
	return false
}

func oracleMember(values []string, value string) bool {
	return slices.Contains(values, "*") || slices.Contains(values, value)
}

func (p oraclePolicy) matches(operation oracleOperation) bool {
	return slices.ContainsFunc(p.include, func(rule oracleRule) bool { return rule.matches(operation) }) &&
		!slices.ContainsFunc(p.exclude, func(rule oracleRule) bool { return rule.matches(operation) })
}

func (g oracleGraph) allowed(node, removed int, operation oracleOperation) bool {
	if g.policies[node].matches(operation) {
		return true
	}
	for index, edge := range g.edges {
		if index != removed && edge.from == node && edge.bound.matches(operation) && g.allowed(edge.to, removed, operation) {
			return true
		}
	}
	return false
}

func (g oracleGraph) decision(request oracleOperation, removed int) model.Result {
	covered := true
	for _, operation := range oracleFootprint(request) {
		if g.prohibition.matches(operation) {
			return "Deny"
		}
		covered = covered && g.allowed(0, removed, operation)
	}
	if covered {
		return "Allow"
	}
	return "NoOpinion"
}

func oracleFootprint(request oracleOperation) []oracleOperation {
	namespaces := []string{request.ingress}
	if request.ingress == "" {
		namespaces = []string{"one", "two", "other-namespace", "<namespace-less-witness>"}
	}
	names := []string{request.name}
	if request.name == "" {
		names = []string{"first", "second", "other-name"}
	}
	resources := [][2]string{{request.resource, request.subresource}}
	if request.resource == "*" {
		resources = [][2]string{{"pods", ""}, {"pods", "log"}, {"secrets", ""}, {"other-resource", ""}, {"other-resource", "other-subresource"}}
	}
	operations := make([]oracleOperation, 0, len(namespaces)*len(names)*len(resources))
	for _, resource := range resources {
		for _, namespace := range namespaces {
			for _, name := range names {
				operation := request
				operation.resource, operation.subresource, operation.affected, operation.name = resource[0], resource[1], namespace, name
				operations = append(operations, operation)
			}
		}
	}
	return operations
}

func oracleRequests() []oracleOperation {
	requests := make([]oracleOperation, 0, 120)
	for _, resource := range [][2]string{{"pods", ""}, {"pods", "log"}, {"secrets", ""}, {"other-resource", ""}, {"*", ""}} {
		for _, namespace := range []string{"one", "two", "other-namespace", ""} {
			for _, verb := range []string{"get", "list"} {
				for _, name := range []string{"first", "other-name", ""} {
					requests = append(requests, oracleOperation{resource: resource[0], subresource: resource[1], verb: verb, ingress: namespace, name: name})
				}
			}
		}
	}
	return requests
}

func generatedOracleGraph(seed uint64) oracleGraph {
	random := rand.New(rand.NewPCG(seed, 91))
	policy := func() oraclePolicy {
		rule := func() oracleRule {
			return oracleRule{
				resources:  [][]string{{"*"}, {"pods"}, {"pods/log"}, {"secrets"}, {"pods", "secrets"}}[random.IntN(5)],
				verbs:      [][]string{{"*"}, {"get"}, {"list"}}[random.IntN(3)],
				namespaces: [][]string{nil, {""}, {"*"}, {"one"}, {"two"}, {"one", "two"}}[random.IntN(6)],
				names:      [][]string{nil, {"first"}, {"first", "second"}}[random.IntN(3)],
			}
		}
		return oraclePolicy{include: []oracleRule{rule(), rule()}, exclude: []oracleRule{rule()}}
	}
	graph := oracleGraph{policies: make([]oraclePolicy, 5), prohibition: policy()}
	for index := range graph.policies {
		graph.policies[index] = policy()
	}
	for _, pair := range [][2]int{{0, 1}, {0, 2}, {1, 3}, {2, 3}, {2, 4}, {3, 4}} {
		graph.edges = append(graph.edges, oracleEdge{from: pair[0], to: pair[1], bound: policy()})
	}
	return graph
}

func (g oracleGraph) fixture(removed int) *sourceFixture {
	fixture := newSourceFixture()
	name := func(index int) string {
		if index == 0 {
			return "root"
		}
		return fmt.Sprintf("node-%d", index)
	}
	for index, policy := range g.policies {
		fixture.put("Policy", name(index), policy.spec())
		fixture.put("PolicyBinding", name(index), bindingSpec(name(index)))
		delegations := []any{}
		for edgeIndex, edge := range g.edges {
			if edge.from != index || edgeIndex == removed {
				continue
			}
			edgeName := fmt.Sprintf("edge-%d", edgeIndex)
			fixture.put("Policy", edgeName, edge.bound.spec())
			fixture.put("PolicyBinding", edgeName, map[string]any{"policyRef": map[string]any{"kind": model.KindPolicySet, "name": name(edge.to)}, "constraints": map[string]any{"policyRef": reference(edgeName), "maxDepth": 5}, "subjectMatch": map[string]any{}})
			delegations = append(delegations, reference(edgeName))
		}
		set := map[string]any{"bindingRefs": append([]any{reference(name(index))}, delegations...)}
		if index == 0 {
			fixture.put("Policy", "prohibition", g.prohibition.spec())
			fixture.put("PolicyBinding", "prohibition", bindingSpec("prohibition"))
			set["prohibitionRefs"] = []any{reference("prohibition")}
		}
		fixture.put(model.KindPolicySet, name(index), set)
	}
	return fixture
}

func (p oraclePolicy) spec() map[string]any {
	encode := func(rules []oracleRule) []any {
		result := make([]any, 0, len(rules))
		for _, rule := range rules {
			value := map[string]any{"apiGroups": []string{"*"}, "resources": rule.resources, "verbs": rule.verbs}
			if len(rule.namespaces) > 0 {
				value["namespaces"] = rule.namespaces
			}
			if len(rule.names) > 0 {
				value["resourceNames"] = rule.names
			}
			result = append(result, value)
		}
		return result
	}
	return map[string]any{"include": encode(p.include), "exclude": encode(p.exclude)}
}

var _ = Describe("Source-qualified contextual authorization", func() {
	It("confines the same child independently under narrow and explicit multi-source delegations", func(ctx SpecContext) {
		platform, team, permissions := newSourceFixture(), contextualSource("team"), contextualSource("permissions")
		platform.config.Endpoints[0].Sources = []model.SourceKey{platform.source.Key, team.source.Key, permissions.source.Key}
		platform.put(model.KindPolicyBinding, "entry", map[string]any{"policyRef": map[string]any{"kind": model.KindPolicySet, "name": "root"}, "subjectMatch": map[string]any{}, "constraints": map[string]any{"sourceRefs": platform.config.Endpoints[0].Sources}})
		platform.put(model.KindPolicy, "bound", map[string]any{"include": []any{map[string]any{"apiGroups": []string{"*"}, "resources": []string{"*"}, "verbs": []string{"*"}}}})
		permissions.put(model.KindPolicy, "permission", map[string]any{"include": []any{operationRule("pods")}})
		team.put(model.KindPolicyBinding, "binding", map[string]any{"policyRef": contextualReference(permissions, "permission"), "subjectMatch": map[string]any{}})
		team.put(model.KindPolicySet, "shared", map[string]any{"bindingRefs": []any{reference("binding")}})
		for _, user := range []string{"narrow", "wide"} {
			target := contextualReference(team, "shared")
			target.Kind = model.KindPolicySet
			constraints := map[string]any{"policyRef": reference("bound")}
			edge := map[string]any{"policyRef": target, "constraints": constraints, "subjects": []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: user}}}
			if user == "wide" {
				constraints["sourceRefs"] = []any{team.source.Key, permissions.source.Key}
			}
			platform.put(model.KindPolicyBinding, user, edge)
		}
		platform.put(model.KindPolicySet, "root", map[string]any{"bindingRefs": []any{reference("narrow"), reference("wide")}})

		var diagnostics []model.Issue
		compile := func() model.ContentRevision {
			GinkgoHelper()
			compilation, err := compiler.Compile(platform.config, map[model.SourceKey]model.SourceObservation{platform.source.Key: platform.observation, team.source.Key: team.observation, permissions.source.Key: permissions.observation}, compiler.DefaultLimits())
			Expect(err).NotTo(HaveOccurred())
			content, _, err := engine.FinalizeContent(compilation.Prepared, "service-1")
			Expect(err).NotTo(HaveOccurred())
			diagnostics = compilation.Diagnostics
			return content
		}
		content := compile()
		prepared := prepareEvaluator(ctx, content)
		narrow := evaluateDecisionPrepared(ctx, prepared, utils.SubjectAccessReview("narrow", "get", "pods", "team"))
		wide := evaluateDecisionPrepared(ctx, prepared, utils.SubjectAccessReview("wide", "get", "pods", "team"))
		Expect(narrow.Decision.Result).To(Equal(model.Result("NoOpinion")))
		Expect(narrow.Decision.EvaluationError).To(BeEmpty())
		Expect(wide.Decision.Result).To(Equal(model.Result("Allow")))
		Expect(diagnostics).To(ContainElement(HaveField("Reason", model.ReasonSourceNotAllowed)))

		By("resolving an omitted source relative to the document, without searching another collected source")
		team.put(model.KindPolicyBinding, "binding", map[string]any{"policyRef": reference("permission"), "subjects": []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "wide"}}})
		content = compile()
		Expect(diagnostics).To(ContainElement(HaveField("Reason", model.ReasonMissingReference)))
		Expect(evaluateDecision(ctx, content, utils.SubjectAccessReview("wide", "get", "pods", "team")).Decision.Result).To(Equal(model.Result("NoOpinion")))

		By("keeping identically named documents in different sources distinct")
		team.put(model.KindPolicy, "permission", map[string]any{"include": []any{operationRule("secrets")}})
		content = compile()
		prepared = prepareEvaluator(ctx, content)
		Expect(evaluateDecisionPrepared(ctx, prepared, utils.SubjectAccessReview("wide", "get", "pods", "team")).Decision.Result).To(Equal(model.Result("NoOpinion")))
		Expect(evaluateDecisionPrepared(ctx, prepared, utils.SubjectAccessReview("wide", "get", "secrets", "team")).Decision.Result).To(Equal(model.Result("Allow")))
	})
})

func contextualSource(name string) *sourceFixture {
	fixture := newSourceFixture()
	fixture.source.Key.Name, fixture.source.UID, fixture.source.Origin = name, name+"-uid", name+"-api"
	fixture.observation.Instance = fixture.source
	return fixture
}

func contextualReference(fixture *sourceFixture, name string) api.PolicyRef {
	return api.PolicyRef{SourceRef: &api.SourceRef{Namespace: fixture.source.Key.Namespace, Name: fixture.source.Key.Name}, Namespace: "policies", Name: name}
}
