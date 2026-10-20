package compiler

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	api "github.com/zcayou/k8s-authz/api/v1alpha1"
	"github.com/zcayou/k8s-authz/internal/model"
)

// maxAdvisories bounds the diagnostics, and separately the exclusion proofs,
// a compilation keeps.
const maxAdvisories = 128

// MaxSelectorKeys bounds the label and field selector dimensions of every
// diagram a program holds. Unlike Limits it is fixed: the engine's traversal
// is generated to the depth it allows.
const MaxSelectorKeys = 128

// Limits bound compilation. Every cap on one diagram or branch is fixed, so
// it doesn't depend on how many authorities, bindings or prohibitions
// a service has.
type Limits struct {
	// MaxDelegationDepth bounds the PolicySets a use enters below its root.
	MaxDelegationDepth int
	// MaxContextualUsesPerBranch bounds the documents one branch resolves.
	MaxContextualUsesPerBranch int
	// MaxExpandedRulesPerBranch bounds the rule cubes one branch expands.
	MaxExpandedRulesPerBranch int
	// MaxBranchNodes bounds the arena of each branch: an authority's root
	// branch, one per binding and prohibition of its root PolicySet, and one
	// per PolicySet a selection matches.
	MaxBranchNodes int
	// MaxMergeNodes bounds an authority's composed Allow diagram and its merged
	// prohibition diagram.
	MaxMergeNodes int
	// MaxExclusionNodes bounds the program's exclusion proofs together.
	MaxExclusionNodes int
	// MaxDiagramNodes bounds the program's diagrams together. Each authoritative
	// failure is labeled, and an authority's failures are merged, within it.
	MaxDiagramNodes int
	// MaxSelectionMatches bounds the PolicySets one selection matches.
	MaxSelectionMatches int
	// MaxSelectedBranches bounds the branches an authority's selections detach,
	// counted across every selection beneath it.
	MaxSelectedBranches int
}

// DefaultLimits are the limits the operator compiles with.
func DefaultLimits() Limits {
	return Limits{
		MaxDelegationDepth:         16,
		MaxContextualUsesPerBranch: 4096,
		MaxExpandedRulesPerBranch:  16384,
		MaxBranchNodes:             65536,
		MaxMergeNodes:              65536,
		MaxExclusionNodes:          32768,
		MaxDiagramNodes:            262144,
		MaxSelectionMatches:        256,
		MaxSelectedBranches:        1024,
	}
}

// failureClass decides what a compile failure does at evaluation time.
type failureClass int

const (
	// allowFailure grants nothing and is only reported, as a broken RBAC
	// binding is.
	allowFailure failureClass = iota
	// authoritativeFailure makes the endpoint answer with its whenEvaluationFails
	// result wherever the failure is reached.
	authoritativeFailure
)

type authorityKey struct {
	endpoint, authority string
}

type builder struct {
	limits         Limits
	sources        map[model.SourceKey]model.SourceObservation
	output         Compilation
	failures       map[authorityKey][]recordedFailure
	discovered     map[authorityKey]*discovered
	selections     map[string]model.Selection
	diagnostics    map[string]model.Issue
	exclusionNodes int
}

// discovered is what an authority's selections detached: how many branches,
// and their Allow diagrams.
type discovered struct {
	branches int
	allows   []string
}

// recordedFailure is an authoritative failure's issue and the bound
// it is labeled over.
type recordedFailure struct {
	issueID string
	bound   model.Diagram
}

type branch struct {
	owner               *builder
	arena               *model.Arena
	advisoryArena       *model.Arena
	advisoriesExhausted bool
	uses                int
	ruleCount           int
}

// compileError is why part of a use couldn't be compiled. failureIssue turns
// it, like every other compile error, into the use's issue.
type compileError struct {
	reason   model.IssueReason
	message  string
	document *model.DocumentKey
}

func (e *compileError) Error() string {
	return e.message
}

func errorf(reason model.IssueReason, document *model.DocumentKey, format string, args ...any) error {
	return &compileError{reason: reason, message: fmt.Sprintf(format, args...), document: document}
}

// Compile emits the service's complete program, including authoritative
// failures for invalid graph regions and diagnostics for invalid Allow paths.
// config's builtin ceiling caps every use's conditions. It fails, with an error
// wrapping model.ErrLimit, only when an authority's authoritative failures
// or the whole program exceed MaxDiagramNodes, or when the failures branch
// on more than MaxSelectorKeys selector keys. A source missing from sources,
// or without a complete view, is unavailable. Compile only reads sources, whose
// observations it shares with the caller.
func Compile(config model.ServiceConfig, sources map[model.SourceKey]model.SourceObservation, limits Limits) (Compilation, error) {
	b := &builder{limits: limits, sources: sources, output: Compilation{Limits: limits, References: map[model.Reference]struct{}{}, Prepared: model.PreparedRevision{Endpoints: map[string]model.EndpointProgram{}, Predicates: map[string]model.Matcher{}, Contributions: map[string]model.Contribution{}, Diagrams: map[string]model.Diagram{}, Issues: map[string]model.ProgramIssue{}, Conditions: map[string]model.Condition{}}}, failures: map[authorityKey][]recordedFailure{}, discovered: map[authorityKey]*discovered{}, selections: map[string]model.Selection{}, diagnostics: map[string]model.Issue{}}
	for _, endpoint := range config.Endpoints {
		program := model.EndpointProgram{Name: endpoint.Name, WhenEvaluationFails: endpoint.WhenEvaluationFails, Callers: endpoint.Callers}
		for _, authority := range endpoint.Authorities {
			result := b.authority(endpoint, authority, config.BuiltinCeiling)
			var err error
			if result.AuthoritativeFailureDiagramID, err = b.authoritativeFailures(authorityKey{endpoint.Name, result.Name}); err != nil {
				return Compilation{}, err
			}
			program.Authorities = append(program.Authorities, result)
		}
		b.output.Prepared.Endpoints[endpoint.Name] = program
	}
	return b.finalize()
}

func (b *builder) predicate(matcher model.Matcher) string {
	id := model.Digest(matcher)
	b.output.Prepared.Predicates[id] = matcher
	return id
}

// save adds diagram to the program. It refuses a diagram that branches on more
// than MaxSelectorKeys selector keys, which the engine's traversal can't walk
// to the end.
func (b *builder) save(diagram model.Diagram) (string, error) {
	if err := checkSelectorKeys(diagram); err != nil {
		return "", err
	}
	id := model.Digest(diagram)
	b.output.Prepared.Diagrams[id] = diagram
	return id, nil
}

func checkSelectorKeys(diagram model.Diagram) error {
	keys := map[string]bool{}
	for _, node := range diagram.Nodes {
		if strings.HasPrefix(node.Dimension, model.LabelPrefix) || strings.HasPrefix(node.Dimension, model.FieldPrefix) {
			keys[node.Dimension] = true
		}
	}
	if len(keys) > MaxSelectorKeys {
		return fmt.Errorf("permission diagram branches on %d selector keys, more than %d: %w", len(keys), MaxSelectorKeys, model.ErrLimit)
	}
	return nil
}

func (b *builder) newBranch() *branch {
	limits := b.limits
	return &branch{owner: b, arena: model.NewArena(limits.MaxBranchNodes), advisoryArena: model.NewArena(limits.MaxDiagramNodes)}
}

// authority compiles one authority: it selects the entry binding, applies
// the entry's bound, compiles its target in the root branch, and merges
// the resulting Allow diagrams with those its selections detached. ceiling caps
// the builtins its conditions call.
func (b *builder) authority(endpoint model.EndpointConfig, authority model.AuthorityConfig, ceiling *model.BuiltinSet) model.AuthorityProgram {
	result := model.AuthorityProgram{Name: authority.Binding.String(), Fallback: authority.Fallback, ProhibitionDiagramID: b.empty()}
	u := useContext{endpoint: endpoint.Name, authority: result.Name, root: true, sources: map[model.SourceKey]bool{}, remaining: b.limits.MaxDelegationDepth, bound: 1, advisoryBound: 1, builtins: ceiling}
	for _, key := range endpoint.Sources {
		u.sources[key] = true
	}
	root := b.newBranch()
	entry, err := root.entry(authority.Binding, &u)
	if err != nil {
		issue := failureIssue(u, err)
		id := model.Digest(issue)
		b.output.Prepared.Issues[id] = issue
		result.SelectionErrorIDs = []string{id}
		return result
	}
	result.MatcherID = b.predicate(entry.Binding.Principal)
	result.Root = entry.Binding.Policy
	u.principals = append(u.principals, result.MatcherID)
	u.path = append(u.path, entry.Key)
	// The bound of an entry that targets a leaf Policy narrows only an Allow,
	// so failing to resolve it grants nothing.
	boundClass := allowFailure
	if entry.Binding.Policy.Kind == model.KindPolicySet {
		boundClass = authoritativeFailure
	}
	if err = root.constrain(entry.Binding, &u, model.EffectAllow); err != nil {
		root.failure(u, boundClass, err)
		return result
	}
	var allows []string
	if entry.Binding.Policy.Kind != model.KindPolicySet {
		allows = []string{root.persist(root.leaf(entry.Binding, u, model.EffectAllow), u, allowFailure)}
	} else {
		var prohibitions string
		allows, prohibitions, err = root.rootSet(entry.Binding, &u)
		if err != nil {
			root.failure(u, authoritativeFailure, err)
		}
		if prohibitions != "" {
			result.ProhibitionDiagramID = prohibitions
		}
	}
	if found := b.discovered[authorityKey{endpoint.Name, result.Name}]; found != nil {
		allows = append(allows, found.allows...)
	}
	if err = b.merge(&result, allows); err != nil {
		root.failure(u, allowFailure, err)
	}
	return result
}

// entry resolves an authority's entry binding.
func (w *branch) entry(ref model.Reference, u *useContext) (*model.Document, error) {
	entry, err := w.document(ref, u)
	if err != nil {
		return nil, err
	}
	if entry.Binding == nil {
		return nil, errorf(model.ReasonKindMismatch, &entry.Key, "entry %s is not a binding", ref)
	}
	if entry.Binding.Selection != nil {
		return nil, errorf(model.ReasonKindMismatch, &entry.Key, "entry %s selects PolicySets; an entry targets one Policy or PolicySet", ref)
	}
	w.narrow(u, entry.Key)
	return entry, nil
}

// rootSet compiles the root PolicySet the entry binding targets. Each of its
// prohibitions and bindings compiles in its own branch under the entry's
// bound. It returns the bindings' Allow diagrams and the merged prohibition
// diagram, which is empty when the returned error is from the merge.
func (w *branch) rootSet(entry *model.Binding, u *useContext) ([]string, string, error) {
	if err := w.enter(entry, entry.Policy.Source, u); err != nil {
		return nil, "", err
	}
	root, err := w.document(entry.Policy, u)
	if err != nil {
		return nil, "", err
	}
	if root.Set == nil {
		return nil, "", errorf(model.ReasonKindMismatch, &root.Key, "root %s is not a PolicySet", entry.Policy)
	}
	w.narrow(u, root.Key)
	u.path = append(u.path, root.Key)
	u.aliases = append(u.aliases, alias(root.Key))
	var allows, prohibitions []string
	for _, slot := range []struct {
		refs   []model.Reference
		effect model.Effect
		ids    *[]string
	}{
		{root.Set.Prohibitions, model.EffectDeny, &prohibitions},
		{root.Set.Bindings, model.EffectAllow, &allows},
	} {
		for _, ref := range slot.refs {
			worker, context, forkErr := w.fork(*u)
			if forkErr != nil {
				w.failure(context, classFor(slot.effect), forkErr)
				continue
			}
			node := worker.binding(ref, context, slot.effect)
			*slot.ids = append(*slot.ids, worker.persist(node, context, classFor(slot.effect)))
		}
	}
	merged, err := w.owner.union(prohibitions, w.owner.limits.MaxMergeNodes)
	if err != nil {
		return allows, "", fmt.Errorf("merge prohibitions: %w", err)
	}
	return allows, merged, nil
}

// fork returns a new branch and a use derived from u that holds u's bounds
// in it. When the bound doesn't fit the new branch, it returns the error,
// with the use keeping u's bound for its failure.
func (w *branch) fork(u useContext) (*branch, useContext, error) {
	worker := w.owner.newBranch()
	context := u.derive()
	context.root = false
	var err error
	if context.bound, err = worker.arena.Import(w.arena.Snapshot(u.bound)); err != nil {
		context.bound = u.bound
		return worker, context, err
	}
	if context.advisoryBound, err = worker.advisoryArena.Import(w.advisoryArena.Snapshot(u.advisoryBound)); err != nil {
		worker.stopAdvisories()
		context.advisoryBound = 0
	}
	return worker, context, nil
}

// merge sets the authority's composed Allow diagram. One that exceeds
// MaxMergeNodes or MaxSelectorKeys is omitted, and the independent diagrams
// are pushed in its place. Each grants only what its root binding or discovered
// PolicySet grants alone, so a request they cover only together is no longer
// granted, which the returned error reports.
func (b *builder) merge(result *model.AuthorityProgram, allows []string) error {
	if len(allows) == 1 {
		result.ComposedAllowDiagramID = allows[0]
		return nil
	}
	composed, err := b.union(allows, b.limits.MaxMergeNodes)
	if err != nil {
		result.IndependentAllowDiagramIDs = allows
		return errorf(model.ReasonGrantsNotComposed, nil, "the authority's grants can't be composed (%v), so a request is granted only when one root binding or discovered PolicySet covers all of it", err)
	}
	result.ComposedAllowDiagramID = composed
	return nil
}

func classFor(effect model.Effect) failureClass {
	if effect == model.EffectDeny {
		return authoritativeFailure
	}
	return allowFailure
}

// empty adds the diagram that grants nothing to the program.
func (b *builder) empty() string {
	diagram := model.Diagram{Nodes: []model.Node{{}}}
	id := model.Digest(diagram)
	b.output.Prepared.Diagrams[id] = diagram
	return id
}

// union saves the union of stored diagrams, or fails when it exceeds maxNodes
// or MaxSelectorKeys.
func (b *builder) union(ids []string, maxNodes int) (string, error) {
	if len(ids) == 0 {
		return b.empty(), nil
	}
	arena := model.NewArena(maxNodes)
	root := model.NodeID(0)
	for _, id := range ids {
		next, err := arena.Import(b.output.Prepared.Diagrams[id])
		if err != nil {
			return "", err
		}
		if root, err = arena.Union(root, next); err != nil {
			return "", err
		}
	}
	return b.save(arena.Snapshot(root))
}

// authoritativeFailures saves the union of an authority's authoritative
// failures, each labeled over its bound. Failures are never dropped, so
// a union that exceeds MaxDiagramNodes or MaxSelectorKeys fails the compile.
func (b *builder) authoritativeFailures(key authorityKey) (string, error) {
	ids := make([]string, 0, len(b.failures[key]))
	for _, failure := range b.failures[key] {
		id, err := b.label(failure)
		if err != nil {
			return "", fmt.Errorf("failures of authority %s: %w", key.authority, err)
		}
		ids = append(ids, id)
	}
	id, err := b.union(ids, b.limits.MaxDiagramNodes)
	if err != nil {
		return "", fmt.Errorf("failures of authority %s: %w", key.authority, err)
	}
	return id, nil
}

// label saves failure's issue labeled over its bound, in an arena
// of MaxDiagramNodes of its own.
func (b *builder) label(failure recordedFailure) (string, error) {
	arena := model.NewArena(b.limits.MaxDiagramNodes)
	root, err := arena.Import(failure.bound)
	if err != nil {
		return "", err
	}
	if root, err = arena.Label(root, failure.issueID); err != nil {
		return "", err
	}
	return b.save(arena.Snapshot(root))
}

// persist saves the branch's diagram rooted at root. When save refuses it,
// that is a failure of class for u, and the empty diagram takes its place.
func (w *branch) persist(root model.NodeID, u useContext, class failureClass) string {
	id, err := w.owner.save(w.arena.Snapshot(root))
	if err != nil {
		w.failure(u, class, err)
		return w.owner.empty()
	}
	return id
}

func (b *builder) finalize() (Compilation, error) {
	maxNodes := b.limits.MaxDiagramNodes
	b.finalizeDiagnostics()
	for _, id := range slices.Sorted(maps.Keys(b.selections)) {
		b.output.Selections = append(b.output.Selections, b.selections[id])
	}
	prunePrepared(&b.output.Prepared)
	if !preparedWithinNodeLimit(b.output.Prepared, maxNodes) && len(b.output.Prepared.Exclusions) > 0 {
		b.output.Prepared.Exclusions = nil
		b.output.Prepared.ExclusionsTruncated = true
		prunePrepared(&b.output.Prepared)
	}
	if !preparedWithinNodeLimit(b.output.Prepared, maxNodes) {
		return Compilation{}, fmt.Errorf("policy program exceeds its %d diagram nodes: %w", maxNodes, model.ErrLimit)
	}
	return b.output, nil
}

func preparedWithinNodeLimit(prepared model.PreparedRevision, maxNodes int) bool {
	nodes := 0
	for _, diagram := range prepared.Diagrams {
		nodes += len(diagram.Nodes)
		if nodes > maxNodes {
			return false
		}
	}
	return true
}

func prunePrepared(prepared *model.PreparedRevision) {
	diagramIDs := map[string]bool{}
	predicateIDs := map[string]bool{}
	contributionIDs := map[string]bool{}
	issueIDs := map[string]bool{}

	addIssue := func(id string) {
		if issueIDs[id] {
			return
		}
		issue, found := prepared.Issues[id]
		if !found {
			return
		}
		issueIDs[id] = true
		for _, predicateID := range issue.PrincipalIDs {
			predicateIDs[predicateID] = true
		}
	}
	addDiagram := func(id string) {
		if id == "" || diagramIDs[id] {
			return
		}
		diagram, found := prepared.Diagrams[id]
		if !found {
			return
		}
		diagramIDs[id] = true
		for _, node := range diagram.Nodes {
			for _, terminal := range node.Terminals {
				if contribution, found := prepared.Contributions[terminal]; found {
					contributionIDs[terminal] = true
					for _, predicateID := range contribution.PrincipalIDs {
						predicateIDs[predicateID] = true
					}
				}
				addIssue(terminal)
			}
		}
	}
	for _, proof := range prepared.Exclusions {
		addDiagram(proof.DiagramID)
		for _, id := range proof.PrincipalIDs {
			predicateIDs[id] = true
		}
	}
	for _, endpoint := range prepared.Endpoints {
		for _, authority := range endpoint.Authorities {
			predicateIDs[authority.MatcherID] = true
			for _, id := range authority.SelectionErrorIDs {
				addIssue(id)
			}
			for _, id := range authority.IndependentAllowDiagramIDs {
				addDiagram(id)
			}
			addDiagram(authority.ComposedAllowDiagramID)
			addDiagram(authority.ProhibitionDiagramID)
			addDiagram(authority.AuthoritativeFailureDiagramID)
		}
	}
	prepared.Diagrams = retain(prepared.Diagrams, diagramIDs)
	prepared.Predicates = retain(prepared.Predicates, predicateIDs)
	conditionIDs := map[string]bool{}
	for id := range contributionIDs {
		for _, conditionID := range prepared.Contributions[id].ConditionIDs {
			conditionIDs[conditionID] = true
		}
	}
	prepared.Contributions = retain(prepared.Contributions, contributionIDs)
	prepared.Issues = retain(prepared.Issues, issueIDs)
	prepared.Conditions = retain(prepared.Conditions, conditionIDs)
}

func retain[T any](values map[string]T, retained map[string]bool) map[string]T {
	result := make(map[string]T, len(retained))
	for id := range retained {
		if value, found := values[id]; found {
			result[id] = value
		}
	}
	return result
}

// failureIssue is the issue err records for u.
func failureIssue(u useContext, err error) model.ProgramIssue {
	issue := u.issue(model.ReasonInternalError, err.Error())
	if failure, ok := errors.AsType[*compileError](err); ok {
		issue.Reason, issue.Document = failure.reason, failure.document
	} else if errors.Is(err, model.ErrLimit) {
		issue.Reason = model.ReasonResourceLimitExceeded
	}
	return issue
}

// failure records why part of an authority couldn't be compiled. An Allow
// failure becomes a diagnostic. An authoritative failure is recorded
// with the use's bound, which it is labeled over, so it only affects requests
// that use could have decided.
func (w *branch) failure(u useContext, class failureClass, err error) {
	issue := failureIssue(u, err)
	if class == allowFailure {
		var origin model.DocumentKey
		if issue.Document != nil {
			origin = *issue.Document
		}
		w.owner.addDiagnostic(issue.ContextID, origin, issue.Issue)
		return
	}
	id := model.Digest(issue)
	w.owner.output.Prepared.Issues[id] = issue
	key := authorityKey{u.endpoint, u.authority}
	w.owner.failures[key] = append(w.owner.failures[key], recordedFailure{issueID: id, bound: w.arena.Snapshot(u.bound)})
}

// use counts one contextual use of the branch, and checks that it may read
// source.
func (w *branch) use(u useContext, source model.SourceKey) error {
	w.uses++
	if limit := w.owner.limits.MaxContextualUsesPerBranch; w.uses > limit {
		return fmt.Errorf("branch exceeds %d contextual uses: %w", limit, model.ErrLimit)
	}
	if !u.sources[source] {
		return errorf(model.ReasonSourceNotAllowed, nil, "source %s/%s is outside the delegated source set", source.Namespace, source.Name)
	}
	return nil
}

func (w *branch) document(ref model.Reference, u *useContext) (*model.Document, error) {
	if err := w.use(*u, ref.Source); err != nil {
		return nil, err
	}
	w.owner.output.References[ref] = struct{}{}
	source, err := available(w.owner.sources, ref.Source)
	if err != nil {
		return nil, err
	}
	key := model.DocumentKey{Source: source.Instance, Group: ref.Group, Kind: ref.Kind, Namespace: ref.Namespace, Name: ref.Name}
	state, found := source.Documents[ref]
	if !found {
		return nil, errorf(model.ReasonMissingReference, &key, "document %s doesn't exist", ref)
	}
	if state.Document == nil {
		return nil, errorf(model.ReasonInvalidDocument, &key, "document %s is invalid", ref)
	}
	for _, issue := range state.Issues {
		if issue.Severity == api.IssueSeverityWarning {
			w.owner.addDiagnostic("", state.Key, issue)
		}
	}
	return state.Document, nil
}

type policyResult struct {
	root         model.NodeID
	advisoryRoot model.NodeID
	policy       model.DocumentKey
	condition    *model.Condition
	exclusions   []exclusionCandidate
}

func (w *branch) policy(ref model.Reference, u *useContext) (policyResult, error) {
	doc, err := w.document(ref, u)
	if err != nil {
		return policyResult{}, err
	}
	if doc.Policy == nil {
		return policyResult{}, errorf(model.ReasonKindMismatch, &doc.Key, "reference %s is not a permission policy", ref)
	}
	root, err := w.rules(doc.Policy.Include)
	if err != nil {
		return policyResult{}, err
	}
	result := policyResult{root: root, advisoryRoot: w.advisoryRules(doc.Policy.Include), policy: doc.Key, condition: doc.Policy.Condition}
	for _, item := range doc.Policy.Imports {
		imported, importErr := w.policy(item.Reference, u)
		if importErr != nil {
			return policyResult{}, importErr
		}
		if item.Namespaces != nil {
			if importErr = w.scope(&imported, item.Namespaces); importErr != nil {
				return policyResult{}, importErr
			}
		}
		for index := range imported.exclusions {
			imported.exclusions[index].path = append([]model.DocumentKey{doc.Key}, imported.exclusions[index].path...)
		}
		result.root, err = w.arena.Union(result.root, imported.root)
		if err != nil {
			return policyResult{}, err
		}
		result.advisoryRoot = w.advisoryUnion(result.advisoryRoot, imported.advisoryRoot)
		result.exclusions = append(result.exclusions, imported.exclusions...)
	}
	excluded, err := w.rules(doc.Policy.Exclude)
	if err != nil {
		return policyResult{}, err
	}
	result.root, err = w.arena.Subtract(result.root, excluded)
	if err != nil {
		return policyResult{}, err
	}
	advisoryExcluded := w.advisoryRules(doc.Policy.Exclude)
	removed := w.advisoryIntersect(result.advisoryRoot, advisoryExcluded)
	if removed != 0 {
		result.exclusions = append(result.exclusions, exclusionCandidate{node: removed, path: []model.DocumentKey{doc.Key}})
	}
	result.advisoryRoot = w.advisorySubtract(result.advisoryRoot, advisoryExcluded)
	return result, nil
}

// scope restricts policy's resource permissions to namespaces.
func (w *branch) scope(policy *policyResult, namespaces []string) error {
	scopes := model.NamespaceCubes(namespaces)
	for _, scope := range scopes {
		scope[model.Category] = model.Values(model.Atom("resource"))
	}
	bound, err := w.rules(scopes)
	if err != nil {
		return err
	}
	if policy.root, err = w.arena.Intersect(policy.root, bound); err != nil {
		return err
	}
	advisoryBound := w.advisoryRules(scopes)
	policy.advisoryRoot = w.advisoryIntersect(policy.advisoryRoot, advisoryBound)
	w.narrowExclusions(policy.exclusions, advisoryBound)
	return nil
}

func (w *branch) rules(cubes []model.Cube) (model.NodeID, error) {
	w.ruleCount += len(cubes)
	if limit := w.owner.limits.MaxExpandedRulesPerBranch; w.ruleCount > limit {
		return 0, fmt.Errorf("branch exceeds %d expanded rules: %w", limit, model.ErrLimit)
	}
	roots := make([]model.NodeID, 0, len(cubes))
	for _, cube := range cubes {
		next, err := w.arena.Cube(cube)
		if err != nil {
			return 0, err
		}
		roots = append(roots, next)
	}
	return w.arena.UnionAll(roots)
}
func (w *branch) binding(ref model.Reference, u useContext, effect model.Effect) model.NodeID {
	doc, err := w.document(ref, &u)
	if err != nil {
		w.failure(u, classFor(effect), err)
		return 0
	}
	u.path = append(u.path, doc.Key)
	if doc.Binding == nil {
		w.failure(u, classFor(effect), errorf(model.ReasonKindMismatch, &doc.Key, "reference %s is not a binding", ref))
		return 0
	}
	w.narrow(&u, doc.Key)
	u.principals = append(u.principals, w.owner.predicate(doc.Binding.Principal))
	if err := w.constrain(doc.Binding, &u, effect); err != nil {
		w.failure(u, classFor(effect), err)
		return 0
	}
	if doc.Binding.Selection != nil {
		if effect == model.EffectDeny {
			w.failure(u, authoritativeFailure, errorf(model.ReasonKindMismatch, &doc.Key, "prohibition %s selects PolicySets, not a leaf", ref))
			return 0
		}
		w.selection(doc.Binding, u)
		return 0
	}
	if doc.Binding.Policy.Kind == model.KindPolicySet {
		if effect == model.EffectDeny {
			w.failure(u, authoritativeFailure, errorf(model.ReasonKindMismatch, &doc.Key, "prohibition %s targets a PolicySet, not a leaf", ref))
			return 0
		}
		if err := w.enter(doc.Binding, doc.Binding.Policy.Source, &u); err != nil {
			w.failure(u, allowFailure, err)
			return 0
		}
		return w.set(doc.Binding.Policy, u)
	}
	return w.leaf(doc.Binding, u, effect)
}
func (w *branch) leaf(binding *model.Binding, u useContext, effect model.Effect) model.NodeID {
	policy, err := w.policy(binding.Policy, &u)
	if err == nil && binding.Namespace != "" {
		err = w.scope(&policy, []string{binding.Namespace})
	}
	if err == nil {
		err = w.admitCondition(&u, policy.condition, policy.policy)
	}
	// A prohibition decides without evaluating conditions, so one that would
	// carry a condition fails over its bound instead.
	if err == nil && effect == model.EffectDeny && len(u.conditions) > 0 {
		err = errorf(model.ReasonConditionalProhibition, &policy.policy, "a prohibition can't carry Rego conditions")
	}
	if err == nil {
		policy.root, err = w.arena.Intersect(policy.root, u.bound)
		w.narrowExclusions(policy.exclusions, u.advisoryBound)
	}
	if err != nil {
		w.failure(u, classFor(effect), err)
		return 0
	}
	w.emitExclusionProofs(policy.exclusions, u, effect)
	u.path = append(u.path, policy.policy)
	contribution := model.Contribution{Effect: effect, PrincipalIDs: slices.Clone(u.principals), ContextID: u.identity(), Path: slices.Clone(u.path)}
	if len(u.conditions) > 0 {
		contribution.ConditionIDs = slices.Compact(slices.Sorted(slices.Values(u.conditions)))
	}
	contribution.ID = model.Digest(contribution)
	labeled, err := w.arena.Label(policy.root, contribution.ID)
	if err != nil {
		w.failure(u, classFor(effect), err)
		return 0
	}
	w.owner.output.Prepared.Contributions[contribution.ID] = contribution
	return labeled
}
func (w *branch) constrain(binding *model.Binding, u *useContext, effect model.Effect) error {
	if binding.Bound == nil {
		return nil
	}
	bound, err := w.policy(*binding.Bound, u)
	if err != nil {
		return err
	}
	if err = w.admitCondition(u, bound.condition, bound.policy); err != nil {
		return err
	}
	// A failed intersection leaves the incoming bound, which still covers
	// every request this use could decide.
	narrowed, err := w.arena.Intersect(u.bound, bound.root)
	if err != nil {
		return err
	}
	u.bound = narrowed
	w.narrowExclusions(bound.exclusions, u.advisoryBound)
	w.emitExclusionProofs(bound.exclusions, *u, effect)
	u.advisoryBound = w.advisoryIntersect(u.advisoryBound, bound.advisoryRoot)
	return nil
}

// selection compiles each PolicySet binding's selection matches in a branch
// of its own, as a delegation from u to it. The selection counts as one
// contextual use of w, and fails as a whole when its matches would exceed
// the branches the authority has left. The matches' diagrams join
// the authority's merge, not w's.
func (w *branch) selection(binding *model.Binding, u useContext) {
	selection := *binding.Selection
	if err := w.use(u, selection.Source); err != nil {
		w.failure(u, allowFailure, err)
		return
	}
	w.owner.selections[model.Digest(selection)] = selection
	selected := Select(selection, w.owner.sources, w.owner.limits.MaxSelectionMatches)
	if err := selected.err(); err != nil {
		w.failure(u, allowFailure, err)
		return
	}
	key := authorityKey{u.endpoint, u.authority}
	found := w.owner.discovered[key]
	if found == nil {
		found = &discovered{}
		w.owner.discovered[key] = found
	}
	if limit := w.owner.limits.MaxSelectedBranches; found.branches+len(selected.Matches) > limit {
		w.failure(u, allowFailure, fmt.Errorf("selections beneath the authority match more than %d PolicySets: %w", limit, model.ErrLimit))
		return
	}
	found.branches += len(selected.Matches)
	for _, match := range selected.Matches {
		worker, context, err := w.fork(u)
		if err != nil {
			w.failure(context, allowFailure, err)
			continue
		}
		if err := worker.enter(binding, match.Source, &context); err != nil {
			worker.failure(context, allowFailure, err)
			continue
		}
		found.allows = append(found.allows, worker.persist(worker.set(match, context), context, allowFailure))
	}
}

// enter delegates from u, through binding, to a PolicySet of target.
func (w *branch) enter(binding *model.Binding, target model.SourceKey, u *useContext) error {
	if !u.root {
		if u.remaining <= 0 {
			return errorf(model.ReasonDepthExceeded, nil, "delegation depth exhausted")
		}
		u.remaining--
	}
	if binding.MaxDepth != nil {
		u.remaining = min(u.remaining, *binding.MaxDepth)
	}
	if !u.sources[target] {
		return errorf(model.ReasonSourceNotAllowed, nil, "target source is outside incoming source set")
	}
	sources := map[model.SourceKey]bool{target: true}
	if binding.Sources != nil {
		sources = map[model.SourceKey]bool{}
		for _, source := range binding.Sources {
			if !u.sources[source] {
				return errorf(model.ReasonInvalidSourceRestriction, nil, "sourceRefs widen incoming set")
			}
			sources[source] = true
		}
	}
	u.sources = sources
	u.root = false
	return nil
}
func (w *branch) set(ref model.Reference, u useContext) model.NodeID {
	doc, err := w.document(ref, &u)
	if err != nil {
		w.failure(u, allowFailure, err)
		return 0
	}
	if slices.Contains(u.path, doc.Key) || doc.Key.Source.Origin != "" && slices.Contains(u.aliases, alias(doc.Key)) {
		w.failure(u, allowFailure, errorf(model.ReasonCycle, &doc.Key, "delegation cycle"))
		return 0
	}
	u.path = append(u.path, doc.Key)
	u.aliases = append(u.aliases, alias(doc.Key))
	if doc.Set == nil {
		w.failure(u, allowFailure, errorf(model.ReasonKindMismatch, &doc.Key, "child %s is not a PolicySet", ref))
		return 0
	}
	w.narrow(&u, doc.Key)
	if len(doc.Set.Prohibitions) > 0 {
		w.failure(u, allowFailure, errorf(model.ReasonDenyOutsideRoot, &doc.Key, "descendant PolicySet contains prohibitionRefs"))
		return 0
	}
	root := model.NodeID(0)
	for _, binding := range doc.Set.Bindings {
		next := w.binding(binding, u.derive(), model.EffectAllow)
		root, err = w.arena.Union(root, next)
		if err != nil {
			w.failure(u, allowFailure, err)
			return 0
		}
	}
	return root
}

// narrow applies the allowlist of the source that serves a binding or PolicySet
// on the use's path. Only delegation narrows: the Policies a use reaches,
// and the roles they import, are content.
func (w *branch) narrow(u *useContext, key model.DocumentKey) {
	allowed := w.owner.sources[key.Source.Key].AllowedBuiltins
	switch {
	case allowed == nil:
		if u.forbiddenBy == nil {
			u.forbiddenBy = new(key.Source.Key)
		}
	case u.builtins == nil:
		u.builtins = allowed
	default:
		u.builtins = new(u.builtins.Intersect(*allowed))
	}
}

// admitCondition adds a Policy's condition to the use. The Policy's own source
// and every source on the path must allow Rego conditions, and the condition
// may call only builtins its own source and the path allow.
func (w *branch) admitCondition(u *useContext, c *model.Condition, key model.DocumentKey) error {
	if c == nil {
		return nil
	}
	own := w.owner.sources[key.Source.Key].AllowedBuiltins
	forbidden := u.forbiddenBy
	if own == nil {
		forbidden = &key.Source.Key
	}
	if forbidden != nil {
		return errorf(model.ReasonRegoNotAllowed, &key, "source %s/%s doesn't allow Rego conditions", forbidden.Namespace, forbidden.Name)
	}
	allowed := *own
	if u.builtins != nil {
		allowed = allowed.Intersect(*u.builtins)
	}
	if missing := allowed.Missing(c.Builtins); len(missing) > 0 {
		return errorf(model.ReasonBuiltinNotAllowed, &key, "condition calls builtins this path doesn't allow: %s", strings.Join(missing, ", "))
	}
	u.conditions = append(u.conditions, c.ID)
	w.owner.output.Prepared.Conditions[c.ID] = *c
	return nil
}
