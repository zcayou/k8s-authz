// Package compiler resolves source-qualified policy graphs in contextual uses
// and compiles bounded, immutable permission programs without network access.
// A Compilation records the documents it read, including unresolved references,
// and the selections it evaluated, so a cache can tell when it's stale.
// Diagnostics retain each use's inherited restrictions.
//
// A failure is classified by what it breaks. A failure on an Allow path grants
// nothing and is reported as a diagnostic. So is a failure resolving the bound
// of an entry binding that targets a leaf Policy, because that bound narrows
// only an Allow. A failure resolving the entry binding, the bound of an entry
// that targets a PolicySet, the root PolicySet or a prohibition
// is authoritative: it is labeled over its use's bound, and the engine answers
// with the endpoint's whenEvaluationFails result for requests inside it.
//
// A Policy's Rego condition propagates like a binding's principal: every
// contribution beneath a use carries the conditions of the Policies it reached,
// its bounds' and its target's. Sources allow conditions along the path: each
// binding and PolicySet narrows the builtins its conditions may call to its
// source's allowlist, a source without rego forbids them, and the service's
// ceiling caps them all. A condition must also be allowed by its own Policy's
// source. The Policies a use reaches, and the roles they import, don't narrow.
// A prohibition decides without conditions, so a Deny use that would carry one
// fails authoritatively.
//
// A binding with a selection delegates to each PolicySet the selection matches,
// as a binding that references it would. [Select] evaluates a selection,
// for the compiler, the program cache and the CLI alike. Each match compiles
// in a branch of its own under the selecting use's bound, principals,
// conditions and sources, so a match that exceeds its branch's limits fails
// alone, and its diagram joins the authority's merge beside those of its root
// bindings. A selection that matches more than MaxSelectionMatches PolicySets,
// or whose matches would take the authority past MaxSelectedBranches detached
// branches, fails as a whole. A selecting binding used as an authority's entry
// or as a prohibition fails authoritatively.
//
// [Limits] bound each branch and each merged diagram with fixed caps, so one
// authority's configuration never changes another's decisions, and every saved
// diagram branches on at most [MaxSelectorKeys] selector keys, the depth
// the engine's traversal walks. A branch or prohibition merge over its limits
// records a failure for its use. A composed Allow diagram over its limits
// is omitted, and the independent diagrams take its place. Each grants only
// what its root binding or discovered PolicySet grants alone, so
// the authority's root use records a GrantsNotComposed diagnostic: a request
// they cover only together is no longer granted. Only two limits fail
// a compile: an authority's authoritative failures that don't fit
// MaxDiagramNodes or MaxSelectorKeys, and a program whose diagrams together
// exceed MaxDiagramNodes. Compile then returns an error wrapping
// model.ErrLimit.
package compiler
