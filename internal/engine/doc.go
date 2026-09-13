// Package engine owns the contract between the operator and stock OPA:
// the release-owned Rego modules every engine loads, the OPA configuration,
// the bootstrap each pod starts from, and the state document the operator
// pushes.
//
// [Prepare] compiles a service's configuration and finalizes the resulting
// program into the state document, stamped with the service UID
// and the evaluator ID, addressed by the digest of its encoding and bounded
// by [MaxContentBytes]; [Cache] keeps one prepared program per service,
// and records the duration and outcome of each compilation it runs
// on controller-runtime's metrics registry. Executable Rego comes from
// the release and, for Policies' Rego conditions, from the conditions module
// [FinalizeContent] generates with the state, bounded
// by [MaxConditionModuleBytes]. The operator installs the module under
// condition.PolicyID before the state, and reads what a pod serves from
// data.authz.evaluator.installed: its state's revision and its module's digest.
// A contribution applies only when its principal predicates match and then
// every condition it carries holds; a condition the module doesn't define
// doesn't hold. [EvaluatorID] digests the runtime version and the modules,
// and a pod is ready only while its state was compiled for its bootstrap's
// service and evaluator. Installed state has no expiry. A request the evaluator
// can't evaluate gets the endpoint's whenEvaluationFails result; a broken Allow
// grants nothing and doesn't change the result. An authority grants through its
// composed Allow diagram, or through its independent ones when the composed
// diagram was omitted.
//
// The permission-diagram traversal is non-recursive: traversal_base.rego holds
// its static rules and [GenerateTraversal] unrolls its levels to a fixed depth,
// which compiler.MaxSelectorKeys bounds for every compiled diagram. It returns
// the terminals a query reaches, trusting the compiled diagram's structure,
// and is undefined past that depth. A walk visits each node once, so
// the compiled node bound limits it.
//
// [EvaluateSnapshot] explains an installed state document with the same
// modules, when this release's evaluator compiled it. It treats the state's
// conditions as untrusted: it checks them again, regenerates their module,
// and runs them without network or runtime builtins.
package engine
