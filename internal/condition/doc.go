// Package condition owns the Rego condition language: checking a Policy's
// condition, recording the builtins it calls, the default builtins a source
// allows, and generating the conditions module engines run.
//
// A condition is a Rego v1 module in package condition. Its boolean rule allow
// decides whether the Policy applies to a request, with input the request's
// principal and attributes. It may define helper rules and functions and import
// only rego.v1 and future.keywords. It may not use with, reference data beyond
// its own rules, or declare rules with reference heads. Check enforces this
// and records the builtins the module calls, so the compiler can hold them
// to the allowlists along each use path. That check is the only gate: stock OPA
// can't restrict the builtins of modules pushed through its API.
//
// Generate compiles each condition alone, renames its rules c_<id>_<rule>
// into package authz.conditions, and concatenates the conditions in ID order
// with a digest of the result. Engines install the module under PolicyID.
package condition
