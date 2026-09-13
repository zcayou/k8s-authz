// Package validation turns API objects into the operator's model. The CRD
// schemas, including every structural and CEL rule, have already validated them
// at admission, so this package applies only the semantic rules CEL can't
// express and the normalization the compiler relies on. Set-like input, such
// as repeated subjects, imports, binding references or selector values,
// is normalized rather than rejected. Documents are decoded strictly: a field
// the Go types don't declare rejects the document. A cached document, which
// the API server admitted earlier, drops such a field instead, as the API
// server prunes it on read. A Policy's Rego condition is checked
// by internal/condition, which also records the builtins it calls. Errors
// are field.ErrorLists, reported with the single reason Invalid.
package validation
