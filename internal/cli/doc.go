// Package cli implements the k8s-authz command: offline document and graph
// validation, explanation of an engine's installed snapshot, and kube-apiserver
// caller configuration.
//
// NewCommand builds the command tree; Execute runs it and maps its result
// to a process exit code: 0 on success, 1 when a validation report found
// errors, and 2 when the command couldn't run. Commands read and write
// the command's own streams.
//
// Commands that read the cluster take kubectl's --kubeconfig and override
// flags, and read through one client built from the resulting configuration.
// Target services are a positional name plus -n.
//
// Connected explain reads the snapshot installed on an engine pod from
// the operator's diagnostics endpoint. It port-forwards to a ready operator pod
// through kube-apiserver with the caller's credentials, over a websocket
// with a SPDY fallback as kubectl does, and presents the same credentials over
// the tunnel, so they only ever reach kube-apiserver and the operator
// it tunnels to. Explain evaluates the export's state with this release's
// evaluator and refuses state another evaluator compiled. An export without
// state means the engine pod has no installed policy.
//
// Validation decodes documents strictly with the operator's own decoders,
// applies the API server's metadata rules for each kind, and applies only
// the operator's semantic rules; the CRD schemas and their CEL rules need
// an API server, such as kubectl apply --dry-run=server. validate graph
// compiles an AuthorizationService file against complete offline sources
// that --source NAMESPACE/NAME=FILE assembles, through engine.Prepare,
// as the operator does, including the documents that have errors.
package cli
