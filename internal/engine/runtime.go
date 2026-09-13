package engine

// RuntimeVersion is the OPA release the evaluator is built and tested against:
// the engines' image and the OPA module the operator links.
const RuntimeVersion = "1.20.2"

// DefaultImage is the stock OPA image of RuntimeVersion, pinned by the digest
// of its multi-platform index.
const DefaultImage = "docker.io/openpolicyagent/opa:" + RuntimeVersion + "@sha256:7b15f9d96345dfa639322ad97f65a0b38260f95efcdd7f5c24e284228708f06c"
