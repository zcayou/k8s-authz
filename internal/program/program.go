package program

import "embed"

// Assets holds the Kubernetes integration's Rego modules under assets/.
// They normalize SubjectAccessReviews, format the response and route each
// endpoint in the pushed state to its decision.
//
//go:embed assets/*.rego
var Assets embed.FS
