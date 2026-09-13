// Package program implements the built-in authorization request integrations
// as Rego. The Kubernetes integration normalizes SubjectAccessReviews into
// the shared principal and query model. It reads only the fields normalization
// needs, so fields a newer kube-apiserver adds are ignored, and a review
// it can't encode gets the endpoint's whenEvaluationFails response. It reads
// namespace and subresource "*" literally, as RBAC does. Its fixed Rego
// modules, which [Assets] holds, serve every endpoint the pushed state lists
// and format responses from shared policy decisions. Integration selection
// is trusted service configuration, never request data.
//
// The Kubernetes integration also builds each Rego condition's input:
// the normalized principal {user, groups, uid, extra}, with extra an object,
// and the request as exactly one of resourceAttributes, with its string fields
// and its fieldSelector and labelSelector, or nonResourceAttributes, with its
// path and verb. An absent field reads as "" or {}.
package program
