// Package diagnostics serves the operator's diagnostics endpoint: the snapshot
// actually installed on one engine pod of an AuthorizationService, never
// the desired compilation.
//
// [NewHandler] authenticates each request, then authorizes it as a get request
// for the service's authorizationservices/diagnostics subresource, so RBAC can
// scope access to one service by resourceNames. The operator supplies
// the authenticator and authorizer, which delegate to the API server,
// and serves the handler on every replica.
//
// The route is [SnapshotPath]. The pod must be one of the service's engine
// pods in the operator's cache. The handler reads the digest of the pod's
// conditions module, then its state document, through the engine management
// client, and relays both, the document without decoding it, with the time
// they were read; the state is null when the pod has none. A failed engine
// read is a bad gateway.
package diagnostics
