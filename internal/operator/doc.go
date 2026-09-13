// Package operator assembles the Kubernetes manager, source readers
// and authenticated engine management and diagnostics. [ManagerOptions]
// is the manager configuration that main and the tests share, and [Setup] adds
// the controllers and runnables, building the engine management client unless
// a test injects one. The diagnostics server runs on every replica
// and delegates authentication and authorization to the API server through
// the manager's config and HTTP client. The operator's configuration
// is the command-line flags bound by [Options].
package operator
