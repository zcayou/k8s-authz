# Internals

This page maps the user-facing behavior described in the rest of the docs onto the code.

## Binaries

- **`cmd/main.go`** builds the manager. `internal/operator.ManagerOptions` configures the controller-runtime manager (shared with the tests), and `internal/operator.Setup` wires the source registry, the three controllers, the program cache (`engine.Cache`), and the diagnostics server.
- **`cmd/k8s-authz`** is the CLI, implemented in `internal/cli`. Commands that read the cluster use one controller-runtime client with a static REST mapper, so they need no discovery.
- **`cmd/evaluator-gen`** generates the unrolled traversal levels in `internal/engine/assets/traversal.rego`.

## The policy pipeline

1. **Acquire.** The `PolicySourceSupervisor` (every replica, not leader-elected) registers each `PolicySource` under its UID in `source.Registry`, with a credential-scoped reader from `internal/source/kubernetes` built on filtered client-go informers. The registry holds each source's last complete view and reports acquisition health. Before registering a source, the supervisor restores its view from the persistent cache in `internal/source/storage`.
2. **Fan out.** Leader controllers subscribe to the registry. The `PolicySource` controller projects health into status and persists views to Secrets. The `AuthorizationService` controller finds the services whose endpoints read a changed source through a field index.
3. **Compile.** `AuthorizationServiceReconciler` waits until every source the endpoints name is registered under its current UID, then calls `engine.Cache.Prepare`, which compiles with `compiler.Compile` and finalizes with `engine.FinalizeContent` into one content-addressed `model.ContentRevision` per service.
4. **Install.** The leader server-side applies the objects `internal/resources` builds, each independently, then for every started engine pod whose startup digest matches, reads its installed revision and conditions digest through `internal/engineclient` over mTLS, pushes the conditions module if it differs, then the state if it differs. Pods whose pushes keep failing past `--remediation-after` are evicted with a UID precondition.
5. **Serve.** Stock OPA evaluates webhook requests with the fixed evaluator modules (`internal/engine/assets`), the program modules (`internal/program/assets`), the pushed conditions module, and the pushed state. `system.authz` admits webhook callers whose certificate Common Name the endpoint's state lists, and the management identity when its chain verifies against the bootstrap roots.

## Runtime model

The manager's cache runs on every replica, and everything is read from it except Secret contents; the Pod cache holds only engine pods. The source supervisor runs on every replica so followers stay warm. The `PolicySource` and `AuthorizationService` controllers are leader-elected with warmup, so only the leader reconciles, compiles, pushes, and writes.

Reconciles are event-driven. Expected waits return no error and no requeue, because the awaited event enqueues the object. Transient failures return the error. Failures only a spec or source change can fix return `reconcile.TerminalError`. Status is server-side applied whole, without a resourceVersion, so a status computed from a cache that hasn't yet seen the operator's own last write replaces it instead of conflicting. Destructive actions and failures are recorded as Events.

## Package ownership

| Area | Packages |
| --- | --- |
| Policy semantics, no network access | `internal/model` (principals, regions, permission diagrams), `internal/validation` (strict decoding and normalization), `internal/condition` (the Rego condition language and builtins), `internal/compiler` (graph resolution, bounds, failures, limits) |
| Request integration | `internal/program`: the Rego that turns a `SubjectAccessReview` into a principal and a query, and formats the response |
| Engine contract | `internal/engine`: state encoding and limits, bootstrap and evaluator identity, OPA configuration, evaluator assets, explanation, the traversal. `internal/engineclient`: the management client |
| Workloads | `internal/resources`: apply configurations for the owned objects, the engine pod layout, and override merging |
| Sources | `internal/source`, `internal/source/kubernetes`, `internal/source/storage` |
| Controllers | `internal/controller` |
| Diagnostics | `internal/diagnostics` (handler and route), served from `internal/operator` behind delegated authentication and authorization |

The traversal is non-recursive and fixed-depth: the number of permission dimensions plus `compiler.MaxSelectorKeys`. Regenerate it with `make update` after changing `internal/engine/traversal.go` or that constant.

## Conventions

- `sort` is forbidden by depguard; use `slices`.
- The custom golangci-lint build includes `logcheck` and the `deadcode`, `testlayout`, and `zlines` linters.
- Log messages follow the [Kubernetes message style](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-instrumentation/logging.md#message-style-guidelines): capitalized, no trailing period, past tense for failures, and naming the object type.
