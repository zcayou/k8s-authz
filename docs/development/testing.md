# Testing

Tests use Ginkgo/Gomega, with one `suite_test.go` per package, and the repository-pinned toolchain.

## Test tiers

| Tier | Command | What runs |
| --- | --- | --- |
| Unit | `make test-unit` | Package tests beside each package, which never start envtest or OPA, and the `_test.rego` suites in `internal/engine/testdata` and `internal/program/testdata` under `opa test`. |
| Integration | `make test-integration` | The `integration`-tagged suite in `test/integration`: envtest API servers, a leader-elected manager built through `operator.Setup`, and stock OPA. |
| Both | `make test` | Unit and integration. |
| Race | `make test-race` | Unit and integration with the race detector. |
| End to end | `make test-e2e` | The `e2e`-tagged suite in `test/e2e` against two disposable Kind clusters. |

`make validate` also checks the Rego modules with `opa fmt`, `opa check --strict`, and Regal. The engine's unit tests compile the embedded modules strictly and pin `engine.RuntimeVersion` to the linked OPA module.

Use focused runs while editing, and full runs once the affected pieces are connected:

```sh
go test ./internal/compiler -ginkgo.focus "regex"

make setup-envtest opa
go test -tags integration ./test/integration -ginkgo.focus "regex"
```

Run directly, the integration suite uses what `make setup-envtest opa` installed under `bin/`. A `KUBEBUILDER_ASSETS` or `OPA_BINARY` you set yourself must be an absolute path, because Go runs the suite from its package directory.

## Conventions

- Unit tests are black-box (`package <pkg>_test`) and named for the source file they exercise, which the `testlayout` linter enforces. Only `internal/controller` keeps Kubebuilder's in-package tests.
- Shared helpers go in `helpers_test.go` or `fakes_test.go`, or `*_fixture_test.go` in the integration and e2e suites. Helpers that more than one test package uses belong in `test/utils`, never in a test-only package under `internal/`.
- Suites fail rather than skip when a binary they need is missing.

## The integration suite

`test/integration` exercises only exported APIs. It shares one envtest API server and one leader-elected manager built through `operator.Setup`, with a fake engine management client injected. The multi-API specs start a second API server on first use, and the engine specs run stock OPA from the rendered ConfigMap and argument vector.

envtest runs no namespace, garbage-collection, or workload controllers, so each spec deletes the `AuthorizationService`s and `PolicySource`s it creates, reports workload status itself, and restores any suite-wide file it changes. Specs that change the shared CRDs are marked `Serial`.

## The e2e suite

`make test-e2e` follows the Kubebuilder flow:

1. `setup-test-e2e` creates two Kind clusters when they're missing, on `KIND_NODE_IMAGE` if set, and exports the control cluster's kubeconfig:
   - The **control cluster** (`KIND_CLUSTER`, from `test/e2e/kind-config.yaml`) runs the operator and the engines.
   - The **member cluster** (`KIND_MEMBER_CLUSTER`, `k8s-authz-member-e2e` by default, from `test/e2e/kind-member-config.yaml`) is a single node with no operator. It serves the remote source's policy, and its API server calls the engines in the control cluster.

   It copies `test/e2e/authorization-config.yaml` into `tmp/e2e/apiserver` and `tmp/e2e/member-apiserver`, which the Kind configs mount into each control-plane node as the API server's `--authorization-config`.
2. The suite refuses to run unless the current context is `kind-$KIND_CLUSTER` and Kind runs `KIND_MEMBER_CLUSTER`. It reaches the member only through the kubeconfig Kind reports for it, which it writes to `tmp/e2e/member.kubeconfig`. Its `BeforeSuite`:
   - removes any installation a previous run left in either cluster;
   - builds and loads the manager image, builds the CLI, and creates the operator's Secrets with certificates issued in memory;
   - installs the CRDs, the remote policy and a reader ServiceAccount in the member;
   - runs `make install` and `make deploy` in the control cluster, and applies a baseline with a local source and a remote source that reads the member's API server with the reader's token;
   - installs the configurations `render-caller-config` renders, which each API server reloads in place. The control API server calls the `cluster` endpoint through the listener's ClusterIP, and the member's calls the `member` endpoint through the listener's NodePort on the control cluster's node.
3. `cleanup-test-e2e` deletes both clusters only when the suite passes, so a failed run leaves them for debugging. A failed spec records resources, Events, operator logs, and a cluster-info dump under `artifacts/e2e-<run>/`, with the member's under `member/`.

Each feature is a labeled, self-contained `Describe` that checks the baseline before every spec and restores what it changes, so features run in any order against one installation. The cluster's own components and its administrator are recovery identities that bypass the webhook.

To iterate, create the cluster once and focus:

```sh
make setup-test-e2e
KIND_CLUSTER=k8s-authz-test-e2e KIND_MEMBER_CLUSTER=k8s-authz-member-e2e go test -tags e2e ./test/e2e -ginkgo.focus "regex"
```

## CI

CI runs `make validate` and the unit tests with `-race`, then one leg per Kubernetes minor, each running `make test-integration` with `-race` and `make test-e2e`:

| Kubernetes | envtest | Kind node |
| --- | --- | --- |
| 1.36 | 1.36.2 | v1.36.1 |
| 1.37 | 1.37.0 | v1.37.0 |

## What is covered where

| Contract | Coverage |
| --- | --- |
| CRD schemas and validation rules, admission of every sample, RBAC-shaped subjects | `internal/validation`, `test/integration/admission_test.go`, `test/integration/validation_test.go` |
| The permission algebra, broad requests, selectors, subtraction, and native namespace semantics | `internal/model`, `internal/program`, `internal/engine/traversal_test.go` |
| Compiler decisions checked against independently enumerated operation tuples | `internal/engine/traversal_test.go` |
| Shared `PolicySet`s, contextual roots, source, permission, and depth bounds, cycles, missing references | `internal/compiler`, `internal/engine/traversal_test.go` |
| Scoped grant failures, authoritative root failures, limit overflows, namespace warnings | `internal/compiler/compiler_test.go`, `internal/validation/documents_test.go`, `internal/cli/graph_test.go` |
| Source registry, reader replacement, narrowing and failures, pause, query planning, the persistent cache and its restore, the registration barrier, credential rotation, `WatchFailing`, schema verification | `internal/source`, `internal/source/kubernetes`, `internal/source/storage`, `internal/controller`, `test/integration/reader_test.go`, `test/integration/policysource_test.go` |
| The Rego condition language, recorded and default builtins, the generated conditions module | `internal/condition`, `internal/validation/documents_test.go` |
| Conditions through bounds, allowlists narrowing from the root under a service ceiling, `RegoNotAllowed`, `BuiltinNotAllowed`, `ConditionalProhibition` | `internal/compiler/compiler_test.go`, `internal/cli/graph_test.go` |
| State digest, evaluator identity, byte limits, and explanation refusals | `internal/engine/snapshot_test.go`, `internal/engine/bootstrap_test.go`, `internal/engine/explain_test.go`, `internal/cli/explain_test.go` |
| Condition input for resource and non-resource reviews | `internal/program/program_test.go` |
| Caller admission by Common Name, management admission by identity and chain, readiness, conditions checked after principals, decisions | `internal/engine/testdata/*_test.rego`, `internal/program/testdata/endpoints_test.rego` |
| Stock OPA from the rendered ConfigMap: management path protection, readiness after a push, caller edits by push, `whenEvaluationFails`, large state, conditions module ordering and repair, restarts | `test/integration/engine_test.go` |
| Engine client verification, certificate renewal, state and module reads and writes | `internal/engineclient` |
| Controllers under `operator.Setup`: owned objects, drift repair, override removal, CA changes, push on start, eviction, runtime switch, status | `internal/resources`, `internal/controller`, `test/integration/authorizationservice_test.go`, `test/integration/replicas_test.go` |
| Independent control and source APIs, native RoleBinding composition | `test/integration/multi_api_composition_test.go` |
| Diagnostics authentication and authorization, the state relay, connected explain over websocket and SPDY | `test/integration/diagnostics_test.go`, `internal/diagnostics`, `internal/cli` |
| Offline validation, graph compilation, caller rendering | `internal/cli` |
| Decision logs of endpoint decisions only, with the request masked | `internal/engine/configuration_test.go`, `test/integration/logging_test.go` |
| Generated code equality; chart rendering, lint, and packaging | `make generate-check`, `make helm-package` |
| A local source and a source on the member cluster, allow and deny through the API server's authorizer chain | `test/e2e/authorization_service_test.go` |
| The member cluster's API server authorized by the control cluster's engines, member policy edits pushed without a roll, each API server admitted only to its own endpoint | `test/e2e/member_cluster_test.go` |
| NoOpinion passed on to RBAC | `test/e2e/native_fallback_test.go` |
| A root prohibition denying a request RBAC allows | `test/e2e/prohibition_test.go` |
| Policy and caller edits pushed without a roll, CA changes, state pushed again after an OPA restart | `test/e2e/policy_delivery_test.go` |
| Delegated Rego conditions through the authorizer chain, stopped by a source without `rego` and by the service's ceiling | `test/e2e/rego_conditions_test.go` |
| Deployment to DaemonSet switch | `test/e2e/runtime_kind_test.go` |
| Engines serving while no operator runs | `test/e2e/operator_outage_test.go` |
| Connected explain, offline export equality, refusal without access | `test/e2e/diagnostics_test.go` |
| Metrics served only to an authorized ServiceAccount | `test/e2e/metrics_test.go` |

Compiler limits establish the project's own resource contracts. The suites don't benchmark stock OPA, and upstream throughput, TLS performance, garbage collection, and runtime memory aren't release gates.
