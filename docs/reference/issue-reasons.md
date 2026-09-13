# Issue reasons

Issues appear in `AuthorizationService` and `PolicySource` status and in `k8s-authz validate` output. Each has a stable `reason`. Errors on a grant remove that grant; errors on a guard (an entry binding, a root `PolicySet`, a root bound, or a prohibition) make matching requests return `whenEvaluationFails`. See [Failures](../concepts/policy-model.md#failures).

## Document issues

| Reason | Severity | Meaning |
| --- | --- | --- |
| `Invalid` | Error | The document failed strict decoding or validation. The message lists every problem. Also used for an invalid `AuthorizationService` spec. |
| `NamespaceScopeConservative` | Warning | A rule that matches every group or resource and names namespaces also covers every request without a namespace when it removes or denies access. See [Namespace scoping](../guides/writing-policies.md#namespace-scoping). |
| `AllNamespacesNotGranted` | Warning | A collection rule uses `namespaces: ["*"]` alone, which doesn't grant all-namespace lists. Add `""`. |
| `UniversalEnvelope` | Warning | A Policy with a condition and no `include` or `imports` lets its condition decide every request inside its bound. |

## Graph issues

| Reason | Meaning |
| --- | --- |
| `MissingReference` | A referenced document doesn't exist in the source's view: it's absent, or outside the source's collection. |
| `InvalidDocument` | A referenced document exists but is invalid. The document's own `Invalid` issue says why. |
| `KindMismatch` | A reference points at the wrong kind of document, for example an entry that isn't a binding, a root that isn't a `PolicySet`, or a prohibition that targets a `PolicySet`. |
| `SourceUnavailable` | The referenced source isn't registered, hasn't completed its first read, or is `Inert`. The message names the source's state. |
| `SourceNotAllowed` | The referenced document's source is outside the set this use may read. |
| `InvalidSourceRestriction` | A binding's `constraints.sourceRefs` names a source it didn't itself receive. |
| `DepthExceeded` | A delegation goes past its `maxDepth`, or past 16 levels below the root. |
| `Cycle` | A `PolicySet` reaches itself. |
| `DenyOutsideRoot` | A delegated `PolicySet` has `prohibitionRefs`. |
| `RegoNotAllowed` | A Policy carries a Rego condition, but its source, or a source on its path, doesn't allow conditions. |
| `BuiltinNotAllowed` | A condition calls builtins its path or the service doesn't allow. The message lists them. |
| `ConditionalProhibition` | A prohibition would carry a Rego condition, from its Policy or a bound. |
| `ResourceLimitExceeded` | A branch of the graph exceeded a compilation limit. |
| `GrantsNotComposed` | An authority's grants exceed the composition [limits](../guides/writing-policies.md#limits), so each root binding's grants cover a request only on their own. A broad request the bindings cover only together isn't granted. |
| `InternalError` | The compiler failed in a way no document explains. Please report it. |

## CLI-only reasons

`k8s-authz validate` adds these for problems with its input files:

| Reason | Meaning |
| --- | --- |
| `InvalidSyntax` | A document isn't well-formed YAML or JSON. |
| `UnsupportedDocument` | A document's `apiVersion` and `kind` aren't ones the command validates. |
| `SourceRequired` | A policy or RBAC document was given without `--source`. |
| `DuplicateDocument` | A source holds two documents with the same kind, namespace, and name. |
| `InvalidGraphInput` | The service file doesn't hold exactly one `AuthorizationService`. |
| `CompilationFailed` | The whole program couldn't be compiled, for example because it exceeds the overall size limit. |
| `DiagnosticsTruncated` | The compiler kept only part of its diagnostics. |

## Condition reasons

| Resource | Condition | Reasons |
| --- | --- | --- |
| `AuthorizationService` | `Prepared` | `Prepared`, `Invalid`, `PreparationUnavailable` |
| `AuthorizationService` | `Ready` | `Serving`, `InsufficientCapacity` |
| `AuthorizationService` | `PolicyHealthy` | `PolicyHealthy`, `PolicyErrors` |
| `PolicySource` | `Synchronized` | `Synchronized`, `Pending`, `Paused`, `InvalidCredential`, `WatchFailing`, `IncompatibleSchema` |
