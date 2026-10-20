# PolicySource

`authorization.zctx.io/v1alpha1`, namespaced, short name `azsrc`, category `authz`.

A `PolicySource` registers a Kubernetes API and the policy documents the operator may collect from it. Its name can be at most 63 characters. See [Policy sources](../guides/policy-sources.md) for how to use it.

For exact field validation, see the [generated API reference](api.md#policysource).

## Example

```yaml
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicySource
metadata:
  namespace: authz-system
  name: teams
spec:
  provider:
    type: Kubernetes
    kubernetes:
      kubeconfig:
        secretRef:
          name: teams-api-reader
          key: kubeconfig
  collection:
    - kinds: [Policy, PolicyBinding, PolicySet, Role, RoleBinding]
      namespaces: [team-a, team-b]
      names: ["*"]
    - kinds: [ClusterRole]
      names: [view]
  namespaceLabels: Ignore
  synchronization: Active
  contribution: Active
  rego:
    allowedBuiltins: [concat, startswith]
```

## spec

| Field | Required | Default | Description |
| --- | --- | --- | --- |
| `provider.type` | yes | | `Kubernetes`. |
| `provider.kubernetes.kubeconfig.secretRef` | no | | A Secret key (`name`, `key`) in the `PolicySource`'s namespace holding a self-contained kubeconfig. Omitted, the source reads the operator's own cluster with the operator's identity. |
| `collection` | yes | | Up to 64 ranges of documents to collect. See [collection](#collection). |
| `namespaceLabels` | no | `Ignore` | `Collect` reads the labels of the namespaces the collection covers: every namespace when a range selects `"*"`, otherwise each namespace a range names. A `policySelector` with a non-empty `namespaceSelector` needs it. See [namespace labels](../guides/policy-sources.md#namespace-labels). |
| `synchronization` | no | `Active` | `Paused` stops reading and keeps serving the last complete view. |
| `contribution` | no | `Active` | `Inert` removes the source's documents from compiled policy without stopping its reader. |
| `rego` | no | | Present, allows the source's documents to carry Rego conditions. `rego: {}` allows the default builtins, and `rego.allowedBuiltins` allows exactly the listed ones. Absent, no conditions are allowed in this source or beneath its bindings and `PolicySet`s. |

### collection

Each range:

| Field | Required | Description |
| --- | --- | --- |
| `kinds` | yes | Any of `Policy`, `PolicyBinding`, `PolicySet`, `Role`, `ClusterRole`, `RoleBinding`, `ClusterRoleBinding`. All namespaced or all cluster-scoped. |
| `namespaces` | for namespaced kinds | Namespaces to read, or `["*"]` for all. Forbidden for cluster-scoped kinds. |
| `names` | yes | Document names to read, or `["*"]` for all. |

## status

| Field | Description |
| --- | --- |
| `observedGeneration` | The spec generation this status describes. |
| `lastAdmittedTime` | When the source last admitted a complete view that changed its documents or ended a period of failed acquisition. |
| `conditions` | `Synchronized`, with reason `Synchronized`, `Pending`, `Paused`, `InvalidCredential`, `WatchFailing`, or `IncompatibleSchema`. |
| `issues` | Up to 128 diagnostics about the documents in the source's view. |
| `issuesTruncated` | More issues existed than were recorded. |

## Owned objects

Secrets of type `authorization.zctx.io/source-cache` named `<name>-source-cache-<n>` in the `PolicySource`'s namespace, holding the persisted view, its namespace labels included. They're deleted with the `PolicySource`.
