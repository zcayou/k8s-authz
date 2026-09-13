# Policy

`authorization.zctx.io/v1alpha1`, namespaced, short name `azpol`, category `authz`.

A `Policy` is a reusable set of permissions with no principals attached. Its permissions are (include ∪ imports) − exclude, narrowed by its condition if it has one. See [Writing policies](../guides/writing-policies.md).

For exact field validation, see the [generated API reference](api.md#policy).

## Example

```yaml
apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata:
  namespace: team-a
  name: deployer
spec:
  include:
    - apiGroups: [apps]
      resources: [deployments, deployments/scale]
      verbs: [get, list, watch, create, update, patch, delete]
      namespaces: [team-a]
  exclude:
    - apiGroups: [apps]
      resources: [deployments]
      verbs: [delete]
      resourceNames: [ingress-gateway]
  imports:
    - kind: ClusterRole
      name: view
      namespaces: [team-a]
```

## spec

At least one of `include`, `imports`, or `condition` is required.

| Field | Description |
| --- | --- |
| `include` | Up to 256 [operation rules](#operation-rules) this Policy grants. `[]` grants nothing. Omitted together with `imports` on a Policy with a `condition`, the Policy covers every operation the condition allows. |
| `exclude` | Up to 256 operation rules removed from `include` and `imports`. Affects only this Policy. |
| `imports` | Up to 64 native roles whose rules are added. See [imports](#imports). |
| `condition.rego` | A Rego v1 module (up to 64 KiB) declaring `package condition`, whose rule `allow` narrows the Policy. See [Rego conditions](../guides/rego-conditions.md). |

### Operation rules

A rule is a resource rule (`apiGroups` and `resources` required) or a non-resource rule (`nonResourceURLs`), never both.

| Field | Description |
| --- | --- |
| `verbs` | Required. Lowercase verbs, or `*`. |
| `apiGroups` | Resource API groups. `""` is the core group; `*` is every group. |
| `resources` | `resource`, `resource/subresource`, `*/subresource`, or `*`. |
| `apiVersions` | Resource versions. Omitted means every version. |
| `resourceNames` | Exact object names. |
| `namespaces` | Namespaces of the requests covered: names, `*` for every named namespace, `""` for requests without a namespace. Omitted means every request. See [Namespace scoping](../guides/writing-policies.md#namespace-scoping). |
| `nonResourceURLs` | Absolute paths, exact or with one trailing `*`; `*` for every path. |
| `labelSelector` | A native label selector. Only with collection verbs (`list`, `watch`, `deletecollection`). |
| `fieldSelector.requirements` | Field selector requirements (`key`, `operator`, `values`). Only with collection verbs. |

### imports

| Field | Description |
| --- | --- |
| `kind` | `Role` or `ClusterRole`. |
| `name` | The role's name. |
| `namespace` | A Role's namespace. Defaults to the Policy's namespace. Forbidden for `ClusterRole`. |
| `sourceRef` | Another `PolicySource` (`namespace`, `name`). Defaults to the Policy's own source. With `sourceRef`, a Role needs `namespace`. |
| `namespaces` | Restricts the imported rules to these namespaces, as a rule's `namespaces` does. |

A `Role` import always grants only in the Role's own namespace.

## Warnings

The operator reports these as `Warning` issues on documents that are otherwise valid:

| Reason | When |
| --- | --- |
| `NamespaceScopeConservative` | An `exclude` rule, or an `include` rule that could be used as a prohibition, matches every group or resource and names specific namespaces. It also covers every request without a namespace. |
| `AllNamespacesNotGranted` | A collection rule uses `namespaces: ["*"]` alone, which doesn't grant all-namespace lists. |
| `UniversalEnvelope` | The Policy has a `condition` and no `include` or `imports`, so its condition decides every request inside its bound. |
