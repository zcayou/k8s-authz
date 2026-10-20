# Writing policies

This guide covers the permission language: how a `Policy` describes operations, and how a `PolicyBinding` selects principals. For how bindings and `PolicySet`s compose, see [Delegation](../concepts/delegation.md). For narrowing a grant with Rego, see [Rego conditions](rego-conditions.md).

## Anatomy of a Policy

```yaml
apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata:
  namespace: platform-policies
  name: operator-access
spec:
  include:                      # operations this policy grants
    - apiGroups: ["*"]
      resources: ["*"]
      verbs: ["*"]
  exclude:                      # operations removed from everything above
    - apiGroups: [""]
      resources: [secrets]
      verbs: [get, list, watch]
  imports:                      # native roles whose rules are added to include
    - kind: ClusterRole
      name: view
```

A Policy's permissions are **(include ∪ imports) − exclude**. It names no principals; a `PolicyBinding` attaches it to them.

- `include: []` grants nothing. That's useful as an explicit empty grant.
- A Policy needs at least one of `include`, `imports`, or `condition`. A Policy with only a `condition` covers every operation, narrowed by the condition. See [Rego conditions](rego-conditions.md).
- `exclude` removes operations from this Policy only. It isn't a prohibition: another Policy can still grant what this one excludes. To deny something across an authority, use a [prohibition](../concepts/delegation.md#prohibitions).

## Operation rules

`include` and `exclude` hold operation rules. A rule describes either resource operations or non-resource URLs, never both.

### Resource rules

```yaml
- verbs: [get, list, watch]
  apiGroups: ["", apps]
  resources: [pods, pods/log, deployments]
  apiVersions: [v1]             # optional; omitted means every version
  resourceNames: [web]          # optional; exact object names
  namespaces: [team-a]          # optional; see below
```

| Field | Meaning |
| --- | --- |
| `verbs` | Required. Kubernetes verbs (`get`, `list`, `watch`, `create`, `update`, `patch`, `delete`, `deletecollection`, custom verbs such as `impersonate` or `escalate`), or `*` for every verb. Verbs are lowercase. |
| `apiGroups` | Required. `""` is the core group. `*` is every group. |
| `resources` | Required. A resource (`pods`), a resource and subresource (`pods/log`), `*/<subresource>` for that subresource of every resource, or `*` for every resource and subresource. `pods` doesn't include `pods/log`; list subresources explicitly. |
| `apiVersions` | Optional. Limits the rule to specific versions. `*`, if used, must stand alone. |
| `resourceNames` | Optional. Limits the rule to objects with these exact names. As in RBAC, a request without a name, such as a plain `list` or a `create`, isn't covered by a rule with `resourceNames`. |
| `namespaces` | Optional. Limits the rule by the namespace the request affects. See [Namespace scoping](#namespace-scoping). |
| `labelSelector`, `fieldSelector` | Optional. Limit collection requests by selector. See [Selector-scoped rules](#selector-scoped-rules). |

Values are literal. The only wildcards are a standalone `*` and the `*/<subresource>` form; `pods/*` or `app*` are rejected.

### Non-resource rules

```yaml
- verbs: [get]
  nonResourceURLs: [/healthz, /version, /apis/*]
```

`nonResourceURLs` are absolute paths, matched exactly or, with a single trailing `*`, by prefix. `*` alone matches every path. Verbs are lowercase HTTP methods (`get`, `post`, `put`, `delete`, …) or `*`.

## Namespace scoping

A request carries a namespace when it targets a namespaced object or collection in a namespace. Requests for cluster-scoped resources (Nodes, Namespaces, CRDs, PersistentVolumes), and list or watch requests across all namespaces, carry no namespace.

A rule's `namespaces` field decides which of those requests it covers:

| `namespaces` | Covers |
| --- | --- |
| omitted | Every resource request, namespaced or not. |
| `[team-a, team-b]` | Requests in `team-a` or `team-b`. Not cluster-scoped requests, and not all-namespace lists. |
| `["*"]` | Requests in any namespace. Not cluster-scoped requests, and not all-namespace lists. |
| `[""]` | Requests without a namespace: cluster-scoped resources and all-namespace lists and watches. |
| `["*", ""]` | Everything; the same as omitting the field. |

An all-namespace `list` or `watch` may return objects from every namespace, so granting it requires the empty namespace `""`, not just `*`. The operator warns with `AllNamespacesNotGranted` when a collection rule uses `["*"]` alone.

**Named namespaces reach further when they deny.** Because a request without a namespace can affect every namespace, an exclusion or prohibition scoped to a named namespace also removes every request without a namespace that it matches. For example, a prohibition of `apiGroups: ["*"], resources: ["*"], verbs: ["*"], namespaces: [kube-system]` also denies `get nodes`, `list namespaces`, and every all-namespace list, because each of those requests could touch `kube-system`. A narrower rule, such as Secrets in `kube-system`, only affects the matching resource: it denies an all-namespace Secret list and nothing cluster-scoped. The operator warns with `NamespaceScopeConservative` when an exclusion, or a Policy that could be used as a prohibition, combines a `*` resource or group with named namespaces.

The namespace a `Policy` or `PolicyBinding` itself lives in never limits the namespaces it grants. Only rules, bounds, and native `RoleBinding`s and `Role`s scope by namespace.

## Selector-scoped rules

Rules for `list`, `watch`, and `deletecollection` can carry a `labelSelector` or `fieldSelector`. Such a rule covers a collection request only if the request's own selector guarantees that every returned object matches:

```yaml
- verbs: [list, watch]
  apiGroups: [""]
  resources: [pods]
  namespaces: [shared]
  labelSelector:
    matchLabels:
      team: a
```

- `kubectl get pods -n shared -l team=a` is covered.
- `kubectl get pods -n shared` isn't, because it could return other teams' Pods.

A rule with selectors may list only collection verbs. `labelSelector` accepts `matchLabels` and `matchExpressions` with `In`, `NotIn`, `Exists`, and `DoesNotExist`. `fieldSelector.requirements` uses the same operators on field paths. A field requirement on `metadata.name` behaves like `resourceNames`, so a rule with `resourceNames: [web]` also covers a `list` or `watch` whose field selector pins `metadata.name=web`.

Selector-scoped decisions rely on kube-apiserver including selectors in the `SubjectAccessReview`, which the `AuthorizeWithSelectors` feature does.

## Importing native roles

`imports` adds the rules of existing `Role`s and `ClusterRole`s to a Policy:

```yaml
imports:
  - kind: ClusterRole
    name: edit
    namespaces: [team-a, team-b]     # optional filter
  - kind: Role
    namespace: team-c
    name: deployer
```

- A `ClusterRole` import is unscoped unless `namespaces` restricts it.
- A `Role` import is always limited to the Role's own namespace.
- `namespaces` works like a rule's `namespaces` field.
- Imported rules are subject to the Policy's `exclude`.
- The imported role must be in a source the use may read, like any other reference. A `sourceRef` selects another source.

Aggregated ClusterRoles are imported with whatever rules the API server has aggregated into them at read time.

## Selecting principals

A `PolicyBinding` selects principals with exactly one of `subjects` or `subjectMatch`.

### `subjects`

`subjects` uses the RBAC subject shape. A principal matches if it matches **any** entry:

```yaml
subjects:
  - kind: Group
    name: oidc:team-a-admins
  - kind: User
    name: alice@example.com
  - kind: ServiceAccount
    namespace: ci
    name: deployer
```

`User` matches the user name exactly, `Group` matches membership, and `ServiceAccount` matches the user `system:serviceaccount:<namespace>:<name>`.

### `subjectMatch`

`subjectMatch` takes requirements that are **all** checked. An empty `subjectMatch: {}` matches every principal, which is the usual choice for a delegation or prohibition that shouldn't narrow who its parent selected.

```yaml
subjectMatch:
  requirements:
    - kind: Group
      operator: StartsWith
      names: ["oidc:"]
    - kind: Group
      operator: NotIn
      names: ["oidc:k8s-root-admins"]
```

| `kind` | Operand fields | Tested value |
| --- | --- | --- |
| `User` | `names` | The user name. |
| `Group` | `names` | Every group the principal has. |
| `ServiceAccount` | `namespace`, `names` | The service account name, if the principal is a service account in `namespace`. |
| `UID` | `values` | The user UID. |
| `Extra` | `key`, `values` | The values of the extra attribute `key`. |

| `operator` | Holds when |
| --- | --- |
| `In` | Any tested value is in the list. |
| `NotIn` | No tested value is in the list. It holds for a principal without the attribute. |
| `StartsWith` | Any tested value starts with one of the prefixes. `User`, `Group`, and `ServiceAccount` only. |
| `NotStartsWith` | No tested value starts with one of the prefixes. `User`, `Group`, and `ServiceAccount` only. |
| `Exists` | The attribute is present: a non-empty user or UID, at least one group, a service account in `namespace`, or the extra key. |
| `DoesNotExist` | The attribute isn't present. |

`Exists` and `DoesNotExist` take no operands; every other operator requires them.

## Common patterns

**Discovery for Deny authorities.** An authority with `whenNoPolicyAllows: Deny` rejects everything it doesn't grant, including the discovery and self-review requests `kubectl` makes on every run. Grant them to everyone the authority selects:

```yaml
kind: Policy
metadata:
  name: basic-access
spec:
  include:
    - verbs: [get]
      nonResourceURLs: [/api, /api/*, /apis, /apis/*, /version, /healthz, /livez, /readyz, /openapi, /openapi/*]
    - verbs: [create]
      apiGroups: [authorization.k8s.io]
      resources: [selfsubjectaccessreviews, selfsubjectrulesreviews]
    - verbs: [create]
      apiGroups: [authentication.k8s.io]
      resources: [selfsubjectreviews]
```

**Everything except Secrets.**

```yaml
spec:
  include:
    - apiGroups: ["*"]
      resources: ["*"]
      verbs: ["*"]
  exclude:
    - apiGroups: [""]
      resources: [secrets]
      verbs: ["*"]
```

**Read-only across a set of namespaces, reusing the built-in `view` role.**

```yaml
spec:
  imports:
    - kind: ClusterRole
      name: view
      namespaces: [team-a, team-b]
```

## Checking your work

Validate documents before applying them, and compile a whole service against local files to see its issues:

```sh
k8s-authz validate documents --source authz-system/platform policies.yaml
k8s-authz validate graph service.yaml --source authz-system/platform=policies.yaml
```

See [Validating and explaining](validating-and-explaining.md).

## Limits

The CRDs bound individual fields: up to 256 rules per list, 256 values per rule field, 64 imports per Policy, and 64 requirements per `subjectMatch`. Compilation adds limits per branch of the policy graph: 4096 document uses, 16384 expanded rules, and 128 distinct selector keys. A branch that exceeds a limit fails with `ResourceLimitExceeded` and follows the usual [failure rules](../concepts/policy-model.md#failures).

Each `PolicySet` a [selection](../concepts/delegation.md#discovering-policysets) matches is a branch of its own with the same limits. A selection matches at most 256 `PolicySet`s, and an authority's selections at most 1024 together.

An authority's grants are then composed into one permission diagram, which is what lets different grants cover different parts of a broad request. That composition is limited to 65536 nodes and to 128 distinct selector keys across all of the root `PolicySet`'s bindings and discovered `PolicySet`s together. Past either limit, each binding's or discovered `PolicySet`'s grants are kept but decide on their own: a request is allowed only when one of them covers all of it, and a broad request that they cover only together falls through to `whenNoPolicyAllows`. The authority reports `GrantsNotComposed`. To stay within the limits, use fewer distinct label and field selector keys across the root bindings, or split principals across authorities.
