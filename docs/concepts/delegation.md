# Delegation

Delegation lets a platform team hand a slice of authority to another team, which can manage its own grants inside that slice without being able to exceed it. In k8s-authz, a `PolicyBinding` that targets a `PolicySet` is a delegation, and its `constraints` define the slice.

This page builds on the [policy model](policy-model.md).

## PolicySets

A `PolicySet` groups binding references:

```yaml
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicySet
metadata:
  namespace: platform-policies
  name: root
spec:
  bindingRefs:
    - name: platform-admins          # a PolicyBinding in this namespace
    - name: team-a                   # a PolicyBinding that delegates to team-a's PolicySet
  prohibitionRefs:
    - name: protect-system-secrets
```

- `bindingRefs` contribute grants (Allow). Each entry can be a `PolicyBinding`, a native `RoleBinding`, or a `ClusterRoleBinding`.
- `prohibitionRefs` contribute prohibitions (Deny). They are honored only in the **root** `PolicySet`, the one an authority's entry binding targets directly.

A `PolicySet` does nothing until a binding targets it, and every binding that targets it can apply different constraints. The same `PolicySet` can be reused under several authorities or delegated to different audiences with different bounds.

## A delegation chain

Here a platform team delegates to the team that owns the `team-a` namespace:

```yaml
# Owned by the platform team, in the platform source.
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata:
  namespace: platform-policies
  name: team-a
spec:
  subjectMatch: {}                   # everyone the authority already selected
  policyRef:
    kind: PolicySet
    namespace: team-a
    name: team-a
  constraints:
    policyRef:
      name: team-a-bound             # a Policy: everything in namespace team-a
    maxDepth: 1
---
apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata:
  namespace: platform-policies
  name: team-a-bound
spec:
  include:
    - apiGroups: ["*"]
      resources: ["*"]
      verbs: ["*"]
      namespaces: [team-a]
---
# Owned by team-a, in namespace team-a.
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicySet
metadata:
  namespace: team-a
  name: team-a
spec:
  bindingRefs:
    - name: admins
    - name: readers
---
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata:
  namespace: team-a
  name: admins
spec:
  subjects:
    - kind: Group
      name: oidc:team-a-admins
  policyRef:
    name: everything
---
apiVersion: authorization.zctx.io/v1alpha1
kind: Policy
metadata:
  namespace: team-a
  name: everything
spec:
  include:
    - apiGroups: ["*"]
      resources: ["*"]
      verbs: ["*"]
```

Team-a's `everything` Policy grants every verb on every resource everywhere, but it's reached only through the `team-a` binding, whose bound limits it to namespace `team-a`. Members of `oidc:team-a-admins` get full access to `team-a` and nothing else. Team-a can add bindings, rename groups, and write any Policy it likes, but it can't grant anything outside `team-a`. Only an edit to the platform team's binding or bound can do that.

## Constraints

`constraints` on a `PolicyBinding` narrow what its target contributes.

### `policyRef`: the permission bound

`constraints.policyRef` names a leaf permission definition: a `Policy`, `Role`, or `ClusterRole`, never a `PolicySet`. Every grant reached through the binding is intersected with it.

- On a binding to a `PolicySet`, the bound applies to every grant anywhere below that `PolicySet`, including grants from further delegations.
- On a binding to a `Policy` or role, the bound narrows just that grant.

Bounds accumulate. A grant three delegations deep is intersected with every bound on its path, so each level can only narrow what it received.

A bound also carries its Rego condition, if it has one: every grant below a bound with a condition applies only when that condition holds. See [Rego conditions](../guides/rego-conditions.md).

### `sourceRefs`: which sources the subtree may read

Every use of a document is checked against a set of sources it may come from:

- At an authority's root, the set is the endpoint's `sourceRefs`.
- When a binding delegates to a `PolicySet`, the set narrows to **only the target `PolicySet`'s own source**, unless the binding sets `constraints.sourceRefs`.
- `constraints.sourceRefs` must include the target's own source, and it can only name sources the binding itself received. Naming any other source fails the branch with `InvalidSourceRestriction`.

A reference to a document in a source outside the set fails with `SourceNotAllowed`, and that branch grants nothing. This keeps a team's `PolicySet` from reaching into another team's source, even if the operator can read both.

In the example above, the `team-a` binding sets no `sourceRefs`, so everything team-a references must be in the same source as its `PolicySet`. An authority's entry binding often lists several sources, so the root `PolicySet` can delegate into each of them:

```yaml
kind: PolicyBinding
metadata:
  namespace: platform-policies
  name: employees
spec:
  subjectMatch:
    requirements:
      - kind: Group
        operator: StartsWith
        names: ["oidc:"]
  policyRef:
    kind: PolicySet
    name: root
  constraints:
    sourceRefs:
      - namespace: authz-system
        name: platform
      - namespace: authz-system
        name: teams
```

### `maxDepth`: how far delegation may go

`constraints.maxDepth` caps how many further `PolicySet` levels may exist below the target. `maxDepth: 0` means the target `PolicySet` may hold bindings to policies and roles but no bindings to other `PolicySet`s. `maxDepth: 1` allows one more level of delegation. A binding can lower the remaining depth but never raise it.

Independently, no chain may go more than 16 `PolicySet` levels below its root. A delegation past either limit fails with `DepthExceeded` and grants nothing.

`sourceRefs` and `maxDepth` apply only to bindings that target a `PolicySet`.

## Prohibitions

Prohibitions are the root's guarantee that some requests are denied no matter what anything below grants:

```yaml
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata:
  namespace: platform-policies
  name: protect-system-secrets
spec:
  subjectMatch: {}
  policyRef:
    name: protect-system-secrets     # a Policy including get/list/watch on Secrets in kube-system
```

Referenced from the root `PolicySet`'s `prohibitionRefs`, this binding denies Secret reads in `kube-system` to every principal the authority selects, including platform administrators granted `*` in the same `PolicySet`.

Rules for prohibitions:

- They apply only in the root `PolicySet`. A `PolicySet` reached through delegation that has `prohibitionRefs` fails with `DenyOutsideRoot`, and its whole branch grants nothing. Delegates can't deny; they can only decline to grant.
- A prohibition binding must target a `Policy`, `Role`, or `ClusterRole`. Targeting a `PolicySet` is an authoritative failure.
- A prohibition applies to principals that match both the entry binding and the prohibition binding, and only within the entry binding's bound.
- A prohibition can't carry a Rego condition, from its own Policy or from a bound. One that would fails with `ConditionalProhibition`. Prohibitions are decided without running conditions.
- A prohibition that can't be resolved makes matching requests return `whenEvaluationFails` rather than silently allowing them.

## Native RBAC in a PolicySet

A `PolicySet` can reference native `RoleBinding` and `ClusterRoleBinding` objects, and a `PolicyBinding` can target a native `Role` or `ClusterRole`. This lets teams keep using RBAC objects they already have, while the platform's bounds and prohibitions still apply.

- A `RoleBinding` grants only within its own namespace, whether it refers to a `Role` or a `ClusterRole`, as in RBAC.
- A `ClusterRoleBinding` grants cluster-wide, subject to the bounds above it.
- A `Role` grants only within its own namespace, however it's reached: through a `RoleBinding`, a `PolicyBinding`, or a `Policy` import.
- Native subjects work as in RBAC. A `ServiceAccount` subject without a namespace means the binding's namespace.

Native bindings keep their normal RBAC effect in the API where they're installed. Referencing them from a `PolicySet` adds their grants to the k8s-authz graph under its bounds; it doesn't disable them in RBAC.

## Resolving references

References in policy documents resolve relative to the document that holds them:

- An omitted `sourceRef` means the referencing document's own source.
- An omitted `namespace` means the referencing document's namespace, for namespaced kinds.
- A reference into another source must name a `namespace`, except for `ClusterRole` and `ClusterRoleBinding`.
- An omitted `kind` means `Policy` in a `policyRef` and `PolicyBinding` in a `bindingRef`.

An authority's `bindingRef` has no referencing document, so it always names its `sourceRef` and, for namespaced kinds, its `namespace`.

A reference cycle (a `PolicySet` that reaches itself) fails with `Cycle` and grants nothing.

## Writers are the real boundary

Delegation keeps each team inside its bounds, but only if teams can't edit the documents that set those bounds. The operator doesn't know who wrote a document. Use native RBAC in each source API to control who may write which documents:

- Teams must not be able to edit ancestor bindings, bounds, root `PolicySet`s, prohibitions, `PolicySource`s, `AuthorizationService`s, or the credentials and generated resources in the control namespace.
- A document's namespace doesn't limit which request namespaces it can grant. A `Policy` in namespace `team-a` can grant access to `kube-system` if nothing above it bounds it. Namespaces matter for who may write documents, and for the bounds you set.

[Security](../operations/security.md) describes a writer layout.
