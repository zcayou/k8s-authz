# PolicyBinding

`authorization.zctx.io/v1alpha1`, namespaced, short name `azpb`, category `authz`.

A `PolicyBinding` attaches principals to one permission definition: a `Policy`, a `PolicySet`, a `Role`, or a `ClusterRole`, or to every `PolicySet` a selector matches. A binding that targets or selects `PolicySet`s is a delegation. See [Writing policies](../guides/writing-policies.md#selecting-principals) and [Delegation](../concepts/delegation.md).

For exact field validation, see the [generated API reference](api.md#policybinding).

## Example

```yaml
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata:
  namespace: platform-policies
  name: team-a
spec:
  subjectMatch:
    requirements:
      - kind: Group
        operator: StartsWith
        names: ["oidc:team-a-"]
  policyRef:
    kind: PolicySet
    sourceRef:
      namespace: authz-system
      name: teams
    namespace: team-a
    name: team-a
  constraints:
    policyRef:
      name: team-a-bound
    sourceRefs:
      - namespace: authz-system
        name: teams
    maxDepth: 1
```

## spec

Exactly one of `subjects` or `subjectMatch` is required, and exactly one of `policyRef` or `policySelector`.

| Field | Description |
| --- | --- |
| `policyRef` | The target. See [references](#references). |
| `policySelector` | The `PolicySet`s to delegate to. See [policy selectors](#policy-selectors). |
| `subjects` | 1–256 RBAC-style subjects. A principal matches if it matches any. `kind` is `User`, `Group`, or `ServiceAccount`. `ServiceAccount` requires `namespace` and no `apiGroup`; `User` and `Group` forbid `namespace`. |
| `subjectMatch.requirements` | Up to 64 requirements, all of which must hold. `subjectMatch: {}` matches every principal. See [subject requirements](#subject-requirements). |
| `constraints` | Narrows what the target contributes. See [constraints](#constraints). |

### References

| Field | Description |
| --- | --- |
| `kind` | `Policy` (default), `PolicySet`, `Role`, or `ClusterRole`. |
| `apiGroup` | Derived from `kind` when omitted. |
| `name` | The target's name. |
| `namespace` | Defaults to the binding's namespace. Forbidden for `ClusterRole`. |
| `sourceRef` | Another `PolicySource` (`namespace`, `name`). Defaults to the binding's own source. With `sourceRef`, namespaced kinds need `namespace`. |

### Policy selectors

| Field | Description |
| --- | --- |
| `sourceRef` | The `PolicySource` (`namespace`, `name`) whose `PolicySet`s are selected. Defaults to the binding's own source. |
| `namespaceSelector` | Required. A label selector over the labels of the source's namespaces. `{}` selects every namespace the source collects; any other selector needs a source with `namespaceLabels: Collect`. |
| `selector` | Required. A label selector over the `PolicySet`s' own labels. |

Each selector holds at most 64 requirements. A selection matches at most 256 `PolicySet`s, and an authority's selections at most 1024 together. See [Discovering PolicySets](../concepts/delegation.md#discovering-policysets).

### Subject requirements

| Field | Description |
| --- | --- |
| `kind` | `User`, `Group`, `ServiceAccount`, `UID`, or `Extra`. |
| `operator` | `In`, `NotIn`, `StartsWith`, `NotStartsWith`, `Exists`, or `DoesNotExist`. The prefix operators apply only to `User`, `Group`, and `ServiceAccount`. |
| `names` | Operands for `User`, `Group`, and `ServiceAccount`. |
| `values` | Operands for `UID` and `Extra`. |
| `namespace` | Required for `ServiceAccount`, forbidden otherwise. |
| `key` | The extra attribute's key. Required for `Extra`, forbidden otherwise. |

`Exists` and `DoesNotExist` take no operands. See [the operator table](../guides/writing-policies.md#subjectmatch) for what each operator tests.

### Constraints

| Field | Description |
| --- | --- |
| `policyRef` | A bound: a `Policy`, `Role`, or `ClusterRole` (never a `PolicySet`) that every grant through this binding is intersected with. Its Rego condition, if any, applies to every grant beneath. |
| `sourceRefs` | Only for `PolicySet` targets and selections. Up to 64 sources the delegated subtree may read. Must include the target's or selection's source, and may only name sources this binding itself may read. Omitted, the subtree may read only that source. |
| `maxDepth` | Only for `PolicySet` targets and selections. 0–64: how many further `PolicySet` levels may exist below the target, or below each match. |

## As an authority's entry binding

When an endpoint's authority names a binding, the binding's principals decide which requests the authority governs, and its target is the authority's root. A `PolicySet` target is the root `PolicySet`, whose prohibitions apply. A binding with a `policySelector` can't be an entry binding; one is an authoritative failure with `KindMismatch`.

## As a prohibition

When a root `PolicySet` lists a binding under `prohibitionRefs`, the binding's target must be a `Policy`, `Role`, or `ClusterRole`, and neither it nor any bound above it may carry a Rego condition. A binding with a `policySelector` is an authoritative failure with `KindMismatch`.
