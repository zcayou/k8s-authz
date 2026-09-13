# PolicyBinding

`authorization.zctx.io/v1alpha1`, namespaced, short name `azpb`, category `authz`.

A `PolicyBinding` attaches principals to one permission definition: a `Policy`, a `PolicySet`, a `Role`, or a `ClusterRole`. A binding that targets a `PolicySet` is a delegation. See [Writing policies](../guides/writing-policies.md#selecting-principals) and [Delegation](../concepts/delegation.md).

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

Exactly one of `subjects` or `subjectMatch` is required.

| Field | Description |
| --- | --- |
| `policyRef` | The target. See [references](#references). |
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
| `sourceRefs` | Only for `PolicySet` targets. Up to 64 sources the delegated subtree may read. Must include the target's own source, and may only name sources this binding itself may read. Omitted, the subtree may read only the target's own source. |
| `maxDepth` | Only for `PolicySet` targets. 0–64: how many further `PolicySet` levels may exist below the target. |

## As an authority's entry binding

When an endpoint's authority names a binding, the binding's principals decide which requests the authority governs, and its target is the authority's root. A `PolicySet` target is the root `PolicySet`, whose prohibitions apply.

## As a prohibition

When a root `PolicySet` lists a binding under `prohibitionRefs`, the binding's target must be a `Policy`, `Role`, or `ClusterRole`, and neither it nor any bound above it may carry a Rego condition.
