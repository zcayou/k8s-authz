# PolicySet

`authorization.zctx.io/v1alpha1`, namespaced, short name `azps`, category `authz`.

A `PolicySet` groups binding references into a unit that a binding can target, as an authority's root or as a delegation. A binding can also attach it by its labels through a [`policySelector`](policybinding.md#policy-selectors), so a `PolicySet`'s labels are policy input. See [Delegation](../concepts/delegation.md).

For exact field validation, see the [generated API reference](api.md#policyset).

## Example

```yaml
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicySet
metadata:
  namespace: platform-policies
  name: root
spec:
  bindingRefs:
    - name: platform-admins
    - name: team-a
    - kind: RoleBinding
      namespace: shared
      name: shared-viewers
  prohibitionRefs:
    - name: protect-system-secrets
```

## spec

| Field | Description |
| --- | --- |
| `bindingRefs` | Up to 256 bindings that contribute grants. A selecting binding here delegates to each `PolicySet` it matches. |
| `prohibitionRefs` | Up to 256 bindings that contribute prohibitions. Honored only when this `PolicySet` is an authority's root. In a delegated `PolicySet`, any `prohibitionRefs` fail the whole branch with `DenyOutsideRoot`. A selecting binding here is an authoritative `KindMismatch`, as a prohibition targeting a `PolicySet` is. |

Each reference:

| Field | Description |
| --- | --- |
| `kind` | `PolicyBinding` (default), `RoleBinding`, or `ClusterRoleBinding`. |
| `apiGroup` | Derived from `kind` when omitted. |
| `name` | The binding's name. |
| `namespace` | Defaults to the `PolicySet`'s namespace. Forbidden for `ClusterRoleBinding`. |
| `sourceRef` | Another `PolicySource` (`namespace`, `name`). Defaults to the `PolicySet`'s own source. With `sourceRef`, namespaced kinds need `namespace`. |

Every reference must be in a source the use may read. See [`sourceRefs`](../concepts/delegation.md#sourcerefs-which-sources-the-subtree-may-read).
