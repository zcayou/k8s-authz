# Policy model

This page explains how an endpoint turns a `SubjectAccessReview` into Allow, Deny, or NoOpinion. [Delegation](delegation.md) covers how `PolicySet`s and binding constraints hand out bounded authority, and [Writing policies](../guides/writing-policies.md) covers the permission language itself.

## Endpoints and authorities

An `AuthorizationService` has one or more **endpoints**. Each endpoint is a separate decision route with its own URL, callers, sources, and rules. A typical installation has one endpoint per population of API servers it authorizes.

An endpoint holds an ordered list of **authorities**. An authority names one **entry binding**, a `PolicyBinding` (or native `RoleBinding`/`ClusterRoleBinding`) in one of the endpoint's sources, and a fallback:

```yaml
endpoints:
  - name: cluster
    callers:
      - commonName: kube-apiserver
    sourceRefs:
      - namespace: authz-system
        name: platform
    whenEvaluationFails: Deny
    authorities:
      - bindingRef:
          sourceRef:
            namespace: authz-system
            name: platform
          namespace: platform-policies
          name: employees
        whenNoPolicyAllows: Deny
      - bindingRef:
          sourceRef:
            namespace: authz-system
            name: platform
          namespace: platform-policies
          name: contractors
        whenNoPolicyAllows: NoOpinion
```

The entry binding does two jobs. Its principals decide **who the authority governs**, and its target (a `Policy`, `Role`, `ClusterRole`, or a root `PolicySet`) is **what those principals may be granted**.

## How a decision is made

For each request, the engine:

1. **Selects an authority.** It takes the first authority, in list order, whose entry binding matches the request's principal. Later authorities are never consulted for that request, even if the selected one grants nothing. If no authority matches, the result is **NoOpinion** and kube-apiserver moves on to its next authorizer.
2. **Checks for authoritative failures.** If part of the selected authority that could decide this request couldn't be compiled (for example, its root `PolicySet` is missing), the result is the endpoint's `whenEvaluationFails`.
3. **Checks prohibitions.** If any prohibition in the root `PolicySet` covers the request and matches the principal, the result is **Deny**. Nothing in the authority can override a prohibition.
4. **Checks grants.** If the authority's grants cover the request in full, the result is **Allow**.
5. **Falls back.** Otherwise the result is the authority's `whenNoPolicyAllows`: **Deny** or **NoOpinion**.

The outcomes and how they're reported:

| Result | When | `code` in the response reason |
| --- | --- | --- |
| Allow | Grants cover the request | `PolicyAllowed` |
| Deny | A root prohibition covers the request | `RootProhibited` |
| `whenNoPolicyAllows` | An authority was selected and nothing grants the request | `AuthorityFallback` |
| NoOpinion | No authority's entry binding matches the principal | `NoMatchingAuthority` |
| `whenEvaluationFails` | The request can't be evaluated | `EvaluationError` |

## Principals

The principal is what kube-apiserver authenticated: user name, groups, UID, and extra attributes. The engine takes them from the `SubjectAccessReview` as-is. Groups include those kube-apiserver adds itself, such as `system:authenticated`. A service account is the user `system:serviceaccount:<namespace>:<name>`.

A grant applies only if the principal matches **every binding on the path** that reached it, not just the last one. If an entry binding selects groups starting with `oidc:`, and a binding deeper in the tree selects the group `oidc:team-a-admins`, a grant reached through both applies to members of `oidc:team-a-admins`. A binding can narrow who receives a delegated grant but never widen it past its ancestors.

## Coverage

A grant covers a request only if it covers **every object the request could touch**. For a single-object request this is simple. For a broad request, such as a `list` or `watch` without a namespace, the request spans every namespace, and it's allowed only if every part of it is granted:

- `list pods` in `team-a` is allowed by a grant for Pods in `team-a`.
- `list pods --all-namespaces` isn't allowed by that grant, because it would also return Pods from other namespaces. It needs a grant with no namespace restriction, or one that includes the empty namespace `""`. See [namespace scoping](../guides/writing-policies.md#namespace-scoping).

Different parts of a broad request can be covered by different grants, as long as together they cover all of it. This holds while the authority's grants compose within their [limits](../guides/writing-policies.md#limits); past them, one of the root `PolicySet`'s bindings has to cover the request alone.

Prohibitions work the other way: a prohibition applies if it covers **any part** of the request. A prohibition on reading Secrets in `kube-system` denies `get secrets -n kube-system` and also denies `list secrets --all-namespaces`. It doesn't affect a Secret list scoped to another namespace.

## Deny and NoOpinion

Every fallback is either `Deny` or `NoOpinion`, and they behave very differently in kube-apiserver's authorizer chain:

- **Deny** ends the chain. The request is rejected even if RBAC would have allowed it.
- **NoOpinion** hands the request to the next authorizer, usually Node and then RBAC.

Choose `whenNoPolicyAllows` per authority:

- `Deny` makes the authority the only source of permissions for its principals. Anything it doesn't grant is rejected, including API discovery (`/api`, `/apis`), `SelfSubjectAccessReview`, and other requests RBAC's default roles usually allow. Grant those explicitly.
- `NoOpinion` makes the authority additive. Its principals keep whatever RBAC gives them, the authority adds its own grants, and root prohibitions still take precedence over both.

`whenEvaluationFails` is set once per endpoint, and it has the same tradeoff. With the webhook ahead of Node and RBAC, `Deny` keeps prohibitions in force while they can't be evaluated, at the cost of rejecting requests RBAC would have allowed. `NoOpinion` keeps RBAC working, but the webhook's prohibitions don't apply until the failure is fixed.

kube-apiserver caches both Deny and NoOpinion as "unauthorized" responses for its `unauthorizedTTL` (30 seconds by default), so a fallback can persist that long after the underlying failure is fixed.

## Failures

Policy documents can be missing, invalid, unreachable, or wrong. k8s-authz handles a failure according to what the broken piece could have done:

**A broken grant grants nothing.** A missing `Policy`, an invalid binding below the root, a delegation cycle, or a source outside what a branch may read removes that branch's grants and is reported in status. As with a broken RBAC binding, the rest of the authority is unaffected, and requests that branch would have allowed fall through to `whenNoPolicyAllows`.

**A broken guard fails the request.** Some failures would silently widen access if they were ignored, so they make the endpoint answer `whenEvaluationFails` instead, for exactly the requests they could have decided:

- The authority's entry binding can't be resolved. Because the engine can't tell whose requests it governs, the authority matches **every principal**, and every request that reaches it gets `whenEvaluationFails`. Authorities listed after it are never consulted.
- The root `PolicySet` the entry binding targets can't be resolved, or the entry binding's own bound can't be resolved when it targets a `PolicySet`.
- A prohibition can't be resolved. The failure is scoped to the prohibition's principals and the region its bound covers.

A request that can't be parsed as a `SubjectAccessReview` also gets `whenEvaluationFails`.

An engine that has no installed state can't read the endpoint's settings, so it answers with an HTTP error, and kube-apiserver applies the webhook's `failurePolicy`. `render-caller-config` sets that `failurePolicy` from `whenEvaluationFails`, so both paths behave the same way. See [Connecting API servers](../guides/connecting-api-servers.md).

Every failure is reported in the `AuthorizationService`'s status `issues` with a reason such as `MissingReference`, `SourceUnavailable`, or `Cycle`. See [Issue reasons](../reference/issue-reasons.md).

## Everything else stays in kube-apiserver

k8s-authz decides only the requests that reach its webhook. It can't make kube-apiserver skip later authorizers after a NoOpinion, and it doesn't replace RBAC for principals no authority selects. Native RBAC bindings keep their normal effect in the API where they're installed, even when a `PolicySet` also imports them. To make an authority authoritative for its principals, use `whenNoPolicyAllows: Deny`. To keep a population out of k8s-authz entirely (for example, break-glass administrators), exclude them with match conditions in the caller configuration.
