# Status and troubleshooting

k8s-authz reports its state through conditions, attributed issues, and Events on its resources. This page explains how to read them and how to work through common problems.

## AuthorizationService status

```sh
kubectl -n authz-system get authorizationservices
```

```
NAME   READY   PREPARED   READYREPLICAS   CURRENTREPLICAS   DESIREDREVISION        AGE
demo   True    True       2               2                 sha256:9c1e...         3d
```

### Conditions

| Condition | `True` means | Reasons when not `True` |
| --- | --- | --- |
| `Prepared` | The policy for the current spec and sources compiled into `status.desiredRevision`. | `Invalid`: the spec failed validation, and the message lists every field error. `PreparationUnavailable`: compilation failed, or the service is waiting for a `PolicySource` it reads to be registered, which the message names. |
| `Ready` | At least `runtime.minReadyReplicas` engines serve `desiredRevision` under the current startup configuration. | `InsufficientCapacity`. |
| `PolicyHealthy` | The compiled policy has no errors. | `PolicyErrors`: see `status.issues`. |

`Ready` and `PolicyHealthy` are independent. A service can serve traffic with a partly broken policy graph: broken grants grant nothing, broken guards return `whenEvaluationFails`, and the rest works. Alert on both.

An invalid spec, or a compile failure, never replaces what the engines already serve. They keep their installed policy until a new revision can be prepared.

### Replica counts

| Field | Counts |
| --- | --- |
| `desiredReplicas` | Engine pods the workload expects. Absent until a DaemonSet has reported its scheduled count. |
| `readyReplicas` | Ready engine pods, each serving whatever policy it has installed. |
| `currentReplicas` | Pods confirmed serving `desiredRevision` and started from the current startup configuration. |

The service has converged when `currentReplicas` equals `desiredReplicas`. `readyReplicas` above `currentReplicas` means some pods still serve an older revision: during a rollout, while a push is failing, or while the current policy can't be prepared.

### Issues

`status.issues` lists up to 128 diagnostics about the compiled policy. `issuesTruncated: true` means there were more; use `k8s-authz validate graph` for the full list.

```yaml
issues:
  - severity: Error
    reason: MissingReference
    message: document authz-system/teams:authorization.zctx.io/Policy/team-a/deployer doesn't exist
    scope: Use
    endpoint: cluster
    authority: authz-system/platform:authorization.zctx.io/PolicyBinding/platform-policies/employees
    sourceRef: {namespace: authz-system, name: teams}
    documentRef: {group: authorization.zctx.io, kind: Policy, namespace: team-a, name: deployer}
    path:
      - {group: authorization.zctx.io, kind: PolicyBinding, namespace: platform-policies, name: employees}
      - {group: authorization.zctx.io, kind: PolicySet, namespace: platform-policies, name: root}
      - {group: authorization.zctx.io, kind: PolicyBinding, namespace: platform-policies, name: team-a}
      - {group: authorization.zctx.io, kind: PolicySet, namespace: team-a, name: team-a}
      - {group: authorization.zctx.io, kind: PolicyBinding, namespace: team-a, name: deployers}
```

- `scope: Document` issues are about a document on its own, such as a validation warning. `scope: Use` issues are about one place a document is used, and `path` shows how the authority reached it.
- `endpoint` and `authority` say which decision route is affected.
- `reason` is stable and machine-readable; see [Issue reasons](../reference/issue-reasons.md).

### Events

Problems that aren't about policy content are reported as Events on the `AuthorizationService`, or on the engine Pod for push problems:

| Reason | Type | Meaning |
| --- | --- | --- |
| `CAReadFailed` | Warning | The client or serving CA bundle couldn't be read. While the client CA is unreadable, the engine ConfigMap and workload are left as they are. While the serving CA is unreadable, nothing is pushed. |
| `ApplyFailed` | Warning | An owned object couldn't be built or applied, for example because another controller owns an object with the same name, or an immutable field such as `clusterIP` changed. Other objects are still applied. |
| `PushFailed` | Warning | A push to an engine pod failed. It's retried with backoff. |
| `Evicted` | Warning | An engine pod was evicted after its pushes kept failing for `--remediation-after`. |
| `DeletedWorkload` | Normal | The former workload was removed after a runtime switch. |

```sh
kubectl -n authz-system get events --field-selector involvedObject.name=demo
```

## PolicySource status

```sh
kubectl -n authz-system get policysources
```

```
NAME       SYNCHRONIZED   LASTADMITTED   AGE
platform   True           4m             3d
teams      False          2h             3d
```

`Synchronized` reports acquisition health; see [Source health](../guides/policy-sources.md#source-health-and-staleness) for its reasons. A source that isn't synchronized still serves its last complete view. `status.issues` lists problems with the source's documents, such as documents that failed validation.

## Common problems

### The service is `Prepared=False`

- **Reason `Invalid`**: the message lists each invalid field. A common one is an authority whose `bindingRef.sourceRef` isn't in the endpoint's `sourceRefs`.
- **Reason `PreparationUnavailable`, waiting for a source**: a `PolicySource` named in `sourceRefs` exists but isn't registered yet. This is expected briefly after an operator restart. If it persists, check that the source is in a namespace the operator controls (`--control-namespaces`) and look at the operator logs.
- **Reason `PreparationUnavailable`, compile failure**: the whole program exceeded a limit. Look for `ResourceLimitExceeded` and reduce the policy's size or fan-out.

### The service is `Ready=False`

- Check the engine pods: `kubectl -n authz-system get pods -l app.kubernetes.io/instance=demo,app.kubernetes.io/component=engine`.
- Pods pending or crash-looping: scheduling, image pulls, or pod template overrides. The operator never pushes to an engine that hasn't started.
- Pods running but unready: an engine becomes ready only after the leader pushes to it. Check for `PushFailed` Events on the pods and `CAReadFailed` on the service. The serving certificate must cover `authz-<name>.<namespace>.svc` and be issued by `tls.server.caRef`.
- Fewer ready engines than `minReadyReplicas`: scale up, or lower `minReadyReplicas`.

### Requests are denied unexpectedly

1. Explain the request against the installed policy: `k8s-authz explain <service> -n <namespace> --endpoint <endpoint> --sar request.json`. See [Validating and explaining](../guides/validating-and-explaining.md).
2. Check the `code`:
   - `RootProhibited`: a prohibition covers the request. The report names it. Remember that prohibitions apply to any part of a broad request, and that a named-namespace prohibition on `*` resources also covers cluster-scoped requests.
   - `AuthorityFallback`: nothing granted the request in full, and the authority's `whenNoPolicyAllows` is `Deny`. Check [coverage](../concepts/policy-model.md#coverage): an all-namespace list needs a grant that includes the empty namespace `""`, and a request without a name isn't covered by `resourceNames`. If `status.issues` reports `GrantsNotComposed` for the authority, a broad request must be covered by a single root binding or discovered `PolicySet`; see [Limits](../guides/writing-policies.md#limits).
   - `EvaluationError`: a guard is broken. The report and `status.issues` name it.
3. Check `PolicyHealthy` and `status.issues` for broken grants on the path you expected. A broken branch grants nothing.
4. Remember kube-apiserver's decision cache: a fixed policy may take up to `--unauthorized-ttl` (30 seconds by default) to take effect.

### An application's `PolicySet` isn't attached

A selecting binding attaches a `PolicySet` only while its labels match the `selector` and its namespace's labels match the `namespaceSelector`; see [Discovering PolicySets](../concepts/delegation.md#discovering-policysets).

- Run `k8s-authz validate graph` with `--namespace-labels` for the selection's source. It lists each selection's matches, and warns with `NamespaceNotSelected` of each `PolicySet` the `selector` matches in a namespace the `namespaceSelector` leaves out, or whose labels the source holds none of.
- `NamespaceLabelsNotCollected` in `status.issues` means the selection has a non-empty `namespaceSelector` but its source's `namespaceLabels` is `Ignore`.
- A source with `namespaceLabels: Collect` reads only the labels of namespaces its collection covers, and needs `list` and `watch` on them.
- `ResourceLimitExceeded` on the selecting binding means it, or the authority's selections together, match more `PolicySet`s than the [limits](../guides/writing-policies.md#limits) allow; the selection then attaches none.

### Everyone in an authority is denied, or everything returns `whenEvaluationFails`

The authority's entry binding probably can't be resolved: it's missing, invalid, or in a source that's unavailable or `Inert`. Such an authority matches **every** principal, so it also shadows every authority after it. Look for an issue on that authority with reason `MissingReference`, `InvalidDocument`, `SourceUnavailable`, or `KindMismatch`.

### Requests are allowed that should be denied

- Check that the request reaches the webhook: it may match a recovery identity in the caller configuration's match conditions, or an authorizer placed before the webhook.
- Check the result: `NoOpinion` or a `NoOpinion` fallback hands the request to RBAC, which may allow it. Use `whenNoPolicyAllows: Deny` to make an authority authoritative, or add a prohibition.
- Check kube-apiserver's cache: a revoked grant may stay allowed for up to `--authorized-ttl` (5 minutes by default).

### A source is `Synchronized=False`

| Reason | What to check |
| --- | --- |
| `InvalidCredential` | The kubeconfig Secret exists in the `PolicySource`'s namespace, has the named key, and is self-contained (https, embedded credentials, no exec plugins). |
| `WatchFailing` | Network reachability and the reader's RBAC: `list` and `watch` on every collected kind and namespace, on those Namespaces when `namespaceLabels` is `Collect`, and on the k8s-authz CRDs it collects. |
| `IncompatibleSchema` | The source API's k8s-authz CRDs are from a release that serves `v1alpha1`. |
| `Pending` | The first read hasn't completed. Large collections take longer; otherwise treat it like `WatchFailing`. |

### Engines keep getting evicted

Pushes to those pods keep failing for longer than `--remediation-after`. Common causes are a serving certificate that doesn't match `tls.server.caRef` or the Service DNS name, network policy blocking the operator from the engines on port 8181, or management certificate problems. `PushFailed` Events carry the error.

## Operator logs

```sh
kubectl -n k8s-authz-system logs deployment/k8s-authz-controller-manager
```

Only the leader compiles and pushes, so look at the leader's logs for compile and push problems. `kubectl -n k8s-authz-system get lease` shows the current holder.
