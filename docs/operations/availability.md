# Availability

An authorization webhook sits in the path of every API request it covers, so k8s-authz is built to keep answering, and to answer the same way, when parts of the system fail. This page describes what happens in each failure and what you control.

## The principle: installed policy never expires

Once an engine has policy installed, it keeps serving it until the operator pushes a newer revision. Time alone never changes a decision. Operator outages, source outages, and network partitions between the operator and a source stop policy from being updated, but they don't change what the engines decide.

## Operator outage

If every operator replica stops:

- Ready engines keep making the same decisions.
- Policy updates, status updates, and engine remediation stop.
- New or restarted engines can't reconstruct policy on their own. They stay unready, and the listener Service doesn't route to them, until an operator pushes to them.

So the engines' serving capacity slowly erodes during a long operator outage, as pods are rescheduled or restarted. Run more than one operator replica, keep `minReadyReplicas` and the engines' replica count high enough to absorb node loss, and give the operator a suitable priority class.

When an operator becomes leader, it reconciles every service from its already-warm caches, and pushes only to engines that don't already serve the current revision.

## Source outage

When a source can't be read, it keeps its last complete view, which keeps contributing to compiled policy. Its `Synchronized` condition turns `False` with reason `WatchFailing` or `InvalidCredential`, and `lastAdmittedTime` stops advancing. Nothing is removed from policy until the source is read successfully and the documents are actually gone.

## Operator restart

The leader persists every source's view in Secrets owned by the `PolicySource`. A restarted operator restores each view before it registers the source, whether or not the source or its credential is reachable, and a service is compiled only after every source its endpoints read has been registered. A restart therefore never installs policy with a source missing.

## Engine failure

If an engine pod fails, the listener Service stops routing to it and kube-apiserver's calls go to the remaining engines. kube-apiserver retries a webhook call that fails.

If no engine can answer, kube-apiserver applies the webhook's `failurePolicy`, which `render-caller-config` sets from the endpoint's `whenEvaluationFails`:

- `Deny`: requests the webhook would have decided are rejected. Only recovery identities excluded by match conditions keep working.
- `NoOpinion`: requests go on to Node and RBAC. Prohibitions don't apply until the engines return.

An engine that is running but has no installed policy answers with an HTTP error, so kube-apiserver applies the same `failurePolicy`.

## Push failures and remediation

The leader pushes policy directly to each engine pod. A failed push is recorded as a `PushFailed` Event on the pod and retried with backoff. A pod that hasn't started its `opa` container (still pulling, crash-looping) is never pushed to; it belongs to its workload and the kubelet.

If pushes to a started pod keep failing for `--remediation-after` (two minutes by default), the leader evicts it through the Eviction API and records an `Evicted` Event, and its workload replaces it. The service's PodDisruptionBudget guards capacity: an eviction the budget refuses is retried later, and pods that aren't Ready can always be evicted. The failure timer lives in the leader's memory, so a failover restarts it, and a widespread management outage can't replace pods faster than the budget allows.

## Voluntary disruptions

Each service's PodDisruptionBudget keeps `minReadyReplicas` engines through node drains, cluster autoscaler scale-downs, and descheduling. With `minReadyReplicas` equal to a Deployment's `replicas`, no ready engine can be evicted, so drains block. Leave at least one engine of headroom.

## Rollouts

Engine rollouts surge one pod at a time with no planned unavailability. Old pods keep serving their installed revision until they're replaced. A rollout that can't progress, for example because a replacement is unschedulable or a runtime switch's new workload never becomes ready, leaves the old pods serving a frozen revision; `currentReplicas` below `desiredReplicas` shows it. See [Engine workloads](../guides/engine-workloads.md#rollouts).

## Recovery access

Plan for the case where the webhook denies everything, whether from a bad policy, a misconfigured endpoint, or unreachable engines with `failurePolicy: Deny`:

- Keep at least one [recovery identity](../guides/connecting-api-servers.md#recovery-identities) excluded from the webhook by match conditions, with independent RBAC permissions.
- Keep the cluster's own control-plane components excluded as well, so that controllers and nodes keep working through a webhook outage.
- Test the recovery path.

## Existing sessions

Authorization is checked when a request starts. A running watch, `exec`, `attach`, or port-forward isn't interrupted by a policy change or an engine outage.
