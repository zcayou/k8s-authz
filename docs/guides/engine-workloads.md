# Engine workloads

Each `AuthorizationService` owns a set of native Kubernetes objects that run its engines. You configure them through `spec.runtime` and `spec.listener`. This guide covers what gets created, how to size and place engines, and which parts you can customize.

## What the operator creates

For a service named `demo` in namespace `authz-system`:

| Object | Name | Purpose |
| --- | --- | --- |
| Deployment or DaemonSet | `authz-demo` | Runs the engine pods. |
| Service | `authz-demo` | The listener callers connect to, port `https` (443 by default). |
| ConfigMap | `authz-demo-engine` | The engines' startup files: the release's Rego modules, OPA configuration, a bootstrap document, and the client CA bundle. |
| PodDisruptionBudget | `authz-demo` | Keeps `minReadyReplicas` engines available through voluntary disruptions. |

Every object carries the service as its controller owner, so deleting the service deletes them. The operator applies them with server-side apply and repairs drift. If an object with the same name is already controlled by something else, the operator leaves it alone and reports an `ApplyFailed` Event.

Engine pods run the stock OPA image pinned by digest (see the operator's `--engine-image` flag). They run as non-root with a read-only root filesystem, no privilege escalation, all capabilities dropped, and no service account token. They listen on 8181 (HTTPS, for callers and the operator) and 8182 (plain HTTP health and metrics).

## Deployment or DaemonSet

`runtime.type` selects the workload kind:

```yaml
spec:
  runtime:
    type: Deployment
    deployment:
      replicas: 3                # default 2
    minReadyReplicas: 2          # default 1
```

```yaml
spec:
  runtime:
    type: DaemonSet              # one engine per eligible node
    minReadyReplicas: 2
```

`deployment` applies only when `type` is `Deployment`. With `DaemonSet` it's ignored, so switching back restores the Deployment's settings.

A Deployment suits a central service that API servers reach over the network. A DaemonSet suits running an engine next to each API server, for example on control-plane nodes, combined with a node selector and `listener.spec.trafficDistribution`.

`minReadyReplicas` is the number of engines serving current policy that the service keeps through rollouts, node drains, and runtime switches. It sets the PodDisruptionBudget's `minAvailable` and the threshold for the `Ready` condition. With a Deployment it can't exceed `replicas`.

With `minReadyReplicas` equal to `replicas`, no ready engine may be evicted, so node drains block until you scale up or lower the minimum.

## Rollouts

Engine rollouts allow zero planned unavailability and one surge pod. Most changes never roll the engines at all:

| Change | Effect on engines |
| --- | --- |
| Policy documents, authorities, callers, Rego conditions | Pushed to running engines. No restart. |
| Serving certificate renewal, client CA bundle change | Reloaded in place. No restart. |
| Management certificate identity or CA, operator release, `--engine-decision-logs` | Rolls the engines. |
| `runtime.podTemplate` changes | Rolls the engines, as with any pod template. |

Each engine pod records the startup configuration it was created from in its `authorization.zctx.io/startup-digest` annotation. The operator pushes policy only to pods that started from the current configuration. During a rollout, old pods keep serving the policy they have until their replacements are ready. If a rollout stalls, for example on an unschedulable replacement, the old pods keep serving a frozen revision; `status.currentReplicas` shows how many engines serve current policy.

### Switching between Deployment and DaemonSet

Changing `runtime.type` from `Deployment` to `DaemonSet`, or back, creates the new workload and keeps the old one until the new one has `minReadyReplicas` ready engines. The listener Service and PodDisruptionBudget select engines from both workloads during the switch. When the old workload is removed, the operator records a `DeletedWorkload` Event.

## Customizing engine pods

`runtime.podTemplate` is merged onto the generated pod template with Kubernetes' strategic-merge rules:

```yaml
spec:
  runtime:
    type: Deployment
    deployment:
      replicas: 3
    minReadyReplicas: 2
    metadata:                        # labels/annotations for the Deployment or DaemonSet
      labels:
        team: platform
    podTemplate:
      metadata:
        labels:
          team: platform
      spec:
        priorityClassName: system-cluster-critical
        nodeSelector:
          node-role.kubernetes.io/control-plane: ""
        tolerations:
          - key: node-role.kubernetes.io/control-plane
            effect: NoSchedule
        imagePullSecrets:
          - name: registry-credentials
        containers:
          - name: opa
            resources:
              requests:
                cpu: 250m
                memory: 512Mi
              limits:
                memory: 1Gi
```

The engines have no installation-wide resource, scheduling, or image-pull settings. The generated pod sets no resources, affinity, tolerations, or pull secrets, so set them per service here.

Merge rules:

- Omitted fields keep their generated values. The override types can't tell an explicit `false` or `0` from an omitted field, so those also keep the generated value. The exception is a listener port's `nodePort: 0`, which is honored.
- Maps merge by key. Containers, volumes, and environment variables merge by name, and volume mounts by mount path. The `opa` container is customized in place, and you can add sidecars and init containers.
- Removing an override restores the generated default.

You can set resources, environment, extra volumes and mounts, security contexts, scheduling, DNS, priority, pull secrets, probe timing, and extra containers. Engines run as the namespace's `default` ServiceAccount unless `serviceAccountName` names another, and they never mount its token.

Don't override these, which are unsupported and can break the engine: the `opa` container's image, command, arguments, ports, and probe handlers; the `engine` and `tls` volumes and their mounts; labels and annotations under `authorization.zctx.io/`; and the generated `app.kubernetes.io/name`, `instance`, `component`, and `managed-by` labels. Names, owner references, the Service selector, and the engine's target port aren't part of the override types at all.

An override can give engine pods anything the Pod spec allows, including host namespaces and privileged containers. Control who can create and edit `AuthorizationService`s with RBAC, and what their pods may run with Pod Security Admission in the service's namespace.

The top-level `metadata` of the `AuthorizationService` isn't copied anywhere. Use `runtime.metadata`, `runtime.podTemplate.metadata`, and `listener.metadata`.

## The listener Service

`spec.listener` customizes the Service callers connect to:

```yaml
spec:
  listener:
    metadata:
      annotations:
        example.com/owner: platform
    spec:
      type: LoadBalancer
      externalTrafficPolicy: Local
      loadBalancerSourceRanges: [10.20.0.0/16]
      ports:
        - name: https
          port: 8443
```

- `type` can be `ClusterIP` (default), `NodePort`, or `LoadBalancer`. `ExternalName` and headless Services aren't supported.
- The `https` port's `port` and `nodePort` can be changed, and other named ports added. Its target port, 8181, stays operator-managed; don't change its `protocol` or `appProtocol`.
- `clusterIP` reserves an address. The API server treats a ClusterIP as immutable, so changing it on an existing Service fails, and the failure is reported as an `ApplyFailed` Event.
- The operator never sends allocated ClusterIPs or NodePorts, so they survive updates. To remove NodePorts from a LoadBalancer Service, set `allocateLoadBalancerNodePorts: false` and the port's `nodePort: 0`.
- `trafficDistribution: PreferSameNode`, `PreferSameZone`, or `PreferClose` asks the dataplane to prefer nearby engines, with remote fallback, if your cluster supports it. `internalTrafficPolicy` defaults to `Cluster` and also accepts `Local`.
- IP family policy, session affinity, load balancer class, and source ranges work as native Service fields.

## Sizing

Engines evaluate every request against in-memory state, so memory scales with the size of the compiled policy and CPU with request volume. A service's compiled state is limited to 32 MiB and its Rego conditions module to 1 MiB. Start with modest requests (for example 100m CPU and 256Mi memory), watch OPA's own metrics on port 8182, and add replicas for throughput and availability. kube-apiserver's decision cache takes much of the load off the engines.

## Termination

On termination, OPA stops accepting connections and allows ten seconds for in-flight requests to finish. kube-apiserver retries a failed webhook call and reaches another engine once the Service drops the terminating pod. The pod's termination grace period defaults to 30 seconds and can be changed in the pod template.
