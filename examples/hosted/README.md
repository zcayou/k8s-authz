# Hosted control planes example

This example runs the operator and engines on a management cluster that serves authorization for other API servers: the management cluster's own, and those of hosted control planes. Platform policy lives on the management cluster; the orchestration team's policy lives on a separate Kubernetes API that the operator reads remotely.

Where policy is stored and which cluster is being authorized are independent choices. Here, one endpoint serves every API server, and its policy comes from two APIs.

## What's in it

| File | Install on | Contents |
| --- | --- | --- |
| `control.yaml` | Management API, `authz-system` | The `platform` (local) and `orchestration` (remote) `PolicySource`s, and the `AuthorizationService` `fleet-authz`. |
| `platform.yaml` | Management API, `platform-policies` | The root `PolicySet`, platform admins, the `kube-system` Secrets prohibition, and the bounded delegation to orchestration. |
| `orchestration.yaml` | Source API, `elastic-system` and `confluent` | The orchestration team's `PolicySet`, admins, native viewers, and a delegation to an application team. |
| `expressions.yaml` | Management API, `platform-policies` | Two reusable Policies, not referenced by anything, that show exclusions and multi-namespace grants. |

The policy graph is the same as the [single-cluster example](../local/README.md#how-its-put-together); what differs is where it runs and where it's read from.

## How it differs from the single-cluster example

**Engines as a DaemonSet.** `runtime.type: DaemonSet` runs one engine on every eligible node, and `minReadyReplicas: 2` keeps at least two ready through rollouts and drains. That needs at least two eligible, ready nodes. To use a Deployment instead, set `type: Deployment` and `deployment.replicas`, and keep `minReadyReplicas` no higher than it.

**A fixed listener address.** `listener.spec.clusterIP: 10.245.0.11` reserves a stable address, and `trafficDistribution: PreferSameNode` asks the dataplane to prefer the engine on the caller's node. Hosted API servers call that address directly. The rendered configuration verifies the engines as `authz-fleet-authz.authz-system.svc`, so the API servers need no cluster DNS, only a route to the address.

**A remote source.** The `orchestration` source reads another API with the kubeconfig in `authz-system/trace-policy-api`, key `kubeconfig`. That API needs the k8s-authz CRDs and a reader identity, and nothing else: no operator, no engines.

**Extra expressions.** `expressions.yaml` holds two Policies that nothing references yet: `operator-access` grants everything except Secret reads, and `netsec-access` grants a mix of custom resources, logs, and `exec` in specific namespaces. They're inert until a binding uses them.

## Running it

1. **Install the CRDs on both APIs**, from the same release as the operator, and install the operator on the management cluster. See [Installation](../../docs/operations/installation.md).

2. **Create the namespaces** each file names: `authz-system` and `platform-policies` on the management API, `elastic-system` and `confluent` on the source API.

3. **Set up the remote reader.** Get a self-contained, TLS-verified kubeconfig for the source API whose identity can read the `orchestration` collection: Policies, PolicyBindings, PolicySets, Roles, and RoleBindings in `elastic-system` and `confluent`, and the `workload-reader` ClusterRole. Store it on the management API:

   ```sh
   kubectl -n authz-system create secret generic trace-policy-api --from-file=kubeconfig=orchestration-reader.kubeconfig
   ```

   The local `platform` source uses the operator's own identity, which already has read access. See [Policy sources](../../docs/guides/policy-sources.md).

4. **Create the TLS Secrets** in `authz-system`:

   | Secret | Contents |
   | --- | --- |
   | `fleet-authz-server-tls` | A `kubernetes.io/tls` serving certificate for `authz-fleet-authz.authz-system.svc`. |
   | `fleet-authz-serving-ca` | `ca.crt`: the CA that issued it. |
   | `hosted-api-client-ca` | `ca.crt`: the CA that issues the API servers' client certificates. |

   Set the caller's `commonName` in `control.yaml` to the Common Name of those client certificates, and replace `10.245.0.11` with an unused address in the management cluster's Service range.

5. **Validate the documents** before applying them:

   ```sh
   k8s-authz validate documents examples/hosted/control.yaml
   k8s-authz validate documents --source authz-system/platform examples/hosted/platform.yaml examples/hosted/expressions.yaml
   k8s-authz validate documents --source authz-system/orchestration examples/hosted/orchestration.yaml
   ```

   These check each document on its own. `kubectl apply --dry-run=server` also checks the CRD schemas' validation rules. Neither proves the graph resolves or that sources are reachable; the service's status does that once it's running.

6. **Apply** `platform.yaml`, `expressions.yaml`, and `control.yaml` to the management API, and `orchestration.yaml` to the source API. Wait for the `orchestration` source to report `Synchronized=True` and the service `Ready=True`.

7. **Connect the API servers.** Once the listener has its address, render the caller configuration with `--webhook-server https://10.245.0.11:443`, keep a recovery identity outside the webhook with independent RBAC permissions, and install the result on each API server. See [Connecting API servers](../../docs/guides/connecting-api-servers.md).

## What each group can do

The same as the [single-cluster example](../local/README.md#what-each-group-can-do), on every API server that calls the endpoint. For example, a Secret list scoped to `elastic-system` remains allowed for `oidc:elk-a`, while any read of Secrets in `kube-system` is denied to everyone the authority selects. An `oidc:` group that nothing grants falls back to Deny. `oidc:k8s-root-admins` is outside the authority, so its permissions must come from an independent authorizer.

## Operating it

- **Protect the writers.** On the management API, only the platform team may write `authz-system` and `platform-policies`: sources, the service, TLS and kubeconfig Secrets, the root `PolicySet`, prohibitions, and bounds. On the source API, limit the orchestration team to the policy kinds and namespaces in its collection. Native RoleBindings there are also live RBAC on that API.
- **Rotate the reader credential** by updating the `trace-policy-api` Secret before the credential expires. The operator swaps readers and keeps serving the source's current view until the new reader has caught up. Check `Synchronized` and `lastAdmittedTime` on the `PolicySource` after a rotation.
- **Upgrade operators before CRDs**, on both APIs. A source API whose CRDs don't serve `v1alpha1` reports `IncompatibleSchema` and keeps serving its last view. See [Upgrading](../../docs/operations/installation.md#upgrading).
