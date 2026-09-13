# Single-cluster example

This example runs everything in one cluster: the operator, the engines, both policy sources, and the API server being authorized. It models a platform team that governs every OIDC user, grants its own administrators broad access, and delegates two namespaces to an orchestration team, which in turn delegates read access to an application team.

## What's in it

| File | Contents |
| --- | --- |
| `namespaces.yaml` | The control namespace `authz-system`, the platform's `platform-policies`, and the orchestration team's `elastic-system` and `confluent`. |
| `control.yaml` | Two `PolicySource`s and the `AuthorizationService` `fleet-authz`. |
| `policies.yaml` | The platform's root policy and bounds, and the orchestration team's delegated policy. |
| `native-viewers.yaml` | A native `workload-reader` ClusterRole and two RoleBindings that the orchestration team's `PolicySet` includes. |

## How it's put together

**Sources.** Both `PolicySource`s read this cluster with the operator's own identity, but with separate collections. `platform` reads only `platform-policies`. `orchestration` reads the orchestration team's two namespaces, including native Roles and RoleBindings, plus the one `workload-reader` ClusterRole. Neither can see the other's documents.

**The authority.** The `trace` endpoint has one authority, whose entry binding `platform-policies/oidc` selects every principal with a group starting `oidc:`, except members of `oidc:k8s-root-admins`. Its fallback is `Deny`, so anything not granted to those principals is rejected. Everyone else, including service accounts, nodes, and the root admins, gets NoOpinion and falls through to Node and RBAC.

**The root `PolicySet`**, `platform-policies/trace-root`, contains:

- `platform-admins`: members of `oidc:k8s-platform-admins` get every resource and non-resource permission.
- `orchestration`: a delegation to the orchestration team's `PolicySet` `elastic-system/elk`, in the `orchestration` source, bounded by `orchestration-access` to namespaces `elastic-system` and `confluent`, with at most one further level of delegation.
- A prohibition, `protect-system-secrets`: no principal the authority selects may `get`, `list`, or `watch` Secrets in `kube-system`. That includes platform admins, and it also covers all-namespace Secret lists and watches.

The entry binding allows the tree to read both sources (`constraints.sourceRefs`) and to go two levels deep (`maxDepth: 2`).

**The orchestration team's `PolicySet`**, `elastic-system/elk`, contains:

- `elk-admins`: `oidc:elk-a` gets the `full-access` Policy, every verb on every resource. The platform's bound limits that to `elastic-system` and `confluent`, custom resources included.
- The native `elk-viewers` RoleBindings in both namespaces: `oidc:elk-v` gets the `workload-reader` ClusterRole, `get`/`list`/`watch` on Pods and Deployments, in each RoleBinding's own namespace.
- `application-team`: a further delegation to `confluent/application-team`, bounded to reading Deployments in `confluent`. There, `oidc:elk-app-r` is bound to the same `full-access` Policy, but receives only the read access the bound allows.

The orchestration team can edit anything in its two namespaces and still can't grant beyond the platform's bound, add prohibitions, or reach outside its own source.

## What each group can do

| Principal | Result |
| --- | --- |
| `oidc:k8s-platform-admins` | Everything, except reading Secrets in `kube-system` (including all-namespace Secret lists). |
| `oidc:elk-a` | Everything in `elastic-system` and `confluent`. |
| `oidc:elk-v` | `get`/`list`/`watch` on Pods and Deployments in `elastic-system` and `confluent`. |
| `oidc:elk-app-r` | `get`/`list`/`watch` on Deployments in `confluent`. |
| Any other `oidc:` group | Denied. |
| `oidc:k8s-root-admins` | Not governed by the authority; whatever RBAC grants them. |
| Everyone else | Not governed; Node and RBAC decide. |

Because the fallback is `Deny` and nothing grants API discovery, the ELK groups can't run discovery (`/api`, `/apis`). A real deployment would add a discovery grant for everyone the authority selects; see [Writing policies](../../docs/guides/writing-policies.md#common-patterns).

The native RoleBindings also grant `workload-reader` through RBAC in this cluster, since they're ordinary RoleBindings. For `oidc:` principals that makes no difference, because the webhook answers first and its `Deny` fallback ends the chain.

## Running it

1. Install the operator. See [Installation](../../docs/operations/installation.md), or follow [Getting started](../../docs/getting-started.md) through step 4.

2. Create the three Secrets the service references, in `authz-system`:

   | Secret | Contents |
   | --- | --- |
   | `fleet-authz-server-tls` | A `kubernetes.io/tls` serving certificate for `authz-fleet-authz.authz-system.svc`. |
   | `fleet-authz-serving-ca` | `ca.crt`: the CA that issued it. |
   | `apiserver-client-ca` | `ca.crt`: the CA that issues kube-apiserver's client certificate. |

   Set the caller's `commonName` in `control.yaml` to the Common Name of kube-apiserver's client certificate.

3. Apply the example and check the service:

   ```sh
   kubectl apply -k examples/local
   kubectl -n authz-system get policysources,authorizationservices
   ```

   `Ready=True` means at least one engine serves the compiled policy. `PolicyHealthy=True` means nothing in the policy graph is broken; otherwise, `status.issues` says what is.

4. Choose a recovery identity with independent RBAC permissions, render the caller configuration, and review it before installing it on kube-apiserver. See [Connecting API servers](../../docs/guides/connecting-api-servers.md).

   ```sh
   k8s-authz render-caller-config fleet-authz -n authz-system --endpoint trace \
     --webhook-server https://<listener-cluster-ip>:443 \
     --caller-certificate /etc/kubernetes/authz/client.crt \
     --caller-key /etc/kubernetes/authz/client.key \
     --engine-ca /etc/kubernetes/authz/serving-ca.crt \
     --webhook-kubeconfig-path /etc/kubernetes/authz/webhook.kubeconfig \
     --recovery-group oidc:k8s-root-admins \
     --output-dir rendered/
   ```

The example installs no writer permissions, no recovery binding, and no API server configuration. Before using it for real, protect `authz-system` and `platform-policies` so only the platform team can write them, and limit the orchestration team to its own namespaces. See [Security](../../docs/operations/security.md#a-writer-layout).
