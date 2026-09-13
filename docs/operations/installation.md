# Installation

This page covers installing the operator in a control cluster, its certificates and flags, and upgrades. For a guided first install on Kind, see [Getting started](../getting-started.md).

## Prerequisites

- A Kubernetes cluster to run the operator and engines. The project is tested with Kubernetes 1.36 and 1.37.
- For each API server k8s-authz will authorize: the ability to set kube-apiserver's `--authorization-config` flag and place files on its filesystem, plus network reachability from it to the engine Service.
- A way to issue certificates, such as cert-manager, a PKI, or `openssl`. The operator issues none.
- The operator image, built from this repository (`make docker-build IMG=<registry>/k8s-authz:<tag>`) or taken from your organization's registry. The engines use the stock OPA image, which the operator pins by digest.
- The `k8s-authz` CLI, built with `make build` (it lands in `bin/k8s-authz`) or taken from the `k8s-authz-cli` image.

Use the operator image, CLI, CRDs, and charts from the same release.

## What gets installed

| Component | Where | Notes |
| --- | --- | --- |
| CRDs | Every API that holds k8s-authz resources: the control cluster and every source that collects `Policy`, `PolicyBinding`, or `PolicySet` | Five CRDs in `authorization.zctx.io`. |
| Operator Deployment | Control cluster, namespace `k8s-authz-system` | Runs the controllers and the diagnostics endpoint. |
| Operator RBAC | Control cluster | The operator's own permissions; see [Operator permissions](#operator-permissions). Kustomize also installs unbound admin/editor/viewer ClusterRoles for each kind. |

Engines aren't part of the installation. The operator creates them for each `AuthorizationService`.

## Operator certificates

The operator needs three Secrets in its namespace before its pod can start. The Kustomize configuration mounts them by these names, and the Helm chart uses them by default:

| Secret | Keys | Purpose |
| --- | --- | --- |
| `management-client-cert` | `tls.crt`, `tls.key` | The client certificate the operator presents to engines. It needs the `clientAuth` extended key usage. Its Common Name is the operator's management identity. |
| `management-ca` | `ca.crt` | The CA bundle that issues the management certificate. Engines trust it for management calls only. |
| `diagnostics-server-cert` | `tls.crt`, `tls.key` | The serving certificate for the diagnostics endpoint on port 9443. The CLI reaches it through a port-forward, so its names aren't checked. |

The management certificate controls what every engine serves, including the Rego it runs, so treat its key as a high-value secret. Its Common Name must not match any endpoint caller's, and its CA must not issue any caller's Common Name to anyone else, because engines check both in one trust pool (see [Certificates](../guides/connecting-api-servers.md#certificates)).

The operator reloads all three from disk. A renewed management certificate is used from the next connection. A changed management Common Name or CA bundle changes every engine's bootstrap and rolls the engines.

Create them with any tool. For example, with files you've already issued:

```sh
kubectl create namespace k8s-authz-system
kubectl -n k8s-authz-system create secret tls management-client-cert --cert=management.crt --key=management.key
kubectl -n k8s-authz-system create secret generic management-ca --from-file=ca.crt=management-ca.crt
kubectl -n k8s-authz-system create secret tls diagnostics-server-cert --cert=diagnostics.crt --key=diagnostics.key
```

## Installing with Kustomize

The Kustomize configuration under `config/` installs the CRDs, the operator, its RBAC, and a metrics Service.

From a checkout of this repository:

```sh
make install                                   # CRDs only
make deploy IMG=<registry>/k8s-authz:<tag>     # CRDs, RBAC, and the operator
kubectl -n k8s-authz-system rollout status deployment/k8s-authz-controller-manager
```

Or render a single installer to review and apply elsewhere:

```sh
make build-installer IMG=<registry>/k8s-authz:<tag>
kubectl apply --server-side -f dist/install.yaml
```

Always apply the CRDs and the installer with **server-side apply**. The CRDs embed the native Pod and Service template schemas, which exceed the annotation size limit of client-side apply.

The default configuration runs one operator replica. To run several for faster failover, raise the Deployment's replicas in your overlay. Leader election is already enabled: every replica reads sources and serves diagnostics, and only the leader compiles and pushes.

To install only the CRDs on a remote source API, run `make install` against that cluster, or apply `config/crd` with `kubectl apply --server-side -k config/crd`.

## Installing with Helm

The `k8s-authz` chart installs the CRDs, the operator, and its RBAC, and optionally metrics monitoring. Package the charts with `make helm-package REGISTRY=<registry>`, which writes them to `dist/`, or pull them from wherever your release publishes them.

Create the operator's Secrets first, then install into `k8s-authz-system`, the namespace `k8s-authz explain` looks in by default:

```sh
helm install k8s-authz dist/k8s-authz-<version>.tgz -n k8s-authz-system \
  --set image.repository=<registry>/k8s-authz --set image.tag=<tag>
kubectl -n k8s-authz-system rollout status deployment/k8s-authz
```

| Value | Default | Purpose |
| --- | --- | --- |
| `image.repository`, `image.tag`, `image.pullPolicy` | the release's image | Operator image. The tag defaults to the chart's `appVersion`. |
| `replicaCount` | `2` | Operator replicas. Leader election is always on. |
| `controlNamespaces` | `[]`, every namespace | `--control-namespaces`, and the scope of the operator's namespaced permissions; see [Operator permissions](#operator-permissions). Listed namespaces must exist. |
| `management.certificate.secretName` | `management-client-cert` | Secret holding the management `tls.crt` and `tls.key`. |
| `management.ca.secretName`, `management.ca.key` | `management-ca`, `ca.crt` | Secret and key holding the management CA bundle. |
| `diagnostics.certificate.secretName` | `diagnostics-server-cert` | Secret holding the diagnostics `tls.crt` and `tls.key`. |
| `diagnostics.port` | `9443` | Diagnostics port. |
| `engine.image` | the pinned stock OPA release | `--engine-image`. |
| `engine.decisionLogs` | `false` | `--engine-decision-logs`. |
| `remediationAfter` | the operator's default | `--remediation-after`. |
| `metrics.enabled`, `metrics.port` | `false`, `8443` | Serve operator metrics, with a metrics Service and a `<fullname>-metrics-reader` ClusterRole. |
| `metrics.certificate.secretName` | self-signed | Secret holding the metrics `tls.crt`, `tls.key`, and `ca.crt`, as cert-manager writes it. |
| `metrics.reader.subjects` | `[]` | Subjects bound to the metrics reader ClusterRole, such as your Prometheus ServiceAccount. |
| `prometheus.enabled` | `false` | Create a ServiceMonitor for the operator's metrics (with `metrics.enabled`) and a PodMonitor for the engines'. Requires the Prometheus Operator CRDs. |
| `prometheus.scrapeEngines` | `true` | Include the engine PodMonitor. |
| `crds.enabled` | `true` | Install the CRDs with the release. |
| `crds.keep` | `true` | Annotate the CRDs `helm.sh/resource-policy: keep`. |
| `rbac.create`, `serviceAccount.create`, `serviceAccount.name` | `true`, `true`, the fullname | Create the operator's RBAC and ServiceAccount. |
| `extraArgs`, `extraEnv` | `[]` | Further operator flags and environment variables. |

`resources`, `podSecurityContext`, `securityContext`, `podAnnotations`, `podLabels`, `imagePullSecrets`, `nodeSelector`, `tolerations`, `affinity`, `topologySpreadConstraints`, `priorityClassName`, and `rollingUpdate` set the usual pod fields.

The CRDs are templates of the release, not Helm `crds/`, so `helm upgrade` upgrades them. With `crds.keep` they're annotated `helm.sh/resource-policy: keep`, so `helm uninstall` leaves them and every resource in the cluster in place. To manage the CRDs yourself, set `crds.enabled=false`. To install only the CRDs on a remote source API, install the `k8s-authz-crds` chart there.

`k8s-authz explain` finds the operator's pods by the label `authorization.zctx.io/component: operator`, which both installations set whatever the release is named. If you install into another namespace, pass it to `explain` with `--operator-namespace`.

## Operator flags

The operator is configured only through command-line flags. Add them to the manager container's `args` in your Kustomize overlay, or set the matching Helm values or `extraArgs`.

| Flag | Default | Purpose |
| --- | --- | --- |
| `--control-namespaces` | every namespace | Comma-separated namespaces whose `AuthorizationService`s and `PolicySource`s are reconciled. |
| `--engine-image` | the pinned stock OPA release | Engine image. It must be pinned by `@sha256:` digest; use this only to point at a mirror of the same image. |
| `--engine-decision-logs` | `false` | Log every endpoint decision from every engine. See [Monitoring](monitoring.md#decision-logs). |
| `--management-cert-path` | required | Directory holding the management `tls.crt` and `tls.key`. |
| `--management-ca-path` | required | PEM file holding the management CA bundle. |
| `--diagnostics-bind-address` | `:9443` | Diagnostics listener address. |
| `--diagnostics-cert-path` | required | Directory holding the diagnostics `tls.crt` and `tls.key`. |
| `--remediation-after` | `2m` | How long pushes to an engine pod may keep failing before it's evicted. |
| `--leader-elect` | `false` (`true` in both installations) | Enable leader election. |
| `--metrics-bind-address` | `0` (`:8443` in `config/`) | Metrics address; `0` disables metrics. |
| `--metrics-secure` | `true` | Serve metrics over HTTPS with authentication and authorization. |
| `--metrics-cert-path`, `--metrics-cert-name`, `--metrics-cert-key` | self-signed | Metrics serving certificate. |
| `--health-probe-bind-address` | `:8081` | Liveness and readiness probes. |
| `--enable-http2` | `false` | Enable HTTP/2 on the metrics server. |

The `config/default` overlay and the Helm chart mount the three Secrets and set the three required paths. If you use your own manifests, pass them explicitly; the operator refuses to start without them.

## Operator permissions

The operator needs to:

- Read `AuthorizationService`s and `PolicySource`s, patch their status, and update their finalizers.
- Create, patch, and read the objects it manages for each service: ConfigMaps, Deployments, DaemonSets, Services, and PodDisruptionBudgets. Delete Deployments and DaemonSets when switching runtime kinds. Read Pods and evict engine pods.
- Read, create, patch, and delete Secrets, for reading TLS material and writing source caches.
- Read every `Policy`, `PolicyBinding`, `PolicySet`, and native RBAC object, because local sources without a kubeconfig read with the operator's identity. List and watch the k8s-authz CRDs.
- Create TokenReviews and SubjectAccessReviews, for authenticating and authorizing diagnostics callers.
- Record Events.

The Kustomize installation grants all of this cluster-wide through the `manager-role` ClusterRole, whichever namespaces the operator controls.

The Helm chart splits it by scope. The `<fullname>` ClusterRole holds what is cluster-wide by nature: reading policy documents, native RBAC objects, and the CRDs, and creating TokenReviews and SubjectAccessReviews. The `<fullname>-control` ClusterRole holds everything else. It's bound cluster-wide when `controlNamespaces` is empty, and otherwise by a RoleBinding in each listed namespace, so an operator restricted to some namespaces can't read Secrets or change workloads anywhere else.

Both installations also bind a leader-election Role in the operator's namespace. The Helm chart additionally binds the built-in `extension-apiserver-authentication-reader` Role in `kube-system`, from which the diagnostics endpoint reads the CA for client certificates. The Kustomize installation covers that read with its cluster-wide ConfigMap access.

The per-kind `*-admin`, `*-editor`, and `*-viewer` ClusterRoles aren't bound to anyone. Use them to grant people access to the five kinds.

## Upgrading

Operators decode documents strictly against their own types, and the CRDs are the schema. Upgrade in this order:

1. Roll the new operator image out on the existing Deployment, without applying new CRDs yet. An older operator would report documents that use newly added fields as `Invalid`, so the operator goes first.
2. Apply the new CRDs on the control cluster (`make install`, or the installer) and on every source API.
3. Only then publish documents that use the new fields.

When Helm installs the CRDs, one `helm upgrade` performs the first two steps together. Wait for the operator's rollout to finish before publishing documents that use new fields.

A source whose CRDs don't serve `v1alpha1` reports `IncompatibleSchema` and keeps serving its last view until its CRDs are fixed.

An operator upgrade that changes the engines' evaluator rolls the engines. They keep serving until their replacements are ready.

## Uninstalling

Remove k8s-authz from every API server's authorization configuration **before** deleting services. Once the engines are gone, an endpoint whose webhook still has `failurePolicy: Deny` rejects every request that doesn't match a recovery identity.

```sh
kubectl delete authorizationservices,policysources --all -A
make undeploy                                  # or: helm uninstall k8s-authz -n k8s-authz-system
```

`helm uninstall` leaves the CRDs, and with them every policy document. Delete the five `*.authorization.zctx.io` CRDs yourself once nothing needs them.

Deleting an `AuthorizationService` deletes its engines, Service, ConfigMap, and PodDisruptionBudget. Deleting a `PolicySource` deletes its cache Secrets. Policy documents in sources are left alone.
