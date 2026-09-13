# Connecting API servers

An `AuthorizationService` decides nothing until a kube-apiserver calls it. This guide covers the certificates a service needs, how to generate kube-apiserver's authorization configuration, and how to roll it out safely.

## Certificates

The operator issues no certificates. Every service needs these three references in the service's namespace:

| Field | What it holds | Used by |
| --- | --- | --- |
| `tls.server.secretRef` | A `kubernetes.io/tls` Secret with the engines' serving certificate and key. The certificate must cover the DNS name `authz-<service>.<namespace>.svc`, and can add names or addresses callers dial. | Engines serve it. They reload it in place, so renewal needs no restart. |
| `tls.server.caRef` | The CA bundle that issues the serving certificate, in a Secret or ConfigMap key. | The operator verifies engines with it. |
| `tls.client.caRef` | The CA bundle that issues every caller's client certificate, in a Secret or ConfigMap key. | Engines verify callers with it. They reload it in place. |

```yaml
spec:
  tls:
    server:
      secretRef:
        name: demo-serving-tls
      caRef:
        secretKeyRef:
          name: demo-serving-ca
          key: ca.crt
    client:
      caRef:
        configMapKeyRef:
          name: apiserver-client-ca
          key: ca.crt
```

Each caller, which is a kube-apiserver, needs a client certificate that the client CA issues, with a Common Name the endpoint lists:

```yaml
endpoints:
  - name: cluster
    callers:
      - commonName: kube-apiserver-authz
```

An endpoint admits a caller by Common Name alone, after the TLS handshake has verified the certificate chain. Engines verify client certificates against one pool that contains both the service's client CA and the operator's management CA, as kube-apiserver trusts x509 clients from one CA. So **neither CA may issue a Common Name that any endpoint lists to anyone but that caller**, and the management certificate's Common Name must differ from every caller's.

Adding or removing a caller takes effect by push, without restarting the engines. Renewing or re-keying a caller's certificate needs no change at all.

## The listener address

Each service has a Service named `authz-<service>` in its namespace, with an `https` port (443 by default) that forwards to the engines. kube-apiserver needs a network path to it:

- **The control cluster's own API server** can usually reach a ClusterIP, because kube-proxy (or its replacement) runs on control-plane nodes. Reserve a stable address with `listener.spec.clusterIP` so the configuration you render keeps working if the Service is ever recreated.
- **Other API servers**, such as hosted control planes or other clusters, can reach the engines through a `LoadBalancer` or `NodePort` listener, or through TLS-passthrough infrastructure you provide.

```yaml
spec:
  listener:
    spec:
      clusterIP: 10.96.0.11
```

Whatever address a caller dials, the rendered configuration verifies the serving certificate as `authz-<service>.<namespace>.svc`, so the address doesn't need to be in the certificate and the caller doesn't need cluster DNS. See [Engine workloads](engine-workloads.md#the-listener-service) for listener customization.

## Rendering the caller configuration

`k8s-authz render-caller-config` writes the two files kube-apiserver needs for one endpoint:

- `webhook.kubeconfig`: how to reach and authenticate to the endpoint.
- `authorization-config.yaml`: a complete `AuthorizationConfiguration` with the endpoint's webhook authorizer first, followed by `Node` and `RBAC`.

```sh
k8s-authz render-caller-config demo -n authz-system \
  --endpoint cluster \
  --webhook-server https://10.96.0.11:443 \
  --caller-certificate /etc/kubernetes/authz/client.crt \
  --caller-key /etc/kubernetes/authz/client.key \
  --engine-ca /etc/kubernetes/authz/serving-ca.crt \
  --webhook-kubeconfig-path /etc/kubernetes/authz/webhook.kubeconfig \
  --recovery-group system:masters \
  --recovery-group kubeadm:cluster-admins \
  --recovery-group system:nodes \
  --recovery-user system:kube-controller-manager \
  --recovery-user system:kube-scheduler \
  --output-dir rendered/
```

The command reads the `AuthorizationService` from the cluster with kubectl's usual connection flags (`--kubeconfig`, `--context`, `-n`, …). Use `--service-file service.yaml` to render from a file instead. It only writes files; it never changes an API server.

| Flag | Meaning |
| --- | --- |
| `--endpoint` | The endpoint to call. |
| `--webhook-server` | The HTTPS origin, `https://host[:port]` with no path, at which this kube-apiserver reaches the listener. The endpoint's path is appended. |
| `--caller-certificate`, `--caller-key` | Paths **inside the kube-apiserver's filesystem** to its client certificate and key. |
| `--engine-ca` | Path inside kube-apiserver to the CA bundle that verifies the engines' serving certificate. |
| `--webhook-kubeconfig-path` | Path inside kube-apiserver where you'll install `webhook.kubeconfig`. |
| `--recovery-user`, `--recovery-group` | Identities whose requests skip the webhook. Repeatable, up to 64 in total. |
| `--authorized-ttl`, `--unauthorized-ttl` | How long kube-apiserver caches Allow (default `5m`) and Deny/NoOpinion (default `30s`) decisions. `0` disables that cache. |
| `--output-dir` | Where to write the two files. Without it, both are printed to standard output, separated by `---`. |

The rendered webhook authorizer is named `<endpoint>.<service>.<namespace>.k8s-authz`, uses a three-second timeout, and sets `failurePolicy` to the endpoint's `whenEvaluationFails`. Its `matchConditions` exclude each recovery identity:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AuthorizationConfiguration
authorizers:
  - type: Webhook
    name: cluster.demo.authz-system.k8s-authz
    webhook:
      timeout: 3s
      failurePolicy: Deny
      subjectAccessReviewVersion: v1
      matchConditionSubjectAccessReviewVersion: v1
      authorizedTTL: 5m0s
      cacheAuthorizedRequests: true
      unauthorizedTTL: 30s
      cacheUnauthorizedRequests: true
      connectionInfo:
        type: KubeConfigFile
        kubeConfigFile: /etc/kubernetes/authz/webhook.kubeconfig
      matchConditions:
        - expression: '!("system:masters" in request.groups)'
        - expression: request.user != "system:kube-scheduler"
        # ...
  - type: Node
    name: node
  - type: RBAC
    name: rbac
```

**Render again whenever you change the endpoint's `whenEvaluationFails`.** Engines pick up the new value with the next push, but kube-apiserver keeps the `failurePolicy` it was configured with, and that's what applies when an engine can't answer at all.

## Installing it on kube-apiserver

kube-apiserver takes the configuration through `--authorization-config=<path>`, which replaces `--authorization-mode` and the legacy `--authorization-webhook-*` flags. Place the client certificate and key, the engine CA, and `webhook.kubeconfig` at the paths you rendered, and point `--authorization-config` at `authorization-config.yaml`.

kube-apiserver rereads the file while running, roughly once a minute, so later changes need no restart. It reports the loaded configuration in the `apiserver_authorization_config_controller_last_config_info` metric, labeled with the file's hash.

Review the rendered file before installing it, especially:

- **Order.** The webhook comes first so its Deny and prohibitions apply before RBAC can allow a request. Anything you place before it can allow requests the webhook would deny.
- **Match conditions.** A request that matches none of the recovery exclusions goes to the webhook.
- **Other authorizers.** Only `Node` and `RBAC` follow the webhook. Add any others your cluster uses.

### Several endpoints

kube-apiserver loads one `AuthorizationConfiguration`. To call several endpoints, of one service or of several, render each into its own `--output-dir` with its own `--webhook-kubeconfig-path`, then merge them by hand: keep every rendered webhook authorizer, in the order requests should reach them, ahead of a single `Node` entry and a single `RBAC` entry.

## Recovery identities

A recovery identity must still be able to administer the cluster when the engines are unreachable, misconfigured, or answering Deny. Excluding a principal from an authority isn't enough, because the webhook call itself still has to succeed. Only a match condition keeps the request away from the webhook entirely.

Choose recovery identities that:

- Are excluded with `--recovery-user` or `--recovery-group`.
- Have independent permissions in RBAC, since RBAC is what authorizes them.
- Are rarely used and tightly held, because they bypass every prohibition.

Control-plane components are usually recovery identities too, so that a webhook outage can't stop the cluster's own controllers: `system:kube-controller-manager`, `system:kube-scheduler`, and the `system:nodes` group. Whether to also exclude service accounts (`system:serviceaccounts`) depends on whether k8s-authz should govern workloads; excluding them keeps in-cluster controllers independent of the engines, at the cost of k8s-authz having no say over them.

## Caching and propagation

kube-apiserver caches webhook decisions by request attributes. With the default TTLs, a policy change can take up to five minutes to revoke a cached Allow, and up to 30 seconds to replace a cached Deny or NoOpinion. Both fallbacks are cached as unauthorized, so a request can keep its fallback that long after a failure is fixed. Lower `--authorized-ttl` and `--unauthorized-ttl` if faster propagation matters more than load on the engines.

The caches kube-apiserver keeps by default apply even when a TTL is `0`, unless caching is also disabled explicitly. That's why `render-caller-config` sets `cacheAuthorizedRequests` and `cacheUnauthorizedRequests` to `false` when the corresponding TTL is `0`.
