# Monitoring

## What to watch

| Signal | Where | Why |
| --- | --- | --- |
| `Ready` and `PolicyHealthy` conditions | Each `AuthorizationService` | Serving capacity, and whether part of the policy graph is broken. |
| `currentReplicas` vs `desiredReplicas` | Each `AuthorizationService` | Engines still serving an older revision. |
| `Synchronized` and `lastAdmittedTime` | Each `PolicySource` | Sources that can't be read, and how stale their views are. |
| `PushFailed` and `Evicted` Events | Engine pods and services | The operator can't reach or update engines. |
| Webhook latency and errors | kube-apiserver metrics | What callers actually experience. |

## Operator metrics

The operator serves Prometheus metrics on its metrics port (`:8443` in the Kustomize installation, and in the Helm chart with `metrics.enabled`) over HTTPS. Access requires a bearer token whose identity is authorized to `get` the `/metrics` non-resource URL. Both installations include a `k8s-authz-metrics-reader` ClusterRole to bind to your Prometheus ServiceAccount (named `<fullname>-metrics-reader` by Helm, which binds it to `metrics.reader.subjects` for you):

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: prometheus-k8s-authz-metrics
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: k8s-authz-metrics-reader
subjects:
  - kind: ServiceAccount
    namespace: monitoring
    name: prometheus
```

Without `--metrics-cert-path`, the metrics server uses a self-signed certificate. The Kustomize configuration under `config/prometheus` includes a ServiceMonitor you can enable in your overlay. The Helm chart creates one with `prometheus.enabled`, which verifies the metrics certificate when `metrics.certificate.secretName` is set and skips verification otherwise.

Alongside the standard controller-runtime metrics (reconcile counts, errors, latency, and workqueue depth per controller), the operator exports:

| Metric | Type | Meaning |
| --- | --- | --- |
| `k8s_authz_source_synchronized` | Gauge | `1` while a source is synchronized, labeled with the `PolicySource`'s `namespace` and `name`. |
| `k8s_authz_source_acquisition_failures_total` | Counter | Each time a source's acquisition starts failing, labeled with `namespace` and `name`. |
| `k8s_authz_compile_duration_seconds` | Histogram | How long each compilation took, labeled with `result` (`success` or `failure`). Compilations served from the cache aren't counted. |
| `k8s_authz_compile_limit_failures_total` | Counter | Compilations in which a resource limit forced part of the policy to answer `whenEvaluationFails`. |

## Engine metrics

Each engine serves OPA's own Prometheus metrics, including HTTP request counts and latency, on port 8182 at `/metrics`, in plain HTTP. Scrape them with a PodMonitor that selects engine pods by the labels `app.kubernetes.io/component: engine` and `app.kubernetes.io/managed-by: k8s-authz-operator`. The Helm chart creates one in the control namespaces with `prometheus.enabled`.

An HTTP 200 from an engine doesn't tell Allow, Deny, and NoOpinion apart. For decision outcomes, use decision logs or kube-apiserver's authorization metrics.

## Decision logs

`--engine-decision-logs` makes every engine log each endpoint decision to its console, which your cluster's log pipeline collects. Only endpoint decisions are logged, not health or management traffic, and the request is masked so the logs don't carry the full review. Turning decision logs on or off rolls the engines.

## kube-apiserver metrics

kube-apiserver reports on its authorization webhooks directly, including `apiserver_authorization_webhook_evaluations_total`, `apiserver_authorization_webhook_duration_seconds`, and `apiserver_authorization_webhook_evaluations_fail_open_total`, labeled by authorizer name (`<endpoint>.<service>.<namespace>.k8s-authz`). `apiserver_authorization_config_controller_last_config_info` shows which authorization configuration is loaded.

## Network access

The engines and operator expose these ports:

| Port | Who connects | Purpose |
| --- | --- | --- |
| Engine 8181 (Service port 443 by default) | kube-apiserver callers; the operator | Webhook decisions; policy pushes and state reads. |
| Engine 8182 | kubelet; Prometheus | Health and OPA metrics, plain HTTP. |
| Operator 9443 | Port-forwards from `k8s-authz explain` | Diagnostics. |
| Operator 8443 | Prometheus | Operator metrics. |
| Operator 8081 | kubelet | Health probes. |

If you use NetworkPolicy, allow callers to reach the engines on 8181 (after Service translation), the operator to reach engines on 8181 in every control namespace, and the operator to reach its control API and every source API. The Kustomize installation includes a metrics NetworkPolicy under `config/network-policy`, not enabled by default; ingress policies for the engines and the diagnostics port are yours to write.
