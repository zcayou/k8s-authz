# AuthorizationService

`authorization.zctx.io/v1alpha1`, namespaced, short name `azsvc`, category `authz`.

An `AuthorizationService` defines one group of engines and the endpoints they serve. Its name must be a DNS label of at most 57 characters, because its owned objects are named `authz-<name>`.

For exact field validation, see the [generated API reference](api.md#authorizationservice).

## Example

```yaml
apiVersion: authorization.zctx.io/v1alpha1
kind: AuthorizationService
metadata:
  namespace: authz-system
  name: demo
spec:
  program:
    type: Kubernetes
  runtime:
    type: Deployment
    deployment:
      replicas: 3
    minReadyReplicas: 2
  listener:
    spec:
      clusterIP: 10.96.0.11
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
        secretKeyRef:
          name: apiserver-client-ca
          key: ca.crt
  endpoints:
    - name: cluster
      callers:
        - commonName: kube-apiserver-authz
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
  rego:
    allowedBuiltins: [concat, startswith]
```

## spec

| Field | Required | Description |
| --- | --- | --- |
| `program.type` | yes | The request integration. `Kubernetes` is the only value: endpoints evaluate `SubjectAccessReview`s. |
| `runtime` | yes | The engine workload. See [runtime](#runtime). |
| `listener` | no | Overrides for the listener Service `authz-<name>`. See [Engine workloads](../guides/engine-workloads.md#the-listener-service). |
| `tls` | yes | Engine serving identity and caller CA. See [tls](#tls). |
| `endpoints` | yes | 1–16 decision routes, keyed by `name`. See [endpoints](#endpoints). |
| `rego.allowedBuiltins` | no | Caps the builtins any Rego condition compiled into this service may call. Omit it for no cap beyond the sources' allowlists. `[]` admits only conditions that call no builtins. Every name must be a builtin this release defines. |

### runtime

| Field | Default | Description |
| --- | --- | --- |
| `type` | | Required. `Deployment` runs `deployment.replicas` engines; `DaemonSet` runs one engine per node the pod template can schedule on. |
| `deployment.replicas` | `2` | Engine replicas when `type` is `Deployment`. Ignored for a DaemonSet. |
| `minReadyReplicas` | `1` | Engines serving current policy that the service keeps through rollouts and disruptions. Sets the PodDisruptionBudget and the `Ready` threshold. With a Deployment, can't exceed `deployment.replicas`. |
| `metadata` | | Labels and annotations for the Deployment or DaemonSet. |
| `podTemplate` | | Strategic-merge overrides for the engine pods. See [Customizing engine pods](../guides/engine-workloads.md#customizing-engine-pods). |

### tls

| Field | Description |
| --- | --- |
| `server.secretRef.name` | A `kubernetes.io/tls` Secret with `tls.crt` and `tls.key`. The certificate must cover `authz-<name>.<namespace>.svc`. Reloaded in place. |
| `server.caRef` | The CA bundle that issues the serving certificate, as `secretKeyRef` or `configMapKeyRef` (`name`, `key`). The operator verifies engines with it. |
| `client.caRef` | The CA bundle that issues every endpoint's callers' certificates, as `secretKeyRef` or `configMapKeyRef`. Reloaded in place. |

All references are to objects in the service's namespace.

### endpoints

| Field | Required | Description |
| --- | --- | --- |
| `name` | yes | A DNS-1035 label, unique in the service. The endpoint's URL path is `/v0/data/authz/endpoints/<name>/decision`. |
| `callers` | yes | 1–16 entries, each with a `commonName` (up to 64 characters) that this endpoint admits. Changes are pushed without restarting engines. |
| `sourceRefs` | yes | 1–64 `PolicySource`s (`namespace`, `name`) that this endpoint's authorities may read. Delegation can narrow this set but never widen it. |
| `authorities` | yes | Up to 64 authorities, evaluated in order. May be `[]`, in which case every request gets NoOpinion. |
| `whenEvaluationFails` | yes | `Deny` or `NoOpinion`: the answer when the endpoint can't evaluate a request. Also the `failurePolicy` that `render-caller-config` writes. Render the caller configuration again after changing it. |

Each authority:

| Field | Required | Description |
| --- | --- | --- |
| `bindingRef` | yes | The entry binding: `kind` (`PolicyBinding` by default, or `RoleBinding`, `ClusterRoleBinding`), `name`, `namespace` for namespaced kinds, and a `sourceRef` that must be one of the endpoint's `sourceRefs`. |
| `whenNoPolicyAllows` | yes | `Deny` or `NoOpinion`: the answer when this authority is selected and nothing grants the request. |

A later authority identical to an earlier one is ignored. See [Policy model](../concepts/policy-model.md) for how authorities are evaluated.

## status

| Field | Description |
| --- | --- |
| `observedGeneration` | The spec generation this status describes. |
| `desiredRevision` | The `sha256:` revision of the policy prepared for the current spec and sources. |
| `desiredReplicas` | Engine pods the workload expects. |
| `readyReplicas` | Ready engine pods, whatever revision they serve. |
| `currentReplicas` | Engine pods serving `desiredRevision` from the current startup configuration. |
| `conditions` | `Prepared`, `Ready`, `PolicyHealthy`. |
| `issues` | Up to 128 attributed diagnostics about the compiled policy. |
| `issuesTruncated` | More issues existed than were recorded. |

See [Status and troubleshooting](../operations/status-and-troubleshooting.md#authorizationservice-status).

## Owned objects

| Kind | Name |
| --- | --- |
| Deployment or DaemonSet | `authz-<name>` |
| Service | `authz-<name>` |
| ConfigMap | `authz-<name>-engine` |
| PodDisruptionBudget | `authz-<name>` |

Engine pods carry the labels `app.kubernetes.io/name: k8s-authz`, `app.kubernetes.io/instance: <name>`, `app.kubernetes.io/component: engine`, `app.kubernetes.io/managed-by: k8s-authz-operator`, and `authorization.zctx.io/service-uid: <uid>`.
