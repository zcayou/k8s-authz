# Validating and explaining

The `k8s-authz` CLI checks policy before you apply it and explains decisions after. This guide shows the workflows; [CLI reference](../reference/cli.md) lists every flag.

## Validate documents before applying them

`validate documents` checks each document on its own, with no cluster access:

```sh
k8s-authz validate documents --source authz-system/platform platform/*.yaml
k8s-authz validate documents control.yaml
```

It decodes strictly, so a misspelled field is an error rather than silently dropped. It applies kube-apiserver's metadata rules for each kind and the operator's own semantic checks: operation rules, selectors, subjects, and Rego conditions. Policy and RBAC documents belong to the `PolicySource` that `--source NAMESPACE/NAME` names; `PolicySource` and `AuthorizationService` documents need no `--source`.

It doesn't apply the CRD schemas and their CEL validation rules, which need an API server. Check those with a server-side dry run:

```sh
kubectl apply --server-side --dry-run=server -f platform/
```

Warnings, such as `NamespaceScopeConservative`, are reported without failing the run.

## Compile a service offline

`validate graph` compiles an `AuthorizationService` exactly as the operator would, against sources you assemble from files:

```sh
k8s-authz validate graph control/service.yaml \
  --source authz-system/platform=platform/policies.yaml \
  --source authz-system/platform=platform/bindings.yaml \
  --source authz-system/teams=teams/team-a.yaml
```

- Each `--source NAMESPACE/NAME=FILE` adds a file's documents to a source. Repeat it to add several files to one source. Each source holds exactly the documents you give it.
- `--rego-source NAMESPACE/NAME` lets that source's documents carry Rego conditions with the default builtins, and `--rego-source NAMESPACE/NAME=BUILTIN,...` with exactly the builtins listed.
- Documents with errors are compiled as invalid, as the operator does, so you also see what they break downstream: a `MissingReference` here, an `InvalidDocument` there.

This is the fastest way to review a policy change in CI, because it reports every issue the `AuthorizationService` would show in its status. Nothing needs a status writer or cluster access, so authors of remote sources can run it too.

Both commands exit `0` when valid, `1` when the report contains errors, and `2` when the command itself couldn't run. Add `-o json` for machine-readable output.

## Explain a decision

`explain` evaluates a `SubjectAccessReview` against the policy an engine actually has installed, and reports how it was decided. Write the review as JSON:

```json
{
  "apiVersion": "authorization.k8s.io/v1",
  "kind": "SubjectAccessReview",
  "spec": {
    "user": "alice",
    "groups": ["oidc:team-a-admins", "system:authenticated"],
    "resourceAttributes": {
      "namespace": "team-a",
      "verb": "delete",
      "group": "apps",
      "resource": "deployments",
      "name": "web"
    }
  }
}
```

```sh
k8s-authz explain demo -n authz-system --endpoint cluster --sar request.json
```

```
snapshot exported 2026-09-28T14:03:11Z: Allow (PolicyAllowed) endpoint=cluster authority=authz-system/platform:authorization.zctx.io/PolicyBinding/platform-policies/employees content=sha256:9c1e…
contribution 4be0… effect=Allow path=5
```

The report shows the result and code, the selected authority, and the content revision. It lists the grants (`contribution`) that allowed the request, the prohibitions that denied it, the exclusions that removed parts of a grant, and the issues that forced `whenEvaluationFails`. With `-o json`, each entry includes its full path through the policy graph, from the entry binding to the Policy, and the report includes the normalized principal and whether each Rego condition on the path held.

### Which policy explain reads

Connected `explain` never compiles policy itself. It reads the snapshot installed on one engine pod, through the operator's diagnostics endpoint, and evaluates it with the same evaluator the engine runs. So it explains what the engine is actually serving, even if that differs from the latest compilation.

- Without `--pod`, it reads any ready engine pod of the service. Use `--pod` to inspect a specific one, for example one that behaves differently during a rollout.
- A pod without installed policy is reported as such, and an unreachable pod is an error. `explain` never substitutes the desired policy.
- A snapshot compiled by a different release's evaluator is refused, because only that evaluator can explain it. A pod caught between installing a new conditions module and the state that uses it is refused too; run the command again.

### Save and replay a snapshot

```sh
k8s-authz explain demo -n authz-system --endpoint cluster --sar request.json \
  --export-snapshot installed.json
k8s-authz explain --snapshot installed.json --endpoint cluster --sar other-request.json
```

`--export-snapshot` saves exactly what the diagnostics endpoint returned, with owner-only permissions. Offline `explain` evaluates it with no cluster access, for as many requests as you like. A snapshot doesn't expire. When replaying, conditions that call `http.send`, `net.lookup_ip_addr`, or `opa.runtime` are refused, so a snapshot file never makes the CLI reach out.

### Permissions for connected explain

Connected `explain` reaches the diagnostics endpoint through a port-forward to an operator pod that kube-apiserver opens with your credentials, and then presents the same credentials to the endpoint. You need:

- `get` on the `authorizationservices/diagnostics` subresource of the service. The operator's own role doesn't grant this; grant it to the people who debug policy:

  ```yaml
  apiVersion: rbac.authorization.k8s.io/v1
  kind: Role
  metadata:
    name: demo-diagnostics
    namespace: authz-system
  rules:
    - apiGroups: [authorization.zctx.io]
      resources: [authorizationservices/diagnostics]
      resourceNames: [demo]
      verbs: [get]
  ```

- `list` on Pods and `create` on `pods/portforward` in the operator's namespace (`--operator-namespace`, default `k8s-authz-system`). Also granting `get` on `pods/portforward` lets the tunnel use a websocket; otherwise it falls back to SPDY.
- `list` on Pods in the service's namespace, unless you name a pod with `--pod`.

The diagnostics endpoint authenticates bearer tokens with a TokenReview and client certificates against kube-apiserver's client CA, and ignores impersonation headers. It authorizes every request with a SubjectAccessReview.

## Test decisions through the API server

`explain` shows how the engine decides. To see the result of kube-apiserver's whole authorizer chain, including RBAC after a NoOpinion, submit the same review to kube-apiserver as an administrator:

```sh
kubectl create -f request.json -o jsonpath='{.status}'
```

A recovery identity's own request bypasses the webhook, but the review it submits is evaluated for the user named inside it, through the full chain. The `reason` field shows which authorizer decided.
