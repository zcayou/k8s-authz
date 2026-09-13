# k8s-authz

k8s-authz is a Kubernetes operator for declarative, delegated authorization. You write who may do what as Kubernetes resources, and k8s-authz enforces it as an authorization webhook in front of kube-apiserver, served by stock [Open Policy Agent](https://www.openpolicyagent.org/) engines that the operator manages.

It covers what Kubernetes RBAC can't express:

- **Take permissions away.** Prohibitions deny requests no matter what anything else grants, RBAC included. Exclusions subtract from a grant ("everything except Secrets").
- **Delegate safely.** A platform team hands a team a bounded slice of authority. The team manages its own grants inside the slice and can't exceed it, however it writes its policy.
- **Match principals flexibly.** Select users by group prefix, service account namespace, UID, or extra attributes, not just exact names.
- **Reuse what you have.** Import native Roles and ClusterRoles, and include native RoleBindings, under the same bounds and prohibitions.
- **Keep policy anywhere.** Collect policy documents from the local cluster or from other Kubernetes APIs, with a scoped reader for each.
- **Stay up.** Engines keep serving their installed policy through operator and source outages, and installed policy never expires.
- **Explain every decision.** The CLI evaluates a request against the policy an engine actually serves and shows which documents decided it.

Policy is written without code. Rego conditions are available as an opt-in escape hatch for decisions the declarative model can't express.

## How it works

```
 policy documents ──▶ PolicySource ──▶ operator ──compiles & pushes──▶ OPA engines ◀── kube-apiserver
 (any Kubernetes API)                                                  (managed)       (webhook, mTLS)
```

1. **`PolicySource`s** register the Kubernetes APIs that hold policy, and exactly which documents to read from each.
2. **`Policy`**, **`PolicyBinding`**, and **`PolicySet`** documents describe permissions, attach them to principals, and delegate them under bounds.
3. An **`AuthorizationService`** runs a group of engines and defines endpoints. Each endpoint admits specific API servers and evaluates an ordered list of authorities.
4. The operator compiles each service's policy into one snapshot and pushes it to every engine. kube-apiserver calls an endpoint for each request and gets back Allow, Deny, or NoOpinion.

See [Architecture](docs/concepts/architecture.md) for the full picture.

## A taste

A platform team gives team-a everything in its own namespace, delegated so team-a manages the details, and makes sure nobody reads Secrets in `kube-system`:

```yaml
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicySet
metadata:
  namespace: platform-policies
  name: root
spec:
  bindingRefs:
    - name: team-a                      # delegates to team-a's own PolicySet
  prohibitionRefs:
    - name: protect-system-secrets      # denied to everyone, even cluster admins
---
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicyBinding
metadata:
  namespace: platform-policies
  name: team-a
spec:
  subjectMatch: {}
  policyRef:
    kind: PolicySet
    namespace: team-a
    name: team-a
  constraints:
    policyRef:
      name: team-a-bound                # a Policy granting * in namespace team-a
```

Whatever team-a puts in its `PolicySet`, its members get at most namespace `team-a`, and never `kube-system`'s Secrets. [Getting started](docs/getting-started.md) builds this end to end on a Kind cluster.

## Documentation

| | |
| --- | --- |
| **Start here** | [Getting started](docs/getting-started.md) |
| **Concepts** | [Architecture](docs/concepts/architecture.md) · [Policy model](docs/concepts/policy-model.md) · [Delegation](docs/concepts/delegation.md) |
| **Guides** | [Writing policies](docs/guides/writing-policies.md) · [Rego conditions](docs/guides/rego-conditions.md) · [Policy sources](docs/guides/policy-sources.md) · [Connecting API servers](docs/guides/connecting-api-servers.md) · [Engine workloads](docs/guides/engine-workloads.md) · [Validating and explaining](docs/guides/validating-and-explaining.md) |
| **Operations** | [Installation](docs/operations/installation.md) · [Status and troubleshooting](docs/operations/status-and-troubleshooting.md) · [Availability](docs/operations/availability.md) · [Monitoring](docs/operations/monitoring.md) · [Security](docs/operations/security.md) |
| **Reference** | [AuthorizationService](docs/reference/authorizationservice.md) · [PolicySource](docs/reference/policysource.md) · [Policy](docs/reference/policy.md) · [PolicyBinding](docs/reference/policybinding.md) · [PolicySet](docs/reference/policyset.md) · [CLI](docs/reference/cli.md) · [Issue reasons](docs/reference/issue-reasons.md) · [Generated API reference](docs/reference/api.md) |
| **Examples** | [Single cluster](examples/local/README.md) · [Hosted control planes with a remote source](examples/hosted/README.md) · [Conditional delegation for automation](examples/conditional-delegation/README.md) |
| **Development** | [Building](docs/development/building.md) · [Testing](docs/development/testing.md) · [Internals](docs/development/internals.md) |

## The CLI

```sh
k8s-authz validate documents --source authz-system/platform policies.yaml   # check documents offline
k8s-authz validate graph service.yaml --source authz-system/platform=policies.yaml   # compile a service offline
k8s-authz explain demo -n authz-system --endpoint cluster --sar request.json  # explain an installed decision
k8s-authz render-caller-config demo -n authz-system --endpoint cluster ...    # generate kube-apiserver config
```

See the [CLI reference](docs/reference/cli.md).

## Limits of webhook authorization

Kubernetes authorization webhooks see request attributes, not request bodies, so k8s-authz can't distinguish one patch to a Deployment from another; use admission control for that. Broad requests must be granted in full, so a prohibition in one namespace also blocks all-namespace lists of that resource. Sessions that are already open, such as watches and `exec`, aren't cut off by policy changes. See [what the webhook can and cannot see](docs/concepts/architecture.md#what-the-webhook-can-and-cannot-see).

## License

Apache License 2.0. See [LICENSE](LICENSE).
