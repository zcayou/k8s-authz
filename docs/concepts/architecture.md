# Architecture

k8s-authz adds a policy-driven authorizer to kube-apiserver. You describe who may do what in Kubernetes resources, the operator compiles those documents into a data snapshot, and a group of stock [Open Policy Agent](https://www.openpolicyagent.org/) (OPA) pods answers kube-apiserver's authorization webhook calls from that snapshot.

This page describes the moving parts and how a request flows through them. The [policy model](policy-model.md) describes how a decision is reached.

## Components

```
                        control cluster
  ┌───────────────────────────────────────────────────────────────┐
  │                                                               │
  │  PolicySource ──reads──▶ policy documents (this or another    │
  │       │                  Kubernetes API)                      │
  │       ▼                                                       │
  │  k8s-authz operator ──compiles──▶ state snapshot              │
  │       │                                │                      │
  │       │ applies Deployment/DaemonSet,  │ pushes over mTLS     │
  │       │ Service, ConfigMap, PDB        ▼                      │
  │       └───────────────────────▶ OPA engine pods               │
  │                                        ▲                      │
  └────────────────────────────────────────┼──────────────────────┘
                                           │ SubjectAccessReview
                                           │ (webhook, mTLS)
                              kube-apiserver(s) being authorized
```

**The operator** runs in the control cluster. It watches `PolicySource` and `AuthorizationService` resources, reads policy documents through the sources, compiles them, and manages the engines. Several replicas can run; they elect a leader through a native Lease. Every replica reads sources and keeps its caches warm, and only the leader compiles, pushes policy, and writes status.

**Engines** are pods running the unmodified upstream OPA image, pinned by digest. The operator creates them as a Deployment or DaemonSet for each `AuthorizationService`, and fronts them with a Service named `authz-<service-name>`. Engines never read Kubernetes or fetch policy on their own: they start with a fixed set of evaluator modules and wait for the operator to push the compiled state to them.

**Policy sources** are Kubernetes APIs that hold policy documents: `Policy`, `PolicyBinding`, and `PolicySet` resources, plus native `Role`, `ClusterRole`, `RoleBinding`, and `ClusterRoleBinding` objects. A source can be the operator's own cluster or any other Kubernetes API the operator can reach with a kubeconfig. A remote source only needs the CRDs installed and read permissions granted; it runs no operator and no engines.

**Callers** are the kube-apiservers whose requests are being authorized. Each calls an engine endpoint over mutual TLS, presenting a client certificate whose Common Name the endpoint admits. A caller can be the control cluster's own API server, the API server of a hosted control plane, or any other kube-apiserver that can reach the engines' Service address.

## The resources

| Resource | Who writes it | What it does |
| --- | --- | --- |
| `AuthorizationService` | Platform operators | Defines a group of engines, their TLS identity, and one or more endpoints. Each endpoint lists the callers it admits, the sources it may read, and its ordered authorities. |
| `PolicySource` | Platform operators | Registers a Kubernetes API and exactly which documents the operator may collect from it. |
| `Policy` | Policy authors | A set of permissions: operations to include, operations to exclude, native roles to import, and optionally a Rego condition. |
| `PolicyBinding` | Policy authors | Attaches principals (users, groups, service accounts, or attribute predicates) to a `Policy`, `PolicySet`, `Role`, or `ClusterRole`, optionally narrowed by constraints. |
| `PolicySet` | Policy authors | Groups bindings into a unit that can be delegated. A root `PolicySet` may also hold prohibitions. |

All five live in the `authorization.zctx.io/v1alpha1` API group and are namespaced. `AuthorizationService` and `PolicySource` are control resources that belong in the cluster running the operator. The three policy document kinds can live in any source.

A policy document does nothing on its own. It takes effect only when a `PolicySource` collects it and an endpoint's authority reaches it through a chain of bindings.

## How a request is authorized

1. A user runs `kubectl get pods -n team-a`. kube-apiserver authenticates them and walks its authorizer chain. The first authorizer is the k8s-authz webhook.
2. kube-apiserver sends a `SubjectAccessReview` to the endpoint's URL on the engine Service: `https://<address>/v0/data/authz/endpoints/<endpoint>/decision`.
3. The engine verifies the caller's client certificate against the service's client CA and checks that its Common Name is one the endpoint admits.
4. The engine normalizes the review into a principal (user, groups, UID, extra) and a request, and evaluates it against the endpoint's authorities using the pushed snapshot. See [the policy model](policy-model.md).
5. The engine responds with one of three results:
   - **Allow**: `allowed: true`. kube-apiserver allows the request.
   - **Deny**: `denied: true`. kube-apiserver rejects the request without asking any later authorizer.
   - **NoOpinion**: neither. kube-apiserver asks the next authorizer in its chain, typically Node and then RBAC.

The response's `reason` field records how the decision was reached, for example `k8s-authz/v1 result=Allow code=PolicyAllowed endpoint=cluster authority=... revision=sha256:...`.

## How policy reaches the engines

1. A `PolicySource` registers an API and a collection. Every operator replica starts a filtered, credential-scoped reader for it and keeps the last complete view of its documents.
2. When a source's view changes, the leader recompiles every `AuthorizationService` whose endpoints read that source. The result is one content-addressed state document per service, identified by a `sha256:` revision.
3. The leader pushes the state directly to each engine pod over mutual TLS, presenting the operator's management certificate. It pushes only to pods that don't already serve that revision.
4. An engine becomes Ready once it serves state compiled for its own service. A new or restarted engine stays unready until the leader pushes to it.

Policy edits, caller changes, and Rego condition edits reach the engines by push, without restarting them. Only changes to how an engine starts (the management identity, the operator release, decision logging) roll the engine pods.

## Failure behavior

k8s-authz is designed so that losing the control plane doesn't change decisions:

- **Operator outage.** Ready engines keep serving their installed policy indefinitely. Policy updates stop until an operator returns. New engines can't become ready without an operator.
- **Source outage.** The operator keeps each source's last complete view and keeps compiling from it. A source that can't be read is reported in its status; its view never expires.
- **Operator restart.** The leader persists each source's view in Secrets, and a restarted operator restores those views before compiling, so a restart never installs policy with a source missing.
- **Engine unreachable.** kube-apiserver applies the webhook's `failurePolicy`, which the rendered caller configuration sets from the endpoint's `whenEvaluationFails`.

[Availability](../operations/availability.md) covers these cases in depth.

## What the webhook can and cannot see

The Kubernetes webhook authorizer receives request attributes, not request bodies. That limits what any webhook authorizer can express:

- It sees the verb, API group, version, resource, subresource, namespace, and name, plus label and field selectors on collection requests. It doesn't see the object being created or the patch being applied, so it can't tell a `kubectl rollout restart` from any other patch to the same Deployment. Use admission control for decisions that depend on content.
- A broad request must be covered in full. A `list secrets` across all namespaces is allowed only if every namespace it could return is allowed, so a prohibition on Secrets in `kube-system` also blocks an all-namespace Secret list.
- Authorization happens when a request starts. Watches, `exec` sessions, and port-forwards that are already running aren't cut off when policy changes.
