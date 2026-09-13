# k8s-authz documentation

New to k8s-authz? Start with [Getting started](getting-started.md), then read the three concept pages in order.

## Concepts

| Page | What it covers |
| --- | --- |
| [Architecture](concepts/architecture.md) | The operator, sources, engines, and callers; how a request is authorized; how policy reaches the engines. |
| [Policy model](concepts/policy-model.md) | Endpoints and authorities, how a decision is made, coverage, Deny vs NoOpinion, and failure handling. |
| [Delegation](concepts/delegation.md) | `PolicySet`s, bounds, source restrictions, depth limits, prohibitions, and native RBAC. |

## Guides

| Page | What it covers |
| --- | --- |
| [Writing policies](guides/writing-policies.md) | Operation rules, namespace scoping, selectors, exclusions, role imports, and selecting principals. |
| [Rego conditions](guides/rego-conditions.md) | Narrowing a Policy with Rego, enabling conditions on a source, builtin allowlists, and their risks. |
| [Policy sources](guides/policy-sources.md) | Collections, local and remote sources, reader RBAC, credential rotation, and source health. |
| [Connecting API servers](guides/connecting-api-servers.md) | Certificates, listener addresses, `render-caller-config`, recovery identities, and caching. |
| [Engine workloads](guides/engine-workloads.md) | Deployment vs DaemonSet, rollouts, pod template and listener customization. |
| [Validating and explaining](guides/validating-and-explaining.md) | Offline validation and compilation, and explaining installed decisions. |

## Operations

| Page | What it covers |
| --- | --- |
| [Installation](operations/installation.md) | Prerequisites, operator certificates, Kustomize installation, flags, permissions, upgrades. |
| [Status and troubleshooting](operations/status-and-troubleshooting.md) | Conditions, issues, Events, and common problems. |
| [Availability](operations/availability.md) | Behavior through operator, source, and engine failures; remediation; recovery access. |
| [Monitoring](operations/monitoring.md) | What to watch, operator and engine metrics, decision logs, network access. |
| [Security](operations/security.md) | Trust boundaries, writer layout, certificates, and credentials. |

## Reference

| Page | What it covers |
| --- | --- |
| [AuthorizationService](reference/authorizationservice.md) | Fields, status, and owned objects. |
| [PolicySource](reference/policysource.md) | Fields and status. |
| [Policy](reference/policy.md) | Fields, operation rules, imports, and warnings. |
| [PolicyBinding](reference/policybinding.md) | Fields, subject requirements, and constraints. |
| [PolicySet](reference/policyset.md) | Fields. |
| [CLI](reference/cli.md) | Every `k8s-authz` command and flag. |
| [Issue reasons](reference/issue-reasons.md) | Every issue and condition reason. |
| [Generated API reference](reference/api.md) | Field-level API reference generated from the Go types. |

## Examples

- [Single cluster](../examples/local/README.md): platform bounds, administrator and viewer bindings, native RBAC, and subdelegation in one cluster.
- [Hosted control planes](../examples/hosted/README.md): engines on a management cluster serving hosted API servers, with policy read from a remote API.

## Development

- [Building](development/building.md): toolchain, builds, images, charts, and generated files.
- [Testing](development/testing.md): test tiers and what each covers.
- [Internals](development/internals.md): how the code is organized.
