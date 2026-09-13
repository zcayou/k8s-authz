# Security

k8s-authz decides who may do what in the clusters it serves, so its own trust boundaries matter as much as the policy it enforces. This page lays out who can influence decisions and how to lock each path down.

## Who controls what

| Actor | Can change | Protect with |
| --- | --- | --- |
| Writers of `AuthorizationService`s | Which sources and authorities an endpoint uses, which callers it admits, its fallbacks, and the engine pods' spec (including privileged settings) | RBAC on the control namespace; Pod Security Admission in it. |
| Writers of `PolicySource`s | Which APIs and documents feed policy, and whether Rego conditions are allowed | RBAC on the control namespace. |
| Writers of Secrets in the control namespace | Engine serving identity, trusted caller CAs, and source credentials | RBAC on the control namespace. |
| Writers of policy documents in a source | Grants within whatever bounds the documents above them allow | RBAC in each source API, per namespace and kind. |
| Holder of the management key | Everything every engine serves, including Rego code | Secret access in the operator namespace. |
| Holders of caller certificates | Can ask engines for decisions as kube-apiserver would | Your PKI. |

The operator never learns who wrote a document. All of these boundaries are enforced by native Kubernetes RBAC in the APIs that hold the resources.

## A writer layout

A layout that keeps delegation meaningful:

- **Control namespace** (for example `authz-system`): `AuthorizationService`s, `PolicySource`s, TLS Secrets, and source kubeconfigs. Writable only by platform operators.
- **Platform policy namespace** (for example `platform-policies`): authority entry bindings, root `PolicySet`s, prohibitions, and the bounds on every delegation. Writable only by the platform security owners.
- **Team namespaces**, in the control cluster or in remote source APIs: each team's `PolicySet`, bindings, and Policies. Each team may write only the k8s-authz kinds, and native RBAC kinds if its collection includes them, in its own namespaces.

Use the unbound per-kind ClusterRoles the installation ships (`k8s-authz-policy-editor-role`, `k8s-authz-policybinding-editor-role`, and so on) with namespaced RoleBindings to grant teams write access.

Remember that native `RoleBinding`s a `PolicySet` imports are also live RBAC in the API where they're installed. A team that can write RoleBindings in a cluster can grant RBAC there directly, regardless of k8s-authz.

## Delegation boundaries

Within the policy graph, a team can't exceed what it was delegated:

- Every grant is intersected with every bound on its path.
- A delegated `PolicySet` may read only its own source, or the sources its parent binding allows.
- Delegated `PolicySet`s can't hold prohibitions.
- Delegation depth is capped by `maxDepth` and a global limit.
- Principals must match every binding on the path.

These guarantees hold only while teams can't edit the documents that set their bounds. See [Delegation](../concepts/delegation.md).

## Certificates and keys

- **Management certificate.** Engines accept management calls only from the certificate whose Common Name matches their bootstrap identity and whose chain verifies against the management CA alone, with the `clientAuth` usage. Because the operator pushes Rego as well as data, this credential can run code in the engines, and with it make network connections from the engine pods. Keep it in the operator namespace, readable only by the operator.
- **Caller certificates.** An endpoint admits callers by Common Name after verifying the chain against one pool holding both the service's client CA and the management CA. Neither CA may issue a caller's Common Name to anyone else, and the management Common Name must differ from every caller's.
- **Serving certificates.** Callers and the operator verify engines as `authz-<service>.<namespace>.svc` against the serving CA. Keep that CA dedicated to the service, or at least to names you control.
- **Engines hold no credentials** for sources or for the Kubernetes API. They never mount a ServiceAccount token and never see the management private key.

## Source credentials

Source kubeconfigs must be self-contained, use HTTPS with verification, and use no exec plugins or file references. A reader needs only `list` and `watch` on its collection. A broader credential, such as a cluster's admin kubeconfig, works but lets the operator read more than it collects. The operator never falls back to its own identity when a source's credential fails.

## Engine pods

Engines run the stock OPA image pinned by digest, as non-root, with a read-only root filesystem, all capabilities dropped, and the RuntimeDefault seccomp profile. `runtime.podTemplate` can override almost any pod setting, including privileged ones. Anyone who can edit an `AuthorizationService` can run arbitrary pods in its namespace, so apply Pod Security Admission there.

## Rego conditions

Conditions are code that runs in shared engines. They're off unless a source opts in, limited to pure builtins by default, and capped per service by `spec.rego.allowedBuiltins`. A condition can't widen access, but a badly behaved one can hurt availability for every principal the service serves. See [Rego conditions](../guides/rego-conditions.md#risks).

## Diagnostics

The diagnostics endpoint returns the complete installed policy of an engine, which reveals who holds which permissions. It authenticates callers as kube-apiserver does (TokenReview for bearer tokens, the cluster's client CA for certificates), ignores impersonation headers, and authorizes each request with a SubjectAccessReview for `get` on `authorizationservices/diagnostics`. Grant that only to people who need to debug policy. `--export-snapshot` files are written with owner-only permissions; treat them as sensitive.

## Recovery

Recovery identities bypass the webhook entirely, including every prohibition. Keep them few, tightly held, and audited. See [Recovery identities](../guides/connecting-api-servers.md#recovery-identities).
