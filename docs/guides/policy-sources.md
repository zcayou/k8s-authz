# Policy sources

A `PolicySource` tells the operator where policy documents live and exactly which of them it may collect. Policy documents are inert until a source collects them and an endpoint reaches them.

## Registering a source

A source reads a Kubernetes API. Without a `kubeconfig`, it reads the operator's own cluster with the operator's own identity:

```yaml
apiVersion: authorization.zctx.io/v1alpha1
kind: PolicySource
metadata:
  namespace: authz-system
  name: platform
spec:
  provider:
    type: Kubernetes
  collection:
    - kinds: [Policy, PolicyBinding, PolicySet]
      namespaces: [platform-policies]
      names: ["*"]
```

`PolicySource`s and `AuthorizationService`s are control resources. Create them in a namespace that only platform operators can write, such as `authz-system`. The operator reconciles every namespace unless it's started with `--control-namespaces`; a `PolicySource` outside those namespaces is never read, and endpoints that reference it treat it as unavailable.

A `PolicySource` name can be at most 63 characters.

## Collections

`collection` lists ranges of documents to read. Each range names kinds, namespaces, and names:

```yaml
collection:
  - kinds: [Policy, PolicyBinding, PolicySet, Role, RoleBinding]
    namespaces: [team-a, team-b]
    names: ["*"]
  - kinds: [ClusterRole]
    names: [workload-reader, view]
```

- `kinds` can be `Policy`, `PolicyBinding`, `PolicySet`, `Role`, `ClusterRole`, `RoleBinding`, and `ClusterRoleBinding`. The kinds in one range must be all namespaced or all cluster-scoped.
- `namespaces` is required for namespaced kinds and forbidden for cluster-scoped ones. `"*"` selects every namespace and must stand alone.
- `names` selects document names. `"*"` selects every name and must stand alone.

A document outside every range is invisible to the source, even if the reader's credential could read it. Keep collections as narrow as the design allows: a collection is the boundary of what a source can contribute, and a reference to anything outside it fails with `MissingReference`.

Narrowing a collection narrows what the source serves right away. Widening it takes effect once the reader has read the new range.

## Local and remote sources

To read another API, or to read the local one with a different identity, provide a kubeconfig in a Secret in the `PolicySource`'s namespace:

```yaml
spec:
  provider:
    type: Kubernetes
    kubernetes:
      kubeconfig:
        secretRef:
          name: teams-api-reader
          key: kubeconfig
```

The kubeconfig's current context is used. It must be self-contained:

- The server must be an `https://` URL, and TLS verification can't be disabled.
- Credentials and CA data must be embedded (`certificate-authority-data`, `client-certificate-data`/`client-key-data`, or `token`). References to files are rejected.
- Exec and auth-provider plugins are rejected.
- A `proxy-url` in the kubeconfig is used. Otherwise, proxies follow the operator's environment.

When a kubeconfig is set, the operator uses only that credential. It never falls back to its own identity if the credential fails.

A remote API needs:

1. The k8s-authz CRDs, from the same release as the operator, if the source collects `Policy`, `PolicyBinding`, or `PolicySet` documents.
2. A reader identity with `list` and `watch` on the collected kinds, in the collected namespaces, and on the CustomResourceDefinitions of the k8s-authz kinds it collects (the reader checks that they serve `v1alpha1`).

It needs no operator and no engines.

### Credentials

The operator reads as whatever identity the kubeconfig carries. A kubeconfig issued with the cluster, such as the one Cluster API writes for each workload cluster, already has these permissions. To limit the operator to exactly the collection, issue a narrower identity yourself.

Store the kubeconfig in the control cluster:

```sh
kubectl -n authz-system create secret generic teams-api-reader --from-file=kubeconfig=teams-reader.kubeconfig
```

A local source without a kubeconfig reads with the operator's own ServiceAccount, which the default installation already allows to read every policy and RBAC document.

## Credential rotation

Rotating the credential is the job of whatever issues it. The operator watches the Secret: updating it replaces the source's reader, and the source keeps serving its current view until the new reader has read everything. Document identity doesn't depend on the credential, so a rotation changes nothing about compiled policy.

Short-lived tokens must be renewed before they expire. If the Secret goes missing or its kubeconfig can't be used, `Synchronized` turns `False` with reason `InvalidCredential`, and the running reader keeps using the credential it already has until the Secret is fixed.

## Source health and staleness

A source's `Synchronized` condition reports its acquisition:

| Reason | Meaning |
| --- | --- |
| `Synchronized` | Every range was read, nothing is failing, and the latest view was admitted. |
| `Pending` | The first complete read hasn't finished. |
| `Paused` | `synchronization` is `Paused`. |
| `InvalidCredential` | The kubeconfig Secret is missing or unusable. |
| `WatchFailing` | A list or watch against the API is failing. |
| `IncompatibleSchema` | A collected k8s-authz CRD on the source API doesn't serve `v1alpha1`. |

In every non-`Synchronized` state, the source keeps serving its **last complete view**. Views never expire: a source that has been unreachable for a week still contributes the documents it last read. Staleness is reported, never enforced. `status.lastAdmittedTime` records when the view last changed or recovered from a failure, so you can alert on it.

Deleting a document, or a document failing validation, is a change like any other: it's compiled with the usual [failure rules](../concepts/policy-model.md#failures). A read failure, by contrast, never removes documents.

The source's `status.issues` lists problems with its documents, such as `Invalid` documents that failed decoding or validation. Issues about how a service uses those documents appear on the `AuthorizationService`.

## Pausing and removing a source

Two independent settings control a source, both defaulting to `Active`:

- `synchronization: Paused` stops reading and keeps serving the last complete view. Use it to freeze a source's policy, for example while its API is being migrated.
- `contribution: Inert` removes the source's documents from compiled policy without stopping its reader. References into the source then fail as references into an unavailable source (`SourceUnavailable`, naming `Inert`). Use it to take a source out of service while keeping it warm.

## The persistent cache

The leader stores each source's view in Secrets of type `authorization.zctx.io/source-cache` in the `PolicySource`'s namespace, named `<policysource>-source-cache-<n>` and owned by the `PolicySource`, so they're deleted with it. When an operator restarts, it restores each source's view from these Secrets before it compiles anything, so a restart never installs policy with a source missing, even if the source API is down or the credential is broken. A cache Secret that is deleted or edited out of band is rewritten. You don't need to manage them.

## Upgrades and schema versions

The operator reads a source's k8s-authz documents only while the source's CRDs serve `v1alpha1`. When upgrading, upgrade the operators before the CRDs on any source, and publish documents that use new fields only after both are upgraded. An operator decodes documents strictly against its own types, so an older operator reading documents with fields a newer schema added reports them `Invalid`. See [Installation](../operations/installation.md#upgrading).
