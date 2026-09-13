# CLI reference

The `k8s-authz` command validates policy offline, explains installed decisions, and renders kube-apiserver caller configuration. Build it with `make build` (the binary lands in `bin/k8s-authz`), or run the `k8s-authz-cli` image.

```
k8s-authz validate documents FILE...
k8s-authz validate graph SERVICE_FILE --source NAMESPACE/NAME=FILE...
k8s-authz explain (NAME [--pod POD] | --snapshot FILE) --endpoint ENDPOINT --sar FILE
k8s-authz render-caller-config (NAME | --service-file FILE) --endpoint ENDPOINT --webhook-server URL ...
```

Every file argument accepts `-` for standard input, used at most once per command. Commands that read the cluster take kubectl's connection flags: `--kubeconfig`, `--context`, `--cluster`, `--user`, `-n`/`--namespace`, `--token`, `--as`, `--as-group`, `--server`, `--certificate-authority`, and the rest.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. For `validate`, no errors (warnings are allowed). |
| `1` | `validate` found errors. The report explains them. |
| `2` | The command couldn't run. The error is printed to standard error. |

## validate documents

```
k8s-authz validate documents [--source NAMESPACE/NAME] [-o text|json] FILE...
```

Validates each document in the files without network access: strict decoding, kube-apiserver's metadata rules for the kind, and the operator's semantic rules. It doesn't apply the CRD schemas' CEL rules; use `kubectl apply --dry-run=server` for those.

| Flag | Description |
| --- | --- |
| `--source` | The `PolicySource` that every `Policy`, `PolicyBinding`, `PolicySet`, and RBAC document belongs to. Required when the files hold any of them. |
| `-o`, `--output` | `text` (default) or `json`. |

Text output starts with `valid: N document(s)` or `invalid: N document(s)` and then prints one line per diagnostic: `FILE:DOCUMENT: SEVERITY REASON: MESSAGE`.

## validate graph

```
k8s-authz validate graph SERVICE_FILE --source NAMESPACE/NAME=FILE... [--rego-source NAMESPACE/NAME[=BUILTIN,...]]... [-o text|json]
```

Compiles the one `AuthorizationService` in `SERVICE_FILE` as the operator would, against sources made of exactly the documents in their files, and reports document and graph issues.

| Flag | Description |
| --- | --- |
| `--source` | `NAMESPACE/NAME=FILE`. Adds the file's documents to that source. Repeatable, including for the same source. |
| `--rego-source` | `NAMESPACE/NAME` allows that source's documents to carry Rego conditions with the default builtins; `NAMESPACE/NAME=BUILTIN,...` allows exactly the listed builtins. The source must also be given with `--source`. Repeatable. |
| `-o`, `--output` | `text` (default) or `json`. |

## explain

```
k8s-authz explain NAME --endpoint ENDPOINT --sar FILE [--pod POD] [--operator-namespace NS] [--export-snapshot FILE] [-o text|json]
k8s-authz explain --snapshot FILE --endpoint ENDPOINT --sar FILE [-o text|json]
```

Evaluates a `SubjectAccessReview` against the snapshot installed on an engine pod of the `AuthorizationService` `NAME`, read through the operator's diagnostics endpoint, or against a saved snapshot.

| Flag | Description |
| --- | --- |
| `--endpoint` | Required. The endpoint to evaluate. |
| `--sar` | Required. A `SubjectAccessReview` in JSON. |
| `--pod` | The engine pod to read. Defaults to any ready engine pod of the service. |
| `--operator-namespace` | The namespace the operator runs in. Default `k8s-authz-system`. |
| `--export-snapshot` | Save the snapshot read from the cluster to this file, with owner-only permissions. |
| `--snapshot` | Evaluate a saved snapshot instead of reading the cluster. Excludes `NAME`, `--pod`, and `--operator-namespace`. |
| `-o`, `--output` | `text` (default) or `json`. |

The JSON report includes `result`, `reason`, `code`, `evaluationError`, the selected `authority` and its `root`, the `contentRevision`, the normalized `principal`, the `contributions`, `prohibitions`, and `exclusions` that bear on the decision (each with its `path`), the `issues` that forced a failure, and `conditions`, mapping each Rego condition on the path to whether it held.

See [Validating and explaining](../guides/validating-and-explaining.md#permissions-for-connected-explain) for the permissions connected `explain` needs.

## render-caller-config

```
k8s-authz render-caller-config NAME --endpoint ENDPOINT --webhook-server URL \
  --caller-certificate PATH --caller-key PATH --engine-ca PATH --webhook-kubeconfig-path PATH \
  [--recovery-user USER]... [--recovery-group GROUP]... \
  [--authorized-ttl DURATION] [--unauthorized-ttl DURATION] [--output-dir DIR]
k8s-authz render-caller-config --service-file FILE --endpoint ENDPOINT ...
```

Writes the webhook kubeconfig and `AuthorizationConfiguration` with which kube-apiserver calls one endpoint.

| Flag | Description |
| --- | --- |
| `--endpoint` | Required. The endpoint to call. |
| `--webhook-server` | Required. `https://host[:port]`, with no path, query, or credentials, at which kube-apiserver reaches the listener. |
| `--caller-certificate`, `--caller-key` | Required. Absolute paths, in kube-apiserver's filesystem, to the client certificate and key it presents. |
| `--engine-ca` | Required. Absolute path, in kube-apiserver's filesystem, to the CA bundle that verifies the engines. |
| `--webhook-kubeconfig-path` | Required. Absolute path, in kube-apiserver's filesystem, where `webhook.kubeconfig` will be installed. |
| `--recovery-user`, `--recovery-group` | Identities excluded from the webhook by match conditions. Repeatable; up to 64 in total. |
| `--authorized-ttl` | How long kube-apiserver caches Allow decisions. Default `5m`; `0` disables the cache. |
| `--unauthorized-ttl` | How long kube-apiserver caches Deny and NoOpinion decisions. Default `30s`; `0` disables the cache. |
| `--service-file` | Read the `AuthorizationService` from a file instead of the cluster. Excludes `NAME` and the connection flags. |
| `--output-dir` | Write `webhook.kubeconfig` (mode `0600`) and `authorization-config.yaml` here. Without it, both are written to standard output, separated by `---`. |

See [Connecting API servers](../guides/connecting-api-servers.md).
