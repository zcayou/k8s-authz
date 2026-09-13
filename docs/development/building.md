# Building

## Toolchain

The project uses Go 1.26, Kubebuilder 4.16.0, controller-runtime, Kubernetes 0.37 libraries, Ginkgo/Gomega, and stock OPA 1.20.2. Build tools (controller-gen, kustomize, setup-envtest, golangci-lint, OPA, Regal, Kind) are installed on demand into `bin/` as `<tool>-<os>-<arch>`, pinned by the Makefile. `kubectl`, `docker` (with `buildx`), and `helm` come from your `PATH`.

The shared make targets come from the vendored `tools/make/*.mk`, which are synced from a common base and shouldn't be edited here. The `Makefile` adds this repository's generators, test tiers, and tools. `make help` lists every target.

## Common targets

| Task | Command |
| --- | --- |
| Build `bin/manager` and `bin/k8s-authz` | `make build` |
| Regenerate code and manifests after changing API types, markers, or the traversal | `make update` |
| Check formatting, lint, generated-file drift, and the Rego modules, without editing | `make validate` |
| Autofix lint findings | `make lint-fix` |
| Run the manager against your current kubeconfig | `make run RUN_ARGS="--management-cert-path=... --management-ca-path=... --diagnostics-cert-path=..."` |
| Build the manager and CLI images | `make docker-build` |
| Build one image for this machine and load it into Docker | `make docker-build IMG=<name>:<tag>` |
| Render the Kustomize installer to `dist/install.yaml` | `make build-installer IMG=<image>` |
| Install CRDs / deploy the operator to the current cluster | `make install` / `make deploy IMG=<image>` |
| Package the Helm charts into `dist/` | `make helm-package` |

Image builds use `docker buildx bake` (`docker-bake.hcl`) with two targets, `k8s-authz` (the manager) and `k8s-authz-cli`. Base layers come from the public `golang` and `gcr.io/distroless/static` images, which the `BUILDER_IMAGE` and `RUNTIME_IMAGE` build arguments override. Image tags and the charts' image references are named under `REGISTRY`.

## Generated files

`make update` runs every formatter and generator in order:

- **controller-gen** writes `api/v1alpha1/zz_generated.deepcopy.go`, the CRDs in `config/crd/bases/`, and `config/rbac/role.yaml` from the `+kubebuilder:rbac` markers in `internal/controller` and `internal/operator`.
- **controller-gen's applyconfiguration generator** writes the apply configurations under `api/v1alpha1/applyconfiguration`, which the controllers apply status with. It runs through `go run` at the pinned controller-tools version so the generated headers name `controller-gen` on every host.
- **evaluator-gen** (`cmd/evaluator-gen`) writes the unrolled traversal levels in `internal/engine/assets/traversal.rego` from `internal/engine/traversal.go`. The static traversal rules live in `traversal_base.rego`.
- **crd-ref-docs** writes the [generated API reference](../reference/api.md) from the API types.

Never edit generated files by hand. `make generate-check`, part of `make validate`, reruns the generators in an isolated copy of the tree and reports any drift. New generators go into `GENERATE_CMD` in the `Makefile` so both targets run them. The scaffold's `make manifests` and `make generate` run only controller-gen; use `make update`.

RBAC markers reach only `config/rbac/role.yaml`. Mirror permission changes into the `k8s-authz` Helm chart by hand: rules that must hold cluster-wide (policy documents, native RBAC objects, CRDs, TokenReviews, SubjectAccessReviews) go in `templates/clusterrole.yaml`, and the rest in `templates/clusterrole-control.yaml`, which the chart binds only in the control namespaces.

`make helm-crds`, which `make helm-package` runs first, copies the CRDs from `config/crd/bases/` into `deploy/helm/k8s-authz-crds/files/crds/`, which the chart's template renders. That directory is build output and isn't checked in.

## Kubebuilder scaffolding

`PROJECT` belongs to the Kubebuilder CLI; don't edit it by hand. Add new kinds with `kubebuilder create api` so `PROJECT` and the Kustomize configuration stay in sync. If the CLI injects controller setup into `cmd/main.go`, move it into `internal/operator.Setup`. Keep the `// +kubebuilder:scaffold:*` markers in place.

## The CRDs are the schema

The CRDs, generated from the API types, carry every default, enum, bound, list-map key, and CEL rule, and the API server enforces them. The operator decodes live documents strictly and cached ones leniently, and enforces only the rules CEL can't express within its cost budget, reporting them as `Invalid`. Put a validation rule in a CRD marker whenever CEL can express it.
