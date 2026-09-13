# k8s-authz

Kubernetes authorization operator scaffold for `authorization.zctx.io/v1alpha1`.

The repository contains the Kubebuilder manager, six API resource shells, two controller shells, generated manifests, and Ginkgo/Gomega test scaffolding. Resource specifications and authorization behavior are not implemented. The generated samples contain empty specifications and are not application configuration examples.

The application contracts are defined in [DESIGN.md](DESIGN.md) and [IMPLEMENTATION.md](IMPLEMENTATION.md).

Use Kubebuilder v4.16.0 and Go 1.26. Run `make manifests generate` to regenerate CRDs and DeepCopy methods, `make build` to compile the manager, `make test` for the local envtest suite, and `make lint` for lint checks. `make test-e2e` requires a separate, disposable Kind cluster.
