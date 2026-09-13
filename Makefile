TOOL_IMPORTS := go docker helm envtest kubebuilder
include tools/make/*.mk

BINARIES = manager=./cmd k8s-authz=./cmd/k8s-authz
CLEAN_PATHS = dist/ artifacts/
# common is a library chart bundled into k8s-authz, not released on its own.
CHARTS := $(filter-out common,$(CHARTS))

# go run names the binary controller-gen, which the generated files' headers record.
GENERATE_CMD += && rm -rf api/v1alpha1/applyconfiguration \
	&& $(HOST_GO) run sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION) \
	applyconfiguration:headerFile="hack/boilerplate.go.txt" paths="./api/..."
GENERATE_CMD += && $(HOST_GO) run ./cmd/evaluator-gen internal/engine/assets/traversal.rego
GENERATE_CMD += && "$(CRD_REF_DOCS)" --source-path=api/v1alpha1 --config=hack/crd-ref-docs/config.yaml \
	--renderer=markdown --max-depth=100 --output-path=docs/reference/api.md

# Test configuration
INTEGRATION_PKGS = ./test/integration
INTEGRATION_TEST_ENV += OPA_BINARY="$(OPA)"
KIND_CONFIG = test/e2e/kind-config.yaml
KIND_MEMBER_CLUSTER ?= $(notdir $(CURDIR))-member-e2e
KIND_MEMBER_CONFIG = test/e2e/kind-member-config.yaml
E2E_TEST_ENV += CONTAINER_TOOL="$(CONTAINER_TOOL)" KIND_MEMBER_CLUSTER=$(KIND_MEMBER_CLUSTER)
E2E_TEST_ARGS += -timeout 60m

test-integration: opa
regenerate generate-check: crd-ref-docs
test-unit: rego-test
validate: rego-check
setup-test-e2e: setup-test-e2e-apiserver setup-test-e2e-member
cleanup-test-e2e: cleanup-test-e2e-apiserver cleanup-test-e2e-member

.PHONY: test-race
test-race: UNIT_TEST_ARGS += -race
test-race: INTEGRATION_TEST_ARGS += -race
test-race: test ## Run the unit and integration tests with the race detector.

.PHONY: setup-test-e2e-apiserver
setup-test-e2e-apiserver: ## Write the authorization configuration the e2e control plane's API server starts with.
	@mkdir -p tmp/e2e/apiserver
	@cp test/e2e/authorization-config.yaml tmp/e2e/apiserver/authorization-config.yaml

.PHONY: cleanup-test-e2e-apiserver
cleanup-test-e2e-apiserver: ## Remove the files the e2e control plane's API server reads.
	@rm -rf tmp/e2e/apiserver

# The vendored setup-test-e2e matches cluster names by substring, so the member's name must not contain KIND_CLUSTER.
.PHONY: setup-test-e2e-member
setup-test-e2e-member: kind ## Create the e2e member Kind cluster, which serves policy and calls the control cluster's engines.
	@mkdir -p tmp/e2e/member-apiserver
	@cp test/e2e/authorization-config.yaml tmp/e2e/member-apiserver/authorization-config.yaml
	@if "$(KIND)" get clusters | grep -qx "$(KIND_MEMBER_CLUSTER)"; then \
		echo "Kind cluster '$(KIND_MEMBER_CLUSTER)' already exists."; \
	else \
		echo "Creating Kind cluster '$(KIND_MEMBER_CLUSTER)'..."; "$(KIND)" create cluster --name $(KIND_MEMBER_CLUSTER) \
			--config $(KIND_MEMBER_CONFIG) $(if $(KIND_NODE_IMAGE),--image $(KIND_NODE_IMAGE)); \
	fi

.PHONY: cleanup-test-e2e-member
cleanup-test-e2e-member: kind ## Delete the e2e member Kind cluster and the files its API server reads.
	@"$(KIND)" delete cluster --name $(KIND_MEMBER_CLUSTER)
	@rm -rf tmp/e2e/member-apiserver tmp/e2e/member.kubeconfig

REGO_PATHS = internal/engine/assets internal/engine/explain.rego internal/engine/testdata internal/program/assets internal/program/testdata

.PHONY: rego-check
rego-check: opa regal ## Check the Rego modules' formatting, strict compilation and lint.
	"$(OPA)" fmt --list --fail $(REGO_PATHS)
	"$(OPA)" check --strict $(REGO_PATHS)
	"$(REGAL)" lint $(REGO_PATHS)

.PHONY: rego-test
rego-test: opa ## Run the Rego tests.
	"$(OPA)" test $(REGO_PATHS)

##@ Tools

OPA ?= $(LOCALBIN)/opa-$(HOST_PLATFORM)
OPA_VERSION ?= $(call gomodver,github.com/open-policy-agent/opa)

.PHONY: opa
opa: ## Build the OPA CLI matching the module's OPA version.
	$(call go-install-tool,$(OPA),github.com/open-policy-agent/opa,$(OPA_VERSION))

REGAL ?= $(LOCALBIN)/regal-$(HOST_PLATFORM)
REGAL_VERSION ?= v0.42.0

.PHONY: regal
regal: ## Install the Regal Rego linter.
	$(call go-install-tool,$(REGAL),github.com/open-policy-agent/regal,$(REGAL_VERSION))

CRD_REF_DOCS ?= $(LOCALBIN)/crd-ref-docs-$(HOST_PLATFORM)
CRD_REF_DOCS_VERSION ?= v0.3.0

.PHONY: crd-ref-docs
crd-ref-docs: ## Install the CRD API reference generator.
	$(call go-install-tool,$(CRD_REF_DOCS),github.com/elastic/crd-ref-docs,$(CRD_REF_DOCS_VERSION))
