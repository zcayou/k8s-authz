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

test-unit: rego-test
validate: rego-check

.PHONY: test-race
test-race: UNIT_TEST_ARGS += -race
test-race: INTEGRATION_TEST_ARGS += -race
test-race: test ## Run the unit and integration tests with the race detector.

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
