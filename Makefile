TOOL_IMPORTS := go docker helm envtest kubebuilder
include tools/make/*.mk

CLEAN_PATHS = dist/ artifacts/

# go run names the binary controller-gen, which the generated files' headers record.
GENERATE_CMD += && rm -rf api/v1alpha1/applyconfiguration \
	&& $(HOST_GO) run sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION) \
	applyconfiguration:headerFile="hack/boilerplate.go.txt" paths="./api/..."

.PHONY: test-race
test-race: UNIT_TEST_ARGS += -race
test-race: INTEGRATION_TEST_ARGS += -race
test-race: test ## Run the unit and integration tests with the race detector.
