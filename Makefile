TOOL_IMPORTS := go docker helm envtest kubebuilder
include tools/make/*.mk

CLEAN_PATHS = dist/ artifacts/

.PHONY: test-race
test-race: UNIT_TEST_ARGS += -race
test-race: INTEGRATION_TEST_ARGS += -race
test-race: test ## Run the unit and integration tests with the race detector.
