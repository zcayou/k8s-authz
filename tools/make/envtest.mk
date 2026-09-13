# Vendored; do not edit — sync via base-image

INTEGRATION_TEST_ENV = KUBEBUILDER_ASSETS="$$("$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)"

test-integration: setup-envtest

##@ Tools

ENVTEST ?= $(LOCALBIN)/setup-envtest-$(HOST_PLATFORM)

# A replace without a tag leaves these empty; set them explicitly if that happens.
ENVTEST_VERSION ?= $(call gomodver,sigs.k8s.io/controller-runtime)
ENVTEST_K8S_VERSION ?= $(shell printf '%s\n' '$(call gomodver,k8s.io/api)' | sed -E 's/^v?[0-9]+\.([0-9]+).*/1.\1/')

.PHONY: envtest
envtest: ## Install setup-envtest.
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Fetch the envtest control-plane binaries.
	@echo "Setting up envtest binaries for Kubernetes $(ENVTEST_K8S_VERSION)..."
	@"$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path || { \
		echo "Error: failed to set up envtest binaries for $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}
