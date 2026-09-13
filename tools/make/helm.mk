# Vendored; do not edit — sync via base-image
CHART_DIR ?= deploy/helm
HELM ?= helm
ifneq ($(wildcard $(CHART_DIR)),)

##@ Helm Chart

CHARTS ?= $(notdir $(patsubst %/,%,$(dir $(wildcard $(CHART_DIR)/*/Chart.yaml))))
HELM_REGISTRY ?= $(REGISTRY)/$(notdir $(CURDIR))/charts
HELM_OUTPUT_DIR ?= dist
SUBST_VARS ?= REGISTRY
SUBST_FILES ?= Chart.yaml values.yaml
CHART_VERSION ?= $(BUILD_VERSION)
CHART_APP_VERSION ?= $(if $(REL),$(REL),$(CHART_VERSION))
HELM_PACKAGE_ARGS ?= --version $(CHART_VERSION) --app-version $(CHART_APP_VERSION)
CRDS_CHART ?= $(notdir $(CURDIR))-crds
SUBST_FORMAT = $(foreach v,$(SUBST_VARS),$$$(v))

define HELM_RUN
	@set -e; stage=$$(mktemp -d); \
	cp -R "$(CHART_DIR)/." "$$stage/"; \
	charts="$(CHARTS)"; [ -n "$$charts" ] || charts=.; \
	for c in $$charts; do \
		for f in $(SUBST_FILES); do \
			[ -f "$(CHART_DIR)/$$c/$$f" ] || continue; \
			envsubst '$(SUBST_FORMAT)' < "$(CHART_DIR)/$$c/$$f" > "$$stage/$$c/$$f"; \
		done; \
		"$(HELM)" dependency update "$$stage/$$c"; \
		"$(HELM)" lint "$$stage/$$c"; \
		"$(HELM)" package "$$stage/$$c" -d "$$stage" $(HELM_PACKAGE_ARGS); \
	done; \
	$(1); \
	rm -rf "$$stage"
endef

.PHONY: helm-package
helm-package: ## Package the chart(s) locally (no push).
	$(call HELM_RUN,mkdir -p "$(HELM_OUTPUT_DIR)" && cp "$$stage"/*.tgz "$(HELM_OUTPUT_DIR)/")

.PHONY: helm-publish
helm-publish: guard-clean ## Package the chart(s) and push them.
	$(call HELM_RUN,for t in "$$stage"/*.tgz; do "$(HELM)" push "$$t" oci://$(HELM_REGISTRY); done)

ifneq ($(wildcard $(CHART_DIR)/$(CRDS_CHART)/Chart.yaml),)

CRDS_FILES_DIR = $(CHART_DIR)/$(CRDS_CHART)/files/crds

.PHONY: helm-crds
helm-crds: ## Stage the CRDs into the CRDs chart's files/.
	$(if $(CRDS_SOURCE_DIRS),,$(error CRDS_SOURCE_DIRS must name the directories holding the CRDs for $(CRDS_CHART)))
	@set -e; rm -rf "$(CRDS_FILES_DIR)"; mkdir -p "$(CRDS_FILES_DIR)"; cp $(addsuffix /*.yaml,$(CRDS_SOURCE_DIRS)) "$(CRDS_FILES_DIR)/"

helm-package helm-publish: helm-crds

endif

endif
