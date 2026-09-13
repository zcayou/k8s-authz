# Vendored; do not edit — sync via base-image

YEAR ?= $(shell date +%Y)
KIND_CLUSTER ?= $(notdir $(CURDIR))-test-e2e
RUN_PKG ?= ./cmd
CRDS_SOURCE_DIR ?= config/crd/bases
CRDS_SOURCE_DIRS ?= $(CRDS_SOURCE_DIR)

BINARIES = $(if $(wildcard cmd/main.go),manager=./cmd)
INTEGRATION_PKGS += $(addprefix ./,$(addsuffix /...,$(wildcard internal/controller internal/webhook)))
E2E_TEST_ENV = KIND="$(KIND)" KIND_CLUSTER=$(KIND_CLUSTER)
E2E_TEST_ARGS = -v -ginkgo.v
E2E_TEST_SETUP = $(MAKE) setup-test-e2e
E2E_TEST_CLEANUP = $(MAKE) cleanup-test-e2e

ifndef ignore-not-found
  ignore-not-found = false
endif

CONTROLLER_GEN_OBJECT = "$(CONTROLLER_GEN)" object:headerFile="hack/boilerplate.go.txt",year=$(YEAR) paths="./..."
CONTROLLER_GEN_CRD = "$(CONTROLLER_GEN)" rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=$(CRDS_SOURCE_DIR)

GENERATE_CMD = $(CONTROLLER_GEN_OBJECT) && $(CONTROLLER_GEN_CRD)

# staged-drift COMMAND — report what COMMAND would change, without changing it.
define staged-drift
@set -e; stage=$$(mktemp -d); report=$$(mktemp); \
trap 'rm -rf "$$stage" "$$report"' EXIT; \
git ls-files -z --cached --others --exclude-standard | while IFS= read -r -d '' f; do \
	if [ -e "$$f" ]; then printf '%s\0' "$$f"; fi; \
done | tar --null -T - -cf - | tar xf - -C "$$stage"; \
( cd "$$stage" && $(1) ); \
while IFS= read -r f; do \
	if [ ! -e "$$f" ] || ! cmp -s "$$f" "$$stage/$$f"; then \
		printf '%s\n' "$$f" >> "$$report"; \
	fi; \
done < <( cd "$$stage" && find . -type f | sed 's|^\./||' ); \
if [ -s "$$report" ]; then \
	echo "generated files are stale; run 'make update':"; \
	sort "$$report" | sed 's/^/  /'; \
	exit 1; \
fi
endef

# kustomize-render SINK — edits a copy, so the checked-in kustomization is left alone.
define kustomize-render
@set -e; stage=$$(mktemp -d); trap 'rm -rf "$$stage"' EXIT; \
cp -R config "$$stage/config"; \
( cd "$$stage/config/manager" && "$(KUSTOMIZE)" edit set image controller="$(IMG)" ); \
"$(KUSTOMIZE)" build "$$stage/config/default" $(1)
endef

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate CRD, RBAC and webhook manifests.
	$(CONTROLLER_GEN_CRD)

.PHONY: generate
generate: controller-gen ## Generate DeepCopy implementations.
	$(CONTROLLER_GEN_OBJECT)

.PHONY: regenerate
regenerate: controller-gen ## Run every generator this repository owns.
	@set -e; $(GENERATE_CMD)

.PHONY: generate-check
generate-check: controller-gen ## Report drift in generated output.
	$(call staged-drift,$(GENERATE_CMD))

update: regenerate
validate: generate-check

.PHONY: run
run: regenerate fmt vet ## Run the controller from this host.
	$(HOST_GO) run $(RUN_PKG) $(RUN_ARGS)

##@ Testing

test-e2e: regenerate kind

.PHONY: setup-test-e2e
setup-test-e2e: kind ## Create the e2e Kind cluster if it does not exist.
	@case "$$("$(KIND)" get clusters)" in \
		*"$(KIND_CLUSTER)"*) echo "Kind cluster '$(KIND_CLUSTER)' already exists." ;; \
		*) echo "Creating Kind cluster '$(KIND_CLUSTER)'..."; "$(KIND)" create cluster --name $(KIND_CLUSTER) \
			$(if $(KIND_CONFIG),--config $(KIND_CONFIG)) $(if $(KIND_NODE_IMAGE),--image $(KIND_NODE_IMAGE)) ;; \
	esac
	@"$(KIND)" export kubeconfig --name $(KIND_CLUSTER)

.PHONY: cleanup-test-e2e
cleanup-test-e2e: kind ## Delete the e2e Kind cluster.
	@"$(KIND)" delete cluster --name $(KIND_CLUSTER)

##@ Deployment

.PHONY: install
install: regenerate kustomize ## Install CRDs into the cluster named by the current kubeconfig.
	@out=$$("$(KUSTOMIZE)" build config/crd 2>/dev/null || true); \
	if [ -n "$$out" ]; then printf '%s\n' "$$out" | "$(KUBECTL)" apply --server-side -f -; \
	else echo "No CRDs to install; skipping."; fi

.PHONY: uninstall
uninstall: kustomize ## Remove CRDs from the cluster. Set ignore-not-found=true to tolerate absence.
	@out=$$("$(KUSTOMIZE)" build config/crd 2>/dev/null || true); \
	if [ -n "$$out" ]; then printf '%s\n' "$$out" | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -; \
	else echo "No CRDs to delete; skipping."; fi

.PHONY: deploy
deploy: regenerate kustomize ## Deploy the controller to the cluster named by the current kubeconfig.
	$(call kustomize-render,| "$(KUBECTL)" apply --server-side -f -)

.PHONY: undeploy
undeploy: kustomize ## Remove the controller. Set ignore-not-found=true to tolerate absence.
	"$(KUSTOMIZE)" build config/default | "$(KUBECTL)" delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: build-installer
build-installer: kustomize ## Write a consolidated installer to dist/install.yaml.
	@mkdir -p dist
	$(call kustomize-render,> dist/install.yaml)

##@ Tools

KUBECTL ?= kubectl
KIND ?= $(LOCALBIN)/kind-$(HOST_PLATFORM)
KUSTOMIZE ?= $(LOCALBIN)/kustomize-$(HOST_PLATFORM)
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen-$(HOST_PLATFORM)

KUSTOMIZE_VERSION ?= v5.8.1
CONTROLLER_TOOLS_VERSION ?= v0.22.0
KIND_VERSION ?= v0.32.0

.PHONY: kustomize
kustomize: ## Install kustomize.
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: ## Install controller-gen.
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: kind
kind: ## Install kind.
	$(call go-install-tool,$(KIND),sigs.k8s.io/kind,$(KIND_VERSION))
