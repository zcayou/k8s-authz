# Vendored; do not edit — sync via base-image
IMG ?= $(REGISTRY)/$(notdir $(CURDIR)):latest
CONTAINER_TOOL ?= docker
IMAGE_TARGET_PREFIX ?= docker

ifneq ($(wildcard docker-bake.hcl Dockerfile),)

##@ Image

.PHONY: $(IMAGE_TARGET_PREFIX)-build $(IMAGE_TARGET_PREFIX)-push
$(IMAGE_TARGET_PREFIX)-build: ## Build image(s). IMG= builds that one image for this machine and loads it.
$(IMAGE_TARGET_PREFIX)-push: ## Push image(s). IMG= pushes that one image.

ifneq ($(wildcard docker-bake.hcl),)

BAKE_TARGET ?=
BAKE_ARGS   ?=
BAKE_TAGS   ?= $(SHA),latest$(REL:%=,%)
BAKE_FILES  ?= tools/docker/bake.hcl docker-bake.hcl
LABEL_VERSION ?= $(BUILD_VERSION)
IMG_BAKE_TARGET ?= $(notdir $(CURDIR))
IMG_PLATFORM ?= $(shell $(CONTAINER_TOOL) version -f '{{.Server.Os}}/{{.Server.Arch}}')

BAKE = TAGS=$(BAKE_TAGS) docker buildx bake $(addprefix -f ,$(BAKE_FILES)) $(BAKE_ARGS) \
       $(if $(LABEL_VERSION),--set '*.labels.org.opencontainers.image.version=$(LABEL_VERSION)')

.PHONY: $(IMAGE_TARGET_PREFIX)-print
$(IMAGE_TARGET_PREFIX)-print: ## Print the resolved bake plan.

ifeq ($(origin IMG),file)

$(IMAGE_TARGET_PREFIX)-build:
	@set -f; $(BAKE) $(BAKE_TARGET)

$(IMAGE_TARGET_PREFIX)-push: guard-clean
	@set -f; $(BAKE) --push $(BAKE_TARGET)

$(IMAGE_TARGET_PREFIX)-print:
	@set -f; $(BAKE) --print $(BAKE_TARGET)

else

BAKE_IMG = $(BAKE) --set '$(IMG_BAKE_TARGET).tags=$(IMG)' --set '$(IMG_BAKE_TARGET).platform=$(IMG_PLATFORM)'

$(IMAGE_TARGET_PREFIX)-build:
	@set -f; $(BAKE_IMG) --load $(IMG_BAKE_TARGET)

$(IMAGE_TARGET_PREFIX)-push:
	$(CONTAINER_TOOL) push "$(IMG)"

$(IMAGE_TARGET_PREFIX)-print:
	@set -f; $(BAKE_IMG) --print $(IMG_BAKE_TARGET)

endif

else

$(IMAGE_TARGET_PREFIX)-build:
	$(CONTAINER_TOOL) build --build-arg REGISTRY=$(REGISTRY) -t "$(IMG)" .

$(IMAGE_TARGET_PREFIX)-push:
	$(CONTAINER_TOOL) push "$(IMG)"

endif

endif
