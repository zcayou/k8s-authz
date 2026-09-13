# Vendored; do not edit — synced via base-image

REGISTRY ?=
export REGISTRY

_REFRESH := $(shell git update-index -q --refresh 2>/dev/null)

SHA     ?= $(shell git rev-parse --short HEAD)
REL     ?= $(shell git describe --exact-match --tags HEAD 2>/dev/null)
DIRTY   ?= $(shell git diff-index --quiet HEAD -- || echo dirty)

BUILD_VERSION ?= $(shell v=$$(git describe --tags --dirty 2>/dev/null) && printf '%s' "$$v" \
             | sed -e 's/^v//' -e 's/-\([0-9][0-9]*\)-g/-\1.g/' \
             || echo '0.0.0-$(shell git rev-list --count HEAD).g$(SHA)$(DIRTY:%=-%)')

HELP_TARGET ?= help

ifneq ($(HELP_TARGET),)
ifeq ($(.DEFAULT_GOAL),)
.DEFAULT_GOAL := $(HELP_TARGET)
endif

##@ General

.PHONY: $(HELP_TARGET)
$(HELP_TARGET): ## Display this help.
	@sed -e 's/$$(IMAGE_TARGET_PREFIX)/$(IMAGE_TARGET_PREFIX)/g' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }'
endif

.PHONY: guard-clean
guard-clean:
	@[ -z "$(DIRTY)" ] || { echo "refusing to publish from a dirty working tree"; exit 1; }
