# Vendored; do not edit — sync via base-image

SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

PKGS ?= ./...
LOCALBIN ?= $(CURDIR)/bin
CLEAN_PATHS ?=

export PATH := $(LOCALBIN):$(PATH)

HOST_GOENV := $(shell go env GOHOSTOS GOHOSTARCH)
HOST_GOOS := $(word 1,$(HOST_GOENV))
HOST_GOARCH := $(word 2,$(HOST_GOENV))
HOST_PLATFORM := $(HOST_GOOS)-$(HOST_GOARCH)
HOST_GO = GOOS=$(HOST_GOOS) GOARCH=$(HOST_GOARCH) go

# go-install-tool DEST PACKAGE VERSION — DEST carries $(HOST_PLATFORM); bin/ may be shared.
define go-install-tool
@set -e; dest="$(1)-$(3)"; \
if [ ! -f "$$dest" ]; then \
	echo "Downloading $(2)@$(3)"; \
	tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	GOBIN="$$tmp" $(HOST_GO) install "$(2)@$(3)"; \
	mkdir -p "$(LOCALBIN)"; \
	mv "$$tmp"/* "$$dest"; \
fi; \
ln -sf "$$dest" "$(1)"
endef

# gomodver MODULE
define gomodver
$(shell go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' $(1) 2>/dev/null)
endef

# go-list PATTERNS [TAGS] — a shell command printing the packages PATTERNS match, sorted.
go-list = $(if $(strip $(1)),go list $(if $(strip $(2)),-tags=$(2)) $(1) | sort,:)

# go-test-tier NAME PATTERNS TAGS SKIP ENV ARGS
define go-test-tier
@set -e; \
pkgs=$$($(call go-list,$(2),$(3))); \
skip=$$($(4)); \
pkgs=$$(comm -23 <(printf '%s\n' "$$pkgs") <(printf '%s\n' "$$skip" | sort)); \
if [ -z "$$pkgs" ]; then echo "No $(1) packages; skipping."; exit 0; fi; \
$(5) go test $(if $(strip $(3)),-tags=$(3)) $$pkgs $(6)
endef

##@ Development

.PHONY: fmt
fmt: ## Format Go sources.
	go fmt $(PKGS)

.PHONY: fmt-check
fmt-check: ## Report Go sources that are not gofmt-clean.
	@files=$$(git ls-files '*.go'); \
	[ -n "$$files" ] || exit 0; \
	unformatted=$$(gofmt -l $$files); \
	if [ -n "$$unformatted" ]; then \
		echo "Go files require formatting:"; \
		printf '%s\n' "$$unformatted" | sed 's/^/  /'; \
		exit 1; \
	fi

.PHONY: vet
vet: ## Run go vet.
	go vet $(PKGS)

.PHONY: lint
lint: golangci-lint ## Run the linter.
	"$(GOLANGCI_LINT)" run $(PKGS)

.PHONY: lint-fix
lint-fix: golangci-lint ## Run the linter and apply fixes.
	"$(GOLANGCI_LINT)" run --fix $(PKGS)

.PHONY: lint-config
lint-config: golangci-lint ## Verify the linter configuration.
	"$(GOLANGCI_LINT)" config verify

.PHONY: vuln-check
vuln-check: ## Report known vulnerabilities in dependencies.
	$(GOVULNCHECK_ENV) $(HOST_GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) $(PKGS)

##@ Build

BINARIES ?=
BINARY_SUFFIX ?=
GOOS ?= $(HOST_GOOS)
GOARCH ?= $(HOST_GOARCH)
CGO_ENABLED ?= 0
BUILD_FLAGS ?= -trimpath -ldflags="-w -s"
GO_BUILD = CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) go build

.PHONY: build
build: ## Build each BINARIES name=dir into LOCALBIN; with none, compile every package.
	@set -e; \
	if [ -z "$(strip $(BINARIES))" ]; then \
		echo "go build $(PKGS)"; $(GO_BUILD) $(PKGS); \
	else \
		mkdir -p "$(LOCALBIN)"; \
		for b in $(BINARIES); do \
			out="$(LOCALBIN)/$${b%%=*}$(BINARY_SUFFIX)"; \
			echo "go build -o $$out $${b#*=}"; \
			$(GO_BUILD) $(BUILD_FLAGS) -o "$$out" "$${b#*=}"; \
		done; \
	fi

##@ Testing

UNIT_PKGS ?= $(PKGS)
INTEGRATION_PKGS ?= $(if $(wildcard test/integration),./test/integration/...)
INTEGRATION_TAGS ?= integration
E2E_PKGS ?= $(if $(wildcard test/e2e),./test/e2e/...)
E2E_TAGS ?= e2e
UNIT_TEST_ARGS ?=
INTEGRATION_TEST_ARGS ?=
E2E_TEST_ARGS ?=
INTEGRATION_TEST_ENV ?=
E2E_TEST_ENV ?=
E2E_TEST_SETUP ?=
E2E_TEST_CLEANUP ?=

.PHONY: test test-unit test-integration test-e2e
test: test-unit test-integration ## Run the unit and integration tests.

test-unit: ## Run UNIT_PKGS, less the integration and e2e packages.
	$(call go-test-tier,unit,$(UNIT_PKGS),,{ $(call go-list,$(INTEGRATION_PKGS),$(INTEGRATION_TAGS)); $(call go-list,$(E2E_PKGS),$(E2E_TAGS)); },,$(UNIT_TEST_ARGS))

test-integration: ## Run INTEGRATION_PKGS, less the e2e packages.
	$(call go-test-tier,integration,$(INTEGRATION_PKGS),$(INTEGRATION_TAGS),$(call go-list,$(E2E_PKGS),$(E2E_TAGS)),$(INTEGRATION_TEST_ENV),$(INTEGRATION_TEST_ARGS))

test-e2e: ## Run E2E_PKGS.
	$(E2E_TEST_SETUP)
	$(call go-test-tier,e2e,$(E2E_PKGS),$(E2E_TAGS),:,$(E2E_TEST_ENV),$(E2E_TEST_ARGS))
	$(E2E_TEST_CLEANUP)

##@ Maintenance

.PHONY: update
update: fmt tidy ## Run every formatter and generator this repository owns.

.PHONY: validate
validate: fmt-check vet lint tidy-check ## Check formatting, analysis, lint and generated-file drift.

.PHONY: tidy
tidy: ## Tidy the Go module.
	go mod tidy

.PHONY: tidy-check
tidy-check: ## Report module metadata that go mod tidy would change.
	go mod tidy -diff

.PHONY: deps
deps: ## Download and tidy module dependencies.
	go mod download
	go mod tidy

.PHONY: clean
clean: ## Remove build and test artifacts.
	rm -rf "$(LOCALBIN)" $(CLEAN_PATHS)
	find . -name '*.test' -type f -delete
	go clean -cache -testcache

##@ Tools

GOVULNCHECK_VERSION ?= latest
GOVULNCHECK_ENV = $(if $(VULN_GO_TOOLCHAIN),GOTOOLCHAIN=$(VULN_GO_TOOLCHAIN))

GOLANGCI_LINT_DIST = $(LOCALBIN)/golangci-lint-$(HOST_PLATFORM)

.PHONY: golangci-lint
golangci-lint: golangci-lint-dist ## Install the linter.

ifneq ($(wildcard .custom-gcl.yml),)

GOLANGCI_LINT ?= $(LOCALBIN)/custom-gcl-$(HOST_PLATFORM)
GOLANGCI_LINT_VERSION ?= $(shell awk -F"[ \"']+" '/^version:/ { print $$2; exit }' .custom-gcl.yml)

golangci-lint: $(GOLANGCI_LINT)
$(GOLANGCI_LINT): .custom-gcl.yml | golangci-lint-dist
	"$(GOLANGCI_LINT_DIST)" custom --destination "$(LOCALBIN)" --name "$(notdir $(GOLANGCI_LINT))"

else

GOLANGCI_LINT ?= $(GOLANGCI_LINT_DIST)
GOLANGCI_LINT_VERSION ?= v2.13.2

endif

.PHONY: golangci-lint-dist
golangci-lint-dist:
	$(call go-install-tool,$(GOLANGCI_LINT_DIST),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

GINKGO ?= $(LOCALBIN)/ginkgo-$(HOST_PLATFORM)
GINKGO_VERSION ?= $(call gomodver,github.com/onsi/ginkgo/v2)

.PHONY: ginkgo
ginkgo: ## Install the Ginkgo CLI matching the module's Ginkgo version.
	$(call go-install-tool,$(GINKGO),github.com/onsi/ginkgo/v2/ginkgo,$(GINKGO_VERSION))
