# Makefile — build/test/lint facade for pveforge.
#
# This project's real tooling is plain Go (go build, go test, gofmt, go
# vet) — no separate build system to wrap. This facade exists so every
# common task has one name regardless of which tool implements it
# underneath, and so `make` alone is always safe to run (see
# .DEFAULT_GOAL below): it never builds, tests, or installs anything on
# its own.
.DEFAULT_GOAL := help

BINARY  := pveforge
BIN_DIR := bin
PREFIX  ?= $(HOME)/.local

# The actual Go source tree — used to scope gofmt so it never walks
# .git/.claude/.grok/.vibe-palace (gofmt does NOT skip dot-directories on
# its own, confirmed: `gofmt -l .` at the repo root would otherwise
# recurse into all of them for no benefit).
GO_DIRS := cmd internal

##@ General

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)
	@echo ""
	@echo "Quick start:  make build && make test"

##@ Build

.PHONY: build
build: ## Build the pveforge binary into bin/
	go build -o $(BIN_DIR)/$(BINARY) ./cmd/pveforge

##@ Test

.PHONY: test
test: ## Run unit tests (race detector + coverage — this project's standing verification bar)
	go test ./... -race -cover -count=1

.PHONY: integration
integration: ## Run integration-tagged tests (none exist yet — this project's live-host verification has so far been manual, ad-hoc SSH probes against a real PVE cluster, never wired into `go test`; kept as a placeholder so a future -tags=integration test file needs no Makefile change)
	@if [ -z "$$(grep -rl --include='*.go' 'go:build integration\|+build integration' $(GO_DIRS) 2>/dev/null)" ]; then \
		echo "no integration-tagged tests exist yet"; \
	else \
		go test -tags=integration ./...; \
	fi

##@ Lint

.PHONY: lint
lint: ## Check formatting (gofmt) and run static analysis (go vet) — read-only, fails on any issue
	@fmtfiles="$$(gofmt -l $(GO_DIRS))"; \
	if [ -n "$$fmtfiles" ]; then \
		echo "gofmt: the following files need formatting (run 'make fmt'):"; \
		echo "$$fmtfiles"; \
		exit 1; \
	fi
	go vet ./...

.PHONY: fmt
fmt: ## Reformat all Go source files in place (gofmt -w)
	gofmt -w $(GO_DIRS)

##@ Install

# -Dm755 relies on GNU coreutils' install (the -D flag that creates
# leading directories is a GNU extension, absent from BSD/macOS's native
# install) — accepted, not fixed: this project's realistic deployment
# target is Linux, matching the PVE hypervisor hosts it manages.
.PHONY: install
install: build ## Build and install to PREFIX (default: ~/.local)
	install -Dm755 $(BIN_DIR)/$(BINARY) $(PREFIX)/bin/$(BINARY)

##@ Clean

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)
