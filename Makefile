GO           := /opt/homebrew/bin/go
VAULT        := /opt/homebrew/bin/vault
GOLANGCI     := golangci-lint
GOVULNCHECK  := govulncheck

.PHONY: setup setup-phase2 setup-phase3 setup-phase4 stop status \
        build-rest-engine build-auth0-engine build-api build \
        build-plugin-rest-engine build-plugin-auth0-engine \
        test-rest-engine test-auth0-engine test-api test test-integration \
        fmt vet lint vuln hooks install-tools check

# ── Phase 1: Vault foundation ─────────────────────────────────────────────────

setup:
	@chmod +x scripts/phase1-setup.sh scripts/stop-vault.sh
	@./scripts/phase1-setup.sh

stop:
	@./scripts/stop-vault.sh

status:
	@$(VAULT) status 2>/dev/null || echo "Vault is not running. Run: make setup"

# ── Phase 2: cred-rotation-api Vault prerequisites ────────────────────────────

setup-phase2:
	@chmod +x scripts/phase2-setup.sh
	@./scripts/phase2-setup.sh

# ── Phase 3: vault-rest-engine plugin registration ────────────────────────────

setup-phase3:
	@chmod +x scripts/phase3-setup.sh
	@./scripts/phase3-setup.sh

# ── Phase 4: vault-auth0-engine plugin registration ──────────────────────────

setup-phase4:
	@chmod +x scripts/phase4-setup.sh
	@./scripts/phase4-setup.sh

# ── Build ─────────────────────────────────────────────────────────────────────

build-rest-engine:
	cd plugins/vault-rest-engine && $(GO) build ./...

build-auth0-engine:
	cd plugins/vault-auth0-engine && $(GO) build ./...

build-api:
	cd cred-rotation-api && $(GO) build ./...

# Build plugin binary into vault/plugins/ for Vault registration.
build-plugin-rest-engine:
	cd plugins/vault-rest-engine && $(GO) build -o ../../vault/plugins/vault-rest-engine .

build-plugin-auth0-engine:
	cd plugins/vault-auth0-engine && $(GO) build -o ../../vault/plugins/vault-auth0-engine .

build: build-rest-engine build-auth0-engine build-api

# ── Test ──────────────────────────────────────────────────────────────────────

test-rest-engine:
	cd plugins/vault-rest-engine && $(GO) test -race ./...

test-auth0-engine:
	cd plugins/vault-auth0-engine && $(GO) test -race ./...

test-api:
	cd cred-rotation-api && $(GO) test -race ./...

test: test-rest-engine test-auth0-engine test-api

# Integration tests require a running Vault dev server (make setup first).
# Covers: Transit round-trip, KV read, PKI issuance, AppRole auth, JWT/OIDC auth (with self-contained JWKS server).
# SPIFFE/SPIRE auth is validated by unit tests in client_unit_test.go (audience guard) and requires a live SPIRE agent.
test-integration:
	@source .vault-env && cd cred-rotation-api && $(GO) test -tags=integration -race -v ./vault/...

# Run only auth method integration tests (AppRole + JWT).
test-integration-auth:
	@source .vault-env && cd cred-rotation-api && $(GO) test -tags=integration -race -v -run 'TestNew_(AppRole|JWT)' ./vault/...

# ── Hooks — install git hooks that gate on fmt/vet/vuln/lint before push ───────

hooks:
	git config core.hooksPath .githooks
	@echo "Git hooks installed. Pre-push hook runs: gofmt, go vet, govulncheck, golangci-lint"

# install-tools: installs required (govulncheck) and optional (golangci-lint) tools.
# Run once after cloning, then 'make hooks' to activate the pre-push gate.
GOLANGCI_VERSION := v2.13.2

install-tools:
	$(GO) install golang.org/x/vuln/cmd/govulncheck@v1.6.0
	@echo "govulncheck installed."
	@if command -v brew >/dev/null 2>&1; then \
	  brew install golangci-lint; \
	else \
	  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh \
	    | sh -s -- -b $$($(GO) env GOPATH)/bin $(GOLANGCI_VERSION); \
	fi
	@echo "golangci-lint installed."
	@echo "Run 'make hooks' to activate the pre-push gate."

# ── Lint / quality ────────────────────────────────────────────────────────────

fmt:
	gofmt -w plugins/ cred-rotation-api/

vet:
	cd plugins/vault-rest-engine && $(GO) list ./... 2>/dev/null | grep -q . && $(GO) vet ./... || true
	cd plugins/vault-auth0-engine && $(GO) list ./... 2>/dev/null | grep -q . && $(GO) vet ./... || true
	cd cred-rotation-api && $(GO) vet ./...

lint:
	cd plugins/vault-rest-engine && $(GO) list ./... 2>/dev/null | grep -q . && \
	  $(GOLANGCI) run --config $(CURDIR)/.golangci.yml --timeout 5m ./... || true
	cd plugins/vault-auth0-engine && $(GO) list ./... 2>/dev/null | grep -q . && \
	  $(GOLANGCI) run --config $(CURDIR)/.golangci.yml --timeout 5m ./... || true
	cd cred-rotation-api && $(GOLANGCI) run --config $(CURDIR)/.golangci.yml --timeout 5m ./...

vuln:
	cd plugins/vault-rest-engine && $(GO) list ./... 2>/dev/null | grep -q . && \
	  $(GOVULNCHECK) ./... || true
	cd plugins/vault-auth0-engine && $(GO) list ./... 2>/dev/null | grep -q . && \
	  $(GOVULNCHECK) ./... || true
	cd cred-rotation-api && $(GOVULNCHECK) ./...

# check runs all local quality gates (same as pre-push hook, useful in CI too).
check: fmt vet lint vuln
