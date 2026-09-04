GO           := /opt/homebrew/bin/go
VAULT        := /opt/homebrew/bin/vault
GOLANGCI     := golangci-lint
GOVULNCHECK  := govulncheck

.PHONY: setup setup-phase2 stop status \
        build-rest-engine build-auth0-engine build-api build \
        test-rest-engine test-auth0-engine test-api test test-integration \
        fmt vet lint vuln hooks check

# ── Phase 1: Vault foundation ────────────────────────────────────────────────

setup:
	@chmod +x scripts/phase1-setup.sh scripts/stop-vault.sh
	@./scripts/phase1-setup.sh

# ── Phase 2: cred-rotation-api Vault prerequisites ───────────────────────────

setup-phase2:
	@chmod +x scripts/phase2-setup.sh
	@./scripts/phase2-setup.sh

stop:
	@./scripts/stop-vault.sh

status:
	@$(VAULT) status 2>/dev/null || echo "Vault is not running. Run: make setup"

# ── Build ────────────────────────────────────────────────────────────────────

build-rest-engine:
	cd plugins/vault-rest-engine && $(GO) build ./...

build-auth0-engine:
	cd plugins/vault-auth0-engine && $(GO) build ./...

build-api:
	cd cred-rotation-api && $(GO) build ./...

build: build-rest-engine build-auth0-engine build-api

# ── Test ─────────────────────────────────────────────────────────────────────

test-rest-engine:
	cd plugins/vault-rest-engine && $(GO) test ./...

test-auth0-engine:
	cd plugins/vault-auth0-engine && $(GO) test ./...

test-api:
	cd cred-rotation-api && $(GO) test ./...

test: test-rest-engine test-auth0-engine test-api

test-integration:
	@source .vault-env && cd cred-rotation-api && $(GO) test -tags=integration -race -v ./vault/...

# ── Hooks — install git hooks that gate on fmt/vet/vuln/lint before push ───────

hooks:
	git config core.hooksPath .githooks
	@echo "Git hooks installed. Pre-push hook runs: gofmt, go vet, govulncheck, golangci-lint"

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
