GO := /opt/homebrew/bin/go
VAULT := /opt/homebrew/bin/vault

.PHONY: setup stop status \
        build-rest-engine build-auth0-engine build-api build \
        test-rest-engine test-auth0-engine test-api test \
        fmt vet

# ── Phase 1: Vault foundation ────────────────────────────────────────────────

setup:
	@chmod +x scripts/phase1-setup.sh scripts/stop-vault.sh
	@./scripts/phase1-setup.sh

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

# ── Lint ─────────────────────────────────────────────────────────────────────

fmt:
	cd plugins/vault-rest-engine && $(GO) fmt ./...
	cd plugins/vault-auth0-engine && $(GO) fmt ./...
	cd cred-rotation-api && $(GO) fmt ./...

vet:
	cd plugins/vault-rest-engine && $(GO) vet ./...
	cd plugins/vault-auth0-engine && $(GO) vet ./...
	cd cred-rotation-api && $(GO) vet ./...
