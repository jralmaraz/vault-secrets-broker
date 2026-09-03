#!/usr/bin/env bash
# Phase 2 — cred-rotation-api setup
# Extends the Vault foundation from Phase 1 with:
#   - internal-mtls-server PKI role (server_flag=true, allow_ip_sans=true)
#   - Verifies the Transit decrypt works for the stored Auth0 config
#
# Prerequisites: scripts/phase1-setup.sh must have completed successfully.
# The .vault-env file must exist and be sourced.
#
# Usage:
#   source .vault-env
#   ./scripts/phase2-setup.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VAULT_BIN="${VAULT_BIN:-/opt/homebrew/bin/vault}"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
info() { echo -e "${CYAN}→${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
fail() { echo -e "${RED}✗${NC} $*" >&2; exit 1; }

[[ -x "$VAULT_BIN" ]] || fail "Vault not found at $VAULT_BIN"
[[ -f "$REPO_ROOT/.vault-env" ]] || fail ".vault-env not found — run phase1-setup.sh first"

source "$REPO_ROOT/.vault-env"
export VAULT_ADDR VAULT_TOKEN

"$VAULT_BIN" status -format=json > /dev/null 2>&1 || fail "Vault is not reachable at $VAULT_ADDR"
ok "Vault reachable at $VAULT_ADDR"

# ── PKI: server certificate role ─────────────────────────────────────────────
info "Adding internal-mtls-server PKI role..."
"$VAULT_BIN" write pki/roles/internal-mtls-server \
  allow_any_name=true \
  allow_ip_sans=true \
  max_ttl=24h \
  key_type=rsa \
  key_bits=2048 \
  client_flag=false \
  server_flag=true

ok "PKI role internal-mtls-server created (server_flag=true, allow_ip_sans=true, max_ttl=24h)"

# ── Verify Transit decrypt for Auth0 config ───────────────────────────────────
info "Verifying Transit decrypt for stored Auth0 adapter config..."
ENCRYPTED=$("$VAULT_BIN" kv get -field=mgmt_client_secret_encrypted \
  secret/cred-rotation-api/adapters/auth0 2>/dev/null) || {
  warn "Could not read Auth0 config from KV — ensure phase1-setup.sh ran successfully"
  ENCRYPTED=""
}

if [[ -n "$ENCRYPTED" ]]; then
  DECRYPTED=$("$VAULT_BIN" write -field=plaintext \
    transit/decrypt/cred-rotation-key \
    ciphertext="$ENCRYPTED" | base64 -d)
  [[ -n "$DECRYPTED" ]] || fail "Transit decrypt returned empty plaintext"
  ok "Transit decrypt verified for Auth0 mgmt_client_secret (${#DECRYPTED} chars)"
fi

# ── Issue a test server cert to verify the role works ─────────────────────────
info "Testing PKI server cert issuance..."
CERT_JSON=$("$VAULT_BIN" write -format=json pki/issue/internal-mtls-server \
  common_name="cred-rotation-api.internal" \
  ttl=1h 2>&1)

echo "$CERT_JSON" | grep -q '"certificate"' || fail "PKI cert issuance failed"
ok "Test server cert issued for cred-rotation-api.internal"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Phase 2 Vault setup complete${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo ""
echo "  New PKI role:   pki/roles/internal-mtls-server"
echo "  Transit key:    cred-rotation-key (decrypt verified)"
echo ""
echo "  To start cred-rotation-api:"
echo "    source .vault-env"
echo "    cd cred-rotation-api"
echo "    go run . "
echo ""
echo -e "${YELLOW}  Next: Phase 3 — vault-rest-engine plugin${NC}"
echo ""
