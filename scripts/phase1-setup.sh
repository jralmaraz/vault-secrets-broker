#!/usr/bin/env bash
# Phase 1 — Vault Foundation Setup
# Starts a Vault dev server and configures:
#   PKI engine  — internal CA for mTLS certificates
#   Transit     — envelope encryption key for credential values
#   AppRole     — identity for cred-rotation-api
#   KV v2       — encrypted adapter config storage
#
# Usage:
#   cp .env.example .env && vim .env   # fill in real values
#   ./scripts/phase1-setup.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VAULT_BIN="${VAULT_BIN:-/opt/homebrew/bin/vault}"
VAULT_DEV_ROOT_TOKEN="dev-root-token"
VAULT_DEV_ADDR="http://127.0.0.1:8200"
PLUGIN_DIR="$REPO_ROOT/vault/plugins"
PID_FILE="$REPO_ROOT/vault/vault-dev.pid"
ENV_OUT="$REPO_ROOT/.vault-env"

# ── Colour helpers ────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
info() { echo -e "${CYAN}→${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
fail() { echo -e "${RED}✗${NC} $*" >&2; exit 1; }

# ── Prerequisites ─────────────────────────────────────────────────────────────
[[ -x "$VAULT_BIN" ]] || fail "Vault not found at $VAULT_BIN. Run: brew install hashicorp/tap/vault"
[[ -f "$REPO_ROOT/.env" ]] || fail ".env not found. Copy .env.example → .env and fill in values."

source "$REPO_ROOT/.env"
: "${AUTH0_DOMAIN:?AUTH0_DOMAIN not set in .env}"
: "${AUTH0_MGMT_CLIENT_ID:?AUTH0_MGMT_CLIENT_ID not set in .env}"
: "${AUTH0_MGMT_CLIENT_SECRET:?AUTH0_MGMT_CLIENT_SECRET not set in .env}"
: "${AUTH0_MGMT_AUDIENCE:?AUTH0_MGMT_AUDIENCE not set in .env}"
: "${AUTH0_TEST_APP_CLIENT_ID:?AUTH0_TEST_APP_CLIENT_ID not set in .env}"

mkdir -p "$PLUGIN_DIR"

# ── Start Vault dev server ────────────────────────────────────────────────────
if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  warn "Vault dev server already running (PID $(cat "$PID_FILE")). Skipping start."
else
  info "Starting Vault dev server..."
  "$VAULT_BIN" server \
    -dev \
    -dev-root-token-id="$VAULT_DEV_ROOT_TOKEN" \
    -dev-plugin-dir="$PLUGIN_DIR" \
    -log-level=warn \
    > "$REPO_ROOT/vault/vault-dev.log" 2>&1 &
  echo $! > "$PID_FILE"
  sleep 2
  kill -0 "$(cat "$PID_FILE")" 2>/dev/null || fail "Vault failed to start. Check vault/vault-dev.log"
  ok "Vault dev server started (PID $(cat "$PID_FILE"))"
fi

export VAULT_ADDR="$VAULT_DEV_ADDR"
export VAULT_TOKEN="$VAULT_DEV_ROOT_TOKEN"

# Wait for Vault to be ready
for i in {1..10}; do
  "$VAULT_BIN" status -format=json > /dev/null 2>&1 && break
  sleep 1
done
"$VAULT_BIN" status -format=json > /dev/null 2>&1 || fail "Vault is not responding at $VAULT_ADDR"
ok "Vault is ready at $VAULT_ADDR"

# ── PKI Engine — internal CA ─────────────────────────────────────────────────
info "Configuring PKI engine..."
if "$VAULT_BIN" secrets list -format=json | grep -q '"pki/"'; then
  warn "PKI already enabled — skipping."
else
  "$VAULT_BIN" secrets enable pki
  "$VAULT_BIN" secrets tune -max-lease-ttl=87600h pki

  # Generate internal root CA
  "$VAULT_BIN" write -field=certificate pki/root/generate/internal \
    common_name="vault-secrets-broker Internal CA" \
    organization="vault-secrets-broker PoC" \
    ttl=87600h \
    key_type=rsa \
    key_bits=4096 \
    > "$REPO_ROOT/vault/certs/internal-ca.crt" 2>/dev/null || {
      mkdir -p "$REPO_ROOT/vault/certs"
      "$VAULT_BIN" write -field=certificate pki/root/generate/internal \
        common_name="vault-secrets-broker Internal CA" \
        organization="vault-secrets-broker PoC" \
        ttl=87600h \
        key_type=rsa \
        key_bits=4096 \
        > "$REPO_ROOT/vault/certs/internal-ca.crt"
    }

  "$VAULT_BIN" write pki/config/urls \
    issuing_certificates="$VAULT_ADDR/v1/pki/ca" \
    crl_distribution_points="$VAULT_ADDR/v1/pki/crl"

  # Intermediate role for issuing plugin mTLS client certs
  "$VAULT_BIN" write pki/roles/internal-mtls-client \
    allow_any_name=true \
    max_ttl=720h \
    key_type=rsa \
    key_bits=2048 \
    client_flag=true \
    server_flag=false

  ok "PKI engine configured — internal CA created, client cert role ready"
fi

# ── Transit Engine ────────────────────────────────────────────────────────────
info "Configuring Transit engine..."
if "$VAULT_BIN" secrets list -format=json | grep -q '"transit/"'; then
  warn "Transit already enabled — skipping."
else
  "$VAULT_BIN" secrets enable transit

  # AES-256-GCM key with envelope encryption support (Vault 2.x default)
  "$VAULT_BIN" write transit/keys/cred-rotation-key \
    type=aes256-gcm96 \
    derived=false \
    exportable=false \
    allow_plaintext_backup=false

  ok "Transit engine configured — cred-rotation-key created (aes256-gcm96, non-exportable)"
fi

# ── KV v2 ─────────────────────────────────────────────────────────────────────
info "Configuring KV v2..."
if "$VAULT_BIN" secrets list -format=json | grep -q '"secret/"'; then
  warn "KV v2 already enabled at secret/ — skipping."
else
  "$VAULT_BIN" secrets enable -version=2 -path=secret kv
  ok "KV v2 enabled at secret/"
fi

# ── Transit-encrypt Auth0 mgmt secret, store in KV ───────────────────────────
info "Storing Transit-encrypted Auth0 adapter config in KV..."

# Encrypt the management client_secret with Transit before storing
AUTH0_SECRET_PLAINTEXT_B64=$(printf '%s' "$AUTH0_MGMT_CLIENT_SECRET" | base64)
AUTH0_SECRET_CIPHERTEXT=$("$VAULT_BIN" write -field=ciphertext \
  transit/encrypt/cred-rotation-key \
  plaintext="$AUTH0_SECRET_PLAINTEXT_B64")

# Store the encrypted config blob in KV — plaintext secret is NOT stored
"$VAULT_BIN" kv put secret/cred-rotation-api/adapters/auth0 \
  domain="$AUTH0_DOMAIN" \
  mgmt_client_id="$AUTH0_MGMT_CLIENT_ID" \
  mgmt_client_secret_encrypted="$AUTH0_SECRET_CIPHERTEXT" \
  mgmt_audience="$AUTH0_MGMT_AUDIENCE" \
  test_app_client_id="$AUTH0_TEST_APP_CLIENT_ID"

ok "Auth0 adapter config stored — client_secret is Transit-encrypted at rest"

# ── Policies ──────────────────────────────────────────────────────────────────
info "Writing Vault policies..."
"$VAULT_BIN" policy write cred-rotation-api-policy \
  "$REPO_ROOT/vault/policies/cred-rotation-api.hcl"
"$VAULT_BIN" policy write vault-plugin-policy \
  "$REPO_ROOT/vault/policies/vault-plugin.hcl"
ok "Policies written: cred-rotation-api-policy, vault-plugin-policy"

# ── AppRole auth ──────────────────────────────────────────────────────────────
info "Configuring AppRole auth..."
if "$VAULT_BIN" auth list -format=json | grep -q '"approle/"'; then
  warn "AppRole already enabled — skipping enable, updating role."
else
  "$VAULT_BIN" auth enable approle
fi

"$VAULT_BIN" write auth/approle/role/cred-rotation-api \
  token_ttl=1h \
  token_max_ttl=4h \
  token_policies="cred-rotation-api-policy" \
  token_bound_cidrs="127.0.0.1/32"

ROLE_ID=$("$VAULT_BIN" read -field=role_id auth/approle/role/cred-rotation-api/role-id)
SECRET_ID=$("$VAULT_BIN" write -f -field=secret_id auth/approle/role/cred-rotation-api/secret-id)
ok "AppRole configured — cred-rotation-api role ready"

# ── Verify Transit round-trip ─────────────────────────────────────────────────
info "Verifying Transit encrypt → decrypt round-trip..."
TEST_PT_B64=$(printf 'hello-vault-2' | base64)
CIPHER=$("$VAULT_BIN" write -field=ciphertext transit/encrypt/cred-rotation-key plaintext="$TEST_PT_B64")
RECOVERED=$("$VAULT_BIN" write -field=plaintext transit/decrypt/cred-rotation-key ciphertext="$CIPHER" | base64 -d)
[[ "$RECOVERED" == "hello-vault-2" ]] || fail "Transit round-trip verification FAILED"
ok "Transit round-trip verified"

# ── Verify Auth0 mgmt token (optional smoke test) ─────────────────────────────
info "Verifying Auth0 management API connectivity..."
AUTH0_TOKEN_RESP=$(curl -sf --request POST \
  --url "https://$AUTH0_DOMAIN/oauth/token" \
  --header 'content-type: application/json' \
  --data "{
    \"client_id\":\"$AUTH0_MGMT_CLIENT_ID\",
    \"client_secret\":\"$AUTH0_MGMT_CLIENT_SECRET\",
    \"audience\":\"$AUTH0_MGMT_AUDIENCE\",
    \"grant_type\":\"client_credentials\"
  }" 2>&1) || { warn "Auth0 connectivity check failed (non-fatal — check .env values)"; AUTH0_TOKEN_RESP=""; }

if [[ -n "$AUTH0_TOKEN_RESP" ]] && echo "$AUTH0_TOKEN_RESP" | grep -q '"access_token"'; then
  ok "Auth0 Management API reachable and credentials valid"
else
  warn "Auth0 check skipped or failed — verify AUTH0_DOMAIN and credentials in .env"
fi

# ── Write .vault-env ──────────────────────────────────────────────────────────
cat > "$ENV_OUT" <<EOF
# Generated by scripts/phase1-setup.sh — gitignored, local use only.
export VAULT_ADDR=$VAULT_ADDR
export VAULT_TOKEN=$VAULT_DEV_ROOT_TOKEN

# cred-rotation-api AppRole credentials (Phase 1: env var delivery)
export VAULT_APPROLE_ROLE_ID=$ROLE_ID
export VAULT_APPROLE_SECRET_ID=$SECRET_ID
EOF
chmod 600 "$ENV_OUT"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Phase 1 complete — Vault foundation ready${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo ""
echo "  Vault UI:      $VAULT_ADDR/ui  (token: $VAULT_DEV_ROOT_TOKEN)"
echo "  PKI CA cert:   vault/certs/internal-ca.crt"
echo "  Transit key:   cred-rotation-key (aes256-gcm96, envelope encryption)"
echo "  KV path:       secret/cred-rotation-api/adapters/auth0"
echo "  AppRole:       cred-rotation-api (role_id in .vault-env)"
echo ""
echo "  To load Vault env:  source .vault-env"
echo "  To stop Vault:      ./scripts/stop-vault.sh"
echo ""
echo -e "${YELLOW}  Next: Phase 2 — build cred-rotation-api with Auth0 adapter${NC}"
echo ""
