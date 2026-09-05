#!/usr/bin/env bash
# Phase 5 — Splunk and GitHub adapter KV provisioning
# Stores Transit-encrypted adapter credentials in Vault KV v2 so that
# cred-rotation-api can load them at startup without touching plaintext secrets.
#
# Prerequisites: phase1-setup.sh must have run (Vault running, Transit key exists).
#
# Usage:
#   cp .env.example .env && vim .env   # add SPLUNK_* and GITHUB_* vars
#   source .vault-env                  # sets VAULT_ADDR and VAULT_TOKEN
#   ./scripts/phase5-setup.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VAULT_BIN="${VAULT_BIN:-/opt/homebrew/bin/vault}"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
info() { echo -e "${CYAN}→${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
fail() { echo -e "${RED}✗${NC} $*" >&2; exit 1; }

[[ -x "$VAULT_BIN" ]] || fail "Vault not found at $VAULT_BIN."
[[ -f "$REPO_ROOT/.env" ]] || fail ".env not found."

source "$REPO_ROOT/.env"

# ── Required variables ─────────────────────────────────────────────────────────
: "${VAULT_ADDR:?VAULT_ADDR not set. Run: source .vault-env}"
: "${VAULT_TOKEN:?VAULT_TOKEN not set. Run: source .vault-env}"
: "${SPLUNK_BASE_URL:?SPLUNK_BASE_URL not set in .env (e.g. https://splunk.example.com:8089)}"
: "${SPLUNK_AUTH_TOKEN:?SPLUNK_AUTH_TOKEN not set in .env (Splunk management token, plaintext)}"
: "${GITHUB_ADMIN_PAT:?GITHUB_ADMIN_PAT not set in .env (fine-grained PAT with personal_access_tokens:write)}"

TRANSIT_KEY="${VAULT_TRANSIT_KEY:-cred-rotation-key}"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Phase 5 — Splunk + GitHub adapter KV provisioning"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Splunk ─────────────────────────────────────────────────────────────────────
info "Encrypting Splunk auth token with Transit..."
SPLUNK_TOKEN_B64=$(printf '%s' "$SPLUNK_AUTH_TOKEN" | base64)
SPLUNK_TOKEN_CIPHER=$("$VAULT_BIN" write -field=ciphertext \
  "transit/encrypt/$TRANSIT_KEY" \
  plaintext="$SPLUNK_TOKEN_B64")

info "Storing Transit-encrypted Splunk adapter config in KV..."
SPLUNK_KV_ARGS=(
  "base_url=$SPLUNK_BASE_URL"
  "auth_token_encrypted=$SPLUNK_TOKEN_CIPHER"
)
# Optional fields
[[ -n "${SPLUNK_DEFAULT_INDEX:-}" ]]      && SPLUNK_KV_ARGS+=("default_index=$SPLUNK_DEFAULT_INDEX")
[[ -n "${SPLUNK_DEFAULT_SOURCETYPE:-}" ]] && SPLUNK_KV_ARGS+=("default_sourcetype=$SPLUNK_DEFAULT_SOURCETYPE")
[[ -n "${SPLUNK_CA_CERT_PATH:-}" ]]       && SPLUNK_KV_ARGS+=("ca_cert=$(cat "$SPLUNK_CA_CERT_PATH")")

"$VAULT_BIN" kv put secret/cred-rotation-api/adapters/splunk "${SPLUNK_KV_ARGS[@]}"
ok "Splunk adapter config stored — auth_token is Transit-encrypted at rest"

# Verify round-trip decrypt
info "Verifying Splunk Transit round-trip..."
STORED_CIPHER=$("$VAULT_BIN" kv get -field=auth_token_encrypted \
  secret/cred-rotation-api/adapters/splunk)
DECRYPTED=$("$VAULT_BIN" write -field=plaintext \
  "transit/decrypt/$TRANSIT_KEY" \
  ciphertext="$STORED_CIPHER" | base64 -d)
[[ "$DECRYPTED" == "$SPLUNK_AUTH_TOKEN" ]] || fail "Splunk Transit round-trip FAILED — stored value does not match"
ok "Splunk Transit decrypt verified (${#DECRYPTED} chars)"

# ── GitHub ─────────────────────────────────────────────────────────────────────
info "Encrypting GitHub admin PAT with Transit..."
GITHUB_PAT_B64=$(printf '%s' "$GITHUB_ADMIN_PAT" | base64)
GITHUB_PAT_CIPHER=$("$VAULT_BIN" write -field=ciphertext \
  "transit/encrypt/$TRANSIT_KEY" \
  plaintext="$GITHUB_PAT_B64")

info "Storing Transit-encrypted GitHub adapter config in KV..."
GITHUB_KV_ARGS=(
  "admin_pat_encrypted=$GITHUB_PAT_CIPHER"
)
# base_url is only needed for GitHub Enterprise — omit for api.github.com
[[ -n "${GITHUB_BASE_URL:-}" ]] && GITHUB_KV_ARGS+=("base_url=$GITHUB_BASE_URL")

"$VAULT_BIN" kv put secret/cred-rotation-api/adapters/github "${GITHUB_KV_ARGS[@]}"
ok "GitHub adapter config stored — admin_pat is Transit-encrypted at rest"

# Verify round-trip decrypt
info "Verifying GitHub Transit round-trip..."
STORED_CIPHER=$("$VAULT_BIN" kv get -field=admin_pat_encrypted \
  secret/cred-rotation-api/adapters/github)
DECRYPTED=$("$VAULT_BIN" write -field=plaintext \
  "transit/decrypt/$TRANSIT_KEY" \
  ciphertext="$STORED_CIPHER" | base64 -d)
[[ "$DECRYPTED" == "$GITHUB_ADMIN_PAT" ]] || fail "GitHub Transit round-trip FAILED — stored value does not match"
ok "GitHub Transit decrypt verified (${#DECRYPTED} chars)"

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ok "Phase 5 complete. KV paths written:"
echo "   secret/cred-rotation-api/adapters/splunk"
echo "   secret/cred-rotation-api/adapters/github"
echo ""
echo " Plaintext secrets exist only in .env on this machine."
echo " Vault KV stores only Transit-encrypted ciphertext."
echo " cred-rotation-api will decrypt at startup via Transit."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
