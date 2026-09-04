#!/usr/bin/env bash
# Phase 3 — vault-rest-engine plugin registration
# Builds the vault-rest-engine binary, registers it with Vault, and enables
# a secrets engine mount at rotation/.
#
# Prerequisites:
#   - phase1-setup.sh and phase2-setup.sh completed
#   - .vault-env sourced
#   - Go installed at /opt/homebrew/bin/go
#
# Usage:
#   source .vault-env
#   ./scripts/phase3-setup.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VAULT_BIN="${VAULT_BIN:-/opt/homebrew/bin/vault}"
GO_BIN="${GO_BIN:-/opt/homebrew/bin/go}"
PLUGIN_DIR="$REPO_ROOT/vault/plugins"
PLUGIN_NAME="vault-rest-engine"
PLUGIN_BIN="$PLUGIN_DIR/$PLUGIN_NAME"
MOUNT_PATH="rotation"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
info() { echo -e "${CYAN}→${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
fail() { echo -e "${RED}✗${NC} $*" >&2; exit 1; }

[[ -x "$VAULT_BIN" ]] || fail "Vault not found at $VAULT_BIN"
[[ -x "$GO_BIN"    ]] || fail "Go not found at $GO_BIN"
[[ -f "$REPO_ROOT/.vault-env" ]] || fail ".vault-env not found — run phase1-setup.sh first"

source "$REPO_ROOT/.vault-env"
export VAULT_ADDR VAULT_TOKEN

"$VAULT_BIN" status -format=json > /dev/null 2>&1 || fail "Vault is not reachable at $VAULT_ADDR"
ok "Vault reachable at $VAULT_ADDR"

# ── Build the plugin ──────────────────────────────────────────────────────────
info "Building $PLUGIN_NAME..."
mkdir -p "$PLUGIN_DIR"
(cd "$REPO_ROOT/plugins/vault-rest-engine" && \
  GOOS=linux GOARCH=amd64 "$GO_BIN" build -o "$PLUGIN_BIN" . 2>/dev/null || \
  "$GO_BIN" build -o "$PLUGIN_BIN" .)

[[ -x "$PLUGIN_BIN" ]] || fail "Plugin binary not found at $PLUGIN_BIN after build"
ok "Plugin built: $PLUGIN_BIN"

# ── Compute SHA-256 ───────────────────────────────────────────────────────────
SHA256=$(sha256sum "$PLUGIN_BIN" | cut -d' ' -f1)
ok "SHA-256: $SHA256"

# ── Register the plugin ───────────────────────────────────────────────────────
info "Registering $PLUGIN_NAME with Vault..."
"$VAULT_BIN" plugin register \
  -sha256="$SHA256" \
  -command="$PLUGIN_NAME" \
  secret "$PLUGIN_NAME"
ok "Plugin registered: $PLUGIN_NAME"

# ── Enable the mount ──────────────────────────────────────────────────────────
info "Enabling secrets engine at $MOUNT_PATH/..."
if "$VAULT_BIN" secrets list -format=json | grep -q "\"$MOUNT_PATH/\""; then
  warn "$MOUNT_PATH/ already enabled — disabling and re-enabling to pick up new binary"
  "$VAULT_BIN" secrets disable "$MOUNT_PATH"
fi

"$VAULT_BIN" secrets enable \
  -path="$MOUNT_PATH" \
  -plugin-name="$PLUGIN_NAME" \
  plugin
ok "Secrets engine enabled at $MOUNT_PATH/"

# ── Smoke test — configure the engine ────────────────────────────────────────
info "Writing rotation/config/connection (points at cred-rotation-api on :8443)..."
"$VAULT_BIN" write "$MOUNT_PATH/config/connection" \
  api_url="https://127.0.0.1:8443" \
  transit_key="cred-rotation-key" \
  tls_ca_cert="$(cat "$REPO_ROOT/vault/certs/internal-ca.crt" 2>/dev/null || echo '')"
ok "Plugin configured"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Phase 3 complete — vault-rest-engine registered${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo ""
echo "  Plugin:       $MOUNT_PATH/ (vault-rest-engine)"
echo "  SHA-256:      $SHA256"
echo ""
echo "  To rotate Auth0 credentials:"
echo "    vault read $MOUNT_PATH/creds/auth0/<client-id>"
echo ""
echo -e "${YELLOW}  Next: Phase 4 — vault-auth0-engine native plugin${NC}"
echo ""
