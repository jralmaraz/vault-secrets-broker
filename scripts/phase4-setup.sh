#!/usr/bin/env bash
# Phase 4: Register and enable vault-auth0-engine plugin.
# Requires: make setup (Phase 1) and VAULT_TOKEN / VAULT_ADDR set.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VAULT="${VAULT:-vault}"
PLUGIN_NAME="vault-auth0-engine"
PLUGIN_BIN="$REPO_ROOT/vault/plugins/$PLUGIN_NAME"
MOUNT_PATH="auth0"

echo "=== Phase 4: vault-auth0-engine setup ==="

# 1. Build plugin binary
echo "→ Building $PLUGIN_NAME..."
(cd "$REPO_ROOT/plugins/vault-auth0-engine" && \
  go build -o "$PLUGIN_BIN" .)
echo "  Built: $PLUGIN_BIN"

# 2. Compute SHA-256
PLUGIN_SHA=$(sha256sum "$PLUGIN_BIN" | cut -d' ' -f1)
echo "  SHA-256: $PLUGIN_SHA"

# 3. Register plugin
echo "→ Registering plugin..."
"$VAULT" plugin register -sha256="$PLUGIN_SHA" secret "$PLUGIN_NAME"

# 4. Enable secrets engine
echo "→ Enabling secrets engine at $MOUNT_PATH/..."
"$VAULT" secrets enable -path="$MOUNT_PATH" "$PLUGIN_NAME" 2>/dev/null || \
  echo "  (already enabled — skipping)"

# 5. Create Transit key for optional credential encryption
echo "→ Creating Transit key: auth0-engine-key..."
"$VAULT" write -f transit/keys/auth0-engine-key type=aes256-gcm96 2>/dev/null || \
  echo "  (key already exists — skipping)"

# 6. Apply plugin policy
echo "→ Writing vault-auth0-engine policy..."
"$VAULT" policy write vault-auth0-engine \
  "$REPO_ROOT/vault/policies/vault-auth0-engine.hcl"

echo ""
echo "=== Done. Configure the engine with: ==="
echo ""
echo "  vault write $MOUNT_PATH/config/connection \\"
echo "    domain=\"YOUR_TENANT.auth0.com\" \\"
echo "    client_id=\"MGMT_CLIENT_ID\" \\"
echo "    client_secret=\"MGMT_CLIENT_SECRET\" \\"
echo "    audience=\"https://YOUR_TENANT.auth0.com/api/v2/\" \\"
echo "    transit_key=\"auth0-engine-key\""
echo ""
echo "Then rotate a client_secret:"
echo "  vault read $MOUNT_PATH/creds/<application-client-id>"
echo ""
echo "Check status:"
echo "  vault read $MOUNT_PATH/status/<application-client-id>"
