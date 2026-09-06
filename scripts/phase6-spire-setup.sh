#!/usr/bin/env bash
# Phase 6 — SPIFFE/SPIRE Vault JWT auth configuration
#
# Configures Vault to accept JWT-SVIDs issued by SPIRE as the authentication
# mechanism for cred-rotation-api. Replaces static AppRole credentials with
# short-lived, cryptographically-attested workload identity tokens.
#
# Security properties enforced:
#   - bound_subject: only the exact SPIFFE ID for cred-rotation-api can auth
#   - bound_audiences: prevents stolen SVIDs from authenticating to other Vaults
#   - token_ttl aligned with SPIRE JWT-SVID TTL (5 min) so tokens expire quickly
#   - token_policies: minimal policy — rotate credentials only, no admin access
#   - JWKS URL validation: Vault fetches the public key from SPIRE's bundle endpoint
#
# Prerequisites:
#   - Phase 1 complete (Vault running, Transit key, AppRole working)
#   - SPIRE server running and reachable from Vault
#   - cred-rotation-api registered as a SPIRE workload entry
#
# Required environment variables:
#   VAULT_ADDR, VAULT_TOKEN
#   SPIRE_TRUST_DOMAIN   — e.g. "example.org"
#   SPIRE_BUNDLE_URL     — SPIRE's OIDC discovery / JWKS endpoint
#                         e.g. "https://spire-server.internal:8443/oidc/v1/keys"
#                         or the SPIRE OIDC discovery doc URL
#
# Optional:
#   VAULT_JWT_MOUNT      — JWT auth mount path (default: jwt)
#   VAULT_JWT_ROLE       — role name (default: cred-rotation-api)
#   SPIFFE_TOKEN_TTL     — Vault token TTL for authenticated clients (default: 5m)
#   SPIFFE_TOKEN_MAX_TTL — max TTL (default: 1h)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VAULT_BIN="${VAULT_BIN:-/opt/homebrew/bin/vault}"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
info() { echo -e "${CYAN}→${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
fail() { echo -e "${RED}✗${NC} $*" >&2; exit 1; }

[[ -x "$VAULT_BIN" ]] || fail "Vault not found at $VAULT_BIN"
[[ -f "$REPO_ROOT/.env" ]] && source "$REPO_ROOT/.env"

# ── Required variables ─────────────────────────────────────────────────────────
: "${VAULT_ADDR:?VAULT_ADDR not set. Run: source .vault-env}"
: "${VAULT_TOKEN:?VAULT_TOKEN not set. Run: source .vault-env}"
: "${SPIRE_TRUST_DOMAIN:?SPIRE_TRUST_DOMAIN not set (e.g. example.org)}"
: "${SPIRE_BUNDLE_URL:?SPIRE_BUNDLE_URL not set (SPIRE OIDC/JWKS endpoint URL)}"

# ── Optional variables with defaults ─────────────────────────────────────────
JWT_MOUNT="${VAULT_JWT_MOUNT:-jwt}"
JWT_ROLE="${VAULT_JWT_ROLE:-cred-rotation-api}"
TOKEN_TTL="${SPIFFE_TOKEN_TTL:-5m}"
TOKEN_MAX_TTL="${SPIFFE_TOKEN_MAX_TTL:-1h}"

# The SPIFFE ID that cred-rotation-api will present as its subject claim.
# Format: spiffe://<trust-domain>/<workload-path>
SPIFFE_ID="spiffe://${SPIRE_TRUST_DOMAIN}/cred-rotation-api"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Phase 6 — SPIFFE/SPIRE Vault JWT auth"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "Trust domain : $SPIRE_TRUST_DOMAIN"
info "SPIFFE ID    : $SPIFFE_ID"
info "JWKS URL     : $SPIRE_BUNDLE_URL"
info "JWT mount    : $JWT_MOUNT"
info "Role name    : $JWT_ROLE"
info "Token TTL    : $TOKEN_TTL / max $TOKEN_MAX_TTL"
echo ""

# ── Enable JWT auth method ────────────────────────────────────────────────────
info "Enabling JWT auth method at $JWT_MOUNT..."
"$VAULT_BIN" auth enable -path="$JWT_MOUNT" jwt 2>/dev/null \
  || warn "JWT auth already enabled at $JWT_MOUNT — skipping enable"
ok "JWT auth mount ready at $JWT_MOUNT"

# ── Configure JWT auth with SPIRE JWKS ───────────────────────────────────────
# Vault validates incoming JWT-SVIDs against the public keys from the SPIRE bundle.
# jwt_validation_pubkeys can be used instead of jwks_url for air-gapped deployments.
info "Configuring JWT auth with SPIRE JWKS endpoint..."
"$VAULT_BIN" write auth/"$JWT_MOUNT"/config \
  jwks_url="$SPIRE_BUNDLE_URL" \
  default_role="$JWT_ROLE"
ok "JWT auth configured — Vault will fetch JWKS from $SPIRE_BUNDLE_URL"

# ── Create the cred-rotation-api JWT role ────────────────────────────────────
# bound_subject: only the exact SPIFFE ID for cred-rotation-api is accepted.
#   This is the critical control — prevents any other workload from using this role,
#   even if it has a valid JWT-SVID from the same trust domain.
# bound_audiences: Vault will reject SVIDs not addressed to this specific audience,
#   preventing stolen SVIDs from authenticating to other services.
# user_claim=sub: maps the SPIFFE ID (subject) to the Vault entity identity.
info "Creating JWT role '$JWT_ROLE'..."
"$VAULT_BIN" write auth/"$JWT_MOUNT"/role/"$JWT_ROLE" \
  role_type=jwt \
  bound_audiences="https://${VAULT_ADDR##*/}" \
  bound_subject="$SPIFFE_ID" \
  user_claim=sub \
  token_policies=cred-rotation-api \
  token_ttl="$TOKEN_TTL" \
  token_max_ttl="$TOKEN_MAX_TTL" \
  token_type=service
ok "JWT role '$JWT_ROLE' created with bound_subject=$SPIFFE_ID"

# ── Verify role configuration ─────────────────────────────────────────────────
info "Verifying role configuration..."
ROLE_DATA=$("$VAULT_BIN" read -format=json auth/"$JWT_MOUNT"/role/"$JWT_ROLE")

GOT_SUBJECT=$(echo "$ROLE_DATA" | grep -o '"bound_subject":"[^"]*"' | cut -d'"' -f4 || true)
if [[ "$GOT_SUBJECT" != "$SPIFFE_ID" ]]; then
  warn "bound_subject mismatch — got '$GOT_SUBJECT', expected '$SPIFFE_ID'"
  warn "Verify the role was written correctly before proceeding."
else
  ok "bound_subject verified: $SPIFFE_ID"
fi

# ── Runtime environment variables to set on cred-rotation-api ────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ok "Phase 6 complete. Set these env vars on cred-rotation-api:"
echo ""
echo "  VAULT_ADDR=${VAULT_ADDR}"
echo "  VAULT_JWT_MOUNT=auth/${JWT_MOUNT}/login"
echo "  VAULT_JWT_ROLE=${JWT_ROLE}"
echo "  SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/agent.sock   # adjust path"
echo "  VAULT_SPIFFE_AUDIENCE=https://${VAULT_ADDR##*/}"
echo "  VAULT_SPIFFE_TRUST_DOMAIN=${SPIRE_TRUST_DOMAIN}"
echo ""
echo " Remove VAULT_APPROLE_ROLE_ID and VAULT_APPROLE_SECRET_ID."
echo " Remove VAULT_TOKEN (or keep for emergency break-glass only)."
echo ""
warn "SPIRE workload entry must exist for cred-rotation-api before starting the service:"
echo "  spire-server entry create \\"
echo "    -parentID spiffe://${SPIRE_TRUST_DOMAIN}/nodes/worker \\"
echo "    -spiffeID ${SPIFFE_ID} \\"
echo "    -selector k8s:pod-label:app:cred-rotation-api \\"
echo "    -jwt-svid-ttl 5m"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
