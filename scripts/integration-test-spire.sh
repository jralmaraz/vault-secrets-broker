#!/usr/bin/env bash
# SPIFFE/SPIRE end-to-end integration test orchestrator.
#
# Brings up the full Docker Compose stack (Vault dev + SPIRE server + OIDC provider +
# SPIRE agent), configures Vault JWT auth with SPIRE's JWKS endpoint, registers a
# workload entry, builds and runs the Go integration test binary, then tears down.
#
# Usage:
#   make test-integration-spire
#   # or directly:
#   ./scripts/integration-test-spire.sh
#
# Requirements:
#   - Docker Desktop (Mac/Windows) or Docker Engine (Linux) with Compose v2
#   - VAULT_BIN (optional): path to vault binary for policy write (defaults to brew path)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.spire.yml"
VAULT_BIN="${VAULT_BIN:-/opt/homebrew/bin/vault}"

# Use an explicit project name so volume names are predictable across shells.
COMPOSE_PROJECT="vsb-spire-test"
DC="docker compose -p $COMPOSE_PROJECT -f $COMPOSE_FILE"

# Ports exposed on the host (must match docker-compose.spire.yml)
VAULT_PORT=18200
SPIRE_PORT=18081

VAULT_TOKEN_HOST="integ-test-token"
VAULT_ADDR_HOST="http://127.0.0.1:${VAULT_PORT}"

TRUST_DOMAIN="example.org"
SPIFFE_ID="spiffe://${TRUST_DOMAIN}/cred-rotation-api"
WORKLOAD_UID=65532  # cgr.dev/chainguard/static nonroot user UID

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
info() { echo -e "${CYAN}→${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
fail() { echo -e "${RED}✗${NC} $*" >&2; exit 1; }

# ── Cleanup on exit ───────────────────────────────────────────────────────────
cleanup() {
  echo ""
  info "Tearing down SPIRE integration test stack..."
  $DC down -v --remove-orphans 2>/dev/null || true
  info "Cleanup complete."
}
trap cleanup EXIT

# ── Prereq checks ─────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || fail "docker not found"
docker compose version >/dev/null 2>&1 || fail "docker compose (v2) not found"
[[ -x "$VAULT_BIN" ]] || fail "vault binary not found at $VAULT_BIN (set VAULT_BIN=)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " SPIRE end-to-end integration test"
echo " Trust domain : $TRUST_DOMAIN"
echo " SPIFFE ID    : $SPIFFE_ID"
echo " Workload UID : $WORKLOAD_UID (unix workload attestor)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Step 1: Start Vault + SPIRE server + OIDC provider ───────────────────────
info "Starting Vault dev server, SPIRE server, and OIDC discovery provider..."
$DC up -d vault-dev spire-server oidc-provider

info "Waiting for Vault to become healthy..."
until curl -sf "http://127.0.0.1:${VAULT_PORT}/v1/sys/health" >/dev/null 2>&1; do
  sleep 2
done
ok "Vault dev server ready at $VAULT_ADDR_HOST"

# SPIRE images (1.11.x) are distroless — no wget/curl inside the container.
# Poll readiness via the host-exposed ports instead.
info "Waiting for SPIRE server health endpoint (port 18080)..."
until curl -sf "http://127.0.0.1:18080/ready" >/dev/null 2>&1; do
  sleep 2
done
ok "SPIRE server ready"

info "Waiting for OIDC discovery provider JWKS endpoint (port 18083)..."
until curl -sf "http://127.0.0.1:18083/keys" >/dev/null 2>&1; do
  sleep 2
done
ok "OIDC discovery provider ready — JWKS endpoint live"

# ── Step 2: Generate join token and start the SPIRE agent ─────────────────────
# SPIRE agent images are distroless (no shell), so we can't use an entrypoint script
# to receive the join token via a file. Instead we pass it as a CLI flag by generating
# a temporary compose override with the token embedded in the command.
info "Generating SPIRE join token..."
JOIN_TOKEN=$($DC exec -T spire-server \
  /opt/spire/bin/spire-server token generate \
  -spiffeID "spiffe://${TRUST_DOMAIN}/nodes/agent" \
  -ttl 600 2>/dev/null | grep "^Token" | awk '{print $2}')

[[ -n "$JOIN_TOKEN" ]] || fail "Failed to generate join token"
ok "Join token generated"

# Write a temporary compose override that appends -joinToken to the agent command.
OVERRIDE_FILE=$(mktemp /tmp/spire-agent-override.XXXXXX.yml)
trap 'rm -f "$OVERRIDE_FILE"; cleanup' EXIT
cat > "$OVERRIDE_FILE" << OVERRIDE
services:
  spire-agent:
    command:
      - -config
      - /etc/spire/agent/agent.conf
      - -joinToken
      - ${JOIN_TOKEN}
OVERRIDE

info "Starting SPIRE agent (join token embedded in compose override)..."
$DC -f "$OVERRIDE_FILE" up -d spire-agent

info "Waiting for SPIRE agent health endpoint (port 18082)..."
for i in $(seq 1 40); do
  if curl -sf "http://127.0.0.1:18082/ready" >/dev/null 2>&1; then
    break
  fi
  [ "$i" -eq 40 ] && fail "SPIRE agent did not become healthy in time"
  sleep 3
done
ok "SPIRE agent ready and connected to server"

# ── Step 3: Register the workload entry ───────────────────────────────────────
info "Looking up agent SPIFFE ID..."
AGENT_SPIFFE_ID=""
for i in $(seq 1 10); do
  AGENT_SPIFFE_ID=$($DC exec -T spire-server \
    /opt/spire/bin/spire-server agent list 2>/dev/null \
    | grep "SPIFFE ID" | awk '{print $NF}' | head -1 || true)
  [[ -n "$AGENT_SPIFFE_ID" ]] && break
  sleep 3
done
[[ -n "$AGENT_SPIFFE_ID" ]] || fail "Could not determine agent SPIFFE ID from server"
ok "Agent SPIFFE ID: $AGENT_SPIFFE_ID"

info "Registering workload entry (unix:uid:${WORKLOAD_UID} → ${SPIFFE_ID})..."
$DC exec -T spire-server \
  /opt/spire/bin/spire-server entry create \
  -parentID "$AGENT_SPIFFE_ID" \
  -spiffeID "$SPIFFE_ID" \
  -selector "unix:uid:${WORKLOAD_UID}" \
  -jwtSVIDTTL 300 2>/dev/null \
  || warn "Entry may already exist — continuing"
ok "Workload entry registered"

# ── Step 4: Configure Vault JWT auth ──────────────────────────────────────────
# Vault (in Docker) fetches JWKS from the oidc-provider service name.
JWKS_URL="http://oidc-provider:8080/keys"
# VAULT_AUDIENCE must match what the test runner presents as SPIFFEAudience.
VAULT_AUDIENCE="http://vault-dev:8200"

info "Enabling Vault JWT auth method..."
VAULT_ADDR="$VAULT_ADDR_HOST" VAULT_TOKEN="$VAULT_TOKEN_HOST" \
  "$VAULT_BIN" auth enable -path=jwt jwt 2>/dev/null \
  || warn "JWT auth already enabled — continuing"

info "Configuring JWT auth → JWKS URL: $JWKS_URL"
VAULT_ADDR="$VAULT_ADDR_HOST" VAULT_TOKEN="$VAULT_TOKEN_HOST" \
  "$VAULT_BIN" write auth/jwt/config \
    jwks_url="$JWKS_URL" \
    default_role="cred-rotation-api"
ok "JWT auth configured"

info "Writing Vault policy for integration test client..."
VAULT_ADDR="$VAULT_ADDR_HOST" VAULT_TOKEN="$VAULT_TOKEN_HOST" \
  "$VAULT_BIN" policy write cred-rotation-api - <<'HCL'
# Minimal policy for SPIRE integration test — allows token self-lookup only.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
HCL
ok "Policy cred-rotation-api written"

info "Creating JWT role 'cred-rotation-api' (bound_subject=${SPIFFE_ID})..."
VAULT_ADDR="$VAULT_ADDR_HOST" VAULT_TOKEN="$VAULT_TOKEN_HOST" \
  "$VAULT_BIN" write auth/jwt/role/cred-rotation-api \
    role_type=jwt \
    bound_audiences="$VAULT_AUDIENCE" \
    bound_subject="$SPIFFE_ID" \
    user_claim=sub \
    token_policies=cred-rotation-api \
    token_ttl=5m \
    token_max_ttl=1h \
    token_type=service
ok "JWT role created"

# ── Step 5: Build and run the integration test binary ─────────────────────────
info "Building test runner image..."
$DC build spire-test-runner

info "Running SPIRE integration tests..."
echo ""
TEST_EXIT=0
$DC -f "$OVERRIDE_FILE" run --rm \
  -e SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/agent.sock \
  -e VAULT_ADDR="http://vault-dev:8200" \
  -e VAULT_JWT_MOUNT=auth/jwt/login \
  -e VAULT_JWT_ROLE=cred-rotation-api \
  -e VAULT_SPIFFE_TRUST_DOMAIN="$TRUST_DOMAIN" \
  spire-test-runner \
  || TEST_EXIT=$?

echo ""
if [ "$TEST_EXIT" -eq 0 ]; then
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  ok "All SPIRE integration tests passed."
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  fail "SPIRE integration tests FAILED (exit $TEST_EXIT)."
fi
