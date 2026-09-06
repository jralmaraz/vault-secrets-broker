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

# Ports exposed on the host (must match docker-compose.spire.yml)
VAULT_PORT=18200
SPIRE_PORT=18081
OIDC_PORT=18083   # not directly needed; kept for reference

VAULT_TOKEN_HOST="integ-test-token"
VAULT_ADDR_HOST="http://127.0.0.1:${VAULT_PORT}"

TRUST_DOMAIN="example.org"
SPIFFE_ID="spiffe://${TRUST_DOMAIN}/cred-rotation-api"
WORKLOAD_UID=1001   # must match Dockerfile.spire-test adduser UID

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
info() { echo -e "${CYAN}→${NC} $*"; }
warn() { echo -e "${YELLOW}!${NC} $*"; }
fail() { echo -e "${RED}✗${NC} $*" >&2; exit 1; }

# ── Cleanup on exit ───────────────────────────────────────────────────────────
cleanup() {
  echo ""
  info "Tearing down SPIRE integration test stack..."
  docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
  rm -f "$REPO_ROOT/.spire-integ-join-token"
  info "Cleanup complete."
}
trap cleanup EXIT

# ── Prereq checks ─────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || fail "docker not found"
docker compose version >/dev/null 2>&1 || fail "docker compose (v2) not found"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " SPIRE end-to-end integration test"
echo " Trust domain : $TRUST_DOMAIN"
echo " SPIFFE ID    : $SPIFFE_ID"
echo " Workload UID : $WORKLOAD_UID (unix workload attestor)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Step 1: Start Vault + SPIRE server + OIDC provider ───────────────────────
info "Starting Vault dev server and SPIRE server..."
docker compose -f "$COMPOSE_FILE" up -d vault-dev spire-server oidc-provider

info "Waiting for Vault to become healthy..."
until curl -sf "http://127.0.0.1:${VAULT_PORT}/v1/sys/health" >/dev/null 2>&1; do
  sleep 2
done
ok "Vault dev server ready at $VAULT_ADDR_HOST"

info "Waiting for SPIRE server to become healthy..."
until curl -sf "http://127.0.0.1:${SPIRE_PORT}" >/dev/null 2>&1 || \
      docker compose -f "$COMPOSE_FILE" exec -T spire-server \
        wget -qO- "http://127.0.0.1:8080/ready" >/dev/null 2>&1; do
  sleep 2
done
ok "SPIRE server ready"

info "Waiting for OIDC discovery provider to become healthy..."
until docker compose -f "$COMPOSE_FILE" exec -T oidc-provider \
    wget -qO- "http://127.0.0.1:8081/ready" >/dev/null 2>&1; do
  sleep 2
done
ok "OIDC discovery provider ready"

# ── Step 2: Generate join token and start the SPIRE agent ─────────────────────
info "Generating SPIRE join token..."
JOIN_TOKEN=$(docker compose -f "$COMPOSE_FILE" exec -T spire-server \
  /opt/spire/bin/spire-server token generate \
  -spiffeID "spiffe://${TRUST_DOMAIN}/nodes/agent" \
  -ttl 600 2>/dev/null | grep "^Token" | awk '{print $2}')

[[ -n "$JOIN_TOKEN" ]] || fail "Failed to generate join token"
ok "Join token generated"

# Write token to the shared volume by running a temporary container.
# The agent-entrypoint.sh polls for this file before starting the agent.
info "Dropping join token into shared volume..."
docker run --rm \
  -v "$(docker compose -f "$COMPOSE_FILE" config --volumes 2>/dev/null | grep join-token-vol | head -1 | awk '{print $1}' || echo vault-secrets-broker_join-token-vol)":/run/spire-setup \
  alpine:3.20 \
  sh -c "echo '$JOIN_TOKEN' > /run/spire-setup/join-token"

info "Starting SPIRE agent..."
docker compose -f "$COMPOSE_FILE" up -d spire-agent

info "Waiting for SPIRE agent to become healthy..."
for i in $(seq 1 30); do
  if docker compose -f "$COMPOSE_FILE" exec -T spire-agent \
      wget -qO- "http://127.0.0.1:8080/ready" >/dev/null 2>&1; then
    break
  fi
  if [ "$i" -eq 30 ]; then
    fail "SPIRE agent did not become healthy in time"
  fi
  sleep 2
done
ok "SPIRE agent ready and connected to server"

# ── Step 3: Register the workload entry ───────────────────────────────────────
info "Looking up agent SPIFFE ID..."
AGENT_SPIFFE_ID=""
for i in $(seq 1 10); do
  AGENT_SPIFFE_ID=$(docker compose -f "$COMPOSE_FILE" exec -T spire-server \
    /opt/spire/bin/spire-server agent list 2>/dev/null \
    | grep "SPIFFE ID" | awk '{print $NF}' | head -1 || true)
  [[ -n "$AGENT_SPIFFE_ID" ]] && break
  sleep 3
done
[[ -n "$AGENT_SPIFFE_ID" ]] || fail "Could not determine agent SPIFFE ID"
ok "Agent SPIFFE ID: $AGENT_SPIFFE_ID"

info "Registering workload entry for test runner (unix:uid:${WORKLOAD_UID})..."
docker compose -f "$COMPOSE_FILE" exec -T spire-server \
  /opt/spire/bin/spire-server entry create \
  -parentID "$AGENT_SPIFFE_ID" \
  -spiffeID "$SPIFFE_ID" \
  -selector "unix:uid:${WORKLOAD_UID}" \
  -jwtSVIDTTL 300 2>/dev/null \
  || warn "Entry may already exist — continuing"
ok "Workload entry registered: $SPIFFE_ID"

# ── Step 4: Configure Vault JWT auth ──────────────────────────────────────────
# The OIDC provider serves JWKS at http://oidc-provider:8080/keys (Docker service name).
# Vault, also in the Docker network, can reach it via that name.
JWKS_URL="http://oidc-provider:8080/keys"
VAULT_AUDIENCE="http://vault-dev:8200"   # how the test runner container reaches Vault

info "Enabling Vault JWT auth method..."
VAULT_ADDR="$VAULT_ADDR_HOST" VAULT_TOKEN="$VAULT_TOKEN_HOST" \
  "$VAULT_BIN" auth enable -path=jwt jwt 2>/dev/null \
  || warn "JWT auth already enabled"

info "Configuring JWT auth with SPIRE OIDC JWKS URL..."
VAULT_ADDR="$VAULT_ADDR_HOST" VAULT_TOKEN="$VAULT_TOKEN_HOST" \
  "$VAULT_BIN" write auth/jwt/config \
    jwks_url="$JWKS_URL" \
    default_role="cred-rotation-api"
ok "JWT auth configured → Vault will fetch JWKS from $JWKS_URL"

info "Creating Vault policy for integration test client..."
VAULT_ADDR="$VAULT_ADDR_HOST" VAULT_TOKEN="$VAULT_TOKEN_HOST" \
  "$VAULT_BIN" policy write cred-rotation-api - <<'HCL'
# Minimal policy for SPIRE integration test — allows token self-lookup only.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
HCL
ok "Policy cred-rotation-api written"

info "Creating JWT role 'cred-rotation-api'..."
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
ok "JWT role created: bound_subject=$SPIFFE_ID"

# ── Step 5: Build and run the integration test binary ─────────────────────────
info "Building test runner image..."
docker compose -f "$COMPOSE_FILE" build spire-test-runner

info "Running SPIRE integration tests..."
echo ""
TEST_EXIT=0
docker compose -f "$COMPOSE_FILE" \
  run --rm \
  --profile test \
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
