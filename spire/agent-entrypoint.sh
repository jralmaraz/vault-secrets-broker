#!/bin/sh
# Entrypoint for the SPIRE agent container in the integration test stack.
# Waits for the server health check, then waits for a join token dropped by the
# setup script into a shared volume, then starts the agent.
set -eu

echo "→ Waiting for SPIRE server health..."
until wget -qO- "http://spire-server:8080/ready" >/dev/null 2>&1; do
  sleep 2
done
echo "✓ SPIRE server ready"

echo "→ Waiting for join token at /run/spire-setup/join-token..."
until [ -f /run/spire-setup/join-token ]; do sleep 1; done
TOKEN=$(cat /run/spire-setup/join-token)
echo "✓ Join token received"

exec /opt/spire/bin/spire-agent run \
  -config /etc/spire/agent/agent.conf \
  -joinToken "$TOKEN"
