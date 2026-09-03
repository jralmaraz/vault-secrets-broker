#!/usr/bin/env bash
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PID_FILE="$REPO_ROOT/vault/vault-dev.pid"

if [[ -f "$PID_FILE" ]]; then
  PID=$(cat "$PID_FILE")
  if kill -0 "$PID" 2>/dev/null; then
    kill "$PID"
    rm -f "$PID_FILE"
    echo "Vault dev server (PID $PID) stopped."
  else
    echo "No running process at PID $PID — cleaning up stale PID file."
    rm -f "$PID_FILE"
  fi
else
  echo "No vault-dev.pid found — nothing to stop."
fi
