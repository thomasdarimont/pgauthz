#!/usr/bin/env bash
#
# Start the full pgauthz stack (database, PostgREST, OPA, AuthZEN services).
# Builds images if needed. Waits until all services are healthy.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Compose files — base stack + optional authzen overlay
COMPOSE_FILES=(-f "$SCRIPT_DIR/compose.yml")
if [ -f "$SCRIPT_DIR/compose-authzen.yml" ]; then
  COMPOSE_FILES+=(-f "$SCRIPT_DIR/compose-authzen.yml")
fi

echo "==> Starting pgauthz stack..."
docker compose "${COMPOSE_FILES[@]}" up -d --build --wait

echo "==> Stack is running."
docker compose "${COMPOSE_FILES[@]}" ps
