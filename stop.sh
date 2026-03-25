#!/usr/bin/env bash
#
# Stop the full pgauthz stack and optionally remove volumes.
#
# Usage:
#   ./stop.sh          # stop containers (data preserved)
#   ./stop.sh --clean  # stop containers and remove volumes
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Compose files — base stack + optional authzen overlay
COMPOSE_FILES=(-f "$SCRIPT_DIR/compose.yml")
if [ -f "$SCRIPT_DIR/compose-authzen.yml" ]; then
  COMPOSE_FILES+=(-f "$SCRIPT_DIR/compose-authzen.yml")
fi

if [ "${1:-}" = "--clean" ]; then
  echo "==> Stopping pgauthz stack and removing volumes..."
  docker compose "${COMPOSE_FILES[@]}" down -v
else
  echo "==> Stopping pgauthz stack..."
  docker compose "${COMPOSE_FILES[@]}" down
fi

echo "==> Done."
