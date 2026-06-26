#!/usr/bin/env bash
#
# Start the full pgauthz stack (database, PostgREST, OPA, AuthZEN services).
# Builds images if needed. Waits until all services are healthy.
#
# Options:
#   --cel   Build the Postgres image with the pg_cel extension (CEL conditions).
#           Equivalent to PGAUTHZ_CEL=1. Run ./init.sh afterwards to enable it.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for arg in "$@"; do
  case "$arg" in
    --cel)      export PGAUTHZ_CEL=1 ;;
    -h|--help)  sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

# Compose files — base stack + optional authzen overlay
COMPOSE_FILES=(-f "$SCRIPT_DIR/compose.yml")
if [ -f "$SCRIPT_DIR/compose-authzen.yml" ]; then
  COMPOSE_FILES+=(-f "$SCRIPT_DIR/compose-authzen.yml")
fi

# Optional CEL overlay (see env.sh / extensions/pg-cel).
case "${PGAUTHZ_CEL:-}" in
  1|true|yes|on)
    COMPOSE_FILES+=(-f "$SCRIPT_DIR/compose-cel.yml")
    echo "==> CEL enabled (building pg_cel into the Postgres image)"
    ;;
esac

echo "==> Starting pgauthz stack..."
docker compose "${COMPOSE_FILES[@]}" up -d --build --wait

echo "==> Stack is running."
docker compose "${COMPOSE_FILES[@]}" ps
