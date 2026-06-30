#!/usr/bin/env bash
#
# Stop the full pgauthz stack and optionally remove volumes.
#
# Usage:
#   ./stop.sh                      # stop containers (data preserved)
#   ./stop.sh --clean              # stop containers and remove volumes
#   ./stop.sh --keycloak           # also stop the Keycloak overlay (match start.sh)
#   ./stop.sh --keycloak --clean   # ...and remove its volumes too
#
# Pass the same overlay flags you used with start.sh (--cel / --keycloak) so the
# same services are torn down. (docker compose down only removes services it is
# given via -f; un-listed overlay services would otherwise linger as orphans.)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CLEAN=0
KEYCLOAK=0
for arg in "$@"; do
  case "$arg" in
    --clean)    CLEAN=1 ;;
    --cel)      export PGAUTHZ_CEL=1 ;;
    --keycloak) KEYCLOAK=1 ;;
    -h|--help)  sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

# Compose files — base stack + optional overlays, mirroring start.sh.
COMPOSE_FILES=(-f "$SCRIPT_DIR/compose.yml")
if [ -f "$SCRIPT_DIR/compose-authzen.yml" ]; then
  COMPOSE_FILES+=(-f "$SCRIPT_DIR/compose-authzen.yml")
fi

# Optional CEL overlay (matches start.sh --cel / PGAUTHZ_CEL).
case "${PGAUTHZ_CEL:-}" in
  1|true|yes|on)
    COMPOSE_FILES+=(-f "$SCRIPT_DIR/compose-cel.yml")
    ;;
esac

# Optional Keycloak demo overlay (matches start.sh --keycloak).
if [ "$KEYCLOAK" = 1 ]; then
  COMPOSE_FILES+=(-f "$SCRIPT_DIR/compose-keycloak.yml")
fi

if [ "$CLEAN" = 1 ]; then
  echo "==> Stopping pgauthz stack and removing volumes..."
  docker compose "${COMPOSE_FILES[@]}" down -v
else
  echo "==> Stopping pgauthz stack..."
  docker compose "${COMPOSE_FILES[@]}" down
fi

echo "==> Done."
