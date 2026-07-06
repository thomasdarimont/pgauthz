#!/usr/bin/env bash
#
# Stop the full pgauthz stack and optionally remove volumes.
#
# Usage:
#   ./stop.sh                      # stop the running stack (data preserved)
#   ./stop.sh --clean              # stop containers and remove volumes
#   ./stop.sh --opa                # also stop the OPA overlay (match start.sh)
#   ./stop.sh --keycloak           # also stop Keycloak (implies --opa)
#   ./stop.sh --playground         # also stop the playground (implies --keycloak)
#   ./stop.sh --metrics            # also stop Prometheus + Grafana
#   ./stop.sh --keycloak --clean   # ...and remove its volumes too
#
# The overlay state persisted by start.sh (.pgauthz-overlays) is sourced, so a
# plain ./stop.sh tears down exactly the stack that is running — the flags are
# only needed to ADD overlays beyond that (e.g. leftovers from an earlier run).
# (docker compose down only removes services it is given via -f; un-listed
# overlay services would otherwise linger as orphans.)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CLEAN=0
for arg in "$@"; do
  case "$arg" in
    --clean)      CLEAN=1 ;;
    --cel)        export PGAUTHZ_CEL=1 ;;
    --opa)        export PGAUTHZ_OPA=1 ;;
    --keycloak)   export PGAUTHZ_KEYCLOAK=1 ;;
    --playground) export PGAUTHZ_PLAYGROUND=1 ;;
    --metrics)    export PGAUTHZ_METRICS=1 ;;
    -h|--help)    sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

# The overlays of the currently running stack (self-guards with :- defaults, so
# the explicit flags/env vars above take precedence).
if [ -f "$SCRIPT_DIR/.pgauthz-overlays" ]; then
  # shellcheck source=/dev/null
  source "$SCRIPT_DIR/.pgauthz-overlays"
fi

# Implication chain, mirroring env.sh/start.sh: playground → keycloak → opa
# (keycloak/playground OVERRIDE the pgauthzd-opa service that compose-opa.yml
# DEFINES — listing them without it is an invalid compose project).
case "${PGAUTHZ_PLAYGROUND:-}" in 1|true|yes|on) PGAUTHZ_KEYCLOAK=1 ;; esac
case "${PGAUTHZ_KEYCLOAK:-}" in 1|true|yes|on) PGAUTHZ_OPA=1 ;; esac

# Compose files — base stack + optional overlays, mirroring env.sh (same order:
# compose-opa.yml must precede keycloak/playground).
COMPOSE_FILES=(-f "$SCRIPT_DIR/compose.yml")
if [ -f "$SCRIPT_DIR/compose-authzen.yml" ]; then
  COMPOSE_FILES+=(-f "$SCRIPT_DIR/compose-authzen.yml")
fi
case "${PGAUTHZ_CEL:-}" in
  1|true|yes|on) COMPOSE_FILES+=(-f "$SCRIPT_DIR/compose-cel.yml") ;;
esac
case "${PGAUTHZ_OPA:-}" in
  1|true|yes|on) COMPOSE_FILES+=(-f "$SCRIPT_DIR/compose-opa.yml") ;;
esac
case "${PGAUTHZ_KEYCLOAK:-}" in
  1|true|yes|on) COMPOSE_FILES+=(-f "$SCRIPT_DIR/compose-keycloak.yml") ;;
esac
case "${PGAUTHZ_PLAYGROUND:-}" in
  1|true|yes|on) COMPOSE_FILES+=(-f "$SCRIPT_DIR/compose-playground.yml") ;;
esac
case "${PGAUTHZ_METRICS:-}" in
  1|true|yes|on) COMPOSE_FILES+=(-f "$SCRIPT_DIR/compose-metrics.yml") ;;
esac

if [ "$CLEAN" = 1 ]; then
  echo "==> Stopping pgauthz stack and removing volumes..."
  docker compose "${COMPOSE_FILES[@]}" down -v --remove-orphans
else
  echo "==> Stopping pgauthz stack..."
  docker compose "${COMPOSE_FILES[@]}" down --remove-orphans
fi

echo "==> Done."
