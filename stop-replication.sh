#!/usr/bin/env bash
#
# Stop the logical-replication demo started by ./start-replication.sh.
#
# Usage:
#   ./stop-replication.sh            # stop the containers (volumes kept; ./start-replication.sh --no-init resumes)
#   ./stop-replication.sh --clean    # stop and remove the volumes (next start re-initialises)
#
# Honours the same REPLICATION_COMPOSE_FILES / COMPOSE_PROJECT_NAME as
# start-replication.sh; pass --default-ports if you started that way.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CLEAN=0; DEFAULT_PORTS=0
for arg in "$@"; do
  case "$arg" in
    --clean)         CLEAN=1 ;;
    --default-ports) DEFAULT_PORTS=1 ;;
    -h|--help)       sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [ "$DEFAULT_PORTS" = 1 ]; then
  export REPLICATION_COMPOSE_FILES="${REPLICATION_COMPOSE_FILES:-compose-replication.yml}"
else
  export REPLICATION_COMPOSE_FILES="${REPLICATION_COMPOSE_FILES:-compose-replication.yml:compose-replication-ports.yml}"
fi
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-pgauthz-repl}"
COMPOSE=(docker compose)
IFS=: read -ra _files <<< "$REPLICATION_COMPOSE_FILES"
for f in "${_files[@]}"; do COMPOSE+=(-f "$f"); done

if [ "$CLEAN" = 1 ]; then
  echo "==> Stopping the replication stack ($COMPOSE_PROJECT_NAME) and removing its volumes..."
  "${COMPOSE[@]}" down -v
else
  echo "==> Stopping the replication stack ($COMPOSE_PROJECT_NAME); volumes kept..."
  "${COMPOSE[@]}" down
fi
