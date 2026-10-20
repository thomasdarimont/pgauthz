#!/usr/bin/env bash
#
# Start the logical-replication demo (compose-replication.yml): a primary with
# the full engine and three subscribers — a full replica, a derived-permissions
# subscriber (authz.materialized_relations) and a namespace-scoped one. Runs
# NEXT TO the main stack by default: host ports moved by +100
# (compose-replication-ports.yml) and its own compose project, so neither
# stack sees the other's containers, network or volumes. Initialises the
# databases (db/replication/init-replication.sh) unless told not to.
#
# Usage:
#   ./start-replication.sh              # up + init; prints the connection strings
#   ./start-replication.sh --clean      # recreate from scratch (down -v first)
#   ./start-replication.sh --no-init    # containers only (e.g. after a plain ./stop-replication.sh)
#   ./start-replication.sh --default-ports   # the compose file's own ports (55433…); only
#                                            # when the main stack is NOT running
#
# Afterwards:
#   psql "postgresql://authz:authz@localhost:55536/authz"    # derived subscriber
#   ./db/replication/demo-replication.sh                      # narrated walkthrough
#   ./stop-replication.sh [--clean]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CLEAN=0; INIT=1; DEFAULT_PORTS=0
for arg in "$@"; do
  case "$arg" in
    --clean)         CLEAN=1 ;;
    --no-init)       INIT=0 ;;
    --default-ports) DEFAULT_PORTS=1 ;;
    -h|--help)       sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

# The same two variables the init/demo/test scripts honour.
if [ "$DEFAULT_PORTS" = 1 ]; then
  export REPLICATION_COMPOSE_FILES="compose-replication.yml"
  export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-pgauthz-repl}"
  P=55433; PA=55435; PD=55436; PN=55437
else
  export REPLICATION_COMPOSE_FILES="compose-replication.yml:compose-replication-ports.yml"
  export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-pgauthz-repl}"
  P=55533; PA=55535; PD=55536; PN=55537
fi
COMPOSE=(docker compose)
IFS=: read -ra _files <<< "$REPLICATION_COMPOSE_FILES"
for f in "${_files[@]}"; do COMPOSE+=(-f "$f"); done

if [ "$CLEAN" = 1 ]; then
  echo "==> Removing the previous replication stack and its volumes ($COMPOSE_PROJECT_NAME)..."
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
fi

echo "==> Starting the replication stack ($COMPOSE_PROJECT_NAME)..."
"${COMPOSE[@]}" up -d --wait

if [ "$INIT" = 1 ]; then
  # A primary that already carries the engine was initialised by an earlier
  # run on a kept volume: init would fail on "already exists". Say so instead.
  if "${COMPOSE[@]}" exec -T -e PGPASSWORD=authz authz-primary psql -U authz -d authz -tAc "SELECT to_regclass('authz.materialized_relations') IS NOT NULL" 2>/dev/null | grep -q t; then
    echo "==> Primary is already initialised (kept volume) — skipping init. Use --clean for a fresh start."
  else
    echo "==> Initialising primary and subscribers..."
    ./db/replication/init-replication.sh
  fi
fi

cat <<MSG

Replication stack is up (project $COMPOSE_PROJECT_NAME). User/password: authz/authz, database authz.

  primary (engine, source)        postgresql://authz:authz@localhost:$P/authz
  full replica (tuples + engine)  postgresql://authz:authz@localhost:$PA/authz
  derived subscriber              postgresql://authz:authz@localhost:$PD/authz   -- authz.materialized_relations
  namespace subscriber (dms)      postgresql://authz:authz@localhost:$PN/authz

Keep the derived tables current after writes on the primary (≥ 1 s later):
  docker exec -it \$(docker compose -f compose-replication.yml ps -q authz-primary) psql -U authz -d authz -c "SELECT authz.refresh_materialized_relations();"
Walkthrough:  ./db/replication/demo-replication.sh        Stop:  ./stop-replication.sh [--clean]
MSG
