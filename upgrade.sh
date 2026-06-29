#!/usr/bin/env bash
#
# Non-destructive, in-place engine upgrade for a local/CI stack: apply only the
# pending structural migrations (db/migrations/, via sqlx) and reload the
# idempotent engine code — WITHOUT dropping the schema. Existing stores, tuples,
# and audit history are preserved.
#
# This is the local analog of deploy/migrations/run-migrations.sh (the
# CloudNativePG path). Use it to upgrade an already-installed engine to the
# current checkout:
#
#   ./init.sh        # fresh install (resets the schema)
#   ...              # write data
#   ./upgrade.sh     # migrate-in-place to the current code (keeps the data)
#
# Implemented as init.sh with the reset disabled (SKIP_RESET=1), so the install
# and upgrade paths stay one code path.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKIP_RESET=1 exec "$SCRIPT_DIR/init.sh" "$@"
