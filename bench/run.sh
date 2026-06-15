#!/usr/bin/env bash
#
# Runs pgauthz benchmark suites and prints their result tables.
#
#   ./bench/run.sh                 # run all suites in bench/suites/
#   ./bench/run.sh drive           # run one suite
#   ./bench/run.sh drive github    # run several
#
# Each suite (bench/suites/<name>.sql) builds its own model + data and times
# scenarios via the shared harness (bench/lib/harness.sql). Requires init.sh to
# have installed the engine.
set -euo pipefail

# Resolve our own dir BEFORE sourcing env.sh (which redefines SCRIPT_DIR).
BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$BENCH_DIR/../env.sh" >/dev/null

# Which suites? Args, or every suite file by default.
if [ "$#" -gt 0 ]; then
    suites=("$@")
else
    suites=()
    for f in "$BENCH_DIR"/suites/*.sql; do
        suites+=("$(basename "$f" .sql)")
    done
fi

for name in "${suites[@]}"; do
    file="$BENCH_DIR/suites/$name.sql"
    if [ ! -f "$file" ]; then
        echo "!! unknown suite '$name' (expected $file)" >&2
        echo "   available: $(cd "$BENCH_DIR/suites" && ls *.sql 2>/dev/null | sed 's/\.sql//' | tr '\n' ' ')" >&2
        exit 1
    fi
    echo ""
    echo "==> Benchmark suite: $name"
    echo ""
    # Harness + suite in one psql session so the suite can call pg_temp helpers.
    cat "$BENCH_DIR/lib/harness.sql" "$file" \
      | docker exec -i -e PGPASSWORD=authz "$DB_CONTAINER" \
          psql -v ON_ERROR_STOP=1 -U "$PG_USER" -d "$PG_DB" 2>&1 \
      | sed -n 's/^INFO:  //p'
done
