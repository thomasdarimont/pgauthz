#!/usr/bin/env bash
#
# Convenience wrapper: initializes the database and runs all tests.
#
# Options:
#   --cel        Build/enable the pg_cel extension (extensions/pg-cel) so
#                lang='cel' conditions work. Equivalent to PGAUTHZ_CEL=1.
#                The CEL end-to-end tests run instead of being skipped.
#
# Examples:
#   ./bootstrap.sh
#   ./bootstrap.sh --cel
#   PGAUTHZ_CEL=1 ./bootstrap.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for arg in "$@"; do
  case "$arg" in
    --cel)      export PGAUTHZ_CEL=1 ;;
    -h|--help)  sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [ "${PGAUTHZ_CEL:-0}" != "0" ]; then
  echo "==> CEL enabled (pg_cel will be built into the Postgres image)"
fi

# The default stack is OPA-free, but the OPA + AuthZEN-OPA integration suites
# need OPA — so bootstrap enables it by default. Run PGAUTHZ_OPA=0 ./bootstrap.sh
# to exercise the OPA-free suite (those two suites then skip).
export PGAUTHZ_OPA="${PGAUTHZ_OPA:-1}"

"$SCRIPT_DIR/init.sh"
"$SCRIPT_DIR/tests/test-all.sh"
