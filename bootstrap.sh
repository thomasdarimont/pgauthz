#!/usr/bin/env bash
#
# Convenience wrapper: initializes the database and runs all tests.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"$SCRIPT_DIR/init.sh"
"$SCRIPT_DIR/tests/test-all.sh"
