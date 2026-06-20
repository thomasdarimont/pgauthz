#!/usr/bin/env bash
#
# Single-sources the OPA policies + JWKS into the chart's files/ tree so Helm
# can embed them in ConfigMaps (.Files.Glob cannot read outside the chart dir).
# Re-run after editing opa/policies or opa/data, before `helm package`.
#
# The engine SQL is NOT copied here — it is baked into the pgauthz-migrations
# image (deploy/migrations/Dockerfile) and stays single-sourced from db/.
set -euo pipefail

CHART_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$CHART_DIR/../../.." && pwd)"

mkdir -p "$CHART_DIR/files/opa/policies" "$CHART_DIR/files/opa/data"
rm -f "$CHART_DIR"/files/opa/policies/*.rego
cp "$REPO_ROOT"/opa/policies/*.rego "$CHART_DIR/files/opa/policies/"
cp "$REPO_ROOT"/opa/data/jwks.json  "$CHART_DIR/files/opa/data/"

echo "Synced $(ls "$CHART_DIR"/files/opa/policies/*.rego | wc -l | tr -d ' ') policies + jwks.json into the chart."
