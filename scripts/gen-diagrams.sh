#!/usr/bin/env bash
#
# Regenerate the architecture diagram SVGs in docs/ from their PlantUML
# sources (docs/architecture-*.puml). Unlike gen-schema.sh's output, the
# SVGs ARE committed — GitHub renders them in ARCHITECTURE.md, so re-run
# this after editing a .puml and commit both files:
#   ./scripts/gen-diagrams.sh
#
# Requires plantuml (with graphviz) on PATH — `brew install plantuml` —
# or set PLANTUML to an alternative runner, e.g.:
#   PLANTUML="docker run --rm -v $PWD/docs:/data plantuml/plantuml"
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLANTUML="${PLANTUML:-plantuml}"

cd "$ROOT/docs"
$PLANTUML -tsvg architecture-*.puml

echo "==> Rendered:"
ls -1 architecture-*.svg
