#!/usr/bin/env bash
#
# Print the body of one version's section of CHANGELOG.md — everything after
# the '## [X.Y.Z]' heading up to the next '## [' heading, heading excluded.
# That body is the GitHub release's notes (release.sh --release) and what the
# release cheatsheet pastes by hand.
#
# Usage:
#   ./scripts/changelog-section.sh X.Y.Z [CHANGELOG.md]
#
# Exits 1 (printing nothing) when the section is missing or has no content
# besides blank lines and link-reference lines.
set -euo pipefail

VER="${1:?usage: changelog-section.sh X.Y.Z [file]}"
VER="${VER#v}"
FILE="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/CHANGELOG.md}"

body="$(awk -v ver="$VER" '
  $0 ~ "^## \\[" ver "\\]" { insec = 1; next }
  insec && /^## \[/        { exit }
  insec                    { print }
' "$FILE")"

# content = anything but blank lines and "[name]: url" link references
# (no grep -q here: under pipefail its early exit breaks the pipe to printf
# and fails the pipeline on the very input that has content)
content="$(printf '%s\n' "$body" | grep -vE '^[[:space:]]*$|^\[[^]]+\]:' || true)"
[ -n "$content" ] || exit 1
printf '%s\n' "$body"
