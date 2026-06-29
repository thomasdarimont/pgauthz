#!/usr/bin/env bash
#
# Bump the project version across every pinned reference and roll the CHANGELOG.
# EDIT-ONLY: this does NOT commit or tag. Review the diff, commit, then tag with
# scripts/release.sh:
#
#   ./scripts/bump-version.sh 0.1.1     # edits version refs + CHANGELOG
#   git diff                            # review
#   git commit -am "Bump version to 0.1.1"
#   ./scripts/release.sh 0.1.1          # preflight + annotated tag
#
# The current version is read from deploy/helm/pgauthz/Chart.yaml (the single
# source). Touches: Chart.yaml (version + appVersion), values.yaml (image tags),
# start.sh (IMAGE_TAG default + doc comment), and CHANGELOG.md (rolls the
# [Unreleased] section to [X.Y.Z] and updates the compare links).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
die() { echo "!! $*" >&2; exit 1; }

NEW="${1:-}"; NEW="${NEW#v}"
[ -n "$NEW" ] || die "usage: ./scripts/bump-version.sh <new-version>   (e.g. 0.1.1)"
[[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] \
  || die "not a semver version: '$NEW' (expected X.Y.Z or X.Y.Z-suffix)"

CHART=deploy/helm/pgauthz/Chart.yaml
VALUES=deploy/helm/pgauthz/values.yaml
START=deploy/helm/pgauthz/start.sh
CL=CHANGELOG.md

CUR="$(grep -E '^version:' "$CHART" | awk '{print $2}' | tr -d '"')"
[ -n "$CUR" ] || die "could not read current version from $CHART"
[ "$CUR" != "$NEW" ] || die "version is already $NEW"
CUR_RE="${CUR//./\\.}"   # escape dots for use in regex

# date is fine here — this is a normal local script (not a Workflow runtime).
DATE="$(date +%F)"

echo "==> Bumping $CUR -> $NEW"

# Strip the .bak files sed -i.bak leaves (portable across BSD/GNU sed).
edit() { sed -i.bak "$@" && rm -f "${@: -1}.bak"; }

# 1. Chart.yaml — version + appVersion
edit -E -e "s/^(version: ).*/\1$NEW/" -e "s/^(appVersion: ).*/\1\"$NEW\"/" "$CHART"

# 2. values.yaml — image tags (tag: "CUR" -> "NEW")
grep -q "tag: \"$CUR\"" "$VALUES" || die "no image tags pinned to $CUR in $VALUES"
edit "s/tag: \"$CUR_RE\"/tag: \"$NEW\"/g" "$VALUES"

# 3. start.sh — IMAGE_TAG default and the doc comment (only version refs there)
edit "s/$CUR_RE/$NEW/g" "$START"

# 4. CHANGELOG.md — roll [Unreleased] to a new [X.Y.Z] section + fix compare links
grep -q "^## \[$NEW\]" "$CL" && die "CHANGELOG.md already has a [$NEW] section"
base="$(grep -E '^\[Unreleased\]:' "$CL" | sed -E 's#^\[Unreleased\]: (.*)/compare/.*#\1#')"
[ -n "$base" ] || die "could not derive repo URL from the [Unreleased] link in $CL"

# Insert the new version heading right after '## [Unreleased]' so any notes
# accumulated under Unreleased move under [X.Y.Z], leaving a fresh Unreleased.
awk -v ver="$NEW" -v date="$DATE" '
  { print }
  /^## \[Unreleased\]/ && !h { print ""; print "## [" ver "] - " date; h=1 }
' "$CL" > "$CL.tmp" && mv "$CL.tmp" "$CL"

# Point [Unreleased] at vNEW...HEAD and add a [NEW] compare link below it.
edit -E "s#^(\[Unreleased\]: ).*#\1$base/compare/v$NEW...HEAD#" "$CL"
awk -v ver="$NEW" -v cur="$CUR" -v base="$base" '
  { print }
  /^\[Unreleased\]:/ && !h { print "[" ver "]: " base "/compare/v" cur "...v" ver; h=1 }
' "$CL" > "$CL.tmp" && mv "$CL.tmp" "$CL"

echo "==> Updated:"
echo "    $CHART        version + appVersion -> $NEW"
echo "    $VALUES       image tags -> $NEW"
echo "    $START        IMAGE_TAG default -> $NEW"
echo "    $CL           added '## [$NEW] - $DATE' (fill in the notes)"
echo ""
echo "==> Next:"
echo "      \$EDITOR $CL          # write the $NEW release notes"
echo "      git diff                       # review"
echo "      git commit -am \"Bump version to $NEW\""
echo "      ./scripts/release.sh $NEW      # preflight + tag"
