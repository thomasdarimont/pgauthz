#!/usr/bin/env bash
#
# Cut a release tag for pgauthz. Runs preflight checks, then creates an
# annotated git tag (vX.Y.Z) on the current commit. The tag is the point at
# which db/migrations/0001_baseline.sql is frozen — structural changes after a
# release are new db/migrations/NNNN_*.sql files (see docs/adr/0001-schema-migrations.md).
#
# Usage:
#   ./scripts/release.sh 0.1.0          # check + create the local tag
#   ./scripts/release.sh v0.1.0 --push  # ...and push it to origin
#
# Flags:
#   --push            also `git push origin vX.Y.Z` (the irreversible step)
#   --allow-branch    skip the "must be on main" guard
#   --allow-dirty     skip the clean-working-tree guard (NOT recommended)
#   -m <message>      tag message (default: "pgauthz vX.Y.Z")
#
# This script does NOT bump versions or commit: bump Chart.yaml + values.yaml,
# add the CHANGELOG section, and commit those FIRST, then run this to tag.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

die() { echo "!! $*" >&2; exit 1; }

# ── Parse args ───────────────────────────────────────────────────────────────
VERSION="" PUSH=0 ALLOW_BRANCH=0 ALLOW_DIRTY=0 MSG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --push)         PUSH=1 ;;
    --allow-branch) ALLOW_BRANCH=1 ;;
    --allow-dirty)  ALLOW_DIRTY=1 ;;
    -m)             shift; MSG="${1:-}" ;;
    -*)             die "unknown flag: $1" ;;
    *)              [ -z "$VERSION" ] || die "unexpected argument: $1"; VERSION="$1" ;;
  esac
  shift
done

[ -n "$VERSION" ] || die "usage: ./scripts/release.sh <version> [--push]"

# Normalize: accept 0.1.0 or v0.1.0; VER is bare, TAG is v-prefixed.
VER="${VERSION#v}"
TAG="v$VER"
[[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] \
  || die "not a semver version: '$VERSION' (expected X.Y.Z or X.Y.Z-suffix)"
: "${MSG:=pgauthz $TAG}"

echo "==> Releasing $TAG"

# ── Preflight ────────────────────────────────────────────────────────────────
git rev-parse --git-dir >/dev/null 2>&1 || die "not a git repository"

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ "$BRANCH" != "main" ] && [ "$ALLOW_BRANCH" -ne 1 ]; then
  die "on branch '$BRANCH', not 'main' (use --allow-branch to override)"
fi

if [ "$ALLOW_DIRTY" -ne 1 ]; then
  git diff --quiet && git diff --cached --quiet \
    || die "working tree has uncommitted changes — commit the release prep first (or --allow-dirty)"
fi

# Tag must not already exist (locally or on origin).
git rev-parse -q --verify "refs/tags/$TAG" >/dev/null \
  && die "tag $TAG already exists locally (delete with: git tag -d $TAG)"
if git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1; then
  die "tag $TAG already exists on origin"
fi

# Chart version must match the release (single source of the deployed version).
chart_version="$(grep -E '^version:'    deploy/helm/pgauthz/Chart.yaml | awk '{print $2}' | tr -d '"')"
chart_appver="$(grep -E '^appVersion:' deploy/helm/pgauthz/Chart.yaml | awk '{print $2}' | tr -d '"')"
[ "$chart_version" = "$VER" ] \
  || die "Chart.yaml version ($chart_version) != $VER — bump it and commit first"
[ "$chart_appver" = "$VER" ] \
  || die "Chart.yaml appVersion ($chart_appver) != $VER — bump it and commit first"

# CHANGELOG must document this version.
grep -qE "^## \[$VER\]" CHANGELOG.md \
  || die "CHANGELOG.md has no '## [$VER]' section — add release notes first"

echo "    branch:    $BRANCH (clean)"
echo "    commit:    $(git rev-parse --short HEAD)  $(git log -1 --pretty=%s)"
echo "    chart:     version=$chart_version appVersion=$chart_appver"
echo "    changelog: ## [$VER] present"

# ── Tag ──────────────────────────────────────────────────────────────────────
git tag -a "$TAG" -m "$MSG"
echo "==> Created annotated tag $TAG"

if [ "$PUSH" -eq 1 ]; then
  git push origin "$TAG"
  echo "==> Pushed $TAG to origin"
else
  echo "==> Local tag only. Push it with:"
  echo "      git push origin $TAG"
  echo "    (or delete it with: git tag -d $TAG)"
fi
