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
#   ./scripts/release.sh 0.1.4 --auto   # wait for CI green on HEAD, then tag + push
#
# Flags:
#   --push              also `git push origin vX.Y.Z` (the irreversible step)
#   --wait-ci           wait for the GitHub CI run on HEAD to pass before tagging
#                       (HEAD must be pushed; needs the `gh` CLI)
#   --strict-changelog  fail (instead of warn) if the '## [X.Y.Z]' notes are empty
#   --auto              unattended release = --wait-ci + --push + --strict-changelog
#   --allow-branch      skip the "must be on main" guard
#   --allow-dirty       skip the clean-working-tree guard (NOT recommended)
#   -m <message>        tag message (default: "pgauthz vX.Y.Z")
#
# This script does NOT bump versions or commit: bump Chart.yaml + values.yaml,
# add the CHANGELOG section, and commit those FIRST, then run this to tag.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

die() { echo "!! $*" >&2; exit 1; }

# ── Parse args ───────────────────────────────────────────────────────────────
VERSION="" PUSH=0 ALLOW_BRANCH=0 ALLOW_DIRTY=0 MSG="" WAIT_CI=0 STRICT_CHANGELOG=0
while [ $# -gt 0 ]; do
  case "$1" in
    --push)             PUSH=1 ;;
    --wait-ci)          WAIT_CI=1 ;;
    --strict-changelog) STRICT_CHANGELOG=1 ;;
    --auto)             WAIT_CI=1; PUSH=1; STRICT_CHANGELOG=1 ;;
    --allow-branch)     ALLOW_BRANCH=1 ;;
    --allow-dirty)      ALLOW_DIRTY=1 ;;
    -m)                 shift; MSG="${1:-}" ;;
    -*)                 die "unknown flag: $1" ;;
    *)                  [ -z "$VERSION" ] || die "unexpected argument: $1"; VERSION="$1" ;;
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

# Warn (don't block) if that section has no notes. bump-version.sh creates the
# heading but not the body, and tagging an empty section is almost always an
# oversight — extract the lines between this heading and the next '## [' one,
# ignoring blanks and the link-reference lines, and flag if nothing remains.
changelog_body="$(awk -v ver="$VER" '
  $0 ~ "^## \\[" ver "\\]" { insec = 1; next }
  insec && /^## \[/        { exit }
  insec                    { print }
' CHANGELOG.md | grep -vE '^[[:space:]]*$|^\[[^]]+\]:' || true)"
if [ -z "$changelog_body" ]; then
  if [ "$STRICT_CHANGELOG" -eq 1 ]; then
    die "CHANGELOG.md '## [$VER]' section has no notes (required by --auto/--strict-changelog)"
  fi
  changelog_status="## [$VER] is EMPTY"
  echo "!! WARNING: CHANGELOG.md '## [$VER]' section has no notes — add them before publishing." >&2
else
  changelog_status="## [$VER] present"
fi

echo "    branch:    $BRANCH (clean)"
echo "    commit:    $(git rev-parse --short HEAD)  $(git log -1 --pretty=%s)"
echo "    chart:     version=$chart_version appVersion=$chart_appver"
echo "    changelog: $changelog_status"

# ── Wait for CI (--wait-ci / --auto) ─────────────────────────────────────────
# Block until the GitHub Actions run for HEAD passes, so we never tag a red
# commit. HEAD must already be pushed (CI runs against origin).
if [ "$WAIT_CI" -eq 1 ]; then
  command -v gh >/dev/null 2>&1 || die "--wait-ci/--auto needs the GitHub CLI (gh)"
  sha="$(git rev-parse HEAD)"
  git fetch -q origin "$BRANCH" 2>/dev/null || true
  git merge-base --is-ancestor "$sha" "origin/$BRANCH" 2>/dev/null \
    || die "HEAD ($(git rev-parse --short HEAD)) is not on origin/$BRANCH — push the bump commit first"

  echo "==> Waiting for CI on $(git rev-parse --short HEAD)..."
  run_id=""
  for _ in $(seq 1 30); do          # the run can take a moment to register after a push
    run_id="$(gh run list --commit "$sha" -L 1 --json databaseId -q '.[0].databaseId' 2>/dev/null || true)"
    [ -n "$run_id" ] && break
    echo "    no CI run for this commit yet; waiting..."
    sleep 10
  done
  [ -n "$run_id" ] || die "no CI run found for $sha (is it pushed, and is CI enabled?)"

  echo "    watching run $run_id..."
  gh run watch "$run_id" --exit-status --interval 20 >/dev/null \
    || die "CI run $run_id did not succeed — refusing to tag a red commit"
  echo "    CI is green (run $run_id)"
fi

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
