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
#                                       # + publish the GitHub release
#
# Flags:
#   --push              also `git push origin vX.Y.Z` (the irreversible step)
#   --wait-ci           wait for the GitHub CI run on HEAD to pass before tagging
#                       (HEAD must be pushed; needs the `gh` CLI)
#   --strict-changelog  fail (instead of warn) if the '## [X.Y.Z]' notes are empty
#   --release           after the push, publish the GitHub release vX.Y.Z with the
#                       '## [X.Y.Z]' CHANGELOG section as its notes (implies --push;
#                       needs `gh`; checked BEFORE the tag is created, so a missing
#                       section, an existing release or notes over GitHub's size
#                       limit fail with nothing to undo)
#   --auto              unattended release = --wait-ci + --push + --strict-changelog
#                       + --release
#   --allow-branch      skip the "must be on main" guard
#   --allow-dirty       skip the clean-working-tree guard (NOT recommended)
#   -m <message>        tag message (default: "pgauthz vX.Y.Z")
#
# This script does NOT bump versions or commit: bump Chart.yaml + values.yaml,
# add the CHANGELOG section, and commit those FIRST, then run this to tag.
# The CI wait is for HEAD: every push to main after the bump (a late CHANGELOG
# edit, say) gets its own run, and the one for the superseded commit is
# CANCELLED by the workflow's concurrency group — that is not a failure, the
# newer commit's run is the one that counts. Run this script on that commit.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

die() { echo "!! $*" >&2; exit 1; }

# ── Parse args ───────────────────────────────────────────────────────────────
VERSION="" PUSH=0 ALLOW_BRANCH=0 ALLOW_DIRTY=0 MSG="" WAIT_CI=0 STRICT_CHANGELOG=0 RELEASE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --push)             PUSH=1 ;;
    --wait-ci)          WAIT_CI=1 ;;
    --strict-changelog) STRICT_CHANGELOG=1 ;;
    --release)          RELEASE=1; PUSH=1 ;;
    --auto)             WAIT_CI=1; PUSH=1; STRICT_CHANGELOG=1; RELEASE=1 ;;
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
# oversight. changelog-section.sh prints the section body and fails when only
# blanks and link-reference lines remain — the same extraction the GitHub
# release uses for its notes.
changelog_body="$("$ROOT/scripts/changelog-section.sh" "$VER" 2>/dev/null || true)"
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

# ── GitHub release preflight (--release / --auto) ────────────────────────────
# Everything the release step needs is checked here, before the tag exists:
# the notes (the CHANGELOG section, via changelog-section.sh), their size
# against GitHub's limit, and that no release of this version exists yet.
GH_BODY_MAX=125000   # characters, GitHub's release-body limit
notes_file=""
if [ "$RELEASE" -eq 1 ]; then
  command -v gh >/dev/null 2>&1 || die "--release/--auto needs the GitHub CLI (gh)"
  gh auth status >/dev/null 2>&1 || die "gh is not authenticated (gh auth login)"
  notes_file="$(mktemp -t pgauthz-release-notes.XXXXXX)"
  trap 'rm -f "$notes_file"' EXIT
  "$ROOT/scripts/changelog-section.sh" "$VER" > "$notes_file" \
    || die "CHANGELOG.md '## [$VER]' section has no notes — the GitHub release would be empty"
  notes_chars="$(wc -m < "$notes_file" | tr -d ' ')"
  [ "$notes_chars" -le "$GH_BODY_MAX" ] \
    || die "release notes are $notes_chars characters, over GitHub's $GH_BODY_MAX limit — shorten the '## [$VER]' section"
  if gh release view "$TAG" >/dev/null 2>&1; then
    die "GitHub release $TAG already exists (gh release view $TAG)"
  fi
  echo "    release:   notes $(wc -l < "$notes_file" | tr -d ' ') lines / $notes_chars chars, no release $TAG yet"
fi

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
  if ! gh run watch "$run_id" --exit-status --interval 20 >/dev/null; then
    conclusion="$(gh run view "$run_id" --json conclusion -q .conclusion 2>/dev/null || echo unknown)"
    if [ "$conclusion" = "cancelled" ]; then
      echo "!! CI run $run_id was CANCELLED — usually superseded by a newer push to $BRANCH" >&2
      echo "   (the workflow cancels in-progress runs of the same branch). The newer commit" >&2
      echo "   has its own run: pull it and run this script again on that commit." >&2
      die "no green CI run for $(git rev-parse --short HEAD)"
    fi
    die "CI run $run_id did not succeed ($conclusion) — refusing to tag a red commit"
  fi
  echo "    CI is green (run $run_id)"
fi

# ── Tag (signed) ─────────────────────────────────────────────────────────────
# Release tags are SIGNED (SSH signing — see RELEASING.md). Fail with setup
# instructions rather than silently falling back to an unsigned tag.
if [ "$(git config gpg.format || true)" != "ssh" ] || [ -z "$(git config user.signingkey || true)" ]; then
  echo "!! Tag signing is not configured. One-time setup (SSH signing):" >&2
  echo "     git config --global gpg.format ssh" >&2
  echo "     git config --global user.signingkey ~/.ssh/<your-github-key>.pub" >&2
  echo "   Also upload that key to GitHub as a SIGNING key (Settings → SSH and" >&2
  echo "   GPG keys → New SSH key → key type 'Signing Key') so tags show as" >&2
  echo "   Verified. Details: RELEASING.md" >&2
  die "refusing to create an unsigned release tag"
fi
git tag -s "$TAG" -m "$MSG"
echo "==> Created SIGNED tag $TAG ($(git config user.signingkey))"

if [ "$PUSH" -eq 1 ]; then
  git push origin "$TAG"
  echo "==> Pushed $TAG to origin"
  if [ "$RELEASE" -eq 1 ]; then
    # --verify-tag: the release is created only for the tag that is on origin.
    if url="$(gh release create "$TAG" --title "$TAG" --verify-tag --notes-file "$notes_file")"; then
      echo "==> Published GitHub release $TAG: $url"
    else
      # the tag is out; the release is the one step left, and it can be redone
      echo "!! The tag is pushed but the GitHub release failed. Create it by hand:" >&2
      echo "     gh release create $TAG --title $TAG --verify-tag \\" >&2
      echo "       --notes-file <(./scripts/changelog-section.sh $VER)" >&2
      exit 1
    fi
  fi
else
  echo "==> Local tag only. Push it with:"
  echo "      git push origin $TAG"
  echo "    (or delete it with: git tag -d $TAG)"
fi
