#!/usr/bin/env bash
#
# Local pre-release verification — run BEFORE pushing the release work
# (and before bump-version.sh / release.sh, which handle versioning and
# tagging). Mirrors CI's main job locally plus artifact-freshness checks
# CI doesn't have:
#
#   1. Go build + vet (authzen + playground BFF)        — fast fail
#   2. Regenerate the architecture diagrams and fail if the committed
#      SVGs were stale (they are committed; CI has no freshness gate)
#   3. Full stack: ./init.sh + ./tests/test-all.sh (SQL + OPA + AuthZEN
#      + Go suites — the thing that catches demo-model/count regressions
#      before CI does)
#   4. Warn if CHANGELOG's [Unreleased] section is empty
#
# Usage:
#   ./scripts/pre-release.sh                # everything
#   ./scripts/pre-release.sh --skip-stack   # skip init.sh + test-all.sh (fast checks only)
#   ./scripts/pre-release.sh --skip-diagrams
#
# NOTE: step 3 recreates the compose stack from the BASE files — if you run
# the keycloak/playground overlays, their opa/authzen-opa env is reset (the
# script prints the re-apply hint at the end).
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
die() { echo "!! $*" >&2; exit 1; }
step() { echo ""; echo "==> $*"; }

SKIP_STACK=0
SKIP_DIAGRAMS=0
for arg in "$@"; do
    case "$arg" in
        --skip-stack)    SKIP_STACK=1 ;;
        --skip-diagrams) SKIP_DIAGRAMS=1 ;;
        *) die "unknown flag: $arg" ;;
    esac
done

cd "$ROOT"
FAILED=0

# ── 1. Go build + vet ────────────────────────────────────────────────────────
step "Go build + vet (authzen)"
(cd pgauthzd && go build ./... && go vet ./...) || die "pgauthzd build/vet failed"
step "Go build + vet (authzctl)"
(cd authzctl && go build ./... && go vet ./...) || die "authzctl build/vet failed"
if [ -d playground/backend ]; then
    step "Go build + vet (playground BFF)"
    (cd playground/backend && go build ./... && go vet ./...) || die "playground BFF build/vet failed"
fi

# ── 2. Diagram freshness ─────────────────────────────────────────────────────
if [ "$SKIP_DIAGRAMS" = 0 ]; then
    step "Regenerating architecture diagrams"
    ./scripts/gen-diagrams.sh >/dev/null
    if ! git diff --quiet -- docs/'architecture-*.svg'; then
        echo "!! Committed diagram renders were STALE — regenerated now:"
        git diff --stat -- docs/'architecture-*.svg' | sed 's/^/     /'
        echo "   Review + commit the updated SVGs before releasing."
        FAILED=1
    else
        echo "    diagrams up to date"
    fi
fi

# ── 2b. Helm policy-copy freshness ───────────────────────────────────────────
# The chart ships a COPY of the OPA policies (deploy/helm/pgauthz/files/opa/
# policies). It has drifted silently before — fail the release if it differs
# from the source of truth.
step "Helm OPA policy copy in sync"
if ! diff -rq opa/policies deploy/helm/pgauthz/files/opa/policies >/dev/null; then
    echo "!! Helm policy copy is STALE — sync it:"
    echo "     cp opa/policies/*.rego deploy/helm/pgauthz/files/opa/policies/"
    diff -rq opa/policies deploy/helm/pgauthz/files/opa/policies | sed 's/^/     /' || true
    FAILED=1
else
    echo "    policies in sync"
fi

# ── 3. Full stack tests (CI main job) ────────────────────────────────────────
if [ "$SKIP_STACK" = 0 ]; then
    step "Full stack: ./init.sh + ./tests/test-all.sh"
    ./init.sh
    ./tests/test-all.sh || die "test-all.sh failed"
else
    echo ""
    echo "==> SKIPPED stack tests (--skip-stack) — CI is the only test gate now"
fi

# ── 4. CHANGELOG sanity ──────────────────────────────────────────────────────
step "CHANGELOG check"
UNREL="$(awk '/^## \[Unreleased\]/{f=1;next} /^## \[/{f=0} f' CHANGELOG.md | grep -vE '^\s*$' || true)"
if [ -z "$UNREL" ]; then
    echo "    note: CHANGELOG [Unreleased] is empty — fine if the bump already rolled it"
else
    echo "    [Unreleased] has content ($(echo "$UNREL" | grep -c '^- \|^### ' || true) lines) — bump-version.sh will roll it"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
if [ "$FAILED" != 0 ]; then
    die "pre-release checks FAILED (see above)"
fi
echo "==> Pre-release checks passed."
echo "    Next: commit/push, wait for CI, then scripts/bump-version.sh + scripts/release.sh"
if [ "$SKIP_STACK" = 0 ] && docker ps --format '{{.Names}}' 2>/dev/null | grep -q playground-bff; then
    echo ""
    echo "    NOTE: init.sh reset opa/authzen-opa to the base compose env."
    echo "    Re-apply the playground overrides:"
    echo "      docker compose -f compose.yml -f compose-authzen.yml \\"
    echo "        -f compose-keycloak.yml -f compose-playground.yml up -d --no-deps opa authzen-opa"
fi
