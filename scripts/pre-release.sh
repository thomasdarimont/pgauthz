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
# NOTE: step 3 forces the canonical DEMO-mode stack (OPA on, keycloak/playground
# OFF) regardless of any persisted dev overlays — the test suites are demo/
# trusted-PEP suites and would fail against a keycloak token-only OPA. If you had
# the keycloak/playground overlays running, the script prints a re-apply hint at
# the end.
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

# ── 1. Go build + vet + unit tests ───────────────────────────────────────────
step "Go build + vet + tests (pgauthzd)"
# The unit tests include the OpenAPI contract suite (internal/api/openapi_test.go):
# spec↔route coverage in BOTH directions + response-schema validation, so a
# release cannot ship an openapi.yaml that drifted from the actual routes.
(cd pgauthzd && go build ./... && go vet ./... && go test ./...) || die "pgauthzd build/vet/test failed"
step "Go build + vet (pgauthzctl)"
(cd pgauthzctl && go build ./... && go vet ./...) || die "pgauthzctl build/vet failed"
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

# ── 2c. Policy-hook contract (ADR 0011) ──────────────────────────────────────
# Veto-only is a CONTRACT, not a sandbox — the validator is a REQUIRED release
# gate (a mounted module is placed by its declared package, so an unvalidated
# hook could widen or claim another store). Run it over the shipped examples,
# each tier against its scope, plus the hook `opa test` suite.
step "Policy-hook contract (validate-hooks.sh + opa test)"
if ./scripts/validate-hooks.sh --global examples/opa-hooks/global >/dev/null \
   && ./scripts/validate-hooks.sh --store demo examples/opa-hooks/stores/demo >/dev/null \
   && HOOK_HTTP_CAPABILITIES="$ROOT/examples/opa-hooks-http/http-caps.example.json" \
      ./scripts/validate-hooks.sh --global --allow-http examples/opa-hooks-http >/dev/null \
   && docker run --rm -v "$ROOT/opa/policies:/p:ro" -v "$ROOT/examples/opa-hooks-http:/h:ro" \
      "${OPA_IMAGE:-openpolicyagent/opa:1.18.2}" test /p /h >/dev/null \
   && ./scripts/validate-hooks.sh --lib examples/opa-hooks-lib >/dev/null \
   && docker run --rm -v "$ROOT/opa/policies:/p:ro" -v "$ROOT/examples/opa-hooks-lib:/l:ro" \
      "${OPA_IMAGE:-openpolicyagent/opa:1.18.2}" test /p /l >/dev/null \
   && ./scripts/validate-hooks.sh --global examples/opa-hooks-filtering >/dev/null \
   && docker run --rm -v "$ROOT/opa/policies:/p:ro" -v "$ROOT/examples/opa-hooks-filtering:/f:ro" \
      "${OPA_IMAGE:-openpolicyagent/opa:1.18.2}" test /p /f >/dev/null \
   && docker run --rm -v "$ROOT/opa/policies:/p:ro" -v "$ROOT/examples/opa-hooks:/e:ro" \
        "${OPA_IMAGE:-openpolicyagent/opa:1.18.2}" test /p /e >/dev/null 2>&1; then
    echo "    hooks valid + contract suite green"
else
    echo "!! Policy-hook contract failed (run: ./scripts/validate-hooks.sh --global examples/opa-hooks/global; opa test opa/policies examples/opa-hooks -v)"
    FAILED=1
fi

# ── 3. Full stack tests (CI main job) ────────────────────────────────────────
if [ "$SKIP_STACK" = 0 ]; then
    step "Full stack: ./init.sh + ./tests/test-all.sh (demo mode: OPA on, keycloak/playground off)"
    # Release gate must be deterministic: the test-all suites (test-opa,
    # test-authzen) are DEMO / trusted-PEP suites. A persisted keycloak/playground
    # overlay puts OPA in token-only mode, which those suites correctly fail
    # against. Force the canonical demo stack regardless of local overlay state.
    export PGAUTHZ_OPA=1 PGAUTHZ_KEYCLOAK=0 PGAUTHZ_PLAYGROUND=0
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
if [ "$SKIP_STACK" = 0 ]; then
    echo ""
    echo "    NOTE: the stack is now in DEMO mode (OPA on, keycloak/playground OFF),"
    echo "    and .pgauthz-overlays was reset accordingly. To restore the playground:"
    echo "      ./start.sh --playground        (add --cel / --metrics as you had them)"
fi
