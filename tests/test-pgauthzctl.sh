#!/usr/bin/env bash
#
# Integration test for the pgauthzctl model-as-code CLI: builds the binary and
# exercises the full model lifecycle (publish → plan-gated apply → evolve →
# diff/plan → apply → rollout) plus the fixture test runner, against the
# running dev stack. Requires init.sh (engine + registry installed) and Go.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."

export PGAUTHZ_DSN="${PGAUTHZ_DSN:-postgres://authz:${PG_PASSWORD:-authz}@localhost:${PG_PORT:-55433}/authz}"

DB_CONTAINER=$(docker ps --format '{{.Names}}' | grep -E 'authz-db|authz-primary' | head -1)
psqlq() { docker exec -i "$DB_CONTAINER" psql -q -v ON_ERROR_STOP=1 -U authz -d authz -c "$1"; }

pass_count=0
fail_count=0
total=0

check() {
    local description="$1"; shift
    total=$((total + 1))
    if "$@" > /tmp/pgauthzctl-test-out 2>&1; then
        pass_count=$((pass_count + 1))
        echo "    PASS  $description"
    else
        fail_count=$((fail_count + 1))
        echo "    FAIL  $description"
        sed 's/^/          /' /tmp/pgauthzctl-test-out | tail -5
    fi
}

check_fails() {
    local description="$1"; shift
    total=$((total + 1))
    if "$@" > /tmp/pgauthzctl-test-out 2>&1; then
        fail_count=$((fail_count + 1))
        echo "    FAIL  $description (expected non-zero exit)"
    else
        pass_count=$((pass_count + 1))
        echo "    PASS  $description"
    fi
}

cleanup() {
    psqlq "DO \$\$ BEGIN PERFORM authz.delete_store('ctl_it_tenant'); EXCEPTION WHEN OTHERS THEN NULL; END \$\$;" >/dev/null 2>&1 || true
    psqlq "DELETE FROM authz.model_registry WHERE name = 'ctl_it_model';" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

echo "==> Building pgauthzctl..."
(cd "$ROOT/pgauthzctl" && go build -o pgauthzctl .)
CTL="$ROOT/pgauthzctl/pgauthzctl"

echo ""
echo "==> Running pgauthzctl lifecycle checks..."
echo ""

check "version prints" \
    sh -c "'$CTL' version | grep -q '^pgauthzctl '"

# Fixture test runner (ephemeral store, hermetic).
check "model test fixture passes (8 checks + junit)" \
    "$CTL" model test "$ROOT/pgauthzctl/testdata/tests.authz.yaml" --junit /tmp/pgauthzctl-junit.xml
check "junit file written" test -s /tmp/pgauthzctl-junit.xml

# Lifecycle: publish v1 → apply (plan-gated) → status.
check "publish v1 from .fga" \
    "$CTL" model publish "$ROOT/pgauthzctl/testdata/model.fga" --name ctl_it_model --message it-v1
psqlq "SELECT authz.create_store('ctl_it_tenant');" >/dev/null
check "plan-gated apply v1" \
    "$CTL" model apply ctl_it_model --store ctl_it_tenant --plan-first
check "status shows in_sync" \
    sh -c "'$CTL' model status --store ctl_it_tenant | grep -q 'ctl_it_model@1.*in_sync: true'"

# Evolve → v2 → plan/diff/apply → rollout.
sed 's/define can_write: owner/define can_write: owner\n    define can_share: owner/' \
    "$ROOT/pgauthzctl/testdata/model.fga" > /tmp/ctl-it-v2.fga
check "publish v2" \
    "$CTL" model publish /tmp/ctl-it-v2.fga --name ctl_it_model --message it-v2
check "diff shows the new relation" \
    sh -c "'$CTL' model diff ctl_it_model --store ctl_it_tenant | grep -q '+ relations can_share'"
check "plan verdict CAN APPLY" \
    "$CTL" model plan ctl_it_model --store ctl_it_tenant
check "apply v2" \
    "$CTL" model apply ctl_it_model --store ctl_it_tenant
check "rollout shows v2 = latest" \
    sh -c "'$CTL' model rollout ctl_it_model | grep -q '@2/latest 2'"

# Blocked plan exits non-zero (extra type in the store) — CI-gateable.
psqlq "SELECT authz.model_register_type('ctl_it_tenant', 'rogue');" >/dev/null
check_fails "plan exits non-zero on blockers" \
    "$CTL" model plan ctl_it_model --store ctl_it_tenant

echo ""
echo "==> $pass_count passed, $fail_count failed (of $total checks)"
[ "$fail_count" -eq 0 ]
