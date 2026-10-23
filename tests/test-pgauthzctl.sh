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
    psqlq "DELETE FROM authz.issuer_bindings WHERE issuer LIKE 'https://ctl-it.example/%' OR description = 'ctl-it over the admin API';" >/dev/null 2>&1 || true
    rm -f /tmp/ctl-it-issuers.json /tmp/ctl-it-issuers-2.json
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

# The examples' scenarios against the live fixture stores test.sh loads
# (--store: the store's current model, copied into the ephemeral store).
for pair in demo:demo todo:todo gdrive:gdrive aia-acme:aia_acme agents:agents fourquestions:fourq; do
    check "examples/models/${pair%%:*}/scenarios.authz.yaml passes against store ${pair##*:}" \
        "$CTL" model test "$ROOT/examples/models/${pair%%:*}/scenarios.authz.yaml" --store "${pair##*:}"
done

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

# Blocked plan exits non-zero (extra type in the store, still referenced by a
# tuple — an unreferenced extra type is removed by apply, not a blocker) — CI-gateable.
psqlq "SELECT authz.model_register_type('ctl_it_tenant', 'rogue');
       SELECT authz.model_register_relation('ctl_it_tenant', 'rogue_rel');
       SELECT authz.model_add_rule('ctl_it_tenant', 'rogue', 'rogue_rel', 'direct');
       SELECT authz.model_add_type_restriction('ctl_it_tenant', 'rogue', 'rogue_rel', 'user');
       SELECT authz.write_tuple('ctl_it_tenant', 'user', 'x', 'rogue_rel', 'rogue', 'r1');" >/dev/null
check_fails "plan exits non-zero on blockers" \
    "$CTL" model plan ctl_it_model --store ctl_it_tenant

# Issuer bindings as code: import (create), list, export round trip, import
# with an update and a prune (one transaction), dry run, delete, the
# engine's validation surfacing as a non-zero exit.
echo ""
echo "==> Running pgauthzctl issuers checks..."
echo ""
cat > /tmp/ctl-it-issuers.json <<'JSON'
{"bindings": [
  {"issuer": "https://ctl-it.example/a", "stores": ["ctl_a_.*"], "db_roles": [], "client_db_roles": {}, "pep_clients": {"gw": ["ctl_a_docs"]}, "enabled": true, "description": "tenant a"},
  {"issuer": "https://ctl-it.example/b", "stores": ["ctl_b"], "db_roles": ["app_b"], "client_db_roles": {"svc": "app_b"}, "pep_clients": {}, "enabled": false}
]}
JSON
check "issuers import creates two bindings"     sh -c "'$CTL' issuers import /tmp/ctl-it-issuers.json | grep -q '2 created, 0 updated, 0 deleted'"
check "issuers list shows them (one disabled)"     sh -c "'$CTL' issuers list | grep -q 'ctl-it.example/b *DISABLED'"
check "issuers import is idempotent"     sh -c "'$CTL' issuers import /tmp/ctl-it-issuers.json | grep -q '^no changes'"
check "issuers export round-trips the file"     sh -c "'$CTL' issuers export --out /tmp/ctl-it-issuers-2.json && '$CTL' issuers import /tmp/ctl-it-issuers-2.json | grep -q '^no changes'"
cat > /tmp/ctl-it-issuers.json <<'JSON'
{"bindings": [
  {"issuer": "https://ctl-it.example/a", "stores": ["ctl_a_docs"], "db_roles": [], "client_db_roles": {}, "pep_clients": {"gw": ["ctl_a_docs"]}, "enabled": true, "description": "tenant a, narrowed"}
]}
JSON
check "issuers import --dry-run reports the update and the prune without applying"     sh -c "'$CTL' issuers import /tmp/ctl-it-issuers.json --prune --dry-run | grep -q '^dry run: 0 to create, 1 to update, 1 to delete' && '$CTL' issuers list | grep -q 'ctl-it.example/b'"
check "issuers import --prune updates a and deletes b"     sh -c "'$CTL' issuers import /tmp/ctl-it-issuers.json --prune --performed-by ci | grep -q '0 created, 1 updated, 1 deleted'"
check "the audit trail names the actor"     sh -c "docker exec -i '$DB_CONTAINER' psql -Atq -U authz -d authz -c \"SELECT performed_by FROM authz.list_issuer_bindings_audit('https://ctl-it.example/b', 1)\" | grep -q '^ci\$'"
check_fails "issuers import refuses a bad pattern (the engine's validation)"     sh -c "echo '{\"bindings\":[{\"issuer\":\"https://ctl-it.example/a\",\"stores\":[\"ctl_(\"],\"enabled\":true}]}' > /tmp/ctl-it-issuers-2.json && '$CTL' issuers import /tmp/ctl-it-issuers-2.json"
check "issuers delete drops the row"     sh -c "'$CTL' issuers delete https://ctl-it.example/a | grep -q '^deleted'"
check_fails "issuers delete of a missing row exits non-zero"     "$CTL" issuers delete https://ctl-it.example/a

# The same verbs over the admin API (the long-run transport): the demo
# stack serves it on :8096 behind ADMIN_ROLE=pgauthz_admin; a token of the
# demo issuer with that role is the credential, and the audit names it.
ADMIN_URL="${PGAUTHZD_ADMIN_URL:-http://localhost:8096}"
if curl -sf "$ADMIN_URL/livez" >/dev/null 2>&1; then
    echo ""
    echo "==> Running pgauthzctl issuers checks over the admin API ($ADMIN_URL)..."
    echo ""
    # shellcheck source=lib/make-token.sh
    source "$SCRIPT_DIR/lib/make-token.sh"
    export PGAUTHZ_SERVER="$ADMIN_URL"
    export PGAUTHZ_TOKEN
    PGAUTHZ_TOKEN=$(make_token ctl-ops internal_user '["pgauthz_admin"]')
    cat > /tmp/ctl-it-issuers.json <<'JSON'
{"bindings": [
  {"issuer": "https://auth.example.com", "stores": ["demo", "todo", "gdrive", "aia_acme", "agents", "fourq", "authzen_cert", "console.*"], "db_roles": [], "client_db_roles": {}, "pep_clients": {}, "enabled": true, "description": "ctl-it over the admin API"}
]}
JSON
    echo '{"bindings":[{"issuer":"https://ctl-it.example/api","stores":["x"],"enabled":true}]}' > /tmp/ctl-it-issuers-2.json
    check "api: issuers list answers with the revision" \
        sh -c "'$CTL' issuers list | grep -q '^revision '"
    check "api: an untrusted issuer is refused by the daemon (cannot add trust)" \
        sh -c "'$CTL' issuers import /tmp/ctl-it-issuers-2.json 2>&1 | grep -q 'cannot add trust'"
    check "api: issuers import binds the demo issuer (a narrowing row)" \
        sh -c "'$CTL' issuers import /tmp/ctl-it-issuers.json | grep -q 'applied over the admin API: 1 created'"
    check "api: the audit names the token's subject, not a flag" \
        sh -c "docker exec -i '$DB_CONTAINER' psql -Atq -U authz -d authz -c \"SELECT performed_by FROM authz.list_issuer_bindings_audit('https://auth.example.com', 1)\" | grep -q '^internal_user:ctl-ops\$'"
    check "api: issuers export round-trips" \
        sh -c "'$CTL' issuers export --out /tmp/ctl-it-issuers-2.json && '$CTL' issuers import /tmp/ctl-it-issuers-2.json | grep -q '^no changes'"
    check "api: issuers delete restores the environment binding" \
        sh -c "'$CTL' issuers delete https://auth.example.com | grep -q '^deleted'"
    check_fails "api: a token without the admin role is refused (403)" \
        sh -c "PGAUTHZ_TOKEN=\$(make_token ctl-nobody internal_user '[]') '$CTL' issuers list"
    unset PGAUTHZ_SERVER PGAUTHZ_TOKEN
else
    echo ""
    echo "==> Admin API not served at $ADMIN_URL — the API-mode issuers checks are skipped"
fi

echo ""
echo "==> $pass_count passed, $fail_count failed (of $total checks)"
[ "$fail_count" -eq 0 ]
