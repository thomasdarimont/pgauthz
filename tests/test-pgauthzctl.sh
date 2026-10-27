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
    # the bindings that were there before (a tenant's group issuer, …): the
    # import --prune below must not leave the deployment without them
    if [ -s /tmp/ctl-it-backup.json ] && [ -x "${CTL:-}" ]; then
        "$CTL" issuers import /tmp/ctl-it-backup.json --prune >/dev/null 2>&1 || true
        rm -f /tmp/ctl-it-backup.json
    fi
    psqlq "DO \$\$ BEGIN PERFORM authz.delete_store('ctl_it_tenant'); EXCEPTION WHEN OTHERS THEN NULL; END \$\$;" >/dev/null 2>&1 || true
    psqlq "DELETE FROM authz.model_registry WHERE name = 'ctl_it_model';" >/dev/null 2>&1 || true
    psqlq "DELETE FROM authz.issuer_bindings WHERE issuer LIKE 'https://ctl-it.example/%' OR description = 'ctl-it over the admin API';" >/dev/null 2>&1 || true
    psqlq "DO \$\$ BEGIN PERFORM authz.delete_store('ctl_it_api', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END \$\$;" >/dev/null 2>&1 || true
    psqlq "DELETE FROM authz.model_registry WHERE name = 'ctl_it_api_model';" >/dev/null 2>&1 || true
    psqlq "DO \$\$ BEGIN PERFORM authz.delete_store('ctl_it_store', p_purge_audit => true); EXCEPTION WHEN OTHERS THEN NULL; END \$\$;" >/dev/null 2>&1 || true
    rm -f /tmp/ctl-it-issuers.json /tmp/ctl-it-issuers-2.json /tmp/ctl-it-flaky.authz.yaml /tmp/pgauthzctl-junit-api.xml
}
trap cleanup EXIT
cleanup

echo "==> Unit tests (the admin-API mode against a fake server) + build..."
(cd "$ROOT/pgauthzctl" && go test ./... && go build -o pgauthzctl .)
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
for pair in demo:demo todo:todo gdrive:gdrive fileshare:fileshare aia-acme:aia_acme agents:agents fourquestions:fourq; do
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
"$CTL" issuers export --out /tmp/ctl-it-backup.json >/dev/null   # restored by cleanup (other rows survive the prune)
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
# (other bindings may exist in the deployment and are pruned too — the backup restores them)
check "issuers import --dry-run reports the update and the prune without applying"     sh -c "'$CTL' issuers import /tmp/ctl-it-issuers.json --prune --dry-run > /tmp/ctl-it-dry.out && grep -q '^~ update https://ctl-it.example/a' /tmp/ctl-it-dry.out && grep -q '^- delete https://ctl-it.example/b' /tmp/ctl-it-dry.out && grep -q '^dry run: 0 to create, 1 to update' /tmp/ctl-it-dry.out && '$CTL' issuers list | grep -q 'ctl-it.example/b'"
check "issuers import --prune updates a and deletes b"     sh -c "'$CTL' issuers import /tmp/ctl-it-issuers.json --prune --performed-by ci | grep -q '0 created, 1 updated, [0-9]* deleted' && ! '$CTL' issuers list | grep -q 'ctl-it.example/b'"
check "the audit trail names the actor"     sh -c "docker exec -i '$DB_CONTAINER' psql -Atq -U authz -d authz -c \"SELECT performed_by FROM authz.list_issuer_bindings_audit('https://ctl-it.example/b', 1)\" | grep -q '^ci\$'"
check_fails "issuers import refuses a bad pattern (the engine's validation)"     sh -c "echo '{\"bindings\":[{\"issuer\":\"https://ctl-it.example/a\",\"stores\":[\"ctl_(\"],\"enabled\":true}]}' > /tmp/ctl-it-issuers-2.json && '$CTL' issuers import /tmp/ctl-it-issuers-2.json"
check "issuers delete drops the row"     sh -c "'$CTL' issuers delete https://ctl-it.example/a | grep -q '^deleted'"
check_fails "issuers delete of a missing row exits non-zero"     "$CTL" issuers delete https://ctl-it.example/a

# The same verbs over the admin API (the long-run transport): the demo
# stack serves it on :8096 behind ADMIN_ROLE=pgauthz_admin; a token of the
# demo issuer with that role is the credential, and the audit names it. The
# narrowing row below lists demo only: the Keycloak overlay binds the demo
# issuer to [demo] in the environment, and a row may only narrow.
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
  {"issuer": "https://auth.example.com", "stores": ["demo"], "db_roles": [], "client_db_roles": {}, "pep_clients": {}, "enabled": true, "description": "ctl-it over the admin API"}
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
    # the model verbs over the admin API: publish a .fga (converted on the
    # server), plan-gated apply into a store created over the API, status,
    # versions, rollout, export (JSON, DSL, SQL), a blocked apply as the error
    check "api: stores — PUT creates the target store (201)" \
        sh -c "curl -sf -o /dev/null -w '%{http_code}' -X PUT '$ADMIN_URL/pgauthz/v1/admin/stores/ctl_it_api' -H \"Authorization: Bearer \$PGAUTHZ_TOKEN\" -H 'Content-Type: application/json' -d '{\"description\":\"ctl-it over the API\"}' | grep -q '^201\$'"
    check "api: model publish v1 from .fga (server-side conversion)" \
        sh -c "'$CTL' model publish '$ROOT/pgauthzctl/testdata/model.fga' --name ctl_it_api_model --message api-v1 | grep -q '^published ctl_it_api_model@1'"
    check "api: model publish is idempotent" \
        sh -c "'$CTL' model publish '$ROOT/pgauthzctl/testdata/model.fga' --name ctl_it_api_model | grep -q '@1\$'"
    check "api: model plan says CAN APPLY" \
        "$CTL" model plan ctl_it_api_model --store ctl_it_api
    check "api: model apply (plan-first on the daemon)" \
        sh -c "'$CTL' model apply ctl_it_api_model --store ctl_it_api | grep -q '^applied ctl_it_api_model@1 to ctl_it_api'"
    check "api: model status shows in_sync" \
        sh -c "'$CTL' model status --store ctl_it_api | grep -q 'ctl_it_api_model@1.*in_sync: true'"
    check "api: model versions lists v1" \
        sh -c "'$CTL' model versions ctl_it_api_model | grep -q '^ctl_it_api_model@1 '"
    check "api: model rollout shows the store at latest" \
        sh -c "'$CTL' model rollout ctl_it_api_model | grep -q '^ctl_it_api  @1/latest 1'"
    check "api: model export JSON, --dsl and --sql" \
        sh -c "'$CTL' model export --store ctl_it_api | grep -q '\"format\": 1' && '$CTL' model export --store ctl_it_api --dsl | grep -q 'type ' && '$CTL' model export --store ctl_it_api --sql | grep -q 'model_register_type'"
    check "api: model diff after a v2 shows the new relation" \
        sh -c "'$CTL' model publish /tmp/ctl-it-v2.fga --name ctl_it_api_model --message api-v2 | grep -q '@2\$' && '$CTL' model diff ctl_it_api_model --store ctl_it_api | grep -q '+ relations can_share'"
    psqlq "SELECT authz.model_register_type('ctl_it_api', 'rogue');
           SELECT authz.model_register_relation('ctl_it_api', 'rogue_rel');
           SELECT authz.model_add_rule('ctl_it_api', 'rogue', 'rogue_rel', 'direct');
           SELECT authz.model_add_type_restriction('ctl_it_api', 'rogue', 'rogue_rel', 'user');
           SELECT authz.write_tuple('ctl_it_api', 'user', 'x', 'rogue_rel', 'rogue', 'r1');" >/dev/null
    check_fails "api: a blocked apply is the error (409 with the plan)" \
        "$CTL" model apply ctl_it_api_model --store ctl_it_api
    check_fails "api: model plan exits non-zero on blockers" \
        "$CTL" model plan ctl_it_api_model --store ctl_it_api
    # the store group: admin API only
    check_fails "api: store verbs refuse to run without --server" \
        sh -c "PGAUTHZ_SERVER= '$CTL' store list"
    check "api: store set creates ctl_it_store" \
        sh -c "'$CTL' store set ctl_it_store --description 'ctl-it store group' | grep -q '^created store ctl_it_store'"
    check "api: store set updates it" \
        sh -c "'$CTL' store set ctl_it_store --docs-url https://example.com/x | grep -q '^updated store ctl_it_store'"
    check "api: store list shows it live and unmanaged" \
        sh -c "'$CTL' store list | grep -q '^ctl_it_store *live *unmanaged'"
    check "api: store get prints the JSON" \
        sh -c "'$CTL' store get ctl_it_store | grep -q '\"docs_url\": \"https://example.com/x\"'"
    check "api: store namespace-grant / namespaces / namespace-revoke" \
        sh -c "'$CTL' store namespace-grant ctl_it_store hr app_hr --read | grep -q 'read=true write=false' && '$CTL' store namespaces ctl_it_store | grep -q 'hr .*access=app_hr:r-' && '$CTL' store namespace-revoke ctl_it_store hr app_hr | grep -q '^removed'"
    check "api: store recorders is empty, recorder-set needs a declared action" \
        sh -c "'$CTL' store recorders ctl_it_store | grep -q '^no allowlists' && ! '$CTL' store recorder-set ctl_it_store svc nope 2>/dev/null"
    check "api: store set --retired, then delete --purge-audit" \
        sh -c "'$CTL' store set ctl_it_store --retired | grep -q '^updated' && '$CTL' store list | grep -q '^ctl_it_store *RETIRED' && '$CTL' store delete ctl_it_store --purge-audit | grep -q '^deleted'"
    # the subject group: data subject requests over the admin API
    check "api: subject objects prints alice's team membership" \
        sh -c "'$CTL' subject objects demo internal_user:alice --object-types team | grep -Eq '^team +member +payroll_team +\(direct\)'"
    check "api: subject objects --csv --out writes the hand-over file" \
        sh -c "'$CTL' subject objects demo internal_user:alice --object-types team --csv --out /tmp/ctl-it-alice.csv && head -1 /tmp/ctl-it-alice.csv | grep -q '^store,subject_type,subject_id,object_type' && grep -q '^demo,internal_user,alice,team,member,payroll_team,' /tmp/ctl-it-alice.csv"
    check "api: subject export prints the export document" \
        sh -c "'$CTL' subject export demo internal_user:alice | grep -q '\"events_about\"'"
    check_fails "api: there is no subject erase verb" \
        "$CTL" subject erase demo internal_user:nobody_ctl
    # model test over the API: the fixture text and the parsed .fga travel,
    # the daemon runs them in an ephemeral store (no database access for the
    # CI job); a live store's scenarios (gdrive's use contextual tuples: the
    # admin pool holds authz_contextual_reader); --junit; a failing check is
    # the non-zero exit; a fixture that cannot run is the daemon's 400
    check "api: model test runs a model_file fixture on the daemon (8 checks + junit)" \
        sh -c "'$CTL' model test '$ROOT/pgauthzctl/testdata/tests.authz.yaml' --junit /tmp/pgauthzctl-junit-api.xml | grep -q '^==> 8 passed, 0 failed' && test -s /tmp/pgauthzctl-junit-api.xml"
    for pair in demo:demo gdrive:gdrive fileshare:fileshare; do
        check "api: examples/models/${pair%%:*}/scenarios.authz.yaml passes against store ${pair##*:}" \
            "$CTL" model test "$ROOT/examples/models/${pair%%:*}/scenarios.authz.yaml" --store "${pair##*:}"
    done
    printf 'tests:\n  - name: nobody reads\n    check:\n      - {user: "user:nobody_ctl", object: "doc:design_spec", assertions: {can_read: true}}\n' > /tmp/ctl-it-flaky.authz.yaml
    check_fails "api: a failing check exits non-zero" \
        "$CTL" model test /tmp/ctl-it-flaky.authz.yaml --store gdrive
    check "api: the failing check is reported by name" \
        sh -c "'$CTL' model test /tmp/ctl-it-flaky.authz.yaml --store gdrive 2>&1 | grep -q 'FAIL  nobody reads'"
    check "api: an engine error inside one check fails that check, not the run (the runner's savepoint)" \
        sh -c "'$CTL' model test /tmp/ctl-it-flaky.authz.yaml --store demo 2>&1 | grep -q 'FAIL  nobody reads.*Unknown type: doc'"
    check "api: a missing store is the daemon's refusal (400), not a crash" \
        sh -c "'$CTL' model test /tmp/ctl-it-flaky.authz.yaml --store ctl_it_no_such_store 2>&1 | grep -q 'Unknown store: ctl_it_no_such_store'"
    check "api: the ephemeral store left no trace" \
        sh -c "docker exec -i '$DB_CONTAINER' psql -Atq -U authz -d authz -c \"SELECT count(*) FROM authz.stores WHERE name LIKE 'pgauthzd_test_%'\" | grep -q '^0\$'"
    # least privilege: the Keycloak overlay's JWT_ISSUERS gives the demo issuer
    # an admin rule for the pgauthz_tester role — test only, on demo only
    if grep -q 'PGAUTHZ_KEYCLOAK="${PGAUTHZ_KEYCLOAK:-1}"' "$ROOT/.pgauthz-overlays" 2>/dev/null; then
        TESTER_TOKEN=$(make_token ctl-tester internal_user '["pgauthz_tester"]')
        check "api: a test-only credential runs the demo scenarios" \
            sh -c "PGAUTHZ_TOKEN='$TESTER_TOKEN' '$CTL' model test '$ROOT/examples/models/demo/scenarios.authz.yaml' --store demo"
        check "api: … and a model file of its own" \
            sh -c "PGAUTHZ_TOKEN='$TESTER_TOKEN' '$CTL' model test '$ROOT/pgauthzctl/testdata/tests.authz.yaml' | grep -q '^==> 8 passed'"
        check "api: … but not another store (outside its rule's stores)" \
            sh -c "PGAUTHZ_TOKEN='$TESTER_TOKEN' '$CTL' model test '$ROOT/examples/models/gdrive/scenarios.authz.yaml' --store gdrive 2>&1 | grep -q \"does not manage store 'gdrive'\""
        check "api: … not --keep-store (platform only)" \
            sh -c "PGAUTHZ_TOKEN='$TESTER_TOKEN' '$CTL' model test '$ROOT/pgauthzctl/testdata/tests.authz.yaml' --keep-store 2>&1 | grep -q 'keep_store'"
        check "api: … and no other verb (403 names the capabilities)" \
            sh -c "PGAUTHZ_TOKEN='$TESTER_TOKEN' '$CTL' store list 2>&1 | grep -q 'may only test'"
    else
        echo "    SKIP  api: test-only credential checks (the admin rule lives in the Keycloak overlay; start with --keycloak)"
    fi
    unset PGAUTHZ_SERVER PGAUTHZ_TOKEN
else
    echo ""
    echo "==> Admin API not served at $ADMIN_URL — the API-mode issuers checks are skipped"
fi

echo ""
echo "==> $pass_count passed, $fail_count failed (of $total checks)"
[ "$fail_count" -eq 0 ]
