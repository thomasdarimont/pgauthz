#!/usr/bin/env bash
#
# Tests the OPA + Zanzibar (PostgreSQL) integration.
# Requires bootstrap.sh to have been run first.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OPA_URL="${OPA_URL:-http://localhost:8181}"
ADMIN_TOKEN="${OPA_ADMIN_TOKEN:-change-me-in-production}"

pass_count=0
fail_count=0
total=0

check() {
    local description="$1"
    local endpoint="$2"
    local input="$3"
    local expected="$4"

    total=$((total + 1))

    result=$(curl -sf -X POST "$OPA_URL/v1/data/$endpoint" \
        -H "Content-Type: application/json" \
        -d "$input" 2>/dev/null) || {
        fail_count=$((fail_count + 1))
        echo "    FAIL  $description  (HTTP error)"
        return
    }

    # Extract the result value
    actual=$(echo "$result" | jq -r '.result')

    if [ "$actual" = "$expected" ]; then
        pass_count=$((pass_count + 1))
        echo "    PASS  $description"
    else
        fail_count=$((fail_count + 1))
        echo "    FAIL  $description  (expected=$expected, got=$actual)"
    fi
}

# Verify an HTTP request returns an expected status code.
# Usage: check_http "description" expected_status curl_args...
check_http() {
    local description="$1"
    local expected_status="$2"
    shift 2

    total=$((total + 1))

    actual_status=$(curl -s -o /dev/null -w "%{http_code}" "$@" 2>/dev/null) || actual_status="000"

    if [ "$actual_status" = "$expected_status" ]; then
        pass_count=$((pass_count + 1))
        echo "    PASS  $description"
    else
        fail_count=$((fail_count + 1))
        echo "    FAIL  $description  (expected HTTP $expected_status, got $actual_status)"
    fi
}

echo "==> Waiting for OPA..."
for i in $(seq 1 30); do
    if curl -sf "$OPA_URL/health" > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

echo "==> Waiting for a warm PostgREST schema cache (via OPA)..."
# PostgREST is not exposed to the host. On a freshly started stack it may have
# connected before the engine schema existed and be serving a stale/empty
# schema cache (init.sh sends a reload). Wait until a KNOWN demo grant actually
# resolves true through OPA -> PostgREST, so the suite never runs against a
# cold cache. (The demo store is loaded by test.sh before this script.)
for i in $(seq 1 60); do
    result=$(curl -sf -X POST "$OPA_URL/v1/data/authz/allow" \
        -H "Content-Type: application/json" \
        -d '{"input":{"subject":{"type":"internal_user","id":"alice"},"action":"can_read","resource":{"type":"document","id":"doc_payroll_001"}}}' 2>/dev/null)
    if [ "$(echo "$result" | jq -r '.result' 2>/dev/null)" = "true" ]; then
        break
    fi
    sleep 1
done

echo ""
echo "==> Running OPA + Zanzibar authorization checks..."
echo ""

# --- Access checks (allow) ---

check "Alice can read payroll doc" \
    "authz/allow" \
    '{"input":{"subject":{"type":"internal_user","id":"alice"},"action":"can_read","resource":{"type":"document","id":"doc_payroll_001"}}}' \
    "true"

check "Alice can edit payroll doc" \
    "authz/allow" \
    '{"input":{"subject":{"type":"internal_user","id":"alice"},"action":"can_edit","resource":{"type":"document","id":"doc_payroll_001"}}}' \
    "true"

check "Alice cannot read tax doc (wrong team)" \
    "authz/allow" \
    '{"input":{"subject":{"type":"internal_user","id":"alice"},"action":"can_read","resource":{"type":"document","id":"doc_tax_001"}}}' \
    "false"

check "Bob (advisor) can read payroll doc" \
    "authz/allow" \
    '{"input":{"subject":{"type":"internal_user","id":"bob"},"action":"can_read","resource":{"type":"document","id":"doc_payroll_001"}}}' \
    "true"

check "Carol (client org) can read client-space doc" \
    "authz/allow" \
    '{"input":{"subject":{"type":"client_user","id":"carol"},"action":"can_read","resource":{"type":"document","id":"doc_client_001"}}}' \
    "true"

check "Carol cannot edit client-space doc" \
    "authz/allow" \
    '{"input":{"subject":{"type":"client_user","id":"carol"},"action":"can_edit","resource":{"type":"document","id":"doc_client_001"}}}' \
    "false"

check "Eva (accounting_team) can read accounting doc" \
    "authz/allow" \
    '{"input":{"subject":{"type":"internal_user","id":"eva"},"action":"can_read","resource":{"type":"document","id":"doc_acc_001"}}}' \
    "true"

check "Eva cannot read payroll doc" \
    "authz/allow" \
    '{"input":{"subject":{"type":"internal_user","id":"eva"},"action":"can_read","resource":{"type":"document","id":"doc_payroll_001"}}}' \
    "false"

check "Frank (tax_team) can edit tax doc" \
    "authz/allow" \
    '{"input":{"subject":{"type":"internal_user","id":"frank"},"action":"can_edit","resource":{"type":"document","id":"doc_tax_001"}}}' \
    "true"

check "Dave cannot read private doc (only carol)" \
    "authz/allow" \
    '{"input":{"subject":{"type":"client_user","id":"dave"},"action":"can_read","resource":{"type":"document","id":"doc_client_private_001"}}}' \
    "false"

check "Carol can read private doc via viewer" \
    "authz/allow" \
    '{"input":{"subject":{"type":"client_user","id":"carol"},"action":"can_read","resource":{"type":"document","id":"doc_client_private_001"}}}' \
    "true"

# --- Resource search (accessible_objects) ---

echo ""
echo "==> Running OPA + Zanzibar search checks..."
echo ""

result=$(curl -sf -X POST "$OPA_URL/v1/data/authz/accessible_objects" \
    -H "Content-Type: application/json" \
    -d '{"input":{"subject":{"type":"internal_user","id":"bob"},"action":"can_read","resource":{"type":"document"}}}')

total=$((total + 1))
count=$(echo "$result" | jq '.result | length')
if [ "$count" = "3" ]; then
    pass_count=$((pass_count + 1))
    echo "    PASS  Bob can read 3 documents"
else
    fail_count=$((fail_count + 1))
    echo "    FAIL  Bob can read 3 documents  (got $count: $result)"
fi

# --- Action search (permitted_actions) ---

result=$(curl -sf -X POST "$OPA_URL/v1/data/authz/permitted_actions" \
    -H "Content-Type: application/json" \
    -d '{"input":{"subject":{"type":"internal_user","id":"alice"},"resource":{"type":"document","id":"doc_payroll_001"}}}')

total=$((total + 1))
count=$(echo "$result" | jq '.result | length')
if [ "$count" = "2" ]; then
    pass_count=$((pass_count + 1))
    echo "    PASS  Alice has 2 actions on payroll doc (can_read, can_edit)"
else
    fail_count=$((fail_count + 1))
    echo "    FAIL  Alice has 2 actions on payroll doc  (got $count: $result)"
fi

# --- Batch access checks (evaluations) ---

echo ""
echo "==> Running OPA + Zanzibar batch check..."
echo ""

# Batch with shared subject: Alice can_read + can_edit + can_delete on payroll doc
result=$(curl -sf -X POST "$OPA_URL/v1/data/authz/evaluations" \
    -H "Content-Type: application/json" \
    -d '{"input":{"subject":{"type":"internal_user","id":"alice"},"evaluations":[{"action":"can_read","resource":{"type":"document","id":"doc_payroll_001"}},{"action":"can_edit","resource":{"type":"document","id":"doc_payroll_001"}},{"action":"can_delete","resource":{"type":"document","id":"doc_payroll_001"}}]}}')

total=$((total + 1))
decisions=$(echo "$result" | jq -c '[.result[].decision]')
if [ "$decisions" = "[true,true,false]" ]; then
    pass_count=$((pass_count + 1))
    echo "    PASS  Batch: Alice can_read+can_edit but not can_delete"
else
    fail_count=$((fail_count + 1))
    echo "    FAIL  Batch: Alice can_read+can_edit but not can_delete  (got $decisions)"
fi

# Batch with per-evaluation subjects: mixed users
result=$(curl -sf -X POST "$OPA_URL/v1/data/authz/evaluations" \
    -H "Content-Type: application/json" \
    -d '{"input":{"evaluations":[{"subject":{"type":"internal_user","id":"alice"},"action":"can_read","resource":{"type":"document","id":"doc_payroll_001"}},{"subject":{"type":"internal_user","id":"eva"},"action":"can_read","resource":{"type":"document","id":"doc_payroll_001"}}]}}')

total=$((total + 1))
decisions=$(echo "$result" | jq -c '[.result[].decision]')
if [ "$decisions" = "[true,false]" ]; then
    pass_count=$((pass_count + 1))
    echo "    PASS  Batch: Alice can read payroll, Eva cannot"
else
    fail_count=$((fail_count + 1))
    echo "    FAIL  Batch: Alice can read payroll, Eva cannot  (got $decisions)"
fi

# --- API security checks ---

echo ""
echo "==> Running OPA API security checks..."
echo ""

# -- Public access (no token) --
#
# OPA's --authentication=token never rejects requests — it only extracts
# the bearer token and sets input.identity (undefined if no token).
# All access control is done by --authorization=basic which evaluates
# system.authz.allow.  Denied requests always return 401 (not 403).

# Allowed: POST to known policy prefix (authz policy allows it)
check_http "POST /v1/data/authz/... allowed without token" \
    "200" \
    -X POST "$OPA_URL/v1/data/authz/allow" \
    -H "Content-Type: application/json" \
    -d '{"input":{"subject":{"type":"internal_user","id":"__probe__"},"action":"__probe__","resource":{"type":"__probe__","id":"__probe__"}}}'

# Allowed: GET /health (authz policy allows it)
check_http "GET /health allowed without token" \
    "200" \
    "$OPA_URL/health"

# Blocked: POST to unknown prefix (e.g. /v1/data/keys — would leak JWKS)
check_http "POST /v1/data/keys blocked without token" \
    "401" \
    -X POST "$OPA_URL/v1/data/keys" \
    -H "Content-Type: application/json" \
    -d '{}'

# Blocked: GET /v1/data (raw data read requires admin token)
check_http "GET /v1/data blocked without token" \
    "401" \
    "$OPA_URL/v1/data"

# Blocked: GET /v1/policies (would leak source)
check_http "GET /v1/policies blocked without token" \
    "401" \
    "$OPA_URL/v1/policies"

# Blocked: GET /v1/config (would leak URLs/credentials)
check_http "GET /v1/config blocked without token" \
    "401" \
    "$OPA_URL/v1/config"

# Blocked: PUT /v1/data (data write — always denied)
check_http "PUT /v1/data/keys blocked without token" \
    "401" \
    -X PUT "$OPA_URL/v1/data/keys" \
    -H "Content-Type: application/json" \
    -d '{"keys":[]}'

# Blocked: PUT /v1/policies (policy injection)
check_http "PUT /v1/policies/evil blocked without token" \
    "401" \
    -X PUT "$OPA_URL/v1/policies/evil" \
    -H "Content-Type: text/plain" \
    -d 'package evil'

# -- Wrong token --
# Token is present so input.identity is set, but doesn't match
# admin_token → authz policy denies → 401.

check_http "GET /v1/policies blocked with wrong token" \
    "401" \
    -H "Authorization: Bearer wrong-token" \
    "$OPA_URL/v1/policies"

check_http "GET /v1/config blocked with wrong token" \
    "401" \
    -H "Authorization: Bearer wrong-token" \
    "$OPA_URL/v1/config"

# -- Admin token --

# Allowed: GET /v1/policies with admin token
check_http "GET /v1/policies allowed with admin token" \
    "200" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$OPA_URL/v1/policies"

# Allowed: GET /v1/data with admin token
check_http "GET /v1/data allowed with admin token" \
    "200" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$OPA_URL/v1/data"

# Allowed: GET /v1/config with admin token
check_http "GET /v1/config allowed with admin token" \
    "200" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$OPA_URL/v1/config"

# Blocked: PUT /v1/data even with admin token (data writes always denied)
check_http "PUT /v1/data/keys blocked even with admin token" \
    "401" \
    -X PUT "$OPA_URL/v1/data/keys" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"keys":[]}'

# Blocked: DELETE /v1/data even with admin token
check_http "DELETE /v1/data/keys blocked even with admin token" \
    "401" \
    -X DELETE "$OPA_URL/v1/data/keys" \
    -H "Authorization: Bearer $ADMIN_TOKEN"

echo ""
echo "==> $pass_count passed, $fail_count failed (of $total checks)"

if [ "$fail_count" -gt 0 ]; then
    exit 1
fi
