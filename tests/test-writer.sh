#!/usr/bin/env bash
#
# Tests the PostgREST writer API security measures.
# Requires bootstrap.sh to have been run first and the writer services enabled.
#
# Requests go through the Nginx writer-gateway (:3001) which only
# forwards POST /rpc/* to PostgREST.  Everything else gets a 404.
#
set -euo pipefail

WRITER_URL="${WRITER_URL:-http://localhost:3001}"

# Pre-generated HS256 tokens signed with the default dev secret.
WRITER_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYXV0aHpfd3JpdGVyIiwiaXNzIjoiYXV0aHotZGV2IiwiaWF0IjoxNzEwMDAwMDAwLCJleHAiOjE3OTg3NjE2MDB9.um8_wgGTbs6H8bC5nGSbYJXf3WqbLDuSmcAzODOw-Zs"
ADMIN_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYXV0aHpfYWRtaW4iLCJpc3MiOiJhdXRoei1kZXYiLCJpYXQiOjE3MTAwMDAwMDAsImV4cCI6MTc5ODc2MTYwMH0.EHh6xxn8LmhcnaLY7aBD6GiLMgcRkoHCrt2kanzjiBY"

pass_count=0
fail_count=0
total=0

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

echo "==> Waiting for writer gateway..."
for i in $(seq 1 30); do
    if curl -sf "$WRITER_URL/" -o /dev/null 2>/dev/null || curl -sf -o /dev/null -w "%{http_code}" "$WRITER_URL/" 2>/dev/null | grep -q '404'; then
        break
    fi
    sleep 1
done

echo ""
echo "==> Nginx gateway (route filtering)"
echo ""

check_http "GET / blocked by Nginx" \
    "404" \
    "$WRITER_URL/"

check_http "GET /namespace_access blocked by Nginx" \
    "404" \
    "$WRITER_URL/namespace_access"

check_http "GET /namespace_access with writer JWT blocked by Nginx" \
    "404" \
    -H "Authorization: Bearer $WRITER_TOKEN" \
    "$WRITER_URL/namespace_access"

check_http "GET /namespace_access with admin JWT blocked by Nginx" \
    "404" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    "$WRITER_URL/namespace_access"

check_http "POST /namespace_access blocked by Nginx (not /rpc/)" \
    "404" \
    -X POST "$WRITER_URL/namespace_access" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"store_id":1,"namespace":"evil","db_role":"evil","can_read":true,"can_write":true}'

check_http "POST /rpc/does_not_exist returns generic 404 (no schema leak)" \
    "404" \
    -X POST "$WRITER_URL/rpc/does_not_exist" \
    -H "Content-Type: application/json" \
    -d '{}'

echo ""
echo "==> Unauthenticated access (no JWT)"
echo ""

# Read functions work without JWT (api_anon → authz_reader)
check_http "check_access works without JWT" \
    "200" \
    -X POST "$WRITER_URL/rpc/check_access" \
    -H "Content-Type: application/json" \
    -d '{"p_store":"demo","p_user_type":"internal_user","p_user_id":"alice","p_relation":"can_read","p_object_type":"document","p_object_id":"doc_payroll_001"}'

# Write functions blocked without JWT
check_http "write_tuple blocked without JWT" \
    "401" \
    -X POST "$WRITER_URL/rpc/write_tuple" \
    -H "Content-Type: application/json" \
    -d '{"p_store":"demo","p_user_type":"internal_user","p_user_id":"eve","p_relation":"viewer","p_object_type":"document","p_object_id":"doc_payroll_001","p_performed_by":"attacker"}'

# Admin functions blocked without JWT
check_http "create_store blocked without JWT" \
    "401" \
    -X POST "$WRITER_URL/rpc/create_store" \
    -H "Content-Type: application/json" \
    -d '{"p_name":"evil_store"}'

# Audit functions blocked without JWT
check_http "audit_list_user blocked without JWT" \
    "401" \
    -X POST "$WRITER_URL/rpc/audit_list_user" \
    -H "Content-Type: application/json" \
    -d '{"p_store":"demo","p_user_type":"internal_user","p_user_id":"alice"}'

echo ""
echo "==> Writer JWT (authz_writer role)"
echo ""

check_http "write_tuple allowed with writer JWT" \
    "200" \
    -X POST "$WRITER_URL/rpc/write_tuple" \
    -H "Authorization: Bearer $WRITER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"p_store":"demo","p_user_type":"internal_user","p_user_id":"__sectest__","p_relation":"viewer","p_object_type":"document","p_object_id":"doc_test_sec","p_performed_by":"security-test"}'

check_http "delete_tuple allowed with writer JWT" \
    "200" \
    -X POST "$WRITER_URL/rpc/delete_tuple" \
    -H "Authorization: Bearer $WRITER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"p_store":"demo","p_user_type":"internal_user","p_user_id":"__sectest__","p_relation":"viewer","p_object_type":"document","p_object_id":"doc_test_sec","p_performed_by":"security-test"}'

check_http "create_store blocked with writer JWT" \
    "403" \
    -X POST "$WRITER_URL/rpc/create_store" \
    -H "Authorization: Bearer $WRITER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"p_name":"writer_store"}'

check_http "audit_list_user blocked with writer JWT" \
    "403" \
    -X POST "$WRITER_URL/rpc/audit_list_user" \
    -H "Authorization: Bearer $WRITER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"p_store":"demo","p_user_type":"internal_user","p_user_id":"alice"}'

echo ""
echo "==> Admin JWT (authz_admin role)"
echo ""

check_http "write_tuple allowed with admin JWT" \
    "200" \
    -X POST "$WRITER_URL/rpc/write_tuple" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"p_store":"demo","p_user_type":"internal_user","p_user_id":"__sectest__","p_relation":"viewer","p_object_type":"document","p_object_id":"doc_test_sec","p_performed_by":"security-test"}'

check_http "audit_list_user allowed with admin JWT" \
    "200" \
    -X POST "$WRITER_URL/rpc/audit_list_user" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"p_store":"demo","p_user_type":"internal_user","p_user_id":"alice"}'

check_http "find_redundant_tuples allowed with admin JWT" \
    "200" \
    -X POST "$WRITER_URL/rpc/find_redundant_tuples" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"p_store":"demo"}'

# Cleanup test tuple
curl -s -X POST "$WRITER_URL/rpc/delete_tuple" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"p_store":"demo","p_user_type":"internal_user","p_user_id":"__sectest__","p_relation":"viewer","p_object_type":"document","p_object_id":"doc_test_sec","p_performed_by":"security-test"}' > /dev/null 2>&1

echo ""
echo "==> $pass_count passed, $fail_count failed (of $total checks)"

if [ "$fail_count" -gt 0 ]; then
    exit 1
fi
