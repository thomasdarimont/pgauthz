#!/usr/bin/env bash
#
# Integration tests for AuthZEN API endpoints.
# Exercises both authzen-direct (port 8090) and authzen-opa (port 8091).
# Requires bootstrap.sh to have been run first.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PG_DIR="$SCRIPT_DIR/.."
DIRECT_URL="${AUTHZEN_DIRECT_URL:-http://localhost:8090}"
OPA_URL="${AUTHZEN_OPA_URL:-http://localhost:8091}"
KEY_FILE="$PG_DIR/opa/keys/demo.key.txt"

pass_count=0
fail_count=0
total=0

# --- JWT token generation ---

b64url_encode() {
    openssl base64 -A | tr '+/' '-_' | tr -d '='
}

# Generate an ES256 JWT signed with the demo private key.
# Uses a temp file to avoid null-byte issues in bash command substitution.
# Usage: make_token <preferred_username> <subject_type>
make_token() {
    local username="$1"
    local subject_type="${2:-internal_user}"
    local now
    now=$(date +%s)
    local exp=$((now + 3600))

    local header
    header=$(printf '{"alg":"ES256","typ":"JWT","kid":"my-kid"}' | b64url_encode)
    local payload
    payload=$(jq -nc \
        --arg sub "$username" \
        --arg pun "$username" \
        --arg st "$subject_type" \
        --arg iss "https://auth.example.com" \
        --arg aud "authz-api" \
        --argjson iat "$now" \
        --argjson exp "$exp" \
        '{sub:$sub,preferred_username:$pun,subject_type:$st,iss:$iss,aud:$aud,iat:$iat,exp:$exp}' | b64url_encode)

    local signing_input="${header}.${payload}"

    # Sign, convert DER→raw R||S via temp file (avoids null-byte stripping)
    local tmpfile
    tmpfile=$(mktemp)

    printf '%s' "$signing_input" | \
        openssl dgst -sha256 -sign "$KEY_FILE" -binary > "$tmpfile"

    local sig_b64
    sig_b64=$(python3 -c "
import sys, base64
with open('$tmpfile', 'rb') as f:
    der = f.read()
i = 2
rlen = der[i+1]
r = der[i+2:i+2+rlen]
i = i+2+rlen
slen = der[i+1]
s = der[i+2:i+2+slen]
r = r.lstrip(b'\x00').rjust(32, b'\x00')
s = s.lstrip(b'\x00').rjust(32, b'\x00')
print(base64.urlsafe_b64encode(r + s).rstrip(b'=').decode())
")

    rm -f "$tmpfile"
    echo "${signing_input}.${sig_b64}"
}

# Pre-generate tokens for test subjects
TOKEN_ALICE=$(make_token "alice" "internal_user")
TOKEN_BOB=$(make_token "bob" "internal_user")
TOKEN_CAROL=$(make_token "carol" "client_user")
TOKEN_EVA=$(make_token "eva" "internal_user")

AUTH_ALICE="Authorization: Bearer $TOKEN_ALICE"
AUTH_BOB="Authorization: Bearer $TOKEN_BOB"
AUTH_CAROL="Authorization: Bearer $TOKEN_CAROL"
AUTH_EVA="Authorization: Bearer $TOKEN_EVA"

# --- Test helpers ---

check_json() {
    local description="$1"
    local url="$2"
    local auth_header="$3"
    local payload="$4"
    local jq_expr="$5"
    local expected="$6"

    total=$((total + 1))

    result=$(curl -sf -X POST "$url" \
        -H "Content-Type: application/json" \
        -H "$auth_header" \
        -d "$payload" 2>/dev/null) || {
        fail_count=$((fail_count + 1))
        echo "    FAIL  $description  (HTTP error)"
        return
    }

    actual=$(echo "$result" | jq -rc "$jq_expr")

    if [ "$actual" = "$expected" ]; then
        pass_count=$((pass_count + 1))
        echo "    PASS  $description"
    else
        fail_count=$((fail_count + 1))
        echo "    FAIL  $description  (expected=$expected, got=$actual)"
    fi
}

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

run_tests() {
    local base_url="$1"
    local label="$2"

    echo ""
    echo "==> Testing $label ($base_url)"
    echo ""

    # --- Wait for service ---
    echo "  Waiting for $label..."
    for i in $(seq 1 30); do
        if curl -sf "$base_url/healthz" > /dev/null 2>&1; then
            break
        fi
        sleep 1
    done

    # --- Single evaluation ---
    echo ""
    echo "  --- Single evaluation ---"
    echo ""

    check_json "Alice can read payroll doc" \
        "$base_url/access/v1/evaluation" "$AUTH_ALICE" \
        '{"subject":{"type":"internal_user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"doc_payroll_001"}}' \
        '.decision' \
        "true"

    check_json "Alice can edit payroll doc" \
        "$base_url/access/v1/evaluation" "$AUTH_ALICE" \
        '{"subject":{"type":"internal_user","id":"alice"},"action":{"name":"can_edit"},"resource":{"type":"document","id":"doc_payroll_001"}}' \
        '.decision' \
        "true"

    check_json "Alice cannot read tax doc (wrong team)" \
        "$base_url/access/v1/evaluation" "$AUTH_ALICE" \
        '{"subject":{"type":"internal_user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"doc_tax_001"}}' \
        '.decision' \
        "false"

    check_json "Bob (advisor) can read payroll doc" \
        "$base_url/access/v1/evaluation" "$AUTH_BOB" \
        '{"subject":{"type":"internal_user","id":"bob"},"action":{"name":"can_read"},"resource":{"type":"document","id":"doc_payroll_001"}}' \
        '.decision' \
        "true"

    check_json "Carol (client org) can read client-space doc" \
        "$base_url/access/v1/evaluation" "$AUTH_CAROL" \
        '{"subject":{"type":"client_user","id":"carol"},"action":{"name":"can_read"},"resource":{"type":"document","id":"doc_client_001"}}' \
        '.decision' \
        "true"

    check_json "Carol cannot edit client-space doc" \
        "$base_url/access/v1/evaluation" "$AUTH_CAROL" \
        '{"subject":{"type":"client_user","id":"carol"},"action":{"name":"can_edit"},"resource":{"type":"document","id":"doc_client_001"}}' \
        '.decision' \
        "false"

    check_json "Eva cannot read payroll doc" \
        "$base_url/access/v1/evaluation" "$AUTH_EVA" \
        '{"subject":{"type":"internal_user","id":"eva"},"action":{"name":"can_read"},"resource":{"type":"document","id":"doc_payroll_001"}}' \
        '.decision' \
        "false"

    # --- Batch evaluations ---
    echo ""
    echo "  --- Batch evaluations ---"
    echo ""

    check_json "Batch: Alice can_read+can_edit but not can_delete" \
        "$base_url/access/v1/evaluations" "$AUTH_ALICE" \
        '{"subject":{"type":"internal_user","id":"alice"},"evaluations":[{"action":{"name":"can_read"},"resource":{"type":"document","id":"doc_payroll_001"}},{"action":{"name":"can_edit"},"resource":{"type":"document","id":"doc_payroll_001"}},{"action":{"name":"can_delete"},"resource":{"type":"document","id":"doc_payroll_001"}}]}' \
        '[.evaluations[].decision]' \
        "[true,true,false]"

    check_json "Batch: mixed subjects (Alice can read, Eva cannot)" \
        "$base_url/access/v1/evaluations" "$AUTH_ALICE" \
        '{"evaluations":[{"subject":{"type":"internal_user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"doc_payroll_001"}},{"subject":{"type":"internal_user","id":"eva"},"action":{"name":"can_read"},"resource":{"type":"document","id":"doc_payroll_001"}}]}' \
        '[.evaluations[].decision]' \
        "[true,false]"

    check_json "Batch: deny_on_first_deny short-circuits" \
        "$base_url/access/v1/evaluations" "$AUTH_EVA" \
        '{"subject":{"type":"internal_user","id":"eva"},"semantic":"deny_on_first_deny","evaluations":[{"action":{"name":"can_read"},"resource":{"type":"document","id":"doc_payroll_001"}},{"action":{"name":"can_edit"},"resource":{"type":"document","id":"doc_payroll_001"}}]}' \
        '.evaluations[0].decision' \
        "false"

    # --- Resource search ---
    echo ""
    echo "  --- Resource search ---"
    echo ""

    check_json "Bob can read 3 documents" \
        "$base_url/access/v1/search/resource" "$AUTH_BOB" \
        '{"subject":{"type":"internal_user","id":"bob"},"action":{"name":"can_read"},"resource":{"type":"document"}}' \
        '.results | length' \
        "3"

    # --- Action search ---
    echo ""
    echo "  --- Action search ---"
    echo ""

    check_json "Alice has 2 actions on payroll doc" \
        "$base_url/access/v1/search/action" "$AUTH_ALICE" \
        '{"subject":{"type":"internal_user","id":"alice"},"resource":{"type":"document","id":"doc_payroll_001"}}' \
        '.results | length' \
        "2"

    # --- Well-known configuration (exempt from JWT) ---
    echo ""
    echo "  --- Well-known ---"
    echo ""

    total=$((total + 1))
    result=$(curl -sf "$base_url/.well-known/authzen-configuration" 2>/dev/null) || {
        fail_count=$((fail_count + 1))
        echo "    FAIL  Well-known endpoint  (HTTP error)"
        return
    }
    api_version=$(echo "$result" | jq -r '.api_version')
    if [ "$api_version" = "1.0" ]; then
        pass_count=$((pass_count + 1))
        echo "    PASS  Well-known endpoint returns api_version 1.0"
    else
        fail_count=$((fail_count + 1))
        echo "    FAIL  Well-known endpoint  (expected api_version=1.0, got=$api_version)"
    fi

    # --- Health check (exempt from JWT) ---
    check_http "Health check returns 200" \
        "200" \
        "$base_url/healthz"

    # --- JWT authentication ---
    echo ""
    echo "  --- JWT authentication ---"
    echo ""

    check_http "401 without token" \
        "401" \
        -X POST "$base_url/access/v1/evaluation" \
        -H "Content-Type: application/json" \
        -d '{"subject":{"type":"internal_user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"doc_payroll_001"}}'

    check_http "401 with invalid token" \
        "401" \
        -X POST "$base_url/access/v1/evaluation" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer invalid.token.here" \
        -d '{"subject":{"type":"internal_user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"doc_payroll_001"}}'

    # --- Error handling (with valid token) ---
    echo ""
    echo "  --- Error handling ---"
    echo ""

    check_http "400 on missing action" \
        "400" \
        -X POST "$base_url/access/v1/evaluation" \
        -H "Content-Type: application/json" \
        -H "$AUTH_ALICE" \
        -d '{"subject":{"type":"internal_user","id":"alice"},"resource":{"type":"document","id":"doc1"}}'

    # Missing body subject falls back to JWT claims (alice/internal_user)
    check_json "JWT subject fallback when body subject missing" \
        "$base_url/access/v1/evaluation" "$AUTH_ALICE" \
        '{"action":{"name":"can_read"},"resource":{"type":"document","id":"doc_payroll_001"}}' \
        '.decision' \
        "true"

    check_http "400 on empty evaluations array" \
        "400" \
        -X POST "$base_url/access/v1/evaluations" \
        -H "Content-Type: application/json" \
        -H "$AUTH_ALICE" \
        -d '{"evaluations":[]}'

    check_http "400 on invalid JSON" \
        "400" \
        -X POST "$base_url/access/v1/evaluation" \
        -H "Content-Type: application/json" \
        -H "$AUTH_ALICE" \
        -d '{invalid'
}

# --- Run tests for both services ---

run_tests "$DIRECT_URL" "authzen-direct"
run_tests "$OPA_URL" "authzen-opa"

echo ""
echo "==> $pass_count passed, $fail_count failed (of $total checks)"

if [ "$fail_count" -gt 0 ]; then
    exit 1
fi
