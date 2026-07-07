#!/usr/bin/env bash
#
# Mint a DEMO ES256 JWT for the local dev stack (signed with the shipped demo
# key opa/keys/demo.key.txt, which matches the demo JWKS both OPA and pgauthzd
# verify against). DEV ONLY — production uses a real IdP (see the Keycloak
# overlay: ./start.sh --keycloak).
#
# Usage: scripts/make-token.sh [username] [subject_type] [roles_json]
#   scripts/make-token.sh alice                              # plain user
#   scripts/make-token.sh svc internal_user '["authz_writer"]'  # writer role
#
# Mirrors make_token in tests/test-opa.sh (claims: iss https://auth.example.com,
# aud authz-api, kid my-kid, 1h expiry).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_FILE="${KEY_FILE:-$SCRIPT_DIR/../opa/keys/demo.key.txt}"

USERNAME="${1:-alice}"
SUBJECT_TYPE="${2:-internal_user}"
ROLES_JSON="${3:-[]}"

b64url_encode() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

now=$(date +%s)
exp=$((now + 3600))

header=$(printf '{"alg":"ES256","typ":"JWT","kid":"my-kid"}' | b64url_encode)
payload=$(jq -nc \
    --arg sub "$USERNAME" --arg pun "$USERNAME" --arg st "$SUBJECT_TYPE" \
    --arg iss "https://auth.example.com" --arg aud "authz-api" \
    --argjson iat "$now" --argjson exp "$exp" --argjson roles "$ROLES_JSON" \
    '{sub:$sub,preferred_username:$pun,subject_type:$st,roles:$roles,iss:$iss,aud:$aud,iat:$iat,exp:$exp}' | b64url_encode)

signing_input="${header}.${payload}"

# DER ECDSA signature → raw R||S (JWS form), via temp file (command
# substitution would strip null bytes).
tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT
printf '%s' "$signing_input" | openssl dgst -sha256 -sign "$KEY_FILE" -binary > "$tmpfile"
sig=$(python3 - "$tmpfile" <<'PY'
import sys
der = open(sys.argv[1], 'rb').read()
# minimal DER SEQUENCE(INTEGER r, INTEGER s) parse
i = 2 + (1 if der[1] & 0x80 else 0)
def read_int(b, i):
    assert b[i] == 0x02; l = b[i+1]; v = b[i+2:i+2+l]
    return v.lstrip(b'\x00').rjust(32, b'\x00'), i+2+l
r, i = read_int(der, i)
s, _ = read_int(der, i)
import base64
print(base64.urlsafe_b64encode(r + s).decode().rstrip('='))
PY
)
echo "${signing_input}.${sig}"
