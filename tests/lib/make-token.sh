#!/usr/bin/env bash
# make_token — an ES256 JWT signed with the demo key (opa/keys/demo.key.txt),
# as the AuthZEN and pgauthzctl integration tests mint them. Source it:
#   source tests/lib/make-token.sh; TOKEN=$(make_token alice internal_user '["authz_writer"]')
# KEY_FILE may be set beforehand; it defaults to the demo key next to this file.
KEY_FILE="${KEY_FILE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/opa/keys/demo.key.txt}"

b64url_encode() {
    openssl base64 -A | tr '+/' '-_' | tr -d '='
}

# Usage: make_token <preferred_username> [<subject_type>] [<roles json array>]
make_token() {
    local username="$1"
    local subject_type="${2:-internal_user}"
    local roles_json="${3:-[]}"
    local now
    now=$(date +%s)
    local exp=$((now + 3600))
    local header
    header=$(printf '{"alg":"ES256","typ":"JWT","kid":"my-kid"}' | b64url_encode)
    local payload
    payload=$(jq -nc \
        --arg sub "$username" --arg pun "$username" --arg st "$subject_type" \
        --arg iss "https://auth.example.com" --arg aud "authz-api" \
        --argjson iat "$now" --argjson exp "$exp" --argjson roles "$roles_json" \
        '{sub:$sub,preferred_username:$pun,subject_type:$st,roles:$roles,iss:$iss,aud:$aud,iat:$iat,exp:$exp}' | b64url_encode)
    local signing_input="${header}.${payload}"
    local tmpfile
    tmpfile=$(mktemp)
    printf '%s' "$signing_input" | openssl dgst -sha256 -sign "$KEY_FILE" -binary > "$tmpfile"
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
