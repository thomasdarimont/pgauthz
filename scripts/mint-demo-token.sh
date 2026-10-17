#!/usr/bin/env bash
#
# Mints a demo JWT the demo stack's pgauthzd accepts (ES256, opa/keys/demo.key.txt,
# iss https://auth.example.com, aud authz-api) — for Swagger UI's Authorize dialog
# (/pgauthz/v1/docs), curl, or any other hand-driven call. DEMO ONLY: the key is
# public in the repository.
#
#   ./scripts/mint-demo-token.sh                         # alice (internal_user)
#   ./scripts/mint-demo-token.sh bob                     # another demo user
#   ./scripts/mint-demo-token.sh alice authz_writer      # with a role (writes)
#   ./scripts/mint-demo-token.sh alice authz_writer,authz_auditor
#   ./scripts/mint-demo-token.sh --pep                   # no subject: a PEP credential
#                                                        # (the body names the subject;
#                                                        # what the conformance suite uses)
#   SUBJECT_TYPE=client_user ./scripts/mint-demo-token.sh carol
#   TTL=86400 ./scripts/mint-demo-token.sh               # seconds, default 3600
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_FILE="${KEY_FILE:-$SCRIPT_DIR/../opa/keys/demo.key.txt}"
ISSUER="${ISSUER:-https://auth.example.com}"
AUDIENCE="${AUDIENCE:-authz-api}"
KID="${KID:-my-kid}"
TTL="${TTL:-3600}"
SUBJECT_TYPE="${SUBJECT_TYPE:-internal_user}"

subject="${1:-alice}"
roles_csv="${2:-}"
pep=0
if [ "$subject" = "--pep" ]; then pep=1; fi

for tool in openssl jq python3; do
  command -v "$tool" >/dev/null || { echo "ERROR: $tool is required" >&2; exit 1; }
done

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

now=$(date +%s)
exp=$((now + TTL))
roles_json=$(jq -nc --arg r "$roles_csv" '$r | split(",") | map(select(length > 0))')

header=$(printf '{"alg":"ES256","typ":"JWT","kid":"%s"}' "$KID" | b64url)
if [ "$pep" = 1 ]; then
  payload=$(jq -nc --arg iss "$ISSUER" --arg aud "$AUDIENCE" --argjson iat "$now" --argjson exp "$exp" \
    '{iss:$iss,aud:$aud,iat:$iat,exp:$exp}' | b64url)
else
  payload=$(jq -nc --arg iss "$ISSUER" --arg aud "$AUDIENCE" --argjson iat "$now" --argjson exp "$exp" \
    --arg sub "$subject" --arg st "$SUBJECT_TYPE" --argjson roles "$roles_json" \
    '{iss:$iss,aud:$aud,iat:$iat,exp:$exp,sub:$sub,preferred_username:$sub,subject_type:$st} + (if ($roles|length) > 0 then {roles:$roles} else {} end)' | b64url)
fi

signing_input="${header}.${payload}"
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
printf '%s' "$signing_input" | openssl dgst -sha256 -sign "$KEY_FILE" -binary > "$tmp"
# DER (r, s) → raw R||S, each 32 bytes (JWS ES256)
sig=$(python3 -I -c "
import sys, base64
der = open('$tmp', 'rb').read()
i = 2; rl = der[i+1]; r = der[i+2:i+2+rl]; i = i+2+rl; sl = der[i+1]; s = der[i+2:i+2+sl]
r = r.lstrip(b'\x00').rjust(32, b'\x00'); s = s.lstrip(b'\x00').rjust(32, b'\x00')
print(base64.urlsafe_b64encode(r + s).rstrip(b'=').decode())")
echo "${signing_input}.${sig}"
