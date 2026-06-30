#!/usr/bin/env bash
#
# Fetch a real access token from the demo Keycloak — password grant for a demo
# user, or client_credentials for the service account. Prints `export TOKEN=...`
# so you can eval it:
#
#   eval "$(./keycloak/get-token.sh alice)"        # user token (subject alice)
#   eval "$(./keycloak/get-token.sh --service)"          # client_credentials (authz-api SA)
#   eval "$(./keycloak/get-token.sh --service app-dms)"  # client_credentials as the app-dms client
#   curl -s https://api.pgauthz.test/v1/evaluation -H "Authorization: Bearer $TOKEN" ...
#
# Env overrides: ISSUER, CLIENT_ID, CLIENT_SECRET, DEMO_PASSWORD.
# The client secret is read from `terraform output` if not supplied.
set -euo pipefail

ISSUER="${ISSUER:-https://id.pgauthz.test/realms/pgauthz}"
CLIENT_ID="${CLIENT_ID:-authz-api}"
# `--service [<client-id>]` selects a client for client_credentials (e.g. app-dms).
if [ "${1:-}" = "--service" ] && [ -n "${2:-}" ]; then CLIENT_ID="$2"; fi
CLIENT_SECRET="${CLIENT_SECRET:-}"
PASSWORD="${DEMO_PASSWORD:-password}"
TOKEN_URL="$ISSUER/protocol/openid-connect/token"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pull the client secret from terraform state if not provided.
if [ -z "$CLIENT_SECRET" ] && [ -d "$script_dir/terraform/.terraform" ]; then
  secret_out="$(printf '%s' "$CLIENT_ID" | tr '-' '_')_client_secret"
  CLIENT_SECRET="$(cd "$script_dir/terraform" && terraform output -raw "$secret_out" 2>/dev/null || true)"
fi

if [ "${1:-}" = "--service" ]; then
  grant="grant_type=client_credentials"
else
  user="${1:-alice}"
  grant="grant_type=password&username=${user}&password=${PASSWORD}&scope=openid"
fi

resp="$(curl -sS "$TOKEN_URL" \
  -d "client_id=${CLIENT_ID}" \
  ${CLIENT_SECRET:+-d "client_secret=${CLIENT_SECRET}"} \
  -d "$grant")"

token="$(printf '%s' "$resp" | jq -r '.access_token // empty')"
if [ -z "$token" ]; then
  echo "!! no access_token in response:" >&2
  printf '%s\n' "$resp" >&2
  exit 1
fi

echo "export TOKEN=$token"
