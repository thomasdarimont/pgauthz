#!/usr/bin/env bash
#
# Query the pgauthz 'demo' store with REAL Keycloak tokens. This example calls
# OPA's data API directly (POST /v1/data/authz/allow, via the api.pgauthz.test
# gateway) to showcase OPA's custom rules (allow / permitted_actions /
# accessible_objects). Full stack: Keycloak (issues the JWT) -> OPA (verifies it,
# derives the subject from the claims, evaluates policy) -> pgauthzd's native
# /pgauthz/v1 callback -> PostgreSQL engine (check_access). NOTE: this is the
# OPA-data-API entry point; the default/canonical front door is pgauthzd itself
# (AuthZEN /access/v1 + native /pgauthz/v1), which consults OPA as an internal
# sidecar. The subject is NOT passed in the request — it comes from the token's
# preferred_username / subject_type, exactly as a real PEP would call it.
#
# Usage:
#   examples/keycloak/query-demo.sh            # decision table
#   examples/keycloak/query-demo.sh --verbose  # also print each request sent
#   BASE=https://api.pgauthz.test examples/keycloak/query-demo.sh
#
# Prerequisites (see keycloak/README.md): generate-mkcerts.sh, ./start.sh
# --keycloak, terraform apply, the 'demo' store loaded, *.pgauthz.test in /etc/hosts.
set -euo pipefail

VERBOSE=0
for arg in "$@"; do
  case "$arg" in
    -v|--verbose) VERBOSE=1 ;;
    -h|--help)    sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BASE="${BASE:-https://api.pgauthz.test}"
GET_TOKEN="$REPO_ROOT/keycloak/get-token.sh"
CACERT="$REPO_ROOT/keycloak/config/certs/rootCA.pem"

command -v jq >/dev/null || { echo "!! jq is required" >&2; exit 1; }
[ -x "$GET_TOKEN" ] || { echo "!! $GET_TOKEN not found/executable" >&2; exit 1; }

# Verify TLS against the mkcert root CA (real verification, no -k) when present.
CURL=(curl -sS)
[ -f "$CACERT" ] && CURL+=(--cacert "$CACERT")

get_token() { "$GET_TOKEN" "$1" | sed -E 's/^export TOKEN=//'; }

# call <endpoint-path> <json-body> -> prints the raw response. With --verbose it
# also echoes the request (endpoint + body, JWT truncated for readability).
call() {
  # Verbose output goes to stderr so it never pollutes the response that callers
  # capture and pipe to jq.
  if [ "$VERBOSE" = 1 ]; then
    {
      echo "  → POST $BASE/$1"
      printf '    '
      printf '%s' "$2" | jq -c '.input.token = ((.input.token // "")[0:18] + "…<JWT>")'
    } >&2
  fi
  "${CURL[@]}" "$BASE/$1" -H 'Content-Type: application/json' -d "$2"
}

echo "==> Fetching Keycloak tokens for the demo users..."
TOK_alice="$(get_token alice)"
TOK_eva="$(get_token eva)"
TOK_carol="$(get_token carol)"
TOK_bob="$(get_token bob)"

# allow: <token> <action> <doc-id> -> ALLOW | DENY
allow() {
  local res
  res="$(call "v1/data/authz/allow" \
    "{\"input\":{\"token\":\"$1\",\"action\":\"$2\",\"resource\":{\"type\":\"document\",\"id\":\"$3\"}}}" \
    | jq -r '.result')"
  case "$res" in true) echo "ALLOW" ;; false) echo "DENY" ;; *) echo "ERR($res)" ;; esac
}

echo
[ "$VERBOSE" = 1 ] || printf '%-26s %-9s %-24s %s\n' "SUBJECT (from JWT)" "ACTION" "RESOURCE" "DECISION"
[ "$VERBOSE" = 1 ] || printf '%-26s %-9s %-24s %s\n' "------------------" "------" "--------" "--------"
row() {
  [ "$VERBOSE" = 1 ] && echo "• $1"
  printf '%-26s %-9s %-24s %s\n' "$1" "$3" "document:$4" "$(allow "$2" "$3" "$4")"
  [ "$VERBOSE" = 1 ] && echo
  return 0  # else the trailing test returns non-zero and `set -e` aborts the loop
}

row "alice (payroll team)"   "$TOK_alice" can_read doc_payroll_001   # ALLOW
row "alice (payroll team)"   "$TOK_alice" can_read doc_tax_001       # DENY  (other team)
row "eva (accounting team)"  "$TOK_eva"   can_read doc_acc_001       # ALLOW
row "eva (accounting team)"  "$TOK_eva"   can_read doc_payroll_001   # DENY  (other team)
row "carol (client: acme)"   "$TOK_carol" can_read doc_client_001    # ALLOW (client space)
row "carol (client: acme)"   "$TOK_carol" can_read doc_payroll_001   # DENY  (internal only)

echo
echo "==> permitted_actions — what may alice do on document:doc_payroll_001?"
call "v1/data/authz/permitted_actions" \
  "{\"input\":{\"token\":\"$TOK_alice\",\"resource\":{\"type\":\"document\",\"id\":\"doc_payroll_001\"}}}" \
  | jq -c '.result'

echo
echo "==> accessible_objects — which documents can bob (advisor on eng_42) read?"
call "v1/data/authz/accessible_objects" \
  "{\"input\":{\"token\":\"$TOK_bob\",\"action\":\"can_read\",\"resource\":{\"type\":\"document\"}}}" \
  | jq -c '.result'

echo
echo "==> client_credentials — the app-dms SERVICE (no human) reads a document."
echo "    Token via grant_type=client_credentials; subject_type=service_account and"
echo "    db_role=app_dms are hardcoded on the client (the app), not a user."
TOK_appdms="$("$GET_TOKEN" --service app-dms | sed -E 's/^export TOKEN=//')"
printf '%-26s %-9s %-24s %s\n' "service_account:app-dms" "can_read" "document:doc_payroll_001" \
  "$(allow "$TOK_appdms" can_read doc_payroll_001)"

echo
echo "==> Done. The subject was derived from each Keycloak JWT — no subject was"
echo "    passed in the request. Swap in your own OIDC issuer by repointing OPA's"
echo "    JWT_ISSUER / JWKS_URL; the queries above stay identical."
