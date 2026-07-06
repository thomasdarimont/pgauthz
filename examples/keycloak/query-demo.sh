#!/usr/bin/env bash
#
# Query the pgauthz 'demo' store with REAL Keycloak tokens through the canonical
# front door: Keycloak (issues the JWT) -> pgauthzd (AuthZEN 1.0 /access/v1;
# validates the JWT, consults its internal OPA sidecar) -> OPA -> pgauthzd's
# native engine callback -> PostgreSQL (check_access). OPA is internal — the
# gateway (api.pgauthz.test) routes to pgauthzd, never to OPA directly.
#
# The subject is NOT passed in the request — pgauthzd derives it from the token
# (preferred_username / subject_type), exactly as a real PEP would call it. The
# token rides in the Authorization: Bearer header (standard AuthZEN).
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
    -h|--help)    sed -n '2,18p' "$0"; exit 0 ;;
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

# call <token> <endpoint-path> <json-body> -> prints the raw response. The token
# rides in the Authorization header (AuthZEN). With --verbose it also echoes the
# request (endpoint + body, JWT truncated for readability).
call() {
  local token="$1" path="$2" body="$3"
  if [ "$VERBOSE" = 1 ]; then
    {
      echo "  → POST $BASE/$path  (Authorization: Bearer ${token:0:18}…<JWT>)"
      printf '    %s\n' "$body"
    } >&2
  fi
  "${CURL[@]}" "$BASE/$path" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $token" \
    -d "$body"
}

echo "==> Fetching Keycloak tokens for the demo users..."
TOK_alice="$(get_token alice)"
TOK_eva="$(get_token eva)"
TOK_carol="$(get_token carol)"
TOK_bob="$(get_token bob)"

# allow: <token> <action> <doc-id> -> ALLOW | DENY  (AuthZEN evaluation)
allow() {
  local res
  res="$(call "$1" "access/v1/evaluation" \
    "{\"action\":{\"name\":\"$2\"},\"resource\":{\"type\":\"document\",\"id\":\"$3\"}}" \
    | jq -r '.decision')"
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
echo "==> action search — what may alice do on document:doc_payroll_001?"
call "$TOK_alice" "access/v1/search/action" \
  "{\"resource\":{\"type\":\"document\",\"id\":\"doc_payroll_001\"}}" \
  | jq -c '[.results[].action.name]'

echo
echo "==> resource search — which documents can bob (advisor on eng_42) read?"
call "$TOK_bob" "access/v1/search/resource" \
  "{\"action\":{\"name\":\"can_read\"},\"resource\":{\"type\":\"document\"}}" \
  | jq -c '[.results[].resource.id]'

echo
echo "==> client_credentials — the app-dms SERVICE (no human) reads a document."
echo "    Token via grant_type=client_credentials; subject_type=service_account and"
echo "    db_role=app_dms are hardcoded on the client (the app), not a user."
TOK_appdms="$("$GET_TOKEN" --service app-dms | sed -E 's/^export TOKEN=//')"
printf '%-26s %-9s %-24s %s\n' "service_account:app-dms" "can_read" "document:doc_payroll_001" \
  "$(allow "$TOK_appdms" can_read doc_payroll_001)"

echo
echo "==> Done. The subject was derived from each Keycloak JWT — no subject was"
echo "    passed in the request. Swap in your own OIDC issuer by adding it to"
echo "    pgauthzd's JWT_ISSUERS (and OPA's JWKS_URL); the queries above stay identical."
