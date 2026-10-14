#!/usr/bin/env bash
#
# Human → agent delegation, end to end: Keycloak token-exchange DELEGATION
# issues the agent a token that says "acme_assist acts for alice"; pgauthz
# decides what the agent may do while it does — bounded by a TASK the PEP opens
# and closes. See README.md in this directory for the full story.
#
#   1. alice logs in to acme-app and CONSENTS to acme_assist acting for her
#      (scope delegation:client:acme_assist → her token carries may_act)
#   2. acme_assist exchanges her token + its own for a DELEGATED token
#      (sub = alice, act.client_id = acme_assist; no refresh token)
#   3. pgauthzd checks that token AS agent:acme_assist (ACTOR_CLAIM) — with the
#      agent's authority in the `agents` store, never alice's
#   4. the PEP (acme-app's service account) OPENS a task: task scope + operator
#      binding + a subagent delegation, all expiring, written atomically under
#      a precondition on alice's own access
#   5. during the task: the agent reads CustCo (ALLOW), not Globex (task scope),
#      cannot create automations alice can (no inherited authority); the
#      subagent reads through the agent's reach
#   6. Keycloak refuses the wrong actor and a re-exchange of the delegated token
#   7. the PEP CLOSES the task (one conditional delete of the bundle): the same,
#      still-valid delegated token is now DENIED everywhere; time travel shows
#      the window in which it was allowed
#
# Usage:
#   examples/agentic/delegation-demo.sh             # scripted login + consent (curl)
#   examples/agentic/delegation-demo.sh --browser   # you open the consent URL yourself
#   examples/agentic/delegation-demo.sh --verbose   # echo every HTTP call
#   examples/agentic/delegation-demo.sh --keep      # leave the task open (poke around)
#
# Prerequisites (keycloak/README.md): generate-mkcerts.sh, ./start.sh --keycloak,
# terraform apply (creates acme-app / acme_assist / acme-other-agent + the delegate
# permission), the 'agents' store loaded (tests/test.sh or bootstrap.sh),
# *.pgauthz.test in /etc/hosts. Needs curl, jq, python3, terraform (for the client
# secrets — or export ACME_APP_SECRET / ACME_ASSIST_SECRET / ACME_OTHER_AGENT_SECRET).
set -euo pipefail

VERBOSE=0; BROWSER=0; KEEP=0
for arg in "$@"; do
  case "$arg" in
    -v|--verbose) VERBOSE=1 ;;
    --browser)    BROWSER=1 ;;
    --keep)       KEEP=1 ;;
    -h|--help)    sed -n '2,36p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ISSUER="${ISSUER:-https://id.pgauthz.test/realms/pgauthz}"
BASE="${BASE:-https://api.pgauthz.test}"                 # pgauthzd front door (reads)
WRITER="${WRITER:-http://localhost:8092}"                # pgauthzd-full public listener (writes)
INTERNAL="${INTERNAL:-http://localhost:8093}"            # pgauthzd-opa INTERNAL callback listener (trusted-PEP reads)
INTERNAL_TOKEN="${NATIVE_SERVICE_TOKEN:-dev-native-service-token}"
STORE="${STORE:-agents}"
USER_NAME="${DEMO_USER:-alice}"; USER_PASSWORD="${DEMO_PASSWORD:-password}"
AGENT="acme_assist"; OTHER_AGENT="acme-other-agent"; APP="acme-app"; SUBAGENT="research_agent"
TASK_MINUTES="${TASK_MINUTES:-10}"
CACERT="$REPO_ROOT/keycloak/config/certs/rootCA.pem"
TF_DIR="$REPO_ROOT/keycloak/terraform"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

for bin in curl jq python3; do command -v "$bin" >/dev/null || { echo "!! $bin is required" >&2; exit 1; }; done
CURL=(curl -sS); [ -f "$CACERT" ] && CURL+=(--cacert "$CACERT")

# ── helpers ───────────────────────────────────────────────────────────────────
say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '    %s\n' "$*"; }
verbose() { [ "$VERBOSE" = 1 ] && printf '  → %s\n' "$*" >&2; return 0; }

secret() { # secret <client-id> — env override, else terraform output
  local var; var="$(printf '%s' "$1" | tr '[:lower:]-' '[:upper:]_')_SECRET"
  if [ -n "${!var:-}" ]; then printf '%s' "${!var}"; return; fi
  local out; out="$(printf '%s' "$1" | tr '-' '_')_client_secret"
  if command -v terraform >/dev/null && [ -d "$TF_DIR/.terraform" ]; then
    local v; v="$(cd "$TF_DIR" && terraform output -raw "$out" 2>/dev/null || true)"
    if [ -n "$v" ]; then printf '%s' "$v"; return; fi
  fi
  # the demo defaults of keycloak/terraform/variables.tf (override with $var)
  printf '%s-demo-secret' "$(printf '%s' "$1" | tr '_' '-')"
}
claims() { # claims <jwt> — decoded payload (JSON)
  python3 -I -c 'import sys,base64; p=sys.argv[1].split(".")[1]; p+="="*(-len(p)%4); print(base64.urlsafe_b64decode(p).decode())' "$1"
}
token_post() { # token_post <form-fields...> — POST to the token endpoint, print the body
  "${CURL[@]}" "$ISSUER/protocol/openid-connect/token" "${@/#/-d}"
}
# fetch <url> [curl args…] — GET/POST a browser page into $PAGE (cookie jar,
# redirects followed) and remember its final URL in $PAGE_URL.
fetch() {
  local url="$1"; shift
  PAGE_URL="$("${CURL[@]}" -c "$JAR" -b "$JAR" -L -o "$PAGE" -w '%{url_effective}' "$url" "$@")"
}
# form_action <html-file> <input-name> — action URL of the form that contains
# that input, resolved against $PAGE_URL (Keycloak's consent form action is a
# root-relative path).
form_action() {
  python3 -I - "$1" "$2" "${PAGE_URL:-}" <<'PY'
import sys, html
from urllib.parse import urljoin
from html.parser import HTMLParser
class P(HTMLParser):
    def __init__(s): super().__init__(); s.forms=[]; s.cur=None
    def handle_starttag(s, tag, attrs):
        a=dict(attrs)
        if tag=="form": s.cur={"action":a.get("action",""),"inputs":set()}; s.forms.append(s.cur)
        elif tag in ("input","button") and s.cur is not None and a.get("name"): s.cur["inputs"].add(a["name"])
    def handle_endtag(s, tag):
        if tag=="form": s.cur=None
p=P(); p.feed(open(sys.argv[1], encoding="utf-8", errors="replace").read())
for f in p.forms:
    if sys.argv[2] in f["inputs"]: print(urljoin(sys.argv[3], html.unescape(f["action"]))); break
PY
}
# consent_items <html-file> — the consent screen's list items (what alice is asked to allow)
consent_items() {
  python3 -I - "$1" <<'PY'
import sys, re, html
s=open(sys.argv[1], encoding="utf-8", errors="replace").read()
for li in re.findall(r"<li[^>]*>(.*?)</li>", s, re.S):
    t=" ".join(html.unescape(re.sub(r"<[^>]+>", " ", li)).split())
    if t and len(t) < 160 and "{" not in t: print("  - " + t)
PY
}
hidden_value() { # hidden_value <html-file> <input-name>
  python3 -I - "$1" "$2" <<'PY'
import sys, html
from html.parser import HTMLParser
class P(HTMLParser):
    def handle_starttag(s, tag, attrs):
        a=dict(attrs)
        if tag=="input" and a.get("name")==sys.argv[2]: print(html.unescape(a.get("value",""))); raise SystemExit
P().feed(open(sys.argv[1], encoding="utf-8", errors="replace").read())
PY
}

# evaluate <token> <action> <type> <id> → ALLOW | DENY (AuthZEN; subject from the token).
# Cache-Control: no-cache — the PEP just changed the graph and wants the
# decision for THIS request, not one OPA cached a moment ago (pgauthzd forwards
# it as input.no_cache; the direct backend has no decision cache).
evaluate() {
  local body="{\"action\":{\"name\":\"$2\"},\"resource\":{\"type\":\"$3\",\"id\":\"$4\"}}" res
  verbose "POST $BASE/stores/$STORE/access/v1/evaluation  $body"
  res="$("${CURL[@]}" "$BASE/stores/$STORE/access/v1/evaluation" -H 'Content-Type: application/json' \
        -H 'Cache-Control: no-cache' -H "Authorization: Bearer $1" -d "$body")"
  case "$(printf '%s' "$res" | jq -r '.decision')" in true) echo ALLOW ;; false) echo DENY ;; *) echo "ERR($res)" ;; esac
}
# actions <token> <type> <id> → the actions the token's subject may perform (AuthZEN search/action)
actions() {
  "${CURL[@]}" "$BASE/stores/$STORE/access/v1/search/action" -H 'Content-Type: application/json' \
    -H 'Cache-Control: no-cache' -H "Authorization: Bearer $1" -d "{\"resource\":{\"type\":\"$2\",\"id\":\"$3\"}}" \
    | jq -c 'if .results then [.results[].action.name] | sort else . end'
}
# pep_check <type> <id> <action> <obj-type> <obj-id> → ALLOW | DENY, asserting the subject
# (the INTERNAL listener trusts its caller — this is how a PEP in front of a
# SUBAGENT asks; the subagent holds no Keycloak token of its own)
pep_check() {
  local body="{\"subject\":{\"type\":\"$1\",\"id\":\"$2\"},\"action\":{\"name\":\"$3\"},\"resource\":{\"type\":\"$4\",\"id\":\"$5\"}}" res
  verbose "POST $INTERNAL/stores/$STORE/pgauthz/v1/check  $body"
  res="$("${CURL[@]}" "$INTERNAL/stores/$STORE/pgauthz/v1/check" -H 'Content-Type: application/json' \
        -H "Authorization: Bearer $INTERNAL_TOKEN" -d "$body")"
  case "$(printf '%s' "$res" | jq -r '.allowed')" in true) echo ALLOW ;; false) echo DENY ;; *) echo "ERR($res)" ;; esac
}
pep_explain() { # pep_explain <type> <id> <action> <obj-type> <obj-id> → the summary tree
  "${CURL[@]}" "$INTERNAL/stores/$STORE/pgauthz/v1/explain" -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $INTERNAL_TOKEN" \
    -d "{\"subject\":{\"type\":\"$1\",\"id\":\"$2\"},\"action\":{\"name\":\"$3\"},\"resource\":{\"type\":\"$4\",\"id\":\"$5\"}}" \
    | jq -r '.summary // .decision'
}
# write_checked <pep-token> <json-body> — conditional/atomic write on the writer (the PEP's identity)
write_checked() {
  verbose "POST $WRITER/stores/$STORE/pgauthz/v1/write-checked  $2"
  "${CURL[@]}" "$WRITER/stores/$STORE/pgauthz/v1/write-checked" -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $1" -d "$2"
}
expires_at() { python3 -I -c 'import sys,datetime; print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=int(sys.argv[1]))).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$1"; }
DB="$(docker ps --filter name=authz-db --format '{{.Names}}' 2>/dev/null | head -1 || true)"
sql() { docker exec -i -e PGPASSWORD="${PG_PASSWORD:-authz}" "$DB" psql -U "${PG_USER:-authz}" -d "${PG_DB:-authz}" -tA -c "$1"; }
# now_utc — the DATABASE clock when reachable (the audit trail is stamped by it;
# a host clock inside Docker Desktop can be off by hundreds of ms), else host time
now_utc() {
  if [ -n "$DB" ]; then sql "select to_char(clock_timestamp() at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')"; return; fi
  python3 -I -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))'
}
tuple() { printf '{"user_type":"%s","user_id":"%s","relation":"%s","object_type":"%s","object_id":"%s"%s}' "$1" "$2" "$3" "$4" "$5" "${6:-}"; }

# ── 0. The cast, and a clean slate ──────────────────────────────────────────
say "==> Cast"
note "user:$USER_NAME        logs in to $APP; on CustCo's account team (customer#member)"
note "agent:$AGENT   the agent; may work on CustCo AND Globex docs (agent_reader via its reach)"
note "agent:$SUBAGENT the subagent $AGENT fans work out to"
note "$APP's service account = the PEP: it opens and closes the agent's TASK"

SECRET_APP="$(secret "$APP")"; SECRET_AGENT="$(secret "$AGENT")"; SECRET_OTHER="$(secret "$OTHER_AGENT")"

say "==> 0. The PEP's own token (client_credentials as $APP; realm roles authz_writer + authz_recorder)"
TOK_PEP="$(token_post "grant_type=client_credentials" "client_id=$APP" "client_secret=$SECRET_APP" | jq -r '.access_token // empty')"
[ -n "$TOK_PEP" ] || { echo "!! no PEP token — is the realm provisioned (terraform apply)?" >&2; exit 1; }
note "sub=$(claims "$TOK_PEP" | jq -r .preferred_username)  roles=$(claims "$TOK_PEP" | jq -c .realm_access.roles)"

# The seed (examples/models/agents/seed.sql) opens a task for the agent; close
# it so the lifecycle below starts from "no task" — the same bundle the PEP
# removes at task end (idempotent: deleting a missing tuple is a no-op).
note "closing any task the seed left open (so the demo starts from 'no task')"
"${CURL[@]}" "$WRITER/stores/$STORE/pgauthz/v1/delete" -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK_PEP" \
  -d "{\"tuples\":[$(tuple user "$USER_NAME" operator agent "$AGENT"),$(tuple agent "$AGENT" task_scope customer CustCo),$(tuple agent "$SUBAGENT" delegate agent "$AGENT"),$(tuple agent "$SUBAGENT" task_scope customer CustCo)]}" \
  | jq -c . >/dev/null

# ── 1. alice logs in and consents to the agent acting for her ───────────────
say "==> 1. $USER_NAME logs in to $APP and consents to '$AGENT may act on your behalf'"
note "Device Authorization Grant with scope: openid profile delegation:client:$AGENT"
DEV="$("${CURL[@]}" "$ISSUER/protocol/openid-connect/auth/device" -d "client_id=$APP" -d "client_secret=$SECRET_APP" \
       -d "scope=openid profile delegation:client:$AGENT")"
DEVICE_CODE="$(printf '%s' "$DEV" | jq -r '.device_code // empty')"
VERIFY_URL="$(printf '%s' "$DEV" | jq -r '.verification_uri_complete // empty')"
[ -n "$DEVICE_CODE" ] || { echo "!! device authorization failed: $DEV" >&2; exit 1; }

if [ "$BROWSER" = 1 ]; then
  note "open this URL, log in as $USER_NAME / $USER_PASSWORD and accept the consent:"
  note "$VERIFY_URL"
else
  # Drive the login + consent forms (what a browser would do). Each round: fetch
  # the page, find the form by a field it must contain, post it.
  JAR="$WORK/jar"; PAGE="$WORK/page.html"; PAGE_URL=""
  fetch "$VERIFY_URL"
  for _ in 1 2 3 4; do
    if   action="$(form_action "$PAGE" device_user_code)" && [ -n "$action" ]; then
      verbose "submitting the user code"
      fetch "$action" --data-urlencode "device_user_code=$(printf '%s' "$DEV" | jq -r .user_code)"
    elif action="$(form_action "$PAGE" username)" && [ -n "$action" ]; then
      verbose "submitting the login form as $USER_NAME"
      fetch "$action" --data-urlencode "username=$USER_NAME" --data-urlencode "password=$USER_PASSWORD" -d "credentialId="
    elif action="$(form_action "$PAGE" accept)" && [ -n "$action" ]; then
      note "consent screen asks $USER_NAME to allow:"; consent_items "$PAGE" | sed 's/^/    /'
      note "→ accepting"
      fetch "$action" --data-urlencode "code=$(hidden_value "$PAGE" code)" -d "accept=Yes"
    else
      break
    fi
  done
fi

note "polling the token endpoint for the device code…"
TOK_USER=""
for _ in $(seq 1 150); do
  res="$(token_post "grant_type=urn:ietf:params:oauth:grant-type:device_code" "client_id=$APP" "client_secret=$SECRET_APP" "device_code=$DEVICE_CODE")"
  TOK_USER="$(printf '%s' "$res" | jq -r '.access_token // empty')"
  [ -n "$TOK_USER" ] && break
  case "$(printf '%s' "$res" | jq -r '.error // empty')" in
    authorization_pending|slow_down) sleep 2 ;;
    *) echo "!! device token request failed: $res" >&2; [ "$BROWSER" = 1 ] || echo "   (re-run with --browser to do the login/consent yourself)" >&2; exit 1 ;;
  esac
done
[ -n "$TOK_USER" ] || { echo "!! timed out waiting for the login/consent" >&2; exit 1; }
C="$(claims "$TOK_USER")"
note "$USER_NAME's token:  sub=$(jq -r .preferred_username <<<"$C")  azp=$(jq -r .azp <<<"$C")  aud=$(jq -c .aud <<<"$C")"
note "                scope=\"$(jq -r .scope <<<"$C")\""
note "                may_act=$(jq -c .may_act <<<"$C")   ← Keycloak recorded the consent"
jq -e '.may_act.client_id == "'"$AGENT"'"' <<<"$C" >/dev/null || { echo "!! no may_act for $AGENT — is the delegate permission in place (terraform apply) and KC_FEATURES set?" >&2; exit 1; }

# ── 2+3. the agent obtains its delegated token ───────────────────────────────
say "==> 2. $AGENT obtains its own actor token (client_credentials) …"
TOK_ACTOR="$(token_post "grant_type=client_credentials" "client_id=$AGENT" "client_secret=$SECRET_AGENT" | jq -r '.access_token')"
say "==> 3. … and exchanges $USER_NAME's token + its actor token for a DELEGATED token"
XCHG="$(token_post "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" "client_id=$AGENT" "client_secret=$SECRET_AGENT" \
  "subject_token=$TOK_USER" "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  "actor_token=$TOK_ACTOR" "actor_token_type=urn:ietf:params:oauth:token-type:access_token" \
  "requested_token_type=urn:ietf:params:oauth:token-type:access_token")"
TOK_DELEGATED="$(printf '%s' "$XCHG" | jq -r '.access_token // empty')"
[ -n "$TOK_DELEGATED" ] || { echo "!! token exchange failed: $XCHG" >&2; exit 1; }
C="$(claims "$TOK_DELEGATED")"
note "delegated token: sub=$(jq -r .preferred_username <<<"$C")  azp=$(jq -r .azp <<<"$C")  aud=$(jq -c .aud <<<"$C")  subject_type=$(jq -r .subject_type <<<"$C")"
note "                 act=$(jq -c .act <<<"$C")"
note "                 refresh_token: $(printf '%s' "$XCHG" | jq -r 'if .refresh_token then "present" else "none (transient session)" end')   expires in $(printf '%s' "$XCHG" | jq -r .expires_in)s"
note "pgauthzd (ACTOR_CLAIM=act.client_id) checks this token AS agent:$AGENT, on behalf of user:$USER_NAME"

# ── 4. before any task: the token alone grants nothing ──────────────────────
say "==> 4. No task is open. A valid delegated token alone grants the agent nothing:"
printf '    %-44s %-18s %s\n' "agent:$AGENT (delegated token)" "documents_read" "customer_doc:custco-briefing → $(evaluate "$TOK_DELEGATED" documents_read customer_doc custco-briefing)"
printf '    %-44s %-18s %s\n' "user:$USER_NAME (her own token)" "documents_read" "customer_doc:custco-briefing → $(evaluate "$TOK_USER" documents_read customer_doc custco-briefing)"
note "(alice may read it herself; the agent does not inherit that from acting for her)"

# ── 5. the PEP opens the task ────────────────────────────────────────────────
say "==> 5. The PEP opens a task for $AGENT: 'brief $USER_NAME on CustCo', deadline in $TASK_MINUTES minutes"
EXP="$(expires_at "$TASK_MINUTES")"
note "one atomic write-checked call: precondition = $USER_NAME herself is a member of CustCo"
note "(an agent can only be scoped to what the user it acts for may reach); writes, all expiring at $EXP:"
note "  user:$USER_NAME operator agent:$AGENT          — the delegation the token asserts, as a graph fact"
note "  agent:$AGENT task_scope customer:CustCo   — what THIS task is about"
note "  agent:$SUBAGENT delegate agent:$AGENT    — the subagent joins the agent's reach"
note "  agent:$SUBAGENT task_scope customer:CustCo — … for the same task"
T_OPEN="$(now_utc)"
RES="$(write_checked "$TOK_PEP" "{
  \"preconditions\":[{\"match\":\"allowed\",\"user_type\":\"user\",\"user_id\":\"$USER_NAME\",\"relation\":\"member\",\"object_type\":\"customer\",\"object_id\":\"CustCo\"}],
  \"writes\":[
    $(tuple user "$USER_NAME" operator agent "$AGENT" ",\"expires_at\":\"$EXP\""),
    $(tuple agent "$AGENT" task_scope customer CustCo ",\"expires_at\":\"$EXP\""),
    $(tuple agent "$SUBAGENT" delegate agent "$AGENT" ",\"expires_at\":\"$EXP\""),
    $(tuple agent "$SUBAGENT" task_scope customer CustCo ",\"expires_at\":\"$EXP\"")]}")"
note "→ $(printf '%s' "$RES" | jq -c .)  (performed_by = the PEP's token subject)"
printf '%s' "$RES" | jq -e '.written == 4' >/dev/null || { echo "!! task open failed: $RES" >&2; exit 1; }

say "==> 6. During the task — the same delegated token, now checked against an OPEN task:"
hdr() { printf '    %-44s %-18s %-30s %s\n' "$@"; }
hdr "PRINCIPAL (from the token)" "ACTION" "RESOURCE" "DECISION"
hdr "agent:$AGENT (delegated token)" documents_read customer_doc:custco-briefing "$(evaluate "$TOK_DELEGATED" documents_read customer_doc custco-briefing)"
hdr "agent:$AGENT (delegated token)" documents_read customer_doc:globex-plan     "$(evaluate "$TOK_DELEGATED" documents_read customer_doc globex-plan)   ← may work on Globex in general, but not in THIS task"
hdr "agent:$AGENT (delegated token)" create         automation:nightly-report    "$(evaluate "$TOK_DELEGATED" create automation nightly-report)   ← control plane: no agent path exists"
hdr "user:$USER_NAME (her own token)" create         automation:nightly-report    "$(evaluate "$TOK_USER" create automation nightly-report)   ← alice may; the agent did not inherit it"
note "what may the agent do on custco-briefing? (search/action, the planner's question) → $(actions "$TOK_DELEGATED" customer_doc custco-briefing)"
note "the binding the token asserts is now a graph fact the PEP can verify: user:$USER_NAME operator agent:$AGENT → $(pep_check user "$USER_NAME" operator agent "$AGENT")"
note ""
note "the subagent reads THROUGH the agent's reach (no Keycloak token of its own — its PEP asserts it):"
hdr "agent:$SUBAGENT (asserted by its PEP)" documents_read customer_doc:custco-briefing "$(pep_check agent "$SUBAGENT" documents_read customer_doc custco-briefing)"
hdr "agent:$SUBAGENT (asserted by its PEP)" documents_read customer_doc:globex-plan     "$(pep_check agent "$SUBAGENT" documents_read customer_doc globex-plan)"
note "resolution path for agent:$AGENT → documents_read → custco-briefing:"
pep_explain agent "$AGENT" documents_read customer_doc custco-briefing | sed 's/^/      /'

# ── 7. what Keycloak refuses ─────────────────────────────────────────────────
say "==> 7. What the issuer refuses (before pgauthz is even asked):"
TOK_OTHER="$(token_post "grant_type=client_credentials" "client_id=$OTHER_AGENT" "client_secret=$SECRET_OTHER" | jq -r '.access_token')"
R="$(token_post "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" "client_id=$OTHER_AGENT" "client_secret=$SECRET_OTHER" \
  "subject_token=$TOK_USER" "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  "actor_token=$TOK_OTHER" "actor_token_type=urn:ietf:params:oauth:token-type:access_token")"
note "$OTHER_AGENT tries the exchange with $USER_NAME's token → $(printf '%s' "$R" | jq -r '"\(.error): \(.error_description)"')"
R="$(token_post "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" "client_id=$AGENT" "client_secret=$SECRET_AGENT" \
  "subject_token=$TOK_DELEGATED" "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  "requested_token_type=urn:ietf:params:oauth:token-type:access_token")"
note "$AGENT tries to exchange the DELEGATED token again → $(printf '%s' "$R" | jq -r '"\(.error): \(.error_description)"')"
note "(a login requesting delegation:client:$OTHER_AGENT succeeds but drops the scope: no consent, no may_act)"

if [ "$KEEP" = 1 ]; then
  say "==> --keep: the task stays open until $EXP (then every tuple above expires)."
  note "export TOK_DELEGATED=$TOK_DELEGATED"
  exit 0
fi

# ── 8. the PEP closes the task ───────────────────────────────────────────────
say "==> 8. The task is done — the PEP closes it: ONE conditional delete of the bundle"
note "(precondition: the task is still open; the deadline above would have closed it anyway)"
T_DURING="$(now_utc)"
RES="$(write_checked "$TOK_PEP" "{
  \"preconditions\":[{\"match\":\"exists\",\"user_type\":\"agent\",\"user_id\":\"$AGENT\",\"relation\":\"task_scope\",\"object_type\":\"customer\",\"object_id\":\"CustCo\"}],
  \"deletes\":[
    $(tuple user "$USER_NAME" operator agent "$AGENT"),
    $(tuple agent "$AGENT" task_scope customer CustCo),
    $(tuple agent "$SUBAGENT" delegate agent "$AGENT"),
    $(tuple agent "$SUBAGENT" task_scope customer CustCo)]}")"
note "→ $(printf '%s' "$RES" | jq -c .)"
T_CLOSED="$(now_utc)"

say "==> 9. After the task — the SAME delegated token (still valid for $(( $(jq -r .exp <<<"$C") - $(date +%s) ))s), nothing changed at Keycloak:"
hdr "PRINCIPAL (from the token)" "ACTION" "RESOURCE" "DECISION"
hdr "agent:$AGENT (delegated token)" documents_read customer_doc:custco-briefing "$(evaluate "$TOK_DELEGATED" documents_read customer_doc custco-briefing)"
hdr "agent:$SUBAGENT (asserted by its PEP)" documents_read customer_doc:custco-briefing "$(pep_check agent "$SUBAGENT" documents_read customer_doc custco-briefing)"
hdr "user:$USER_NAME (her own token)" documents_read customer_doc:custco-briefing "$(evaluate "$TOK_USER" documents_read customer_doc custco-briefing)   ← alice's own access is untouched"
note "search/action for the agent on custco-briefing → $(actions "$TOK_DELEGATED" customer_doc custco-briefing)"

# ── 10. time travel: when was the agent allowed? ─────────────────────────────
if [ -n "$DB" ]; then
  say "==> 10. Time travel (authz.audit_check_access) — was agent:$AGENT allowed to read custco-briefing …"
  q() { sql "SELECT authz.audit_check_access('$STORE','agent','$AGENT','documents_read','customer_doc','custco-briefing','$1'::timestamptz)"; }
  note "… just before the task opened  ($T_OPEN)?   → $(q "$T_OPEN")"
  note "… while it was open             ($T_DURING)? → $(q "$T_DURING")"
  note "… after it was closed           ($T_CLOSED)? → $(q "$T_CLOSED")"
  note "the audit trail has who opened/closed it (performed_by = the PEP), when, and with which expiry."
fi

say "==> Done."
note "Layer 1 (Keycloak): WHO may act for WHOM — consent, may_act → act; one hop, no re-exchange."
note "Layer 2 (pgauthz):  WHAT the actor may do WHILE it does — the agent's own authority ∩ the task;"
note "                    subagents by delegation tuples; closed by the PEP or by the deadline; replayable."
