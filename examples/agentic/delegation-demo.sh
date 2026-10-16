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
#   6. STEP-UP: mid-task the agent needs Globex (DENY, reason in hand). The PEP
#      asks alice OUT OF BAND — Keycloak CIBA (backchannel authentication):
#      Keycloak hands the request to the "authentication entity" (alice's
#      device — played by this script, listening on :18555); her decline ends
#      in access_denied and nothing changes; her approval yields a fresh token
#      with may_act, and only THEN does the PEP widen the task bundle (one
#      more write-checked, same precondition pattern)
#   7. Keycloak refuses the wrong actor and a re-exchange of the delegated token
#   8. the PEP CLOSES the task (one conditional delete of the bundle): the same,
#      still-valid delegated token is now DENIED everywhere; time travel shows
#      the window in which it was allowed
#
# Usage:
#   examples/agentic/delegation-demo.sh             # scripted: curl drives login + consent, alice's
#                                                   # device declines, then approves the step-up
#   examples/agentic/delegation-demo.sh --browser   # you are alice: open the consent URL yourself,
#                                                   # answer the step-up on the terminal
#   examples/agentic/delegation-demo.sh --verbose   # echo every HTTP call
#   examples/agentic/delegation-demo.sh --keep      # leave the task open (poke around)
#
# Prerequisites (keycloak/README.md): generate-mkcerts.sh, ./start.sh --keycloak,
# terraform apply (creates acme-app / acme_assist / acme-other-agent + the delegate
# permission + the CIBA grant), the 'agents' store loaded (tests/test.sh or
# bootstrap.sh), *.pgauthz.test in /etc/hosts. Needs curl, jq, python3, terraform
# (for the client secrets — or export ACME_APP_SECRET / ACME_ASSIST_SECRET /
# ACME_OTHER_AGENT_SECRET). Keycloak must reach this host on CIBA_AE_PORT (18555;
# compose-keycloak.yml points its authentication channel at host.docker.internal).
set -euo pipefail

VERBOSE=0; BROWSER=0; KEEP=0
for arg in "$@"; do
  case "$arg" in
    -v|--verbose) VERBOSE=1 ;;
    --browser)    BROWSER=1 ;;
    --keep)       KEEP=1 ;;
    -h|--help)    sed -n '2,46p' "$0"; exit 0 ;;
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
CIBA_AE_PORT="${CIBA_AE_PORT:-18555}"                    # where Keycloak delivers CIBA requests (alice's "device")
CACERT="$REPO_ROOT/keycloak/config/certs/rootCA.pem"
TF_DIR="$REPO_ROOT/keycloak/terraform"
WORK="$(mktemp -d)"; AE_PID=""
cleanup() { [ -n "$AE_PID" ] && kill "$AE_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

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
# evaluate_detailed <token> <action> <type> <id> → "ALLOW|DENY  state=… reason=…" — the rich
# decision (X-PGAuthz-Detail): the planner's cue to ask for more rather than retry.
evaluate_detailed() {
  local body="{\"action\":{\"name\":\"$2\"},\"resource\":{\"type\":\"$3\",\"id\":\"$4\"}}" res
  res="$("${CURL[@]}" "$BASE/stores/$STORE/access/v1/evaluation" -H 'Content-Type: application/json' -H 'X-PGAuthz-Detail: true' \
        -H 'Cache-Control: no-cache' -H "Authorization: Bearer $1" -d "$body")"
  jq -r 'if .decision == true then "ALLOW" elif .decision == false then "DENY " else "ERR" end + "  state=\(.context.state) reason=\(.context.reason)"' <<<"$res"
}
# actions <token> <type> <id> → the actions the token's subject may perform (AuthZEN search/action)
actions() {
  "${CURL[@]}" "$BASE/stores/$STORE/access/v1/search/action" -H 'Content-Type: application/json' \
    -H 'Cache-Control: no-cache' -H "Authorization: Bearer $1" -d "{\"resource\":{\"type\":\"$2\",\"id\":\"$3\"}}" \
    | jq -c 'if .results then [.results[].name] | sort else . end'
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
# write_plain <pep-token> <tuple-json…> — unconditional upsert on the writer (demo fixtures)
write_plain() {
  local tok="$1"; shift
  "${CURL[@]}" "$WRITER/stores/$STORE/pgauthz/v1/write" -H 'Content-Type: application/json' -H "Authorization: Bearer $tok" \
    -d "{\"tuples\":[$(IFS=,; printf '%s' "$*")]}"
}
# write_checked <pep-token> <json-body> — conditional/atomic write on the writer (the PEP's identity)
write_checked() {
  verbose "POST $WRITER/stores/$STORE/pgauthz/v1/write-checked  $2"
  "${CURL[@]}" "$WRITER/stores/$STORE/pgauthz/v1/write-checked" -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $1" -d "$2"
}
# exchange <user-token> → the agent's DELEGATED token (RFC 8693 token exchange:
# subject_token = the user's, actor_token = the agent's own; the result says
# sub = user, act.client_id = agent). Prints the whole token response.
exchange() {
  local actor; actor="$(token_post "grant_type=client_credentials" "client_id=$AGENT" "client_secret=$SECRET_AGENT" | jq -r '.access_token')"
  token_post "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" "client_id=$AGENT" "client_secret=$SECRET_AGENT" \
    "subject_token=$1" "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
    "actor_token=$actor" "actor_token_type=urn:ietf:params:oauth:token-type:access_token" \
    "requested_token_type=urn:ietf:params:oauth:token-type:access_token"
}

# ── CIBA: the out-of-band consent channel ────────────────────────────────────
# Keycloak's HTTP authentication channel POSTs every backchannel authentication
# request to an external "authentication entity" (AE) — the thing that reaches
# the user: a push notification, a banking app. Here the AE is alice's device,
# played by this script: a tiny HTTP server that spools what Keycloak sends
# (login_hint, scope, is_consent_required, binding_message, our extra fields)
# and answers 201. The decision itself goes back on Keycloak's callback
# endpoint with the bearer token the request carried: SUCCEED = authenticated
# AND consented (the delegation scope included), CANCELLED = declined.
AE_SPOOL="$WORK/ciba"; mkdir -p "$AE_SPOOL"; AE_SEEN=0
ae_start() {
  cat > "$WORK/ae.py" <<'EOF'
import sys, json, os
from http.server import BaseHTTPRequestHandler, HTTPServer
spool, port = sys.argv[1], int(sys.argv[2])
class AE(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        req = {"bearer": (self.headers.get("Authorization") or "").split(" ", 1)[-1], "body": json.loads(body) if body else {}}
        n = len([f for f in os.listdir(spool) if f.startswith("req-")]) + 1
        tmp = os.path.join(spool, ".tmp"); open(tmp, "w").write(json.dumps(req)); os.rename(tmp, os.path.join(spool, f"req-{n}.json"))
        self.send_response(201); self.end_headers()
HTTPServer(("0.0.0.0", port), AE).serve_forever()
EOF
  python3 -I "$WORK/ae.py" "$AE_SPOOL" "$CIBA_AE_PORT" & AE_PID=$!
  sleep 0.5; kill -0 "$AE_PID" 2>/dev/null || { echo "!! could not listen on :$CIBA_AE_PORT for CIBA requests (set CIBA_AE_PORT + CIBA_AUTH_CHANNEL_URI)" >&2; exit 1; }
}
# ciba_request <binding-message> [extra form fields…] — the PEP (acme-app) asks
# Keycloak to authenticate alice out of band, with the delegation scope. Sets
# CIBA_ACK (auth_req_id, expires_in, interval). binding_message: ≤ 50 plain
# chars, no spaces (the code alice compares on her device); anything else the
# PEP wants shown rides along as extra parameters.
ciba_request() {
  local bm="$1" extra=() x; shift
  for x in "$@"; do extra+=(--data-urlencode "$x"); done
  verbose "POST $ISSUER/protocol/openid-connect/ext/ciba/auth  login_hint=$USER_NAME scope='openid delegation:client:$AGENT' binding_message=$bm $*"
  CIBA_ACK="$("${CURL[@]}" "$ISSUER/protocol/openid-connect/ext/ciba/auth" -d "client_id=$APP" -d "client_secret=$SECRET_APP" \
    -d "login_hint=$USER_NAME" -d "scope=openid delegation:client:$AGENT" -d "binding_message=$bm" "${extra[@]}")"
  jq -e '.auth_req_id' <<<"$CIBA_ACK" >/dev/null 2>&1 || {
    echo "!! backchannel authentication request failed: $CIBA_ACK" >&2
    echo "   (CIBA grant on $APP + the auth-channel URI: terraform apply, compose-keycloak.yml; is :$CIBA_AE_PORT reachable from the keycloak container?)" >&2; exit 1; }
}
# ae_next — waits for the next request Keycloak delivered to alice's device; sets REQ to its file
# (not a subshell/$(…): the consumed-count must survive the call)
ae_next() {
  REQ="$AE_SPOOL/req-$((AE_SEEN + 1)).json"
  for _ in $(seq 1 100); do [ -f "$REQ" ] && break; sleep 0.1; done
  [ -f "$REQ" ] || { echo "!! Keycloak did not deliver the CIBA request to :$CIBA_AE_PORT" >&2; exit 1; }
  AE_SEEN=$((AE_SEEN + 1))
}
# ae_show <req-file> — what alice sees on her device
ae_show() {
  local b; b="$(jq -c .body "$1")"
  note "  ┌─ $USER_NAME's device ─────────────────────────────────────────────"
  note "  │ $(jq -r '.ask // "authentication requested"' <<<"$b")"
  note "  │ task: $(jq -r '.task // "-"' <<<"$b")   code: $(jq -r .binding_message <<<"$b")   requested by: $APP"
  note "  │ consent required: $(jq -r .is_consent_required <<<"$b")   scope: $(jq -r .scope <<<"$b")"
  note "  └─ [Approve]  [Decline]"
}
# ae_answer <req-file> <SUCCEED|CANCELLED> — alice's device answers on Keycloak's callback endpoint
ae_answer() {
  local code; code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$ISSUER/protocol/openid-connect/ext/ciba/auth/callback" \
    -H "Authorization: Bearer $(jq -r .bearer "$1")" -H 'Content-Type: application/json' -d "{\"status\":\"$2\"}")"
  verbose "POST …/ext/ciba/auth/callback {status: $2} → HTTP $code"
}
# ciba_poll → the token response once the answer is in (polls at the ack's interval)
ciba_poll() {
  local res interval; interval="$(jq -r '.interval // 5' <<<"$CIBA_ACK")"
  for _ in $(seq 1 60); do
    res="$(token_post "grant_type=urn:openid:params:grant-type:ciba" "client_id=$APP" "client_secret=$SECRET_APP" "auth_req_id=$(jq -r .auth_req_id <<<"$CIBA_ACK")")"
    case "$(jq -r '.error // empty' <<<"$res")" in authorization_pending|slow_down) sleep "$interval" ;; *) printf '%s' "$res"; return ;; esac
  done
  printf '%s' "$res"
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
note "$APP's service account = the PEP: it opens and closes the agent's TASK — and asks $USER_NAME when the agent needs more"
note "$USER_NAME's device         where an out-of-band consent request lands (CIBA) — played by this script on :$CIBA_AE_PORT"
ae_start

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
  -d "{\"tuples\":[$(tuple user "$USER_NAME" operator agent "$AGENT"),$(tuple agent "$AGENT" task_scope customer CustCo),$(tuple agent "$AGENT" task_scope customer Globex),$(tuple agent "$SUBAGENT" delegate agent "$AGENT"),$(tuple agent "$SUBAGENT" task_scope customer CustCo)]}" \
  | jq -c . >/dev/null
# Demo fixture: the seed puts alice on CustCo's account team only. The step-up
# (step 7) widens the task to a SECOND customer alice herself may reach, so
# she joins Globex's account team for the duration of the demo (removed at the
# end). The agent may work on Globex anyway (agent_reader) — the task doesn't.
note "demo fixture: $USER_NAME joins Globex's account team too (a second customer SHE may reach; the task does not cover it yet)"
write_plain "$TOK_PEP" "$(tuple user "$USER_NAME" member customer Globex)" | jq -c . >/dev/null

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
say "==> 3. … and exchanges $USER_NAME's token + its actor token for a DELEGATED token"
XCHG="$(exchange "$TOK_USER")"
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

# ── 7. step-up: the agent needs more than the task gives — ask alice, out of band ──
say "==> 7. Mid-task the agent needs more — step-up consent, OUT OF BAND (Keycloak CIBA)"
note "the planner wants Globex's plan for the briefing:"
hdr "agent:$AGENT (delegated token)" documents_read customer_doc:globex-plan "$(evaluate_detailed "$TOK_DELEGATED" documents_read customer_doc globex-plan)"
note "(agent_reader AND task_scope — the task half is missing. The rich decision is the cue to ASK, not to retry.)"
note "the PEP does not widen the task silently. It asks $USER_NAME through Keycloak's backchannel authentication endpoint:"
BM="widen-task-$RANDOM"
ciba_request "$BM" "task=brief $USER_NAME on CustCo" "ask=$AGENT asks to ALSO work on customer Globex for this task"
note "  POST …/ext/ciba/auth  client=$APP  login_hint=$USER_NAME  scope='openid delegation:client:$AGENT'  binding_message=$BM"
note "  → auth_req_id (expires in $(jq -r .expires_in <<<"$CIBA_ACK")s, poll every $(jq -r .interval <<<"$CIBA_ACK")s). Keycloak delivered the request to $USER_NAME's device:"
ae_next; ae_show "$REQ"
# step_up_outcome <SUCCEED|CANCELLED> — alice's device answers; the PEP polls the token endpoint
step_up_outcome() {
  ae_answer "$REQ" "$1"
  TOK_STEPUP_RES="$(ciba_poll)"
}
ask_alice() { # interactive: the person at the terminal is alice
  local ans; read -r -p "    approve? [y/N] " ans </dev/tty || ans=n
  case "$ans" in y|Y|yes) echo SUCCEED ;; *) echo CANCELLED ;; esac
}
if [ "$BROWSER" = 1 ]; then
  DECISION="$(ask_alice)"
else
  DECISION=CANCELLED
  note "→ $USER_NAME DECLINES (scripted)"
fi
step_up_outcome "$DECISION"
if [ "$DECISION" = CANCELLED ]; then
  note "token endpoint (grant_type=…:ciba, auth_req_id) → $(jq -r '"\(.error): \(.error_description)"' <<<"$TOK_STEPUP_RES")"
  note "nothing changed — no token, no write, the task is what it was:"
  hdr "agent:$AGENT (delegated token)" documents_read customer_doc:globex-plan "$(evaluate "$TOK_DELEGATED" documents_read customer_doc globex-plan)"
  if [ "$BROWSER" = 0 ]; then
    note ""
    note "the agent asks again (a second request — a new code; the first one is spent):"
    BM="widen-task-$RANDOM"
    ciba_request "$BM" "task=brief $USER_NAME on CustCo" "ask=$AGENT asks to ALSO work on customer Globex for this task"
    ae_next; ae_show "$REQ"
    note "→ $USER_NAME APPROVES (scripted)"
    DECISION=SUCCEED; step_up_outcome SUCCEED
  fi
fi
if [ "$DECISION" = SUCCEED ]; then
  TOK_USER2="$(jq -r '.access_token // empty' <<<"$TOK_STEPUP_RES")"
  [ -n "$TOK_USER2" ] || { echo "!! CIBA token request failed: $TOK_STEPUP_RES" >&2; exit 1; }
  C2="$(claims "$TOK_USER2")"
  note "token endpoint → a FRESH token for $USER_NAME, minted by her out-of-band answer:"
  note "    sub=$(jq -r .preferred_username <<<"$C2")  azp=$(jq -r .azp <<<"$C2")  scope=\"$(jq -r .scope <<<"$C2")\""
  note "    may_act=$(jq -c .may_act <<<"$C2")   ← the renewed consent, the agent named"
  jq -e '.may_act.client_id == "'"$AGENT"'"' <<<"$C2" >/dev/null || { echo "!! no may_act on the CIBA token" >&2; exit 1; }
  XCHG2="$(exchange "$TOK_USER2")"
  TOK_DELEGATED2="$(jq -r '.access_token // empty' <<<"$XCHG2")"
  [ -n "$TOK_DELEGATED2" ] || { echo "!! token exchange of the CIBA token failed: $XCHG2" >&2; exit 1; }
  note "$AGENT exchanges it → a second delegated token: act=$(claims "$TOK_DELEGATED2" | jq -c .act)  (the first one is still valid too)"
  note ""
  note "only NOW does the PEP widen the task — one more write-checked, same pattern, same deadline $EXP:"
  note "  precondition: $USER_NAME herself is a member of Globex;  write: agent:$AGENT task_scope customer:Globex"
  RES="$(write_checked "$TOK_PEP" "{
    \"preconditions\":[{\"match\":\"allowed\",\"user_type\":\"user\",\"user_id\":\"$USER_NAME\",\"relation\":\"member\",\"object_type\":\"customer\",\"object_id\":\"Globex\"}],
    \"writes\":[$(tuple agent "$AGENT" task_scope customer Globex ",\"expires_at\":\"$EXP\"")]}")"
  note "→ $(jq -c . <<<"$RES")"
  jq -e '.written == 1' <<<"$RES" >/dev/null || { echo "!! widening the task failed: $RES" >&2; exit 1; }
  hdr "PRINCIPAL (from the token)" "ACTION" "RESOURCE" "DECISION"
  hdr "agent:$AGENT (new delegated token)" documents_read customer_doc:globex-plan "$(evaluate "$TOK_DELEGATED2" documents_read customer_doc globex-plan)   ← the task now covers Globex"
  hdr "agent:$AGENT (first delegated token)" documents_read customer_doc:globex-plan "$(evaluate "$TOK_DELEGATED" documents_read customer_doc globex-plan)   ← same principal, same task: the graph decides, not the token"
  hdr "agent:$SUBAGENT (asserted by its PEP)" documents_read customer_doc:globex-plan "$(pep_check agent "$SUBAGENT" documents_read customer_doc globex-plan)   ← its own task_scope is still CustCo only"
  hdr "user:$USER_NAME (her own token)" documents_read customer_doc:globex-plan "$(evaluate "$TOK_USER" documents_read customer_doc globex-plan)"
  note "(the widening is a graph write by the PEP — performed_by, expiry and the moment $USER_NAME approved are on record; Keycloak logged the consent)"
else
  note "(you declined — the task stays as it was; the rest of the demo runs with the narrow task)"
fi

# ── 8. what Keycloak refuses ─────────────────────────────────────────────────
say "==> 8. What the issuer refuses (before pgauthz is even asked):"
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
  note "(the demo fixture user:$USER_NAME member customer:Globex stays too — the next run resets it)"
  exit 0
fi

# ── 9. the PEP closes the task ───────────────────────────────────────────────
say "==> 9. The task is done — the PEP closes it: ONE conditional delete of the bundle"
note "(precondition: the task is still open; the deadline above would have closed it anyway — the widened scope goes with the bundle)"
T_DURING="$(now_utc)"
RES="$(write_checked "$TOK_PEP" "{
  \"preconditions\":[{\"match\":\"exists\",\"user_type\":\"agent\",\"user_id\":\"$AGENT\",\"relation\":\"task_scope\",\"object_type\":\"customer\",\"object_id\":\"CustCo\"}],
  \"deletes\":[
    $(tuple user "$USER_NAME" operator agent "$AGENT"),
    $(tuple agent "$AGENT" task_scope customer CustCo),
    $(tuple agent "$AGENT" task_scope customer Globex),
    $(tuple agent "$SUBAGENT" delegate agent "$AGENT"),
    $(tuple agent "$SUBAGENT" task_scope customer CustCo)]}")"
note "→ $(printf '%s' "$RES" | jq -c .)"
T_CLOSED="$(now_utc)"

say "==> 10. After the task — the SAME delegated token (still valid for $(( $(jq -r .exp <<<"$C") - $(date +%s) ))s), nothing changed at Keycloak:"
hdr "PRINCIPAL (from the token)" "ACTION" "RESOURCE" "DECISION"
hdr "agent:$AGENT (delegated token)" documents_read customer_doc:custco-briefing "$(evaluate "$TOK_DELEGATED" documents_read customer_doc custco-briefing)"
hdr "agent:$AGENT (delegated token)" documents_read customer_doc:globex-plan "$(evaluate "${TOK_DELEGATED2:-$TOK_DELEGATED}" documents_read customer_doc globex-plan)   ← the step-up ended with the task"
hdr "agent:$SUBAGENT (asserted by its PEP)" documents_read customer_doc:custco-briefing "$(pep_check agent "$SUBAGENT" documents_read customer_doc custco-briefing)"
hdr "user:$USER_NAME (her own token)" documents_read customer_doc:custco-briefing "$(evaluate "$TOK_USER" documents_read customer_doc custco-briefing)   ← alice's own access is untouched"
note "search/action for the agent on custco-briefing → $(actions "$TOK_DELEGATED" customer_doc custco-briefing)"

# ── 11. time travel: when was the agent allowed? ─────────────────────────────
if [ -n "$DB" ]; then
  say "==> 11. Time travel (authz.audit_check_access) — was agent:$AGENT allowed to read custco-briefing …"
  q() { sql "SELECT authz.audit_check_access('$STORE','agent','$AGENT','documents_read','customer_doc','custco-briefing','$1'::timestamptz)"; }
  note "… just before the task opened  ($T_OPEN)?   → $(q "$T_OPEN")"
  note "… while it was open             ($T_DURING)? → $(q "$T_DURING")"
  note "… after it was closed           ($T_CLOSED)? → $(q "$T_CLOSED")"
  note "the audit trail has who opened/closed it (performed_by = the PEP), when, and with which expiry."
fi

# demo fixture back out (alice's Globex membership from step 0)
"${CURL[@]}" "$WRITER/stores/$STORE/pgauthz/v1/delete" -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK_PEP" \
  -d "{\"tuples\":[$(tuple user "$USER_NAME" member customer Globex)]}" | jq -c . >/dev/null

say "==> Done."
note "Layer 1 (Keycloak): WHO may act for WHOM — consent, may_act → act; one hop, no re-exchange."
note "Layer 2 (pgauthz):  WHAT the actor may do WHILE it does — the agent's own authority ∩ the task;"
note "                    subagents by delegation tuples; closed by the PEP or by the deadline; replayable."
note "Step-up (CIBA):     more than the task gives → the PEP asks the human out of band; her answer is a"
note "                    token (approve) or access_denied (decline); the graph is widened only on approval."
