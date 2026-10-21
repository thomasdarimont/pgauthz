#!/usr/bin/env bash
#
# Smoke test of the compose DEPLOYMENT (deploy/compose): a throwaway .env with
# the demo JWKS, the `derived` profile, the helloworld model — then readiness
# of both instances, a decision through pgauthzd, the production-profile
# doctor, and the derived-relations worker deriving and following a write.
#
# Images: pgauthz-pgauthzd:<tag> and pgauthz-migrations:<tag> must exist
# (PGAUTHZ_VERSION, default 0.17.0) — `docker compose -f deploy/compose/compose.yml build`
# or the CI build step. Ports 18080/18082 on loopback; project pgauthz-deploytest.
# Tears the stack down (volumes included) at the end.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/deploy/compose"
TAG="${PGAUTHZ_VERSION:-0.17.0}"
ENVF="$(mktemp)"; WORK_JAR="$(mktemp)"; trap 'rm -f "$ENVF" "$WORK_JAR"' EXIT
cat > "$ENVF" <<ENV
PGAUTHZ_VERSION=$TAG
PG_PASSWORD=test-pg
AUTHZEN_DIRECT_PASSWORD=test-reader
PGAUTHZD_RW_PASSWORD=test-writer
DERIVED_WORKER_PASSWORD=test-worker
JWT_ISSUER=https://auth.example.com
JWT_AUDIENCE=authz-api
JWKS_FILE=/jwks/jwks.json
READ_PORT=18080
WRITE_PORT=18082
DEFAULT_STORE=helloworld
DERIVED_RELATIONS=1
DERIVED_STORES=helloworld
WORKER_INTERVAL=1
BASE_URL=http://127.0.0.1:18083
CONSOLE_PORT=18083
CONSOLE_COOKIE_SECURE=false
CONSOLE_ENGINE_PASSWORD=test-console-engine
CONSOLE_SESSIONS_DB=pgauthz_console
CONSOLE_SESSIONS_PASSWORD=test-console-sessions
CONSOLE_STORE_INIT=1
CONSOLE_LOCAL_ADMIN_USER=admin
CONSOLE_LOCAL_ADMIN_PASSWORD=test-admin
DEPLOYMENT_ENVIRONMENT=dev
ENV
COMPOSE=(docker compose -p pgauthz-deploytest --env-file "$ENVF" -f compose.yml -f "$ROOT/tests/compose-deploy-test.yml" --profile derived --profile console)
fail=0
assert() { if [ "$2" = "$3" ]; then echo "    PASS  $1"; else echo "    FAIL  $1 (expected '$2', got '$3')"; fail=1; fi; }
cleanup() { "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true; rm -f "$ENVF" "$WORK_JAR"; }
trap cleanup EXIT

echo "==> Resetting + starting the deployment (profile derived)..."
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d --wait --wait-timeout 180 db migrate pgauthzd-decision pgauthzd-full
assert "migrate completed successfully" "0" "$("${COMPOSE[@]}" ps -a --format '{{.ExitCode}}' migrate)"
assert "pgauthzd-decision is ready" "ok" "$(curl -fsS http://127.0.0.1:18080/readyz >/dev/null && echo ok || echo down)"
assert "pgauthzd-full is ready"     "ok" "$(curl -fsS http://127.0.0.1:18082/readyz >/dev/null && echo ok || echo down)"

echo "==> Service roles carry the configured passwords (the dev password is gone)..."
# Over the network (the container's local socket is trust-authenticated).
login() { "${COMPOSE[@]}" run --rm --no-deps -T -e PGPASSWORD="$2" --entrypoint psql migrate -h db -U "$1" -d authz -tA -c 'SELECT 1;' 2>/dev/null || echo no; }
assert "authzen_direct logs in with its .env password" "1"  "$(login authzen_direct test-reader)"
assert "authzen_direct does NOT log in with the dev password" "no" "$(login authzen_direct authz)"
assert "pgauthz_derived_worker logs in with its .env password" "1" "$(login pgauthz_derived_worker test-worker)"

echo "==> Loading the helloworld model, then the worker (registers the store at start)..."
"${COMPOSE[@]}" exec -T db psql -U authz -d authz -q -v ON_ERROR_STOP=1 < "$ROOT/examples/models/helloworld/model.sql" >/dev/null
"${COMPOSE[@]}" exec -T db psql -U authz -d authz -q -v ON_ERROR_STOP=1 < "$ROOT/examples/models/helloworld/seed.sql" >/dev/null
"${COMPOSE[@]}" up -d derived-worker
derived=timeout
for _ in $(seq 1 30); do
  n=$("${COMPOSE[@]}" exec -T db psql -U authz -d authz -tA -c "SELECT count(*) FROM authz.materialized_relations WHERE store='helloworld';" 2>/dev/null || echo 0)
  [ "${n:-0}" -gt 0 ] && { derived=ok; break; }; sleep 1
done
assert "the worker registered helloworld and derived rows" "ok" "$derived"
[ "$derived" = ok ] || { echo "--- derived-worker log"; "${COMPOSE[@]}" logs --no-log-prefix derived-worker | tail -20 | sed 's/^/      /'; }
assert "alice can_read readme is a derived row" "1" \
  "$("${COMPOSE[@]}" exec -T db psql -U authz -d authz -tA -c "SELECT count(*) FROM authz.materialized_relations WHERE store='helloworld' AND user_id='alice' AND relation='can_read' AND object_id='readme';")"

echo "==> A decision through pgauthzd with a demo token..."
TOKEN=$(SUBJECT_TYPE=user "$ROOT/scripts/mint-demo-token.sh" alice)
decision=$(curl -fsS -X POST http://127.0.0.1:18080/access/v1/evaluation -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"readme"}}' 2>&1 || echo "curl-failed")
assert "AuthZEN evaluation: alice can_read readme" "true" "$(echo "$decision" | python3 -c 'import sys,json; print(str(json.load(sys.stdin)["decision"]).lower())' 2>/dev/null || echo "$decision")"

echo "==> A write follows into the derived table..."
"${COMPOSE[@]}" exec -T db psql -U authz -d authz -q -c "SELECT authz.write_tuple('helloworld','user','bob','viewer','document','readme');" >/dev/null
followed=timeout
for _ in $(seq 1 20); do
  n=$("${COMPOSE[@]}" exec -T db psql -U authz -d authz -tA -c "SELECT count(*) FROM authz.materialized_relations WHERE store='helloworld' AND user_id='bob' AND relation='can_read' AND object_id='readme';")
  [ "$n" = "1" ] && { followed=ok; break; }; sleep 1
done
assert "bob's new viewer grant reached the derived table" "ok" "$followed"
assert "status: helloworld registered, feed drained" "t" \
  "$("${COMPOSE[@]}" exec -T db psql -U authz -d authz -tA -c "SELECT feed_drained FROM authz.materialized_relations_status() WHERE store='helloworld';")"

echo "==> The management console: store created once, sessions database, local admin sign-in..."
"${COMPOSE[@]}" up -d --wait --wait-timeout 120 console
assert "migrate created the console store once" "1" "$("${COMPOSE[@]}" exec -T db psql -U authz -d authz -tA -c "SELECT count(*) FROM authz.stores WHERE name='console';")"
assert "migrate created the sessions database owned by console" "console" "$("${COMPOSE[@]}" exec -T db psql -U authz -d authz -tA -c "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='pgauthz_console';")"
assert "console is healthy" "ok" "$(curl -fsS http://127.0.0.1:18083/console/healthz 2>/dev/null || echo down)"
assert "anonymous api/me offers the local sign-in and no OIDC" "false|true" \
  "$(curl -s http://127.0.0.1:18083/console/api/me | python3 -c 'import sys,json; d=json.load(sys.stdin); print(str(d["login"]["oidc"]).lower()+"|"+str(d["login"]["local"]).lower())')"
assert "a wrong password is refused" "401" "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18083/console/auth/local -H 'Content-Type: application/json' -d '{"username":"admin","password":"nope"}')"
JAR="$WORK_JAR"
assert "the local admin signs in" "200" "$(curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -X POST http://127.0.0.1:18083/console/auth/local -H 'Content-Type: application/json' -d '{"username":"admin","password":"test-admin"}')"
assert "…and is user:admin, platform admin through team role_console_admin" "user:admin|True|True" \
  "$(curl -s -b "$JAR" http://127.0.0.1:18083/console/api/me | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["subject"]+"|"+str("role_console_admin" in d["teams"])+"|"+str(d["platform"]["can_manage_access"]))')"
assert "the console lists the stores for them" "t" "$(curl -s -b "$JAR" http://127.0.0.1:18083/console/api/stores | python3 -c 'import sys,json; d=json.load(sys.stdin); print("t" if any(s.get("name")=="helloworld" for s in (d if isinstance(d,list) else d.get("stores",[]))) else json.dumps(d)[:120])')"

echo "==> pgauthzd doctor (production profile) with the reader's configuration..."
doctor_rc=0; doctor_out=$("${COMPOSE[@]}" run --rm --no-deps -T pgauthzd-decision doctor --profile production 2>&1) || doctor_rc=$?
echo "$doctor_out" | sed 's/^/      /' | tail -25
# The demo issuer/JWKS are a deliberate FAIL of the doctor's demo-secret check;
# nothing else may fail.
assert "doctor: no failing check besides the demo material this test mounts" "" \
  "$(echo "$doctor_out" | grep 'FAIL' | grep -v 'demo' || true)"

echo ""
if [ "$fail" -ne 0 ]; then echo "==> COMPOSE DEPLOYMENT TEST FAILED"; exit 1; fi
echo "==> Compose deployment test passed."
