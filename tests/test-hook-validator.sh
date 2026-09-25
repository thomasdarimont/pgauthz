#!/usr/bin/env bash
#
# Regression test for scripts/validate-hooks.sh's http.send destination
# check (ADR 0011; SECURITY-AUDIT F17/F18): the shipped http hook example must
# validate, and every fixture in tests/hooks-invalid must be REJECTED with the
# expected reason — including the IPv6-literal case that an unquoted loop
# under nullglob once dropped silently (skipping the allowlist check).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAPS="$ROOT/examples/opa-hooks-http/http-caps.example.json"
pass=0; fail=0
ok()   { pass=$((pass + 1)); echo "    PASS  $1"; }
bad()  { fail=$((fail + 1)); echo "    FAIL  $1"; }

echo "==> Hook validator: destination canonicalisation + allowlist"
if HOOK_HTTP_CAPABILITIES="$CAPS" "$ROOT/scripts/validate-hooks.sh" --global --allow-http "$ROOT/examples/opa-hooks-http" >/dev/null 2>&1; then
    ok "shipped http example validates"
else
    bad "shipped http example must validate"
fi

out=$(HOOK_HTTP_CAPABILITIES="$CAPS" "$ROOT/scripts/validate-hooks.sh" --global --allow-http "$ROOT/tests/hooks-invalid" 2>&1 || true)
expect() {  # <fixture> <reason substring>
    if grep -q "FAIL  $1" <<< "$out" && grep -F "$1" <<< "$out" | grep -q -- "$2"; then
        ok "$1 rejected ($2)"
    else
        bad "$1 must be rejected with '$2'"; echo "$out" | grep -F "$1" | sed 's/^/          /'
    fi
}
expect bad_ipv6.rego      "is not in the allow_net allowlist"
expect bad_userinfo.rego  "userinfo"
expect bad_plainhttp.rego "must be https"
expect bad_upper.rego     "must be lowercase"
if grep -q "PASS  bad_" <<< "$out"; then bad "no invalid fixture may pass"; else ok "no invalid fixture passes"; fi

# The plain-http opt-in admits exactly the http:// case, nothing else.
out=$(HOOK_HTTP_CAPABILITIES="$CAPS" "$ROOT/scripts/validate-hooks.sh" --global --allow-http --allow-plain-http "$ROOT/tests/hooks-invalid" 2>&1 || true)
if grep -q "PASS  bad_plainhttp.rego" <<< "$out" && ! grep -q "PASS  bad_ipv6\|PASS  bad_userinfo\|PASS  bad_upper" <<< "$out"; then
    ok "--allow-plain-http admits only the http:// fixture"
else
    bad "--allow-plain-http must admit only the http:// fixture"
fi

echo "==> $pass passed, $fail failed"
[ "$fail" -eq 0 ]
