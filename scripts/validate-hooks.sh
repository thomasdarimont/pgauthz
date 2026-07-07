#!/usr/bin/env bash
#
# Validate policy-hook files against the ADR 0011 contract. Veto-only is an
# API CONTRACT, not a Rego sandbox — a mounted module is placed by its
# DECLARED package, so a hook file could otherwise define rules in the
# platform packages (e.g. add an `allow` body = widen access), or a tenant's
# file could claim ANOTHER store's namespace (a cross-tenant DoS, since hooks
# only deny). Run this in CI / pre-deploy over every hook source you mount —
# it is a REQUIRED gate on every supported deployment path, not advisory.
#
# Tiers (pick one per directory so ownership maps to scope):
#   --global        every package must be  authz.hooks.v1.global.<name>
#   --store <name>  every package must be  authz.hooks.v1.stores.<name>.<hook>
#   --lib           operator EXTENSION LIBRARY: authz.hooks.lib.v1.ext.<name>
#                   — shared helper FUNCTIONS hooks may import. Functions
#                   only (no plain rules = shared ambient state) and always
#                   pure: --allow-http is rejected, a shared lib with
#                   http.send would hand network access to network-free
#                   store hooks. Point HOOK_EXTRA_LIBS=<dir> at your libs
#                   when validating hooks that call them.
#   (default)       either hook tier is accepted (mixed dir)
#
# Also enforces (all tiers):
#   - no two files may claim the same hook name (ambiguous attribution)
#   - platform packages (authz, authn, system, authz.pgauthz, ...) off-limits
#   - hooks are PURE by default: enforced by compiling against the hooks-v1
#     capability allowlist (opa/hooks-v1-capabilities.json) — http.send / io.* /
#     opa.* / net.lookup* / time.now_ns etc. are undefined. --allow-http relaxes
#     only http.send. This also pins a reproducible execution ABI across OPA
#     upgrades (a new builtin is disallowed until added to the allowlist).
#   - ISOLATION: a hook may reference only `input`, its OWN package's rules, and
#     pure builtins — any other data.* ref or dynamic data[var] is rejected
#
# *_test.rego files are skipped (they may live in any package).
#
# Usage: scripts/validate-hooks.sh [--global | --store <name> | --lib] [--allow-http] <hooks-dir>
set -euo pipefail

OPA_IMAGE="${OPA_IMAGE:-openpolicyagent/opa:1.18.2}"
ALLOW_HTTP=0
TIER="any"       # any | global | store
STORE=""
DIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --allow-http) ALLOW_HTTP=1 ;;
        --global)     TIER="global" ;;
        --lib)        TIER="lib" ;;
        --store)      TIER="store"; STORE="${2:-}"; shift ;;
        -h|--help)    sed -n '2,36p' "$0"; exit 0 ;;
        *)            DIR="$1" ;;
    esac
    shift
done
[ -n "$DIR" ] && [ -d "$DIR" ] || { echo "usage: $0 [--global | --store <name> | --lib] [--allow-http] <hooks-dir>" >&2; exit 2; }
[ "$TIER" = "store" ] && [ -z "$STORE" ] && { echo "--store requires a store name" >&2; exit 2; }
# Delegated (store) hooks are tenant-authored code — they may NEVER use
# network-capable builtins in v1. http.send is a platform-governance option for
# GLOBAL hooks only.
if [ "$TIER" = "store" ] && [ "$ALLOW_HTTP" = 1 ]; then
    echo "--allow-http is not permitted for store hooks (delegated tenant tier; network builtins are forbidden in v1)" >&2
    exit 2
fi
if [ "$TIER" = "lib" ] && [ "$ALLOW_HTTP" = 1 ]; then
    echo "--allow-http is not permitted for shared libraries: a lib with http.send would hand network access to every caller, including network-free store hooks" >&2
    exit 2
fi
ABS_DIR="$(cd "$DIR" && pwd)"

# Per-tier package regex (anchored).
case "$TIER" in
    global) want='^data\.authz\.hooks\.v1\.global\.[a-zA-Z_][a-zA-Z0-9_]*$'; desc="authz.hooks.v1.global.<name>" ;;
    store)  want="^data\\.authz\\.hooks\\.v1\\.stores\\.${STORE//./\\.}\\.[a-zA-Z_][a-zA-Z0-9_]*\$"; desc="authz.hooks.v1.stores.${STORE}.<name>" ;;
    lib)    want='^data\.authz\.hooks\.lib\.v1\.ext\.[a-zA-Z_][a-zA-Z0-9_]*$'; desc="authz.hooks.lib.v1.ext.<name> (operator shared library)" ;;
    *)      want='^data\.authz\.hooks\.v1\.(global\.[a-zA-Z_][a-zA-Z0-9_]*|stores\.[a-zA-Z_][a-zA-Z0-9_-]*\.[a-zA-Z_][a-zA-Z0-9_]*)$'; desc="authz.hooks.v1.{global|stores.<store>}.<name>" ;;
esac

# The hooks-v1 capability allowlist pins the builtin execution surface (only
# pure builtins; http.send/net.lookup/io.jwt/opa.*/rego.*/time.now_ns removed),
# so `opa check --capabilities` enforces purity by CONSTRUCTION and stays
# correct across OPA upgrades — a future non-pure builtin is disallowed unless
# explicitly added here. Lives next to this script's repo.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPS="${HOOK_CAPABILITIES:-$SCRIPT_DIR/../opa/hooks-v1-capabilities.json}"
CAPS_ABS="$(cd "$(dirname "$CAPS")" && pwd)/$(basename "$CAPS")"

# --allow-http (GLOBAL hooks only) compiles against the http profile instead:
# the pure set + http.send + an allow_net destination allowlist. The shipped
# file is a deny-all TEMPLATE (allow_net: []) — the platform copies it, adds
# its approved destinations, and points HOOK_HTTP_CAPABILITIES at the copy.
# NOTE: capabilities (incl. allow_net) are BUILD/CHECK-TIME validation
# (opa check / opa build) — `opa run` takes no capabilities file, so allow_net
# is NOT a runtime control. Runtime egress must be enforced independently
# (NetworkPolicy / egress proxy); a blocked http.send then fails the decision
# closed via strict-builtin-errors. This check also requires every http.send
# destination to be a STATIC literal (step 5), so the checked allowlist is the
# real destination set.
HTTP_CAPS="${HOOK_HTTP_CAPABILITIES:-$SCRIPT_DIR/../opa/hooks-v1-http-capabilities.json}"
HTTP_CAPS_ABS="$(cd "$(dirname "$HTTP_CAPS")" && pwd)/$(basename "$HTTP_CAPS")"

# The platform hook LIBRARY (authz.hooks.lib.v1.*) is the one namespace a
# hook may reference besides its own package — mounted into the compile
# checks (calls into an absent library are compile errors), pure by the same
# capability set.
LIB_MOUNTS=()
LIB_PATHS=()
for f in "$SCRIPT_DIR"/../opa/policies/hooks_lib*.rego; do
    [ -e "$f" ] || continue
    case "$f" in *_test.rego) continue ;; esac
    fabs="$(cd "$(dirname "$f")" && pwd)/$(basename "$f")"
    LIB_MOUNTS+=(-v "$fabs:/hooklib/$(basename "$f"):ro")
    LIB_PATHS+=("/hooklib/$(basename "$f")")
done
# Operator EXTENSION libraries (authz.hooks.lib.v1.ext.*): point
# HOOK_EXTRA_LIBS at their directory so hooks that call them compile.
if [ -n "${HOOK_EXTRA_LIBS:-}" ] && [ -d "$HOOK_EXTRA_LIBS" ] && [ "$(cd "$HOOK_EXTRA_LIBS" && pwd)" != "$ABS_DIR" ]; then
    EXTRA_ABS="$(cd "$HOOK_EXTRA_LIBS" && pwd)"
    LIB_MOUNTS+=(-v "$EXTRA_ABS:/hooklib-ext:ro")
    LIB_PATHS+=("--ignore=*_test.rego" "/hooklib-ext")
fi

opa_run() { docker run --rm -v "$ABS_DIR:/hooks:ro" -v "$CAPS_ABS:/caps.json:ro" -v "$HTTP_CAPS_ABS:/caps-http.json:ro" ${LIB_MOUNTS[@]+"${LIB_MOUNTS[@]}"} "$OPA_IMAGE" "$@"; }

fail=0
declare -a seen_names=()

echo "==> Validating policy hooks in $DIR (contract: ADR 0011 / $desc)..."

# 0. The directory must compile against the HOOK CAPABILITY SET (pure builtins
# only). --allow-http relaxes only the http.send ban via the full-capability
# check (governed external calls). Rejects http.send/opa.runtime/etc. here.
if [ "$ALLOW_HTTP" = 0 ]; then
    if ! opa_run check --ignore='*_test.rego' --capabilities=/caps.json /hooks ${LIB_PATHS[@]+"${LIB_PATHS[@]}"} >/dev/null 2>&1; then
        echo "    FAIL  directory does not compile under the hooks-v1 capability set (non-pure builtin, or a type/syntax error):"
        opa_run check --ignore='*_test.rego' --capabilities=/caps.json /hooks ${LIB_PATHS[@]+"${LIB_PATHS[@]}"} 2>&1 | sed 's/^/          /'
        exit 1
    fi
elif ! opa_run check --ignore='*_test.rego' --capabilities=/caps-http.json /hooks ${LIB_PATHS[@]+"${LIB_PATHS[@]}"} >/dev/null 2>&1; then
    echo "    FAIL  directory does not compile under the hooks-v1 HTTP capability set (only http.send is added over the pure set):"
    opa_run check --ignore='*_test.rego' --capabilities=/caps-http.json /hooks ${LIB_PATHS[@]+"${LIB_PATHS[@]}"} 2>&1 | sed 's/^/          /'
    exit 1
fi

shopt -s nullglob
for f in "$ABS_DIR"/*.rego; do
    base="$(basename "$f")"
    case "$base" in *_test.rego) echo "    skip  $base (test file)"; continue ;; esac

    ast=$(opa_run parse --format json "/hooks/$base")
    pkg=$(echo "$ast" | jq -r '[.package.path[].value] | join(".")')

    # 1. Namespace: the package must match the tier.
    if ! echo "$pkg" | grep -Eq "$want"; then
        echo "    FAIL  $base: package '$pkg' is outside $desc"
        fail=1
        continue
    fi
    name="${pkg##*.}"

    # LIB tier: a shared library must export FUNCTIONS ONLY — a plain rule
    # would be shared ambient state evaluated in every caller's context.
    if [ "$TIER" = "lib" ]; then
        nonfns=$(echo "$ast" | jq -r '[.rules[]? | select(has("head")) | select((.head.args? // []) | length == 0) | (.head.name // (.head.ref[0].value // "?"))] | unique | .[]' 2>/dev/null)
        if [ -n "$nonfns" ]; then
            echo "    FAIL  $base: shared libraries may export functions only; non-function rule(s): $(echo "$nonfns" | tr '\n' ' ')"
            fail=1
            continue
        fi
    fi

    # 1a. The hook <name> segment follows the same rules as store names
    # (identifier syntax is already enforced by the namespace regex): no Rego
    # reserved words / root documents, and <=63 chars — keyword segments parse
    # inconsistently across Rego tooling, same rationale as migration 0009.
    case "$name" in
        as|contains|default|else|every|false|if|import|in|not|null|package|some|true|with|input|data)
            echo "    FAIL  $base: hook name '$name' is a reserved Rego keyword"
            fail=1
            continue ;;
    esac
    if [ "${#name}" -gt 63 ]; then
        echo "    FAIL  $base: hook name '$name' exceeds 63 characters"
        fail=1
        continue
    fi

    # 1b. IMPORTS: only future.keywords / rego.v1 are allowed. An
    # `import data.other.pkg as x` would surface in the body as `x.*` (not
    # `data.*`), evading the isolation check below — so reject any import whose
    # path roots at `data` or `input` (parsed from the AST, not text).
    bad_imports=$(echo "$ast" | jq -r '
        [.imports[]? | [.path.value[] | .value | tostring] | join(".")]
        | map(select(
            (startswith("future") or startswith("rego")
             or . == "data.authz.hooks.lib.v1" or startswith("data.authz.hooks.lib.v1.")) | not))
        | .[]' 2>/dev/null | sort -u)
    if [ -n "$bad_imports" ]; then
        echo "    FAIL  $base: disallowed import(s): $(echo "$bad_imports" | tr '\n' ' ')(only future.keywords / rego.v1 / the platform library data.authz.hooks.lib.v1 permitted)"
        fail=1
        continue
    fi

    # 2. Duplicate hook names within this directory → ambiguous attribution.
    for n in "${seen_names[@]:-}"; do
        if [ "$n" = "$name" ]; then
            echo "    FAIL  $base: duplicate hook name '$name' (already defined by another file)"
            fail=1
        fi
    done
    seen_names+=("$name")

    # 3. Purity: reject non-pure builtins unless explicitly allowed.
    calls=$(echo "$ast" | jq -r '[.. | objects | select(.type? == "ref") | [.value[]? | .value? // empty] | map(tostring) | join(".")] | .[]' 2>/dev/null | sort -u)
    if [ "$ALLOW_HTTP" = 0 ] && echo "$calls" | grep -q '^http\.send'; then
        echo "    FAIL  $base: uses http.send — hooks are pure by default (re-run with --allow-http to permit governed external calls)"
        fail=1
        continue
    fi
    if echo "$calls" | grep -Eq '^(opa\.runtime|rego\.metadata)'; then
        echo "    FAIL  $base: uses runtime/introspection builtins"
        fail=1
        continue
    fi

    # 4. ISOLATION: a hook may reference only `input`, pure builtins, and its
    # OWN package under data. Any other data.* reference (another store's hooks,
    # a platform rule) or a dynamic data[var] lookup would let a store hook
    # reach across tenants — making "input + own-package only" real, not just a
    # claim. (Own-package helper rules parse as bare vars, so they are fine.)
    own="${pkg#data.}" # e.g. authz.hooks.v1.stores.demo.tenant_guard
    escapes=$(echo "$ast" | jq -r --arg own "$own" '
        [ .. | objects | select(.type? == "ref")
          | select(.value[0]?.type == "var" and .value[0]?.value == "data")
          | { dyn: (([.value[1:][] | select(.type == "var")] | length) > 0),
              path: ([.value[1:][] | select(.type == "string") | .value] | join(".")) } ]
        | map(select(.dyn or ((
              (.path | startswith($own))
              or (.path == "authz.hooks.lib.v1") or (.path | startswith("authz.hooks.lib.v1."))
          ) | not)))
        | map(if .dyn then "data[<dynamic>]" else "data." + .path end)
        | unique | .[]' 2>/dev/null)
    if [ -n "$escapes" ]; then
        echo "    FAIL  $base: references data outside its own package (breaks tenant isolation):"
        echo "$escapes" | sed 's/^/            /'
        fail=1
        continue
    fi

    # 5. http.send destinations must be STATIC: the first argument must be a
    # literal object whose "url" is a literal string — an input-derived or
    # computed URL would make the build-time allow_net check meaningless (and
    # is an exfiltration vector). Conservative: a non-literal request object
    # (built elsewhere, sprintf'd url, variable) is rejected outright.
    if [ "$ALLOW_HTTP" = 1 ]; then
        # http.send appears either in statement position (expr .terms with the
        # ref as head) or nested as a {"type":"call"} term — collect both.
        bad_urls=$(echo "$ast" | jq -r '
            def verdict($req):
                if ($req.type != "object") then "non-literal request object"
                else (
                    ( [ $req.value[] | select(.[0].value == "url") ] | first
                      | if . == null then "missing url key"
                        elif .[1].type != "string" then "non-static url (computed/input-derived)"
                        else empty end ),
                    ( [ $req.value[] | select(.[0].value == "enable_redirect") ] | first
                      | select(. != null)
                      | select((.[1].type == "boolean" and .[1].value == false) | not)
                      | "enable_redirect must be false/absent (an approved URL must not redirect to an unapproved host)" ),
                    # raise_error:false converts a failed call into a
                    # status_code:0 RESPONSE — strict-builtin-errors never
                    # fires, silently defeating fail-closed. Absent or literal
                    # true only; computed values rejected.
                    ( [ $req.value[] | select(.[0].value == "raise_error") ] | first
                      | select(. != null)
                      | select((.[1].type == "boolean" and .[1].value == true) | not)
                      | "raise_error must be true/absent (false would bypass strict-builtin-errors fail-closed)" ),
                    ( [ $req.value[] | select(.[0].value == "tls_insecure_skip_verify") ] | first
                      | select(. != null)
                      | select((.[1].type == "boolean" and .[1].value == false) | not)
                      | "tls_insecure_skip_verify must be false/absent" ),
                    # Explicit request-field ALLOWLIST: hooks execute fresh
                    # on every decision, so the cross-query cache controls
                    # (cache, force_cache, force_cache_duration_seconds,
                    # caching_mode, cache_ignored_headers) are forbidden — a
                    # cached result would decide a later, different request.
                    # An allowlist (not a denylist) also keeps future OPA
                    # request options out of the approved profile implicitly.
                    ( [ $req.value[]
                        | .[0].value as $k
                        | select(($k | type) == "string")
                        | select(["url", "method", "headers", "timeout",
                                  "raise_error", "enable_redirect",
                                  "tls_insecure_skip_verify",
                                  "max_retry_attempts"]
                                 | index($k) | . == null)
                        | "request field [" + $k + "] is not in the hooks-v1 http.send allowlist (cross-query caching and unreviewed options are forbidden)" ]
                      | .[] ),
                    # READ-ONLY network lookup: http.send must not produce
                    # external side effects (OPA gives no exactly-once
                    # semantics — caching/retries can repeat requests).
                    ( [ $req.value[] | select(.[0].value == "method") ] | first
                      | if . == null then "missing method key"
                        elif .[1].type != "string" then "non-static method"
                        elif ((.[1].value | ascii_upcase) | . != "GET" and . != "HEAD")
                          then "method must be GET or HEAD (hooks are read-only network lookups; no side effects)"
                        else empty end ),
                    ( [ $req.value[] | select(.[0].value == "body" or .[0].value == "raw_body") ] | first
                      | select(. != null)
                      | "body/raw_body must be absent (read-only lookup)" ),
                    # a retried non-idempotent call could repeat a side effect;
                    # with GET/HEAD-only this is belt-and-braces.
                    ( [ $req.value[] | select(.[0].value == "max_retry_attempts") ] | first
                      | select(. != null)
                      | select((.[1].type == "number" and .[1].value == 0) | not)
                      | "max_retry_attempts must be 0/absent" ),
                    # a Host header diverging from the URL host would dodge the
                    # host allowlist at the HTTP layer.
                    ( [ $req.value[] | select(.[0].value == "headers") ] | first
                      | select(. != null)
                      | if .[1].type != "object" then "non-literal headers object"
                        else ( [ .[1].value[] | select(.[0].type == "string" and ((.[0].value | ascii_downcase) == "host")) ] | first
                               | select(. != null) | "Host header must be absent (the URL host is the allowlisted destination)" )
                        end ),
                    # timeout 0 = unbounded; require a real bound (decimals
                    # like "0.5s" are fine — only bare zero is rejected).
                    ( [ $req.value[] | select(.[0].value == "timeout") ] | first
                      | select(. != null)
                      | select(
                            ((.[1].type == "number") and (.[1].value == 0))
                            or ((.[1].type == "string") and (.[1].value | test("^0+(ns|us|µs|ms|s|m|h)?$")))
                            or ((.[1].type | . != "number" and . != "string")))
                      | "timeout must be a static non-zero bound (0/computed = unbounded call in the decision path)" )
                )
                end;
            [ ( .. | objects | select(has("terms")) | .terms
                | select(type == "array")
                | select((.[0].type? == "ref")
                         and (.[0].value[0]?.value == "http")
                         and (.[0].value[1]?.value == "send"))
                | verdict(.[1]) ),
              ( .. | objects | select(.type? == "call")
                | select((.value[0].value[0]?.value == "http")
                         and (.value[0].value[1]?.value == "send"))
                | verdict(.value[1]) ) ] | .[]' 2>/dev/null)
        if [ -n "$bad_urls" ]; then
            echo "    FAIL  $base: http.send request violates the static-destination contract:"
            echo "$bad_urls" | sed 's/^/            /'
            fail=1
            continue
        fi

        # 5b. STATIC ALLOWLIST: every (literal, step-5-enforced) destination
        # host must be in the http profile's allow_net. `opa check` does not
        # inspect hosts (allow_net is evaluation-time: opa eval/test
        # --capabilities), but static URLs make the allowlist checkable right
        # here. allow_net ABSENT = allow-all (OPA semantics, warn); present
        # (incl. the shipped deny-all []) = enforced.
        if jq -e 'has("allow_net")' "$HTTP_CAPS_ABS" >/dev/null 2>&1; then
            urls=$(echo "$ast" | jq -r '
                [ ( .. | objects | select(has("terms")) | .terms
                    | select(type == "array")
                    | select((.[0].type? == "ref")
                             and (.[0].value[0]?.value == "http")
                             and (.[0].value[1]?.value == "send"))
                    | .[1] ),
                  ( .. | objects | select(.type? == "call")
                    | select((.value[0].value[0]?.value == "http")
                             and (.value[0].value[1]?.value == "send"))
                    | .value[1] ) ]
                | map(select(.type == "object")
                      | [ .value[] | select(.[0].value == "url") ] | first
                      | select(. != null) | .[1]
                      | select(.type == "string") | .value)
                | .[]' 2>/dev/null | sort -u)
            for url in $urls; do
                host=$(printf '%s' "$url" | sed -E 's#^[a-zA-Z+.-]+://##; s#^[^/@]*@##; s#[/?].*$##; s#:[0-9]+$##')
                if ! jq -e --arg h "$host" '.allow_net | index($h) != null' "$HTTP_CAPS_ABS" >/dev/null 2>&1; then
                    echo "    FAIL  $base: http.send host '$host' is not in the allow_net allowlist ($HTTP_CAPS)"
                    fail=1
                fi
            done
            [ "$fail" -ne 0 ] && continue
        else
            echo "    warn  $base: http profile has no allow_net field — destination hosts are UNRESTRICTED"
        fi
    fi

    echo "    PASS  $base (hook '$name')"
done

if [ "$fail" -ne 0 ]; then
    echo "==> HOOK VALIDATION FAILED"
    exit 1
fi
echo "==> All hooks valid."
