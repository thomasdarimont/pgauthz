# OPA policy hooks — examples

User-supplied **veto rules** that ride along pgauthz's standard OPA decision
pipeline without editing any platform policy file ([ADR 0011](../../docs/adr/0011-opa-policy-hooks.md)).
A hook can only **narrow** — the ReBAC graph answer still has to pass; there is
deliberately no hook that widens access past the graph.

## Your first hook in 5 minutes

A hook is one Rego file: a package under the hooks namespace + a `deny` rule
reading `input`. Scaffold, edit, validate, mount:

```bash
# 1. Scaffold (correct package + inert deny/deny_write skeletons):
scripts/new-hook.sh global quiet_hours ./my-hooks/global

# 2. Edit my-hooks/global/quiet_hours.rego — e.g. deny outside 06:00–22:00 UTC:
#      deny contains {"code": "quiet_hours"} if {
#          hour := time.clock([input.evaluated_at, "UTC"])[0]
#          hour < 6
#      }

# 3. Validate (REQUIRED — enforces the veto-only contract):
scripts/validate-hooks.sh --global ./my-hooks/global

# 4. Mount into the dev stack and try it. Hooks run on the OPA-FRONTED
#    instance (port 8091) — port 8090 is the direct reader, which never
#    consults OPA or hooks:
#      compose:  volume ./my-hooks/global → /policies/hooks/global  (see Mounting)
#      Helm:     opa.extraPoliciesConfigMap
TOKEN=$(scripts/make-token.sh alice)   # demo ES256 JWT, signed with the shipped dev key
curl -s -X POST localhost:8091/access/v1/evaluation -H 'content-type: application/json' \
  -H "authorization: Bearer $TOKEN" -d '{
    "subject":  {"type": "internal_user", "id": "alice"},
    "action":   {"name": "can_read"},
    "resource": {"type": "document", "id": "doc_1"}
  }'
```

`scripts/make-token.sh` mints a token the dev stack's demo JWKS verifies
(dev only — for real IdP tokens use the Keycloak overlay,
`./start.sh --opa --keycloak`). Writer tokens for testing `deny_write` hooks:
`scripts/make-token.sh svc internal_user '["authz_writer"]'`.

Good to know before your first mount (details in the sections below):

- The dev compose stack sets `DEPLOYMENT_ENVIRONMENT=dev` for you; in any
  other deployment **set it explicitly** — with hooks mounted and no
  environment configured, a fail-closed platform guard denies every request.
- Mounting any hook also **turns off search enumeration** by default
  (`accessible_objects`/`subjects` return 403) because hooks don't filter
  those graph-derived lists — opt back in with
  `ALLOW_UNFILTERED_ENUMERATION_WITH_HOOKS=true` if your hooks aren't
  confidentiality rules.
- To see exactly what your hook receives, query the ABI directly — see
  *Seeing exactly what your hook receives*.

Everything below is the reference: the contract, mounting, validation,
testing, and the hardened paths (network hooks, multi-tenant bundles).

## Two tiers

| Package | Scope |
|---|---|
| `authz.hooks.v1.global.<name>` | every store (operator tier) |
| `authz.hooks.v1.stores.<store>.<name>` | only when `input.store == <store>` |

Store hooks are keyed by the request's store, so only the target store's hooks
(plus globals) evaluate — one tenant's hooks never run on another's request.

## The contract

A hook may define (one package per concern; any number compose):

| Rule | Vetoes | Consulted by |
|---|---|---|
| `deny contains d` | a **decision** | `allow`, `allow_detailed`, `evaluations` (**per item** — a veto rejects the whole batch, no bypass), and per-action filtering of `permitted_actions` |
| `deny_write contains d` | a **write** | `write`, all operations (`write`/`delete`/`*_batch`/`delete_user`/`write_checked`) |

Hooks are evaluated against a **normalized, versioned input ABI**
(`api_version: pgauthz.hooks/v1`), not the raw transport input — fields carry a
trust class a security gate must respect:

- **server-derived:** `operation`, `evaluated_at` (OPA clock, ns — time/env
  hooks read this, never caller `context.time`);
- **platform-derived:** `store`, `subject` (from the verified token);
- **caller-supplied:** `action`, `resource`, `context` (decisions) /
  `tuple`/`tuples`/`writes`/`user` (writes).

Bearer/service tokens are structurally invisible. A denial is a string
(→ `code: "denied"`) or `{code, message}`; the aggregation attaches
`{tier, store?, hook}` (unspoofable) and bounds `message` to 256 chars.

**Attribution:** with hooks mounted, `allow_detailed` reports `hooks_loaded`
(globals + this store's hooks) and `hook_denials`; the write veto carries
`denials` + `hooks_loaded`. pgauthzd returns it under `X-PGAuthz-Detail`, else
discards it. `evaluations` and `write` vetoes are `403 denied_by_policy_hook`
with structured denials (`evaluation_index` on a batch veto).

Not covered (v1): result filtering for `accessible_objects/subjects` (they
return graph-derived supersets). `permitted_actions` **is** hook-filtered.

## Examples in this directory

- [`global/business_hours.rego`](global/business_hours.rego) — global decision
  hook: finance documents only during business hours (reads `evaluated_at`).
- [`global/tuple_rules.rego`](global/tuple_rules.rego) — global write
  governance: no wildcard subjects, no `owner` grants via the API.
- [`stores/demo/tenant_guard.rego`](stores/demo/tenant_guard.rego) —
  store-scoped hook for the `demo` store only.
- [`hooks_test.rego`](hooks_test.rego) — the contract test suite.

## Mounting

**Compose** — mount onto the reserved tier mountpoints (no command changes):

```yaml
services:
  opa:
    volumes:
      - ./hooks/global:/policies/hooks/global:ro
      - ./hooks/tenant-a:/policies/hooks/stores/tenant-a:ro
```

**Helm** — a ConfigMap per tier, each owned/validated by its owner:

```yaml
opa:
  extraPoliciesConfigMap: my-global-hooks          # authz.hooks.v1.global.*
  storePoliciesConfigMaps:
    tenant-a: hooks-tenant-a                         # authz.hooks.v1.stores.tenant-a.*
```

OPA runs with `--watch`, so compose-mounted hooks hot-reload; the chart rolls
OPA pods when a referenced ConfigMap changes.

## Validate before you mount — this is REQUIRED

Veto-only + store scoping are an **API contract**, not a Rego sandbox: a
mounted file is placed by its declared package, so it *could* declare
`package authz` and widen, or claim another store. Gate every mounted source
(the validator is wired into `pre-release.sh` and `test-opa.sh`):

```bash
scripts/validate-hooks.sh --global  ./hooks/global
scripts/validate-hooks.sh --global --allow-http ./hooks/global   # global only: governed http.send
scripts/validate-hooks.sh --store tenant-a ./hooks/tenant-a
```

`--global` pins to `authz.hooks.v1.global.*`, `--store <s>` to
`authz.hooks.v1.stores.<s>.*`. Both reject duplicate names, platform-package
definitions, `data`/`input` imports, cross-package/dynamic `data` references,
and non-pure builtins (compiled against the hooks-v1 capability allowlist).
**`--allow-http` is global-only** — delegated store hooks may never use
network-capable builtins in v1.

## Seeing exactly what your hook receives

Hooks never see the raw platform input — they get the normalized ABI document
(`api_version: pgauthz.hooks/v1`). The ABI builders are ordinary Rego rules, so
you can **query them directly** with any request input and inspect the exact
document your hook will be evaluated against.

Against a running OPA (e.g. the compose stack, or a throwaway
`opa run --server` with `opa/policies` mounted):

```bash
# decision ABI — what a `deny` hook sees
curl -s -X POST http://localhost:8181/v1/data/authz/_decision_hook_input \
  -H 'Content-Type: application/json' -d '{
    "input": {
      "store": "demo",
      "subject": {"type": "user", "id": "alice"},
      "action": "can_read",
      "resource": {"type": "document", "id": "doc_1"},
      "context": {"purpose": "audit"}
    }
  }' | jq .result

# write ABI — what a `deny_write` hook sees
curl -s -X POST http://localhost:8181/v1/data/authz/_write_hook_input \
  -H 'Content-Type: application/json' -d '{
    "input": {
      "store": "demo", "operation": "write",
      "tuple": {"user_type": "user", "user_id": "bob", "relation": "editor",
                "object_type": "document", "object_id": "doc_1"}
    }
  }' | jq .result
```

Offline, without a server:

```bash
echo '{"store": "demo", "subject": {"type": "user", "id": "alice"},
       "action": "can_read", "resource": {"type": "document", "id": "doc_1"}}' > /tmp/in.json
opa eval -d opa/policies -i /tmp/in.json 'data.authz._decision_hook_input' \
  --format pretty
```

Two dev-loop tips:

- **`print()` works during development** — drop `print(input)` into your hook
  body and `opa test opa/policies . --verbose` (or `opa eval`) shows it. It is
  rejected by `validate-hooks.sh` (not in the pure capability set — it would
  leak request data into production logs), so remove it before validating.
- To see inputs for **live traffic**, enable console decision logging —
  every query is logged with its full input. The shipped stacks have a flag
  for it, OFF by default (the log includes forwarded bearer JWTs — dev only,
  never where logs are shipped/retained):

```bash
OPA_DECISION_LOGS_CONSOLE=true ./start.sh --opa      # compose
--set opa.decisionLogsConsole=true                    # Helm
opa run --server --set decision_logs.console=true /policies   # standalone
```

Notes: querying via the API you'll see `evaluated_at` filled by the
`time.now_ns()` fallback and `deployment.environment` as `"unknown"` — in
production pgauthzd forwards both on every request. The ABI is versioned;
fields not in the document (tokens, transport headers) are structurally
invisible to hooks, in dev and production alike.

## Testing your hooks

Run against the *real* platform policies (exactly what the sidecar loads):

```bash
docker run --rm \
  -v "$PWD/opa/policies:/p:ro" -v "$PWD/my-hooks:/h:ro" \
  openpolicyagent/opa:1.18.2 test /p /h -v
```

Mock the graph with `with data.authz._graph_allow as true` (single decision) or
`with data.authz._graph_evaluations as [...]` (batch), and time with
`with time.now_ns as ...` — see [`hooks_test.rego`](hooks_test.rego).

## Trust & failure

A mounted hook is **code** in the policy sidecar — same trust tier as a
platform-policy author; review-gate the source (CODEOWNERS / the per-tenant
ConfigMap). A compile error fails the OPA load (deep readiness → NotReady). A
runtime error **fails the request closed** (`policy_evaluation_failed`, 5xx) —
the standard pipeline runs OPA with `strict-builtin-errors`, so a buggy hook
can't silently drop its veto. Write hooks defensively anyway.

## Specifying the http.send destination allowlist (global hooks)

A global hook approved for `http.send` (`--allow-http`) may only call
platform-approved hosts. The allowlist lives in the http capability profile —
the shipped `opa/hooks-v1-http-capabilities.json` is a **deny-all template**
(`"allow_net": []`). To approve destinations:

```bash
# 1. Copy the template and add your approved hosts (exact hostnames):
cp opa/hooks-v1-http-capabilities.json platform/hook-http-caps.json
#    ... edit: "allow_net": ["risk.internal.example", "sanctions.internal.example"]

# 2. Validate the hook directory against YOUR copy:
HOOK_HTTP_CAPABILITIES=platform/hook-http-caps.json \
  scripts/validate-hooks.sh --global --allow-http ./hooks/global
```

The validator enforces the list **statically**: destinations must be literal
string URLs (computed/input-derived URLs are rejected), each URL's host must
be in `allow_net`, and the request fields must not weaken the guarantees —
`enable_redirect` stays `false` (no bouncing an approved URL to an unapproved
host), `raise_error` stays `true` (setting it `false` would turn a failed call
into a `status_code: 0` response and bypass the fail-closed behavior),
`tls_insecure_skip_verify` stays `false`, and `timeout` must be a static
non-zero bound. The contract is **read-only lookup**: `method` must be a
literal `GET`/`HEAD`, `body`/`raw_body` and `Host` headers are rejected, and
`max_retry_attempts` must be `0`/absent (no exactly-once semantics — a retry
could repeat a side effect). Note there is no request-side response-size
limit in OPA's `http.send` — bound it at the approved endpoint or egress
proxy.

One more fail-open trap: an HTTP `404`/`500`/`503` is a *successful*
`http.send` (an ordinary response object — `strict-builtin-errors` does not
apply), so a hook matching only `status_code == 200` contributes **no denial**
when the service errors. Deny explicitly outside your declared success-status
set — `examples/opa-hooks-http/` ships the reference pattern with contract
tests (the isolation rules forbid shared helpers, so inline it per hook). `opa eval` / `opa test --capabilities` enforce the same
list at evaluation time in dev/CI ("unallowed host"). At runtime, mirror the
same hosts in your egress controls (NetworkPolicy / egress proxy) — a blocked
call fails the decision closed via `strict-builtin-errors`.

In production, a global hook using `http.send` **must be deployed through the
signed immutable bundle path** (see ADR 0011) — mutable ConfigMap/`--watch`
mounts are for development or network-free global hooks only.

## Enumeration is refused while hooks are loaded (secure by default)

`accessible_objects` / `accessible_subjects` return **graph-derived supersets**
— your decision hooks do NOT filter them, so a hook-vetoed object would still
be listed. With any hook loaded those queries are refused
(`403 enumeration_refused_with_hooks`). If your hooks are advisory (not
confidentiality rules), opt into superset semantics explicitly:

```
ALLOW_UNFILTERED_ENUMERATION_WITH_HOOKS=true    # env on the OPA container
```

`permitted_actions` is unaffected — it IS hook-filtered per action.

## Environment gates: allowlist-style, "unknown" is restrictive

An unset `DEPLOYMENT_ENVIRONMENT` reaches hooks as the sentinel
`input.deployment.environment == "unknown"` (never `""`). An equality veto like
`environment == "production"` silently fails OPEN when the variable is unset —
and the platform ENFORCES this: with hooks loaded and the environment
"unknown", a platform guard denial (`deployment_environment_unknown`) blocks
decisions and writes until you either set `DEPLOYMENT_ENVIRONMENT` on pgauthzd
or opt out with `ALLOW_UNKNOWN_DEPLOYMENT_ENVIRONMENT=true` on OPA (only for
genuinely environment-independent hooks). Write environment gates
allowlist-style regardless, so "unknown" is automatically the most restrictive
case:

```rego
deny contains {"code": "env_not_permitted"} if {
    not input.deployment.environment in {"dev", "staging"}
}
```
