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
- [`global/claims_guard.rego`](global/claims_guard.rego) — global decision
  hook on **verified claims**: client-scoped and realm-wide role gates via
  the platform hook library (`import data.authz.hooks.lib.v1.keycloak` →
  `keycloak.has_client_role(input.actor, "document-api", "exporter")` /
  `keycloak.has_realm_role(input.actor, "records_officer")`), and a group
  gate reading a custom claim from `input.actor.claims` directly (needs
  `groups` in `HOOK_ACTOR_CLAIMS`) — all fail closed on absent claims. The
  library is the ONE shared namespace hooks may import; everything else
  stays isolated to the hook's own package.
- [`stores/demo/tenant_guard.rego`](stores/demo/tenant_guard.rego) —
  store-scoped hook for the `demo` store only.
- [`hooks_test.rego`](hooks_test.rego) — the contract test suite.
- [`../opa-hooks-lib/`](../opa-hooks-lib/README.md) — **operator extension
  library** example (`authz.hooks.lib.v1.ext.acme`): shared helper functions
  your hooks may import.

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

## Sharing helpers across your hooks (extension libraries)

Common logic (time windows, org-specific role conventions) goes into an
**operator extension library** under the reserved namespace
`authz.hooks.lib.v1.ext.<name>` — the only shared namespace hooks may import
besides the platform modules (`keycloak`, …):

```rego
package authz.hooks.lib.v1.ext.acme
import future.keywords.if
within_utc_hours(evaluated_at_ns, from_h, to_h) if { ... }
```

```rego
# in any of your hooks:
import data.authz.hooks.lib.v1.ext.acme
deny contains {"code": "quiet_hours"} if { not acme.within_utc_hours(input.evaluated_at, 6, 22) }
```

Rules of the road, validator-enforced (`scripts/validate-hooks.sh --lib <dir>`):
**functions only** (no plain rules — that would be shared ambient state),
pure builtins with **no `http.send` exception** (a shared lib with network
access would hand it to network-free store hooks), and libs may compose the
platform modules. Deploy: compose — mount the dir into `/policies`
(e.g. `/policies/hooks-lib`); Helm — `opa.extraLibsConfigMap`. When
validating hooks that use your libs, point the validator at them:
`HOOK_EXTRA_LIBS=./my-libs scripts/validate-hooks.sh --global ./hooks/global`
(a call into an absent or misspelled library function fails validation).
Shared code runs inside every consumer's evaluation, so ext libraries are
operator-trust: review them like platform policy. See
[`examples/opa-hooks-lib/`](../opa-hooks-lib/).

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

## Enumeration while hooks are loaded: refused, filtered, or superset

Raw `accessible_objects` / `accessible_subjects` are **graph-derived
supersets** — decision hooks don't filter them by themselves, so with any
applicable hook loaded those queries are refused by default
(`403 enumeration_refused_with_hooks`). Pick a mode (env on the OPA
container):

```
HOOK_FILTERED_ENUMERATION=true            # evaluate hooks PER CANDIDATE and drop
                                          # denied ids — listings match checks.
                                          # Cap: HOOK_FILTER_MAX_CANDIDATES (1000);
                                          # over-cap queries are refused, never
                                          # partially filtered.
ALLOW_UNFILTERED_ENUMERATION_WITH_HOOKS=true   # serve the raw superset (only for
                                               # advisory, non-confidentiality hooks)
```

With filtering, paginated results may return **short (even empty) pages with a
next_token** — pagination walks the raw keyset space so filtered-out
candidates never end it early. Those cursors are **sealed** (they may name a
hidden id): set a shared `CURSOR_SEAL_KEY` on pgauthzd when running multiple
replicas (comma-separated keyring for rotation — first mints, all accept).
Setting both mode flags is allowed: filtering wins, and if filtering becomes
inoperable (env guard, bad cap) enumeration REFUSES rather than degrading to
the superset. `permitted_actions` is always hook-filtered
per action. `examples/opa-hooks-filtering/` is the runnable reference.

## Role-based exemptions (e.g. a Keycloak client role that must NOT deny)

Hooks see the **verified caller** as `input.actor = {id, roles}` — roles come
from the platform's `JWT_ROLES_CLAIM` aggregation (for Keycloak, point it at
`realm_access.roles` and your app client's `resource_access.<client>.roles`).
An exemption is just a condition on your own denial, so it stays veto-only —
it can never grant what the graph denies:

```rego
deny contains {"code": "classified"} if {
    startswith(input.resource.id, "classified_")
    not "auditor" in input.actor.roles   # app role ⇒ this hook does not deny
}
```

This composes with filtered enumeration: an auditor's listings keep the
classified ids, everyone else's drop them. Note the roles are ONE flat
namespace by default — a role aggregated from `realm_access.roles` is
indistinguishable from the same string under another client's
`resource_access` — so either use globally unambiguous role names and
aggregate only the claim paths you need, or — recommended for
client-scoped hooks — use the **verbatim claim copies** under
`input.actor.claims`: by default the Keycloak structures `realm_access` and
`resource_access`, exactly as they appear in the token (client_ids stay map
keys, so URI-shaped SAML entity IDs need no separator convention):

```rego
deny contains {"code": "classified"} if {
    startswith(input.resource.id, "classified_")
    ra := object.get(input.actor.claims, "resource_access", {})
    not "auditor" in object.get(ra, "document-api", {"roles": []}).roles
}
```

Need more than the default pair — groups, entitlements, a namespaced OIDC
claim? Set `HOOK_ACTOR_CLAIMS=realm_access,resource_access,groups,https://example.com/entitlements`
(OPA env; Helm: `opa.hookActorClaims`; setting it replaces the default, so
re-list the Keycloak pair if you still want it). Selected verified-token
claims arrive verbatim under `input.actor.claims.<name>` (missing claims are
absent — treat absence as most-restrictive; avoid selecting PII you don't
need).

For the writer gate (which consumes the flat set), `JWT_ROLES_SOURCE_PREFIX=true`
(OPA env) emits provenance-prefixed flat roles instead: `realm::<role>` /
`<client_id>::<role>` — update `WRITER_ROLE` to the prefixed form in the same
change. `actor` is the authenticated
caller even when `subject` is someone else (batch items, subject search,
ALLOW_SUBJECT_OVERRIDE); without a token (trusted-PEP mode) `actor` is empty
and exemptions simply never match.

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
