# AuthZEN API

A Go HTTP API implementing the [AuthZEN 1.0](https://openid.net/specs/authorization-api-1_0.html)
standard. One `pgauthzd` binary, capability-scoped by `PGAUTHORIZER_PROFILE`, is
deployed as several demo services sharing a common handler layer but using different backends:

- **pgauthzd-decision** (`decision-only`) — Go &rarr; PostgreSQL (lowest latency, pure Zanzibar)
- **pgauthzd-opa** (OPA-fronted — `OPA_URL` set) — Go &rarr; OPA &rarr; pgauthzd native callback &rarr; PostgreSQL (app-specific Rego policies)

Both expose identical endpoints and require a valid JWT (ES256/RS256).

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/access/v1/evaluation` | Single access check |
| POST | `/access/v1/evaluations` | Batch checks with short-circuit semantics |
| POST | `/access/v1/search/subject` | Who has access to a resource? |
| POST | `/access/v1/search/resource` | What can a subject access? |
| POST | `/access/v1/search/action` | What actions can a subject perform? |
| GET | `/.well-known/authzen-configuration` | PDP discovery (no auth) |
| GET | `/livez` | Liveness — process alive, **no dependency checks** (no auth). Use for `livenessProbe`. Also on the management listener (`MANAGEMENT_LISTEN_ADDR`, with `/metrics`), and only there with `PUBLIC_HEALTH_ENABLED=false` |
| GET | `/readyz` | Readiness — backend (PostgreSQL/OPA) reachable (no auth). Use for `readinessProbe`; same listeners as `/livez` |
| GET | `/healthz` | Deprecated alias of `/readyz` (no auth) |
| GET | `/pgauthz/v1/openapi.json` / `.yaml` | This server's OpenAPI description (no auth) |

Every `access/v1` endpoint (and the discovery document) is also available
**store-scoped** under `/stores/{store}/…` — see
[Multi-Store Support](#multi-store-support).

### OpenAPI description

The full HTTP contract — native `/pgauthz/v1` + AuthZEN `/access/v1`, including
every `X-PGAuthz-*` request/response header, the error envelopes (standard, the
structured freshness `409`), and both security schemes (public JWT vs the
internal callback's service token) — is described in
[`internal/api/openapi.yaml`](internal/api/openapi.yaml), embedded into the
binary and served at `GET /pgauthz/v1/openapi.json` (and `.yaml`), with
`info.version` stamped to the build version. Feed it to openapi-generator /
Postman / Swagger UI for typed clients and exploration:

```bash
curl -s http://localhost:8090/pgauthz/v1/openapi.json | jq .info
```

**Explore it with Swagger UI.** pgauthzd embeds Swagger UI behind a flag:
with `SWAGGER_UI_ENABLED=true` (the demo stack's default via env.sh; off
otherwise) it serves the UI at **`GET /pgauthz/v1/docs`** — same origin as the
API, so "Try it out" works without CORS; click **Authorize** and paste a JWT
(`./scripts/mint-demo-token.sh` mints one from the demo key — `alice` by
default, `alice authz_writer` for writes, `--pep` for a subject-less PEP
credential). The
assets are vendored into the binary (`internal/api/swaggerui/`, swagger-ui-dist
pinned by `scripts/vendor-swagger-ui.sh`, Apache-2.0), nothing is loaded from
a CDN, and the page's Content-Security-Policy allows scripts from this origin
only. The flag needs `OPENAPI_ENABLED`.

```bash
open http://localhost:8090/pgauthz/v1/docs      # e.g. GET /.well-known/authzen-configuration/stores/demo
```

**Log in instead of pasting a token.** With an OpenID Provider in front
(`./start.sh --keycloak`), `SWAGGER_UI_OIDC_ISSUER` + `SWAGGER_UI_OIDC_CLIENT_ID`
add an `oidc` scheme to the Authorize dialog: the UI runs the authorization
code flow with PKCE against the issuer as a public client, lands back on its
own `oauth2-redirect.html`, and sends the access token as the bearer. The
Keycloak overlay sets both on the instances that trust Keycloak
(`pgauthzd-opa` on :8091, `pgauthzd-full` on :8092) and provisions the
`swagger-ui` client with those redirect URIs, the `authz-api` audience and the
`subject_type` claim (`keycloak/terraform/client.swagger-ui.tf`); log in as
`alice` / `password` at `http://localhost:8091/pgauthz/v1/docs`.

An external UI works too: the served document's `servers` entry is stamped
with the instance's public base URL (the same `BASE_URL` /
`TRUST_FORWARDED_HEADERS` rules as discovery), so a Swagger UI or Postman that
loads `/pgauthz/v1/openapi.json` calls pgauthzd, not itself. The public
endpoints (discovery, health, the document) answer any browser origin; for the
authenticated ones the browser needs pgauthzd to allow the UI's origin —
`CORS_ALLOWED_ORIGINS=http://localhost:8095` for
`docker run --rm -p 8095:8080 -e SWAGGER_JSON_URL=http://localhost:8090/pgauthz/v1/openapi.json swaggerapi/swagger-ui`.

The document cannot silently drift from the code: `internal/api/openapi_test.go`
enforces **bidirectional route coverage** (every documented path must resolve in
the production router, every registered route must be documented) and validates
real handler responses against the schemas — `go test` (and the pre-release
check) fail on any mismatch.

The **served** document is **topology-accurate** — it describes exactly the
routes the instance registers: an OPA-fronted instance (whose public listener
does not register the native routes) serves a copy with the native paths
omitted. It is deliberately **not capability-pruned**: a `decision-only`
instance still registers the write routes and answers a documented `403`, so
they stay in its document (pruning them would claim a route doesn't exist
while it demonstrably responds). The source file describes the full surface,
and native operations carry a machine-readable **`x-pgauthz-availability`**
extension (`listeners`, `public_listener: not-when-opa-fronted`, `profile:
full` on writes) for generators and scanners. Set `OPENAPI_ENABLED=false` to
disable the endpoints entirely (exposure minimization).

## Quick Start

```bash
# Start the full stack (PostgreSQL, pgauthzd reader/writer, OPA, both AuthZEN services)
cd authz/pgauthz
docker compose -f compose.yml -f compose-authzen.yml up -d --build

# Initialize schema, model, and seed data
./bootstrap.sh

# Run integration tests
./tests/test-authzen.sh
```

The direct backend is available on port **8090**, the OPA backend on port **8091**.

## Usage Examples

All endpoints require a Bearer JWT. The subject can be provided in the
request body or extracted from JWT claims (`preferred_username` / `subject_type`).

### Single evaluation

```bash
curl -X POST http://localhost:8090/access/v1/evaluation \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject":  {"type": "internal_user", "id": "alice"},
    "action":   {"name": "can_read"},
    "resource": {"type": "document", "id": "doc_payroll_001"}
  }'
# => {"decision": true}
```

**Properties.** `subject.properties`, `resource.properties` and
`action.properties` are not matched by the graph but reach the engine's
conditions: pgauthzd puts each entity that carries properties into the request
`context` under its own key, in the request's shape (`context.action.properties.soft`),
so a SQL or CEL condition reads the wire request. A caller `context` key named
like an entity is replaced by the block. See MODEL_DESIGN §8 "AuthZEN request
properties"; `examples/models/authzen-cert` is the worked example.

### Batch evaluations

Check multiple permissions in a single call. `options.evaluations_semantic`
(AuthZEN 1.0 §7.1.2; the pre-1.0 top-level `semantic` is still read) controls
short-circuit behavior:
- `execute_all` (default) — evaluate all, return all results
- `deny_on_first_deny` — stop on first denial
- `permit_on_first_permit` — stop on first permit

With a short-circuit the response array ends with the decision that stopped
processing. Every item is evaluated with its own context: the shared `context`
overridden per key by the item's own, then the item's entity properties. An evaluation that lacks a subject, action or resource after the
shared defaults are merged in comes back as `{"decision": false}` in its place
(§7.1.1) rather than failing the batch; a request without an `evaluations`
array is handled like the single Access Evaluation API and answered as
`{"decision": …}` (§7.1).

```bash
curl -X POST http://localhost:8090/access/v1/evaluations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "internal_user", "id": "alice"},
    "evaluations": [
      {"action": {"name": "can_read"},  "resource": {"type": "document", "id": "doc_payroll_001"}},
      {"action": {"name": "can_edit"},  "resource": {"type": "document", "id": "doc_payroll_001"}},
      {"action": {"name": "can_delete"},"resource": {"type": "document", "id": "doc_payroll_001"}}
    ]
  }'
# => {"evaluations": [{"decision": true}, {"decision": true}, {"decision": false}]}
```

### Resource search

Find all resources of a type that a subject can access.

```bash
curl -X POST http://localhost:8090/access/v1/search/resource \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject":  {"type": "internal_user", "id": "bob"},
    "action":   {"name": "can_read"},
    "resource": {"type": "document"}
  }'
# => {"results": [{"type": "document", "id": "doc_payroll_001"}, ...]}
```

Add `"page": {"size": 10}` to paginate. The response then carries
`"page": {"next_token": "..."}` when more results exist; pass that token back as
`"page": {"size": 10, "token": "<next_token>"}` for the next page. The token is
opaque and internally a keyset cursor (the last id of the page), so paging never
re-runs the per-candidate access check on earlier pages. Subject search
paginates the same way.

### Subject search

Find all subjects with access to a specific resource.

```bash
curl -X POST http://localhost:8090/access/v1/search/subject \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject":  {"type": "internal_user"},
    "action":   {"name": "can_read"},
    "resource": {"type": "document", "id": "doc_payroll_001"}
  }'
# => {"results": [{"type": "internal_user", "id": "alice"}, ...]}
```

### Action search

Find all actions a subject can perform on a resource.

```bash
curl -X POST http://localhost:8090/access/v1/search/action \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject":  {"type": "internal_user", "id": "alice"},
    "resource": {"type": "document", "id": "doc_payroll_001"}
  }'
# => {"results": [{"name": "can_edit"}, {"name": "can_read"}]}
```

## Authentication

All endpoints (except `/healthz` and `/.well-known/*`) require a Bearer JWT.

- Tokens are verified against a JWKS (via URL or local file)
- Supported algorithms: ES256, ES384, ES512, RS256, RS384, RS512
- Optional validation of `iss`, `aud`, and `scope` claims
- Subject identity is extracted from configurable claims and merged with request body

**Multiple issuers.** The service can trust several issuers at once via
`JWT_ISSUERS` — a JSON array of `{issuer, audience, jwks_url, jwks_file}`
objects, each with its own JWKS cache; the token's `iss` claim selects the
validator (an untrusted `iss` is rejected). The legacy single-issuer variables
(`JWKS_URL`/`JWKS_FILE`/`JWT_ISSUER`/`JWT_AUDIENCE`) still work and form one
issuer; both can be combined. **Every issuer must pin an `audience`** — the
identifier this API expects in `aud` — or pgauthzd refuses to start: without
it, any token the IdP mints for *another* API (same keys, same subject claims)
would be accepted here. `ALLOW_MISSING_AUDIENCE=true` is the deliberately
alarming override (warns on every start); under
`DEPLOYMENT_ENVIRONMENT=production` it is refused outright. Example (adds
Keycloak next to the demo issuer):

```
JWT_ISSUERS=[{"issuer":"https://id.pgauthz.test/realms/pgauthz","audience":"authz-api","jwks_url":"http://keycloak:8080/realms/pgauthz/protocol/openid-connect/certs"}]
```

**Role-gated reverse search.** The search endpoints
(`search/subject|resource|action`) enumerate the access graph, so they can be
restricted: set `SEARCH_REQUIRED_ROLE` to a role the caller's token must carry
(otherwise `403`). Roles are aggregated across the claim paths in
`JWT_ROLES_CLAIM` (comma-separated dotted paths, e.g.
`realm_access.roles,resource_access.authz-api.roles` for Keycloak realm +
client roles). Unset (default), search is open to any authenticated caller.

| JWT claim | Maps to | Default claim name |
|---|---|---|
| Subject ID | `subject.id` | `preferred_username` (fallback: `sub`) |
| Subject type | `subject.type` | `subject_type` (fallback: config default) |
| Delegated actor | `subject` = `ACTOR_SUBJECT_TYPE:<claim>`, token subject → `on_behalf_of` | `ACTOR_CLAIM` (unset; e.g. `act.client_id`) |

**Delegated tokens (`ACTOR_CLAIM`).** A token minted by OAuth token-exchange
delegation says "*actor* acts for *subject*" (`act` claim, RFC 8693; Keycloak's
token-exchange delegation). With `ACTOR_CLAIM=act.client_id` and
`ACTOR_SUBJECT_TYPE=agent`, such a token is checked **as the actor**
(`agent:<client_id>`) with the actor's own authority in the graph — never as
the user, which would hand an agent everything the user may do. The user is
kept as `on_behalf_of` in the decision log and the OPA hook actor. The same
two variables exist on OPA (`authn.rego`), which derives the subject
independently when it is in the path. End-to-end example:
[`examples/agentic/`](../examples/agentic/README.md).

**Freshness (`Cache-Control: no-cache`).** A caller that must observe a
just-committed change — e.g. re-checking immediately after a revoke — sends
the standard `Cache-Control: no-cache` request header. `pgauthzd-opa` maps it
to OPA's `input.no_cache`, bypassing the decision cache for that one request
(one extra PostgreSQL round-trip); `pgauthzd-decision` has no decision cache, so
every decision is fresh by construction. See
[`opa/README.md`](../opa/README.md) for the cache model and the end-to-end
staleness bound.

**Rich decisions (`X-PGAuthz-Detail`).** Send the `X-PGAuthz-Detail: true`
header on `access/v1/evaluation` to receive the AuthZEN response `context`
field alongside the boolean: `state` (`allow | deny | conditional`),
`missing_context` (condition keys the caller failed to supply, namespaced
`request.*`/`stored.*`), `conditions`, `reason`, and the registry `model`
version for managed stores. `conditional` means "a condition would decide,
but its required context was missing" — supply it and re-check (step-up)
instead of treating the deny as final. Without the header the response is
the plain boolean (the detailed path runs the engine's explain machinery,
so it is per-decision opt-in). Both backends support it (direct → 
`check_access_detailed`, OPA → the `allow_detailed` rule). The context also names who decided: `via` is `engine` or `opa`, and an OPA-fronted decision with policy hooks adds `hooks_loaded` and, on a veto, `hook_denials`.

**Subject override.** By default (`ALLOW_SUBJECT_OVERRIDE=false`) the
JWT-derived subject is authoritative: a request-body `subject` is accepted
only if it matches the token, and a *differing* one is rejected with `403`
(it would be an impersonation attempt). This is the safe default for
**user-facing** deployments where the JWT identifies the end user.

Set `ALLOW_SUBJECT_OVERRIDE=true` for **trusted PEP/PDP** deployments — where
the caller is an enforcement point evaluating access for arbitrary subjects.
Then the request-body `subject` is authoritative, which is also what batch
`evaluations` with per-evaluation subjects requires. The JWT subject stands
in only for a body that names *no* subject at all; a partial one (`id`
without `type`, or the reverse) is a `400`, never completed from the token.
When no JWT subject is present (e.g. a no-auth/system deployment), the body
subject is used regardless of the flag. A PEP credential for the OpenID
conformance suite therefore carries no `sub` (see `conformance/`).

**Contextual tuples.** The native check takes `contextual_tuples`: what-if
relationships evaluated with the stored graph for that one decision and
never written ("would alice be allowed if she were a member of team X?").
A caller that can shape the question this way can forge an allow to its
own question and probe the graph with hypotheticals, so
`CONTEXTUAL_TUPLES` says who may, on the public listener: `off` (nobody),
`trusted-peps` (the default: only a caller that may assert a subject for
the store — a `pep_clients` entry, or `ALLOW_SUBJECT_OVERRIDE=true` — the
same trust boundary as above), or `any` (every authenticated caller;
refused in production). Anyone else gets `403`. The OPA callback listener
always accepts them: its caller is OPA. A decision-log line of such a
check carries `contextual_tuples: <count>` (never the tuples), so an
auditor can tell a hypothetical from a decision on the stored graph. The
engine-side gate stays: the instance's DB role must hold
`authz_contextual_reader` (`authzen_direct` does).

### Two ways to call pgauthzd

The flag encodes a choice every integration makes: **whose token** reaches
pgauthzd. Both are first-class; pick per instance, not per request.

| | **Forward the user's token** (self-subject) | **Ask as a PEP** (trusted PEP) |
|---|---|---|
| Who calls | the application, with the end user's access token (a BFF, a gateway, Swagger UI after login) | a backend with its **own** credential (service account, workload identity), on behalf of whichever user it serves |
| Configuration | the default | per client and store: the issuer's `pep_clients` (`"document-service": ["documents", "tenant-.*"]`, keyed by the token's `azp`); or `ALLOW_SUBJECT_OVERRIDE=true` for every token of every issuer |
| Subject of the decision | the token: `preferred_username` + `subject_type` (configurable claims) | the request body: `subject`, per item in a batch |
| Body `subject` | optional; if present it must equal the token's (else `403`) | required (a missing one is `400`, an unresolvable batch item `decision: false`) |
| Can ask about other users? | no — that is the point (a token without any subject claim cannot name one either) | yes — that is the point; the token proves the caller is a PEP you trust |
| Writes / recorded events attributed to | the token's subject (`performed_by` / `recorded_by` must match it) | the body's assertion (same trust) |
| Decision log | `actor` = `subject` | `actor` = the PEP's identity, `subject` = who was decided about |
| Typical | user-facing APIs, the playground, the Keycloak demo on :8091 | a PDP for many apps, batch pre-authorization, the OpenID conformance suite |

```bash
# Forward the user's token: the token says who; the body may omit the subject.
curl -s -X POST http://localhost:8091/stores/demo/access/v1/evaluation \
  -H "Authorization: Bearer $ALICE_TOKEN" -H 'Content-Type: application/json' \
  -d '{"action":{"name":"can_read"},"resource":{"type":"document","id":"doc_payroll_001"}}'

# Ask as a PEP: the service's token authenticates the caller, the body names the user.
curl -s -X POST http://pdp.internal/stores/demo/access/v1/evaluation \
  -H "Authorization: Bearer $SERVICE_TOKEN" -H 'Content-Type: application/json' \
  -d '{"subject":{"type":"internal_user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"doc_payroll_001"}}'
```

Both patterns can share one instance: list the PEPs in their issuer's
`pep_clients` and leave `ALLOW_SUBJECT_OVERRIDE` off — a listed client asserts
subjects in its stores, every other token (end users, other services) is
self-subject, and a listed client asking in a store it is not listed for gets a
`403` that names client and store. A `pep_clients` pattern may not reach
beyond the issuer's `stores` binding (startup error), and the same predicate
gates `performed_by` / `recorded_by`, so asserting *who acts* follows the same
grant as asserting *who asks* ([ADR 0014](../docs/adr/0014-subject-assertion-policy.md)).

```json
[{"issuer": "https://id.example.com/realms/corp", "audience": "authz-api",
  "jwks_url": "https://id.example.com/realms/corp/protocol/openid-connect/certs",
  "stores": ["documents", "hr", "tenant-.*"],
  "pep_clients": {"document-service": ["documents", "tenant-.*"], "pep-gateway": [".*"]}}]
```

The client is the token's `azp` claim (else `client_id`) — a token without one
cannot be a PEP client. The decision log ([ADR 0013](../docs/adr/0013-decision-log.md))
records `actor`, `client` and `subject` separately, so "which app asked about
whom" is answered on every line in either mode; `pgauthzd doctor` prints the
assertion matrix. The operational side — which setting to run with and why —
is in [PRODUCTION.md → AuthZEN subject policy](../docs/PRODUCTION.md#authzen-subject-policy).

## Multi-Store Support

Requests are scoped to an authorization store. The store is selected via
(first match wins):

1. **The URL path** — every endpoint is also available store-scoped, e.g.
   `POST /stores/{store}/access/v1/evaluation`. Each store presents as its
   own AuthZEN PDP with its own metadata: the `policy_decision_point`
   identifier and every endpoint URL carry the `/stores/{store}` prefix.
   Per AuthZEN 1.0 §9.2 (the multi-tenant model), the spec-canonical
   discovery URL is **path-insertion** — the well-known segment goes
   *between* the host and the tenant path:
   `GET /.well-known/authzen-configuration/stores/{store}`. The
   path-appending form `GET /stores/{store}/.well-known/authzen-configuration`
   is also served (OpenFGA-style) and returns the identical document.
2. The `X-PGAuthz-Store` HTTP header (configurable name)
3. The `DEFAULT_STORE` environment variable (default: `demo`)

**Per-issuer store binding.** In multi-tenant setups, bind each trusted
issuer to the stores its tokens may access via the `stores` field in
`JWT_ISSUERS` — a list of **anchored regular expressions** (plain names
match exactly; `tenant_a_.*` covers a store family):

```
JWT_ISSUERS=[{"issuer":"https://tenant-a.idp","jwks_url":"…","stores":["tenant_a","tenant_a_.*"]}]
```

A token from that issuer selecting any other store is rejected with `403`.
Issuers without a `stores` list are **unrestricted**. With a single issuer that
is the default; with **several** issuers configured an unbound one is a startup
**error** (fail-closed — its tokens could reach every store) unless you opt out
deliberately with `ALLOW_UNBOUND_MULTI_ISSUER=true` (refused outright under
`DEPLOYMENT_ENVIRONMENT=production`). Bind every issuer
explicitly (`".*"` if you really mean all stores), and set
`REQUIRE_STORE_BINDING=true` in any multi-tenant deployment to make the gap an
error even for a single issuer. Note that `SEARCH_REQUIRED_ROLE` gates search
globally, not per store.

## Per-App Namespace Enforcement

pgauthz [namespace restrictions](../docs/DEVELOPMENT.md#namespace-based-write-access-control)
key on the **effective DB role**. `pgauthzd-decision` can derive a per-app role
from the verified token and assume it per request (`SET LOCAL ROLE` inside a
transaction), so namespaced types are enforced per calling application:

1. **`DB_ROLE_CLAIM`** — dot-separated claim path carrying the role (mirrors
   the OPA sidecar's own `DB_ROLE_CLAIM`). Prefer configuring the claim
   per client at the IdP (e.g. a hardcoded `db_role` claim on each Keycloak
   client — the `app-dms` pattern): declarative and auditable.
2. **Per-issuer `client_db_roles`** — a client-id (`azp`) → role map inside a
   `JWT_ISSUERS` entry. Preferred in multi-issuer setups: `azp` is only
   unique *within* an issuer, so issuer-scoped maps avoid cross-tenant azp
   collisions.
3. **`CLIENT_DB_ROLES`** — the global fallback map, for single-issuer setups
   or IdPs where neither claims nor per-issuer config apply:
   `{"app-hr":"app_hr","app-dms":"app_dms"}`.

The claim wins, then the issuer-scoped map, then the global map. **Per-issuer
`db_roles` binding:** without it, any trusted issuer could mint a token
claiming another tenant's role — list the roles (anchored regex patterns)
each issuer may yield:

```
JWT_ISSUERS=[{"issuer":"https://tenant-a.idp","jwks_url":"…",
              "stores":["tenant_a_.*"],
              "db_roles":["app_hr","app_hr_.*"],
              "client_db_roles":{"app-hr":"app_hr"}}]
```

A token yielding a non-matching role is rejected with `403` — never silently
downgraded to the fixed connection role (which could widen access). Issuers
without `db_roles` (or `client_db_roles`) are unrestricted — when role
derivation is configured, the service logs a startup warning per unbound
issuer in multi-issuer setups, and `REQUIRE_DB_ROLE_BINDING=true` makes the
gap a startup **error**. Before
assuming a role the backend validates it (member of `authz_reader`, **not**
admin-capable) and `SET LOCAL ROLE`s to it in Go, and fails
closed on unknown roles; validation results are cached for
`DB_ROLE_CACHE_TTL_SECONDS` (default 60, `0` = re-validate every request), so
dropping a role or revoking its membership takes effect within that window.
The role must also be `GRANT`ed to the service's
`DATABASE_URL` user. With neither variable set, behavior is unchanged (the
fixed connection role applies).

> **pgauthzd-opa:** the same isolation applies on the OPA path. The service
> derives the role identically (claim → issuer map → global map, validated
> against the issuer's `db_roles` binding) and forwards it to OPA as
> `input.db_role`; OPA passes it back to the pgauthzd reader (native
> `/pgauthz/v1` callback) as `X-PGAuthz-Role`,
> where the pgauthzd reader validates it (member of `authz_reader`,
> not admin-capable, fail closed) and `SET LOCAL ROLE`s to it in Go. In token-mode
> OPA deployments (`FORWARD_TOKEN_TO_OPA=true` + OPA `DB_ROLE_CLAIM`), OPA
> re-derives the role from the verified claims and ignores `input.db_role`;
> the input field is honored only in trusted-PEP mode
> (`REQUIRE_TOKEN_FOR_READS=false`).

## Preflight: `pgauthzd doctor`

Before promoting a configuration, ask the binary whether it would pass:

```bash
pgauthzd doctor                       # evaluate the config as set
pgauthzd doctor --profile production  # evaluate it as a production deployment
pgauthzd doctor --json --strict       # machine-readable; exit 2 on warnings too
```

It loads the configuration exactly as the daemon does (so the production
profile's gate checks and every invalid value fail here first), then
checks what the production guide otherwise asks you to verify by hand:
demo secrets (the compose service token, demo DB passwords, the
`auth.example.com` issuer), open diagnostic surfaces, issuer store
bindings and JWKS reachability, `ALLOW_SUBJECT_OVERRIDE`, the cursor seal
key on OPA-fronted instances, the database (connect, engine installed,
role read-only or writer-capable as the profile requires), the callback
listener and its mTLS, OPA health, the decision-log sink, and the metrics
listener. Exit code 1 on any failure; it never serves and never writes.
The Helm chart runs it as `helm test` with the reader's configuration
(`doctor.strict` to fail on warnings).

## Configuration

All configuration is via environment variables.

### Common (both services)

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | HTTP bind address |
| `BASE_URL` | auto-detect | Base URL for `.well-known` response and the served OpenAPI `servers` entry (scheme + host the PDP is reachable under) |
| `SWAGGER_UI_ENABLED` | `false` | Serve the embedded Swagger UI at `GET /pgauthz/v1/docs` (same-origin "Try it out"; assets vendored, no CDN). Needs `OPENAPI_ENABLED`. A developer convenience — leave off in production |
| `SWAGGER_UI_OIDC_ISSUER` | | With `SWAGGER_UI_OIDC_CLIENT_ID`: the embedded UI logs in at this OpenID Provider (authorization code + PKCE) instead of a pasted token — the served document gains an `oidc` security scheme on every authenticated operation. Must be an issuer in `JWT_ISSUERS`; the client needs redirect URI `<public base>/pgauthz/v1/docs/oauth2-redirect.html` |
| `SWAGGER_UI_OIDC_CLIENT_ID` | | The public client registered for the UI at that issuer (demo: `swagger-ui`, `keycloak/terraform/client.swagger-ui.tf`) |
| `SWAGGER_UI_OIDC_SCOPES` | `openid` | Scopes the UI requests (space-separated) |
| `SWAGGER_UI_OIDC_AUTHORIZATION_URL`, `SWAGGER_UI_OIDC_TOKEN_URL` | | Optional, both or neither: with them the document describes the one flow the UI uses (oauth2 `authorizationCode`), so Authorize shows a single login; without them it points at the issuer's discovery document and Swagger UI renders a section per grant type the provider advertises |
| `CORS_ALLOWED_ORIGINS` | *empty* | Browser origins (comma-separated, `*` = any) that may call the **authenticated** API cross-origin — a browser-based PEP, Swagger UI's "Try it out". The public endpoints (discovery, health, the OpenAPI document) answer any origin regardless. Empty = no CORS on the authenticated surface |
| `TRUST_FORWARDED_HEADERS` | `false` | Build the `.well-known` base from `X-Forwarded-Proto` / `X-Forwarded-Host` (an instance behind a TLS-terminating proxy that sets them). Off by default — a client could otherwise choose what the PDP advertises as its identifier. `BASE_URL` wins when set |
| `JWKS_URL` | | URL to JWKS endpoint (required if `JWKS_FILE` not set) |
| `JWKS_FILE` | | Path to local JWKS file (required if `JWKS_URL` not set) |
| `JWT_ISSUER` | | Expected `iss` claim (optional) |
| `JWT_AUDIENCE` | | Expected `aud` claim — **required** for the legacy single issuer (every issuer must pin an audience; see `ALLOW_MISSING_AUDIENCE`) |
| `JWT_ISSUERS` | | Additional trusted issuers: JSON array of `{issuer, audience, jwks_url, jwks_file, stores, db_roles, client_db_roles, pep_clients, admin}`; `iss` selects the validator; `stores` / `db_roles` (anchored regex lists) bind the issuer to specific stores / per-app DB roles; `client_db_roles` maps this issuer's client ids to roles; `pep_clients` (client id → store patterns) names the clients that may assert a request-body subject, and where — see [Two ways to call pgauthzd](#two-ways-to-call-pgauthzd); `admin` `{scopes, claims, clients, scope}` names the tokens of this issuer that may call the [admin API](#admin-api-full-profile-admin_api_enabled) and whether they manage the issuer's own binding (`scope: issuer`, default) or every issuer (`platform`) |
| `JWT_ROLES_CLAIM` | | Comma-separated dotted claim paths aggregated into the caller's roles (e.g. `realm_access.roles,resource_access.authz-api.roles`) |
| `SEARCH_REQUIRED_ROLE` | | If set, the `search/*` endpoints require this role (`403` otherwise); empty = search open to any authenticated caller |
| `WATCH_REQUIRED_ROLE` | *unset = watch disabled* | Gates the native changefeed on the public listener (review #10) — the feed exposes authorization topology. Unset: 403. A role name: JWT-role gate. `"*"`: explicitly open (discouraged). Callback listener unaffected |
| `EXPLAIN_REQUIRED_ROLE` | *empty = open* | Gates native explain on the public listener like search (set a role in production — explain reveals model structure and traces) |
| `ALLOW_MISSING_AUDIENCE` | `false` | An issuer without an `audience` is a STARTUP FAILURE (tokens minted for any other API would be accepted — confused deputy). This deliberately alarming override starts anyway (WARNING on every start) — except under `DEPLOYMENT_ENVIRONMENT=production`, where it is a startup failure itself |
| `ALLOW_OPEN_DIAGNOSTICS` | `false` | With `DEPLOYMENT_ENVIRONMENT=production`, an unset `SEARCH_REQUIRED_ROLE` / `EXPLAIN_REQUIRED_ROLE` or a `WATCH_REQUIRED_ROLE` of `"*"` is a STARTUP FAILURE (the production profile). This deliberately alarming override starts anyway (WARNING on every start) |
| `RECORDER_ROLE` | `authz_recorder` | Gates `POST /pgauthz/v1/events` (the action log, [ADR 0012](../docs/adr/0012-action-log.md)) on the public listener; `WRITER_ROLE` passes too. Empty = ungated. Callback listener unaffected (its DB-role check — member of `authz_recorder` — still applies). **Issue this claim to PEPs and ingestion services only** — recorded events drive temporal gates, so a holder can move a gate; never to end-user tokens |
| `ALLOW_UNBOUND_MULTI_ISSUER` | `false` | With >1 trusted issuers, an issuer without stores/db_roles bindings is a STARTUP FAILURE (cross-tenant risk). This deliberately alarming override restores warn-and-continue — except under `DEPLOYMENT_ENVIRONMENT=production`, where it is a startup failure itself |
| `OPA_MAX_RESPONSE_BYTES` | `10485760` | Bounds every OPA response body; oversized → `policy_evaluation_failed` (5xx), never a large allocation |
| `DB_ROLE_CLAIM` | | Dot-separated claim path with the caller's per-app DB role for namespace enforcement (see [Per-App Namespace Enforcement](#per-app-namespace-enforcement)) |
| `CLIENT_DB_ROLES` | | JSON map client id (`azp`) → per-app DB role; fallback when `DB_ROLE_CLAIM` is unset/absent |
| `REQUIRED_SCOPE` | | Required scope in `scope` claim (optional) |
| `SUBJECT_ID_CLAIM` | `preferred_username` | JWT claim for subject ID |
| `SUBJECT_ID_FALLBACK_CLAIM` | `sub` | Fallback JWT claim for subject ID |
| `SUBJECT_TYPE_CLAIM` | `subject_type` | JWT claim for subject type |
| `SUBJECT_TYPE_DEFAULT` | `internal_user` | Default subject type if claim missing |
| `ACTOR_CLAIM` | *(unset)* | Dotted path of a claim naming a **delegated actor** (RFC 8693 `act.client_id`; Keycloak token-exchange delegation). When it resolves to a non-empty string, the principal is `ACTOR_SUBJECT_TYPE:<value>` and the token's own subject is carried as `on_behalf_of` (decision log). Unset = such tokens are their subject |
| `ACTOR_SUBJECT_TYPE` | `agent` | Subject type of a delegated actor |
| `ALLOW_SUBJECT_OVERRIDE` | `false` | Let EVERY token assert a request-body subject (a PDP for trusted callers only). Default false = self-subject: a mismatched body subject is `403` — unless the token's client is a `pep_clients` entry of its issuer for that store ([ADR 0014](../docs/adr/0014-subject-assertion-policy.md)). Refused in production next to `pep_clients` |
| `CONTEXTUAL_TUPLES` | `trusted-peps` | Who may send `contextual_tuples` (what-if tuples) with a native check on the public listener: `off` (nobody), `trusted-peps` (callers that may assert a subject for the store: `pep_clients` / `ALLOW_SUBJECT_OVERRIDE`), `any` (every authenticated caller; refused in production). Others get `403`; the OPA callback listener always accepts them. The decision log counts them per line |
| `DEFAULT_STORE` | `demo` | Default authorization store |
| `STORE_HEADER` | `X-PGAuthz-Store` | HTTP header for store selection |
| `REQUIRE_STORE_BINDING` | `false` | Refuse to start unless **every** trusted issuer has a `stores` binding (recommended `true` for multi-tenant deployments); off = unbound issuers are unrestricted, with a startup warning when several issuers are configured |
| `REQUIRE_DB_ROLE_BINDING` | `false` | When role derivation is configured (`DB_ROLE_CLAIM` / `CLIENT_DB_ROLES`): refuse to start unless every issuer has a `db_roles` or `client_db_roles` binding (recommended `true` for multi-tenant deployments) |
| `FRESHNESS_TOKEN_KEYS` | *empty* | Ordered, comma-separated HMAC secrets enabling freshness tokens ([ADR 0009](../docs/adr/0009-freshness-tokens.md) read-your-writes): the **first** key mints, **every** key verifies — which is what makes key rotation a zero-downtime overlap (`old,new` → `new,old` → `new`; runbook in [PRODUCTION.md](../docs/PRODUCTION.md)). Set the **same** list on the writer and the readers. Empty = feature off: writes mint no token and an `at_least_as_fresh` read is rejected (`400`, fail closed) |
| `FRESHNESS_TOKEN_KEY` | *empty* | Single-key alias for `FRESHNESS_TOKEN_KEYS` (setting both is a startup error) |
| `OPENAPI_ENABLED` | `true` | Serve this instance's OpenAPI description at `GET /pgauthz/v1/openapi.{json,yaml}` (unauthenticated; instance-accurate). Set `false` to disable the endpoints entirely |
| `MANAGEMENT_LISTEN_ADDR` | *empty* | The **management listener** (e.g. `:9090`; [ADR 0010](../docs/adr/0010-metrics-observability.md)): Prometheus `/metrics` and the probes `/livez`, `/readyz`, `/healthz` on a **separate** listener. Bind to the pod/mesh network — **never** the public client listener. Empty = no metrics, probes on the public listener only. `METRICS_LISTEN_ADDR` is the older name, still accepted |
| `PUBLIC_HEALTH_ENABLED` | `true` | `false` takes the probes off the public listener (a client learns nothing about the backend from it); they then answer on the management listener (required) and the admin listener. Point probes, healthchecks and the console's `PGAUTHZD_URL` at the management listener first |
| `METRICS_SAMPLE_INTERVAL_SECONDS` | `30` | Interval for the engine/tenant gauge sampler (per-store tuple counts). Only runs when metrics are exposed; `0` disables it |
| `METRICS_MAX_STORES` | `100` | Cap on per-store series (top-N by tuple count); `pgauthzd_stores_total` still reports the true count |
| `HTTP_READ_HEADER_TIMEOUT` | `5s` | Max time to read request headers on every listener (slowloris hardening) |
| `HTTP_IDLE_TIMEOUT` | `60s` | Max keep-alive idle time on every listener |
| `HTTP_MAX_BODY_BYTES` | `10485760` (10 MiB) | Request-body cap (`http.MaxBytesReader`); generous — batch writes are legitimately large. `0` disables |
| `LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warn`, `error`). Successful health probes (`/livez`, `/readyz`, `/healthz`) log at `debug` so orchestrator polling does not fill the log; a failing probe logs at `info` |
| `DECISION_LOG` | `off` | Decision log sink ([ADR 0013](../docs/adr/0013-decision-log.md)): `off`, `stdout`, `stderr`, `file:<path>` (append-only; rotate externally with copy-truncate), or `postgres` (a sink database, [ADR 0015](../docs/adr/0015-decision-log-postgres-sink.md): `DECISION_LOG_DSN`, batched inserts into daily partitions of `decisionlog.decisions`, the console's Decisions tab reads it). One JSON line per decision on `evaluation(s)`, `check(-batch)`, `explain`, `events/reserve`, both listeners, with provenance (`pgauthzd_version`, the store's `model` name/version/checksum, OPA `policy` version + bundle revisions when fronted, and for OPA-fronted decisions with policy hooks the `hooks` consulted and any `hook_denials`). Context **keys** only, never values |
| `DECISION_LOG_SAMPLE` | `1` | Fraction (0–1) of **allow** lines written; denies, conditionals and errors are always written |
| `DECISION_LOG_DETAIL` | `false` | Run the detailed evaluation for plain checks **for the log only** (every line gets `state`/`reason`); responses are unchanged. Costs the detailed check's second pass on conditional outcomes |
| `DECISION_LOG_REQUIRED` | `false` | Evidence mode: after a failed log write, `/readyz` is 503 and every decision endpoint refuses with 503 until the sink accepts a line again (retried with a marker line at most once per second) — no decision without its record. Needs a sink and `DECISION_LOG_SAMPLE=1`. Regulated deployments only; the default stays best-effort |
| `DECISION_LOG_DSN` | | The `postgres` sink's database (a writable role allowed to create the schema `decisionlog`; in the console deployments the console's own database, `PG_DSN`). Never the engine's read-only role |
| `DECISION_LOG_RETENTION_DAYS` | `30` | `postgres` sink: daily partitions older than this are dropped once an hour, and lines older than this are refused on flush (`pgauthzd_decision_log_expired_lines_total`) so a late delivery cannot outlive an erasure tombstone (every sink sharing the database must use the same value); `0` keeps and accepts everything |
| `DECISION_LOG_QUEUE` | `10000` | `postgres` sink: lines held between flushes (a batch every second or every 500 lines); a full queue drops the line and counts it as a failed write; a failed insert marks the sink down (`DECISION_LOG_REQUIRED` then fails closed) until the next flush succeeds, and its lines go back into the queue — what no longer fits is lost and said so: `pgauthzd_decision_log_dropped_lines_total` plus an ERROR log line (alarm on it; the sink offers no durable spool) |
| `ISSUERS_SOURCE` | `env` | Where an issuer's **bindings** come from. `env`: `JWT_ISSUERS` is the whole truth. `env+db`: the bindings of each environment issuer — `stores`, `db_roles`, `client_db_roles`, `pep_clients`, and whether its tokens are accepted — may be replaced by a row of `authz.issuer_bindings` (managed from the console's Platform → Issuers, `authz.set_issuer_binding`), merged at start and on every change (polled every `ISSUERS_POLL_INTERVAL` seconds, notified on a primary). The environment keeps the **anchors** (issuer, audience, keys) and a row may only narrow: an issuer the environment does not trust is ignored, a row that widens or unbinds `stores` is rejected and logged, the set in force never changes on a bad row. `pgauthzd_issuers_revision`, `pgauthzd_issuers_reloads_total{result}`, the revision in `/readyz` |
| `ISSUERS_POLL_INTERVAL` | `30` | Seconds between revision polls of `authz.issuer_bindings` (`env+db`); a NOTIFY from the primary applies a change sooner |
| `ISSUERS_REQUIRED_ROLE` | | Who may read `GET /pgauthz/v1/issuers` (the effective set, keys redacted to their source) on the public listener; unset = not served there. A caller sees its **own** issuer only (a tenant never learns another tenant's identity provider); a platform admin every issuer. The internal callback listener always serves the whole set |
| `ADMIN_API_ENABLED` | `false` | Serve the [admin API](#admin-api-full-profile-admin_api_enabled) (`/pgauthz/v1/admin/…`). `full` profile only, DB role holding `authz_admin` (`pgauthzd_admin`, asserted at startup), and a gate: an issuer with an `admin` binding or `ADMIN_ROLE` — enabled without one is a startup error |
| `ADMIN_LISTEN_ADDR` | | Serve the admin API on its own listener (recommended; production warns without it) — the public listener then has no `/admin/` route and its OpenAPI document omits them. Health probes are served there too |
| `ADMIN_ROLE` | | Single-issuer shorthand for the admin gate: a role (`JWT_ROLES_CLAIM`) the token must hold; platform scope (every issuer) |
| `ADMIN_DATABASE_URL` | | A second, small pool the management resources run on, connecting as the admin tier (`pgauthzd_admin`), so `DATABASE_URL` keeps the writer tier and the decision paths never run with admin rights. Unset: the main pool serves management and must hold `authz_admin` (`doctor` warns) |
| `ADMIN_TLS_CERT` / `ADMIN_TLS_KEY` / `ADMIN_CLIENT_CA` | | mTLS on the admin listener (all three; needs `ADMIN_LISTEN_ADDR`): the listener terminates TLS and **requires** a client certificate chained to the CA. A verified certificate is a credential of its own when `ADMIN_CLIENT_CERTS` maps it |
| `ADMIN_CLIENT_CERTS` | | JSON array mapping verified client certificates to admin scopes: `[{"cn":"terraform","scope":"platform"},{"uri":"spiffe://acme/ci/tenant-a","scope":"issuer","issuer":"https://idp.tenant-a"}]` (`subject` for the full RFC 2253 subject). The certificate's identity (SAN URI, else subject) is the recorded actor (`cert:…`). For machine identities — CI, Terraform runners; people keep using tokens |
| `TRACING` | `auto` | **OpenTelemetry master switch.** `auto`: tracing is on only when the `OTEL_*` environment configures an OTLP exporter — so it is **off by default**; `on`: propagation and spans even without an exporter (a caller's `traceparent` reaches the decision log); `off`: nothing — no header read, no span, no ids on the log line. Off means the untraced code path: no handler wrapper, no query tracer, no OPA transport wrapper |
| `TRACING_IDENTIFIERS` | `false` | Put subject and resource **ids** on the decision span (`pgauthz.subject`, `pgauthz.resource`). Default: the **types** only (`pgauthz.subject.type`, `pgauthz.resource.type`) — a tracing backend is usually shared more widely than the decision log, which keeps the ids and is joined by `trace_id` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | | Set it (or `OTEL_TRACES_EXPORTER=otlp`) and pgauthzd exports spans over OTLP: one server span per request (health probes excluded), one `pgauthz.<endpoint>` span per decision with `pgauthz.store`, `.subject`, `.action`, `.resource`, `.decision`, `.state`, `.reason`, `.client`, a client span per engine query named after the `authz.*` function it calls (statement text and parameter count, never the arguments), and a client span per OPA call; the request's own span carries `pgauthz.store`, so traces are queried by store without parsing paths. The other standard variables apply as the SDK defines them: `OTEL_EXPORTER_OTLP_PROTOCOL` (`http/protobuf`, default, or `grpc`), `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_SERVICE_NAME` (default `pgauthzd`), `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_TRACES_SAMPLER` / `_ARG`; `OTEL_TRACES_EXPORTER=none` disables export. With tracing on, W3C `traceparent` and B3 are honoured and forwarded, exporter or not: the decision log's `trace_id` / `span_id` join a line to the application's trace, and `X-Request-ID` defaults to the trace id. Demo: `./start.sh --tracing` adds a Jaeger (`compose-tracing.yml`) and points every instance at it |
| `DECISION_LOG_SEARCHES` | `false` | Also write one line per search (`search/subject|resource|action`, native `list-*`): actor, store, endpoint, the query dimensions as given, `result_count`, latency — **never the returned ids**. Not sampled. Needs a sink. Under `DECISION_LOG_REQUIRED`, searches then fail closed (503) while the sink is down, like decisions |

### pgauthzd-decision (`decision-only`) only

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | *required* | PostgreSQL connection string |
| `DB_POOL_MAX` | `25` | Connection pool size |
| `DB_ROLE_CACHE_TTL_SECONDS` | `60` | How long a per-app DB role validation result (allowed *or* denied) is cached before re-checking `pg_has_role`; `0` disables caching (re-validate every request) |
| `FRESHNESS_PRIMARY_URL` | *empty* | Reader-role DSN to the **primary** for transparent freshness fallback ([ADR 0009](../docs/adr/0009-freshness-tokens.md)): a not-fresh-enough `at_least_as_fresh` read is re-run on the primary (marked `X-PGAuthz-Served-By: primary`) instead of `409`. Off in OPA mode. Empty = the `409` behavior |
| `FRESHNESS_PRIMARY_POOL_MAX` | `10` | Max connections in the primary-fallback pool (kept small so a fallback storm can't exhaust the primary) |

### pgauthzd-opa (OPA-fronted — `OPA_URL` set) only

| Variable | Default | Description |
|---|---|---|
| `OPA_URL` | *required* | OPA server base URL (e.g. `http://opa:8181`) |
| `OPA_PACKAGE` | `authz` | OPA Rego package name |
| `FORWARD_TOKEN_TO_OPA` | `false` | Forward the verified bearer token to OPA as `input.token` so OPA re-validates it — lets OPA run token-only (`REQUIRE_TOKEN_FOR_READS=true`) instead of trusting the forwarded subject. Leave off for trusted-PEP setups that check arbitrary subjects |
| `OPA_REQUEST_TIMEOUT` | `10s` | Bounds every OPA HTTP call (decisions, searches, readiness) — a black-holed OPA can't hang requests or startup |
| `OPA_DEEP_READINESS_REQUIRED` | `false` | Fail `/readyz` when the loaded policy set lacks the `callback_healthy` rule, instead of silently degrading to the shallow OPA-`/health`-only check. The active mode is exported as `pgauthzd_opa_readiness_mode{mode}` either way |
| `OPA_EVAL_METRICS` | `true` | Add `metrics=true` to OPA queries and record OPA's own Rego eval time (`pgauthzd_opa_rego_eval_duration_seconds`). Small per-request OPA overhead; disable to shed it |
| `DEPLOYMENT_ENVIRONMENT` | *empty* | Server-configured label forwarded to OPA policy hooks as `input.deployment.environment` (ADR 0011); environment-gated hooks read it instead of caller context. Unset forwards the sentinel `unknown` (never `""`, which fails open on equality gates) — write env gates allowlist-style. **`production` / `prod` also selects the production profile:** search and explain must be role-gated and watch must not be `"*"`, or startup fails (see `ALLOW_OPEN_DIAGNOSTICS`) |
| `CURSOR_SEAL_KEY` | *empty* | Seals filtered-enumeration page cursors (AES-GCM) — they carry raw keyset ids that hooks may have hidden (ADR 0011). REQUIRED (shared value) across replicas when `HOOK_FILTERED_ENUMERATION` is on. Rotation: comma-separated keyring — first key mints, all accept (`new,old` during the window, then drop `old`). Cursors are context-bound (store/query/caller — cross-context replay rejected). Unset = per-process key, **dev only** (cursors don't survive restarts/replica hops; startup warning on OPA-fronted instances; failed unseal = 400, never a leak) |
| `DATABASE_URL` | *empty* | Optional. A **read-only** DSN enables the native raw callback surface (`/pgauthz/v1/check`, `list-*`) an OPA sidecar calls back into (replacing the former PostgREST reader). Asserted read-only at startup |
| `INTERNAL_LISTEN_ADDR` | *empty* | Address for the internal listener serving that native raw surface (e.g. `:8081`). **Do not publish it** — bind to the OPA sidecar network. Empty = raw surface not served |
| `INTERNAL_SERVICE_TOKEN` | *empty* | Shared service credential the internal listener requires (`Authorization: Bearer`), proving the call came from the OPA sidecar. Must match OPA's `NATIVE_SERVICE_TOKEN`. **Required** when `INTERNAL_LISTEN_ADDR` is set — startup fails closed without it. The listener then trusts OPA's asserted subject (body) + role (`X-PGAuthz-Role`), not the end-user JWT |
| `INTERNAL_TLS_CERT` / `INTERNAL_TLS_KEY` / `INTERNAL_CLIENT_CA` | *empty* | Optional mTLS on the internal listener (transport-layer caller auth, layered under the service token). Set all three → the listener serves HTTPS and **requires + verifies a client cert** chained to `INTERNAL_CLIENT_CA` (only the OPA sidecar's cert is accepted). Empty = plain HTTP (fine for same-pod/localhost). Prefer mesh-provided mTLS where available |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Application / Client                 │
│                    (Bearer JWT)                         │
└────────────┬───────────────────────────┬────────────────┘
             │                           │
    ┌────────▼──────────┐      ┌─────────▼──────────┐
    │ pgauthzd-decision │      │   pgauthzd-opa     │
    │ (port 8090)       │      │   (port 8091)      │
    │                   │      │                    │
    │ JWT → SQL         │      │ JWT → OPA → native │
    └────────┬──────────┘      └─────────┬──────────┘
             │                           │
    ┌────────▼──────────┐      ┌─────────▼──────────┐
    │  PostgreSQL       │      │   OPA (Rego)       │
    │  authz schema     │      │       │            │
    │                   │      │       ▼            │
    │                   │      │  pgauthzd native   │
    │                   │      │  callback → PG     │
    └───────────────────┘      └────────────────────┘
```

Both profiles are served by the one `pgauthzd` binary over the same `Backend` interface:

```go
type Backend interface {
    CheckAccess(ctx, req)                    (bool, error)
    CheckAccessBatch(ctx, store, reqs, ...) ([]EvalResult, error)
    ListResources(ctx, store, ...)          ([]string, *PageResponse, error)
    ListSubjects(ctx, store, ...)           ([]string, *PageResponse, error)
    ListActions(ctx, store, ...)            ([]string, error)
    Healthz(ctx)                             error
}
```

- **pgbackend** calls PostgreSQL functions directly via pgx (`check_access`,
  `check_access_batch`, `list_objects`, `list_subjects`, `list_actions`)
- **opabackend** calls OPA's `/v1/data/{pkg}/{rule}` HTTP API, which evaluates
  Rego policies that in turn call **back** into pgauthzd's native `/pgauthz/v1`
  callback

## Project Structure

```
pgauthzd/
├── cmd/
│   └── pgauthzd/main.go          # Single entry point; profile via PGAUTHORIZER_PROFILE
├── internal/
│   ├── api/
│   │   ├── handler.go            # AuthZEN endpoint handlers
│   │   ├── types.go              # Request/response types
│   │   ├── middleware.go         # JWT verification, logging, recovery
│   │   └── errors.go            # Error response helpers
│   ├── authz/authz.go           # Backend interface definition
│   ├── config/config.go         # Environment variable loading
│   ├── pgbackend/backend.go     # Direct PostgreSQL implementation
│   └── opabackend/backend.go    # OPA HTTP implementation
├── Dockerfile                    # Multi-stage build (Alpine)
├── go.mod
└── go.sum
```

## Building

```bash
# Build the single binary
go build ./cmd/pgauthzd

# Docker (one image; select the profile at runtime via PGAUTHORIZER_PROFILE)
docker build -t pgauthzd .
```

## Testing

Integration tests exercise both services against the demo store:

```bash
# Requires the full stack to be running (bootstrap.sh)
./tests/test-authzen.sh
```

The test script generates ES256 JWTs signed with the demo key and verifies
single evaluations, batch evaluations, search endpoints, well-known discovery,
health checks, JWT authentication (401 without/with invalid token), and
error handling (400 on malformed requests).

## Native pgauthz API (`/pgauthz/v1/*`)

Vendor-specific operations beyond the standards-compliant AuthZEN surface,
kept on a separate path so `/access/v1` stays spec-pure. Served by the direct
pgx backend. When **not fronting OPA** (`OPA_URL` unset, `decision-only` /
`full`) they sit on the main listener. When **fronting OPA** (`OPA_URL` set)
they are served — read-only — on a
separate **internal** listener (`INTERNAL_LISTEN_ADDR`) that an OPA sidecar
calls back into (replacing the former PostgREST reader); they are deliberately absent from the
public listener there (a raw graph answer must not bypass the policy layer).
Without a configured native backend the routes return `501 Not Implemented`.

| Method | Path | Profile | Description |
|--------|------|---------|-------------|
| POST | `/pgauthz/v1/check` | direct | Raw, **policy-free** access decision (`{"allowed":bool}`); `context` for conditions, `detail:true` for the rich result, `contextual_tuples` for an ephemeral-tuple check (needs `authz_contextual_reader` on the DB role, and a caller `CONTEXTUAL_TUPLES` admits — trusted PEPs by default). |
| POST | `/pgauthz/v1/check-batch` | direct | Many raw decisions in one round-trip (`{"results":[bool,…]}`); optional `semantic`. Per-check `contextual_tuples` are refused (`400`): the batch evaluates the stored graph only. |
| GET | `/pgauthz/v1/issuers` | direct | The effective trusted-issuer set: anchors (key source redacted), bindings, `binding_source` env/db per issuer, `enabled`, the applied revision. Public listener: `ISSUERS_REQUIRED_ROLE`, the caller's own issuer only (every issuer for a platform admin); callback listener: always, the whole set. |
| GET | `/pgauthz/v1/admin/issuers` | full + admin | The effective set within the caller's admin scope — see [Admin API](#admin-api-full-profile-admin_api_enabled). |
| GET/PUT/DELETE | `/pgauthz/v1/admin/issuer-bindings` | full + admin | The database-managed issuer bindings (`authz.issuer_bindings`) within the caller's scope: list / one (`?issuer=`), create-or-replace (the whole row; validated, narrowing only, the issuer must be trusted), delete (`?issuer=`). |
| GET/PUT/DELETE | `/pgauthz/v1/admin/stores/{store}`, `…/model` | full + admin | Stores and their models as upserts (create, describe, retire, delete; plan and apply a registry version) within the caller's scope — see [Admin API](#admin-api-full-profile-admin_api_enabled). |
| GET/POST | `/pgauthz/v1/admin/models[/{name}/versions\|/rollout]` | full + admin (platform) | The model registry: versions, publish from a store or a definition, the fleet view. |
| POST | `/pgauthz/v1/list-objects` | direct | Objects of a type the subject can act on (`list_objects`); keyset-paginated. |
| POST | `/pgauthz/v1/list-subjects` | direct | Subjects of a type that can act on the object (`list_subjects`); keyset-paginated. |
| POST | `/pgauthz/v1/list-actions` | direct | Relations the subject holds on the object (`list_actions`). |
| POST | `/pgauthz/v1/explain` | direct | Structured "why" — `explain_access` decision + trace. Same subject/store rules as an AuthZEN evaluation. |
| POST | `/pgauthz/v1/watch` | direct | A cursored page of the store's audit **changefeed** (HTTP transport over `authz.watch_changes`). |
| POST | `/pgauthz/v1/write` | **full** | Batch-upsert tuples (`write_tuples_jsonb`). |
| POST | `/pgauthz/v1/delete` | **full** | Batch-delete tuples (`delete_tuples_jsonb`). |
| POST | `/pgauthz/v1/grant-options` | direct | The share dialog's data: per relation with a grant rule, may the subject grant / revoke it and who may hold it (`grant_options`). A read. |
| POST | `/pgauthz/v1/apply-grants` | **full** | A share dialog's save: grants + revokes as one transaction (`apply_grants`); a refused entry → 403 naming it, nothing written. |
| POST | `/pgauthz/v1/grant`, `/pgauthz/v1/revoke` | **full** | Sharing (`authz.grant` / `authz.revoke`): the token subject gives / takes away a relation on an object, allowed iff the store's **grant rules** say so — not `WRITER_ROLE`-gated, end users share; 403 with the engine's reason when refused. |
| POST | `/pgauthz/v1/events` | **full** | Record what principals *actually did* — the action log (`record_events_jsonb`, [ADR 0012](../docs/adr/0012-action-log.md)); `RECORDER_ROLE`-gated, atomic batches, `event_id` idempotency. |
| POST | `/pgauthz/v1/events/reserve` | **full** | Strict tier: full decision + `request` record under a per-subject lock (`reserve_event`); refusals recorded as `denied`. Check-shaped body; `RECORDER_ROLE`-gated. |

The `check` / `list-*` endpoints are **policy-free by construction** — they run
straight against the direct pgx backend, never through a policy layer. That is
what the internal OPA sidecar calls back into when a Rego policy delegates to the
graph, so a compat deployment can front the graph with policy without OPA
needing a separate data bridge (the former PostgREST reader) and without
re-entering its own policy-wrapped `/access/v1` surface. They use the AuthZEN subject/action/resource vocabulary (same
subject-resolution and store-binding) and return pgauthz-native bodies.

All are also available store-scoped under `/stores/{store}/pgauthz/v1/…`.

**Watch cursoring.** The changefeed cursor is the composite
`(after_at, after_seq)` — pass the whole `next_cursor` from a page back to get
the next one; `after_seq` alone is not sufficient. Filters: `object_types`,
`namespaces`, `relations` (arrays), `limit`, `lag` (default `1 second`).

```bash
curl -X POST localhost:8090/pgauthz/v1/watch -H "Authorization: Bearer $TOKEN" \
  -d '{"limit":100}'
# => {"store":"demo","events":[...],"next_cursor":{"after_at":"...","after_seq":42}}
```

The watch/audit surface needs an **auditor-capable** connection role
(`authz_auditor`, which inherits `authz_reader` and adds only audit *reads* —
still write-incapable, so a `decision-only` instance keeps its can't-write
guarantee). The bundled `authzen_direct` login role is granted it.

### Admin API (`full` profile, `ADMIN_API_ENABLED`)

The **management** surface — what a Terraform provider, `pgauthzctl` and the
console use to configure a deployment rather than to ask it for decisions.
Off by default (`ADMIN_API_ENABLED=false`); its routes live under their own
prefix `/pgauthz/v1/admin/…` so a gateway allows or denies them by prefix, and
with `ADMIN_LISTEN_ADDR` on their own listener, which is what a production
instance should do (the public listener then serves no `/admin/` route and its
OpenAPI document omits them — the served document is always instance-accurate).
Only a `full` instance serves it; management runs on its own pool as the
admin tier (`ADMIN_DATABASE_URL`, `pgauthzd_admin` in `roles.sql`; asserted
at startup) while the instance's `DATABASE_URL` stays the writer — or, without
the second pool, on the main pool, which must then hold `authz_admin`.

**The gate.** Every call needs a verified token (the same `JWT_ISSUERS` trust
as the decision paths) that passes the admin gate:

- the token's issuer carries an **`admin` binding** in `JWT_ISSUERS` —
  `{"admin":{"scopes":["pgauthz:admin"],"claims":{"realm_access.roles":["platform-admin"]},"clients":["terraform"],"scope":"platform"}}`:
  every listed scope must be in the token's `scope`, every listed claim value
  present (string or array claims, dotted paths), and the client (`azp` /
  `client_id`) listed when clients are. An empty admin binding is refused
  (it would admit every token of the issuer). The database never grants
  management: admin bindings are the environment's;
- or — the single-issuer shorthand — the token holds **`ADMIN_ROLE`**;
- or, on an admin listener with **mTLS** (`ADMIN_TLS_CERT/KEY` +
  `ADMIN_CLIENT_CA`), the call carries no token and the verified **client
  certificate** is mapped by `ADMIN_CLIENT_CERTS` (`cn`, `uri` or full
  `subject` → `scope`). That is the credential for machines — `pgauthzctl
  --server … --cert/--key`, a Terraform runner — where an identity-provider
  round trip is unwanted or not yet possible (bootstrap). Revocation is the
  CA's: Go verifies chains, not CRLs, so issue short-lived certificates.

**Multi-tenancy: scoped management.** A fleet trusts one identity provider per
tenant, each bound to its stores; a tenant must never see or touch another's.
An admin binding therefore manages, by default, the issuer's **own** binding
only (`scope: issuer`): a tenant admin narrows, pauses (`enabled: false`) or
re-enables their own identity provider and sees only it. The whole fleet is
reachable only with `scope: platform` — the operator's admin identity
provider — or `ADMIN_ROLE`. The read-only `GET /pgauthz/v1/issuers` follows the
same rule (own issuer unless platform admin).

**The resources** (conditions, gates and grant rules travel inside the
model definition; every console management feature gets its endpoint here,
so configuration as code never needs the console's BFF):

| Method | Path | What |
|--------|------|------|
| GET | `/pgauthz/v1/admin/issuers` | The effective issuer set within the caller's scope (as `/pgauthz/v1/issuers`, entries carry their `admin` binding) |
| GET | `/pgauthz/v1/admin/issuer-bindings[?issuer=…]` | The database rows within scope (with their `revision`), or one (`404` outside it) |
| GET | `/pgauthz/v1/admin/issuer-bindings/audit[?issuer=&limit=&before=]` | The rows' history within scope, one page newest first (keyset by `seq`); a tenant admin reads its own issuer's only |
| PUT | `/pgauthz/v1/admin/issuer-bindings` | Create or replace one binding — the whole row `{issuer, stores, db_roles, client_db_roles, pep_clients, enabled, description}`; validated as the daemon validates, a row may only **narrow** the environment's `stores` (never unbind or widen), an issuer the environment does not trust is refused (`400` — the database cannot add trust); `{issuer, revision}`, applied by every `ISSUERS_SOURCE=env+db` instance |
| DELETE | `/pgauthz/v1/admin/issuer-bindings?issuer=…` | Drop the row; the issuer falls back to its environment bindings |
| GET | `/pgauthz/v1/admin/stores[/{store}]` | The stores in scope (a tenant admin: the stores its issuer is bound to), each with its managed-model state |
| PUT | `/pgauthz/v1/admin/stores/{store}` | Create (`201`) or update (`200`): `{description, docs_url, retired}` — absent fields stay, `retired: true` retires (no reopening) |
| DELETE | `/pgauthz/v1/admin/stores/{store}[?purge_audit=true&purge_decisions=true]` | `delete_store`, the erasure path; answers with the deleted `store_id` (incarnation) and `deleted_at`. The audit history and the decision log stay unless asked: `purge_decisions=true` purges this incarnation's lines from the postgres sink this instance writes (`501` before anything is deleted without such a sink; `502 partial` if the sink failed — retry below) |
| DELETE | `/pgauthz/v1/admin/stores/{store}/decisions?store_id=` | Purge a deleted incarnation's decision-log lines; the incarnation must have the engine's deletion receipt (`404` otherwise), so a live store cannot be fenced |
| GET | `/pgauthz/v1/admin/stores/{store}/deletions` | The engine's deletion receipts for the name (`authz.store_deletions`): incarnation, time, actor |
| GET | `/pgauthz/v1/admin/stores/{store}/model` | The live model as the canonical definition, and `model_status` |
| PUT | `/pgauthz/v1/admin/stores/{store}/model[?plan=true]` | `{"model":"name[@version]"}`: plan, then apply when the plan has no blockers (`409` with the plan otherwise); `plan=true` is the dry run |
| GET/PUT/DELETE | `/pgauthz/v1/admin/stores/{store}/recorders[/{role}]` | The recorder allowlists (ADR 0012): list; make a role's allowlist exactly `{"actions":[…]}`; lift it |
| GET/PUT/DELETE | `/pgauthz/v1/admin/stores/{store}/namespaces[/{ns}/access/{role}]` | The namespaces with their types and role grants; make a role's access exactly `{"can_read","can_write"}`; remove it |
| GET | `/pgauthz/v1/admin/stores/{store}/subjects/{type}/{id}/objects[?relations=&object_types=&limit=&format=csv]` | Data subject takeout (`list_subject_objects`): every object the subject reaches, one row per object and relation; `format=csv` is the hand-over file for the application teams |
| GET | `/pgauthz/v1/admin/stores/{store}/subjects/{type}/{id}[?relations=&limit=]` | Data subject export (`export_subject`): one JSON document — tuples both sides, effective objects, events by and about, audit rows (the decision log is the console's addition). There is no erasure over the API, on purpose: it comes last, after the applications, from the console or SQL |
| GET | `/pgauthz/v1/admin/models[?name=]` | The registry's versions (platform scope) |
| POST | `/pgauthz/v1/admin/models/{name}/versions` | Publish the next version from `from_store` or from a `definition` (the export shape; `publish_model_definition`), idempotent on the checksum (platform scope) |
| GET | `/pgauthz/v1/admin/models/{name}/rollout` | Every store under the model with version and drift (platform scope) |

Writes are recorded in `authz.issuer_bindings_audit` with the token's subject
and client (`user:alice via terraform-a`). `403` carries why the gate refused
(`management refused: …`); a scope violation counts in
`pgauthzd_authz_denied_total{reason="admin_scope"}`.

```bash
# the demo stack: env.sh serves the admin API on :8096 with ADMIN_ROLE=pgauthz_admin
TOKEN=$(make_token alice internal_user '["pgauthz_admin"]')   # tests/test-authzen.sh's helper
curl -s -X PUT localhost:8096/pgauthz/v1/admin/issuer-bindings -H "Authorization: Bearer $TOKEN" \
  -d '{"issuer":"https://auth.example.com","stores":["demo"],"enabled":true,"description":"demo only"}'
# → {"issuer":"https://auth.example.com","revision":3}; todo-store calls answer 403 within a poll
curl -s -X DELETE "localhost:8096/pgauthz/v1/admin/issuer-bindings?issuer=https://auth.example.com" -H "Authorization: Bearer $TOKEN"
```

### Native write path (`full` profile)

The `write`/`delete` endpoints exist **only on the `full` profile** — a direct
backend on a **writer-capable** connection role (`pgauthzd_rw`, which inherits
`authz_writer`). The security boundary is the DB role, not a flag:

- a **`decision-only`** instance (read-only role, e.g. `authzen_direct`) returns
  **`403`** — and asserts at startup that its role genuinely cannot write (a
  `full` instance asserts the opposite). On a database where the engine is not
  installed yet (no `authz_writer` role / `authz.tuples` table — a fresh volume
  before `init.sh` or the migration job ran) the assertion cannot be answered;
  pgauthzd then logs one warning and **waits**, re-checking every 2 s, and
  completes startup the moment the engine lands. A role that *can* be checked
  and is wrong for the profile is still fatal;
- an **OPA-fronted** instance (`OPA_URL` set) returns **`501`** (its writes go through the OPA
  write policy (`write.rego`) fronting the `full` writer instance, not this
  native path).

```bash
curl -X POST localhost:8092/pgauthz/v1/write -H "Authorization: Bearer $TOKEN" \
  -d '{"tuples":[{"user_type":"user","user_id":"alice","relation":"viewer",
                  "object_type":"doc","object_id":"readme"}],
       "consistency":"applied"}'
# => {"store":"demo","written":1}
```

The request body is `{ "tuples": [ … ], "consistency": "…" }`: `tuples` is the
`write_tuples_jsonb` array shape (`user_type`, `user_id`, `relation`,
`object_type`, `object_id`, plus optional `user_relation`, `condition`,
`context`, `expires_at`). The audit author (`performed_by`) is the
authenticated subject; the per-app DB role from the token governs namespace
scope exactly as it does for reads. `consistency` maps per-transaction to
`synchronous_commit`: `applied` (= `remote_apply`, strict revocation),
`durable` (`on`), `eventual` (`local`); omitted = the connection default.

**The action log** (`POST /pgauthz/v1/events`, [ADR 0012](../docs/adr/0012-action-log.md))
shares the write path's shape — full profile, per-app `SET LOCAL ROLE`,
`consistency`, and `recorded_by` under the same attribution rules as
`performed_by` — but has its own claim gate (`RECORDER_ROLE`, default
`authz_recorder`; `WRITER_ROLE` passes too) and DB-role check (member of
`authz_recorder`, which every `authz_writer` is), so an app that only reports
actions needs no tuple-write rights. Body: `{ "events": [ … ], "consistency",
"recorded_by" }` in the `record_events_jsonb` shape (`subject_type`,
`subject_id`, `action` — a declared relation of the store — plus optional
`object_type`/`object_id`, `kind` (`request|response|denied`), `payload`,
`occurred_at`, `event_id`). Response: `{"store", "recorded", "duplicates",
"seqs"}`. Engine content rejections (undeclared action, out-of-bounds
`occurred_at`, malformed element) are `400`; a namespace refusal `403`.

#### Read-your-writes: freshness tokens (ADR 0009)

Set `FRESHNESS_TOKEN_KEYS` (the **same** list on the writer and the readers) to
turn on LSN-watermark freshness tokens. A write then returns a signed token — in
the `X-PGAuthz-Revision` response header and a `"revision"` body field:

```
{ "store": "demo", "written": 1, "revision": "MTowLzNBQjEy..." }
```

A later read presents it to demand read-your-writes, via two request headers:

```
X-PGAuthz-Consistency: at_least_as_fresh
X-PGAuthz-Revision:    <token from the write>
```

The reader checks whether its connection has replayed to the token's WAL
position **on the token's timeline** — the same verdict logic on a replica and
on a primary, so a promoted primary rejects a cross-timeline token
(`wrong_epoch`) instead of confirming a write a lossy failover lost. Satisfied →
the read is served normally. Not satisfied → **`409`** with
`X-PGAuthz-Stale: <verdict>` and a structured body telling the caller the
*right* recovery for the verdict:

```json
{
  "status": 409,
  "error": "freshness_constraint_unsatisfied",
  "verdict": "wrong_epoch",
  "primary_consulted": true,
  "message": "…the write it covers may have been lost — re-read and reconcile…"
}
```

| Verdict | Client action |
|---|---|
| `stale` | retry the primary / another replica, or wait |
| `unknown` | this node can't judge its timeline; retry the primary |
| `wrong_epoch` | **not retryable, and not fixed by an unrelated re-mint** — a failover happened and the write may have been **lost**; re-read and reconcile the intended state on the new primary (reapply idempotently), then use that write's token |

`primary_consulted: true` means the transparent fallback already re-checked the
primary and it can't satisfy the token either. Without the header pair a read
uses the default (`minimize_latency`, answer from the local replica). A
malformed/forged token, a token minted under a key no longer in the keyring, or
the feature disabled — all rejected with **`400`** and one fixed opaque message
(fail closed, and no oracle: a probe can't distinguish "key rotated away" from
"forged"; the reason is logged server-side only). See
[ADR 0009](../docs/adr/0009-freshness-tokens.md).

Every write also reports the mint outcome in **`X-PGAuthz-Revision-Status`**:
`issued` (token in `X-PGAuthz-Revision`), `unavailable` (freshness is enabled
but minting failed — the write itself committed; counted in
`pgauthzd_freshness_mint_failures_total` and logged), or `disabled` (feature not
configured).

**Key rotation.** Tokens embed a key id derived from the secret
(`base64url(sha256(secret)[:4])`), so the verifier picks the right keyring entry
during an overlap. Rotate with three rollouts, each safe under instance skew:
`FRESHNESS_TOKEN_KEYS="old,new"` everywhere (readers learn the new key before
anyone mints with it) → `"new,old"` everywhere (mint flips; outstanding old
tokens still verify) → `"new"` once the old key's
`pgauthzd_freshness_key_verifications_total{kid=…}` series flatlines.

**Paginated reads** (`list-objects` / `list-subjects` and AuthZEN
`search/subject|resource`) bind the freshness floor **into** the `next_token`
cursor, so a scan started under `at_least_as_fresh` keeps every later page at
least as fresh as the first — a client can't drop the floor mid-scan, and a
lagging replica reached on page 2+ still returns `409 + X-PGAuthz-Stale`.

Roadmap: `/pgauthz/v1/audit` (time-travel), `/pgauthz/v1/models` +
`/pgauthz/v1/stores` (inspection), and model publish/apply on the `full`
profile.
