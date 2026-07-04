# AuthZEN API

A Go HTTP API implementing the [AuthZEN 1.0](https://openid.net/specs/authorization-api-1_0.html)
standard. Two services share a common handler layer but use different backends:

- **authzen-direct** — Go &rarr; PostgreSQL (lowest latency, pure Zanzibar)
- **authzen-opa** — Go &rarr; OPA &rarr; PostgREST &rarr; PostgreSQL (app-specific Rego policies)

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
| GET | `/healthz` | Health check (no auth) |

Every `access/v1` endpoint (and the discovery document) is also available
**store-scoped** under `/stores/{store}/…` — see
[Multi-Store Support](#multi-store-support).

## Quick Start

```bash
# Start the full stack (PostgreSQL, PostgREST, OPA, both AuthZEN services)
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

### Batch evaluations

Check multiple permissions in a single call. The `semantic` field controls
short-circuit behavior:
- `execute_all` (default) — evaluate all, return all results
- `deny_on_first_deny` — stop on first denial
- `permit_on_first_permit` — stop on first permit

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
# => {"results": [{"resource": {"type": "document", "id": "doc_payroll_001"}}, ...]}
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
# => {"results": [{"subject": {"type": "internal_user", "id": "alice"}}, ...]}
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
# => {"results": [{"action": {"name": "can_edit"}}, {"action": {"name": "can_read"}}]}
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
issuer; both can be combined. Example (adds Keycloak next to the demo issuer):

```
JWT_ISSUERS=[{"issuer":"https://id.pgauthz.test/realms/pgauthz","jwks_url":"http://keycloak:8080/realms/pgauthz/protocol/openid-connect/certs"}]
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

**Freshness (`Cache-Control: no-cache`).** A caller that must observe a
just-committed change — e.g. re-checking immediately after a revoke — sends
the standard `Cache-Control: no-cache` request header. `authzen-opa` maps it
to OPA's `input.no_cache`, bypassing the decision cache for that one request
(one extra PostgreSQL round-trip); `authzen-direct` has no decision cache, so
every decision is fresh by construction. See
[`opa/README.md`](../opa/README.md) for the cache model and the end-to-end
staleness bound.

**Subject override.** By default (`ALLOW_SUBJECT_OVERRIDE=false`) the
JWT-derived subject is authoritative: a request-body `subject` is accepted
only if it matches the token, and a *differing* one is rejected with `403`
(it would be an impersonation attempt). This is the safe default for
**user-facing** deployments where the JWT identifies the end user.

Set `ALLOW_SUBJECT_OVERRIDE=true` for **trusted PEP/PDP** deployments — where
the caller is an enforcement point evaluating access for arbitrary subjects.
Then the request-body `subject` is authoritative (JWT subject as fallback),
which is also what batch `evaluations` with per-evaluation subjects requires.
When no JWT subject is present (e.g. a no-auth/system deployment), the body
subject is used regardless of the flag.

## Multi-Store Support

Requests are scoped to an authorization store. The store is selected via
(first match wins):

1. **The URL path** — every endpoint is also available store-scoped, e.g.
   `POST /stores/{store}/access/v1/evaluation`. Each store presents as its
   own AuthZEN PDP, including a store-scoped discovery document at
   `GET /stores/{store}/.well-known/authzen-configuration` (whose endpoint
   URLs carry the store prefix).
2. The `X-AuthZ-Store` HTTP header (configurable name)
3. The `DEFAULT_STORE` environment variable (default: `demo`)

**Per-issuer store binding.** In multi-tenant setups, bind each trusted
issuer to the stores its tokens may access via the `stores` field in
`JWT_ISSUERS` — a list of **anchored regular expressions** (plain names
match exactly; `tenant-a-.*` covers a store family):

```
JWT_ISSUERS=[{"issuer":"https://tenant-a.idp","jwks_url":"…","stores":["tenant-a","tenant-a-.*"]}]
```

A token from that issuer selecting any other store is rejected with `403`.
Issuers without a `stores` list are **unrestricted** — with several issuers
configured the service logs a startup warning for each unbound one, and
`REQUIRE_STORE_BINDING=true` turns the gap into a startup **error** (set it in
any multi-tenant deployment). Note that `SEARCH_REQUIRED_ROLE` gates search
globally, not per store.

## Per-App Namespace Enforcement

pgauthz [namespace restrictions](../docs/DEVELOPMENT.md#namespace-based-write-access-control)
key on the **effective DB role**. `authzen-direct` can derive a per-app role
from the verified token and assume it per request (`SET LOCAL ROLE` inside a
transaction), so namespaced types are enforced per calling application:

1. **`DB_ROLE_CLAIM`** — dot-separated claim path carrying the role (mirrors
   the OPA front door's `DB_ROLE_CLAIM`). Prefer configuring the claim
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
              "stores":["tenant-a-.*"],
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
admin-capable — mirroring the writer's `_pre_request()` policy) and fails
closed on unknown roles; validation results are cached for
`DB_ROLE_CACHE_TTL_SECONDS` (default 60, `0` = re-validate every request), so
dropping a role or revoking its membership takes effect within that window.
The role must also be `GRANT`ed to the service's
`DATABASE_URL` user. With neither variable set, behavior is unchanged (the
fixed connection role applies).

> **authzen-opa:** the same isolation applies on the OPA path. The service
> derives the role identically (claim → issuer map → global map, validated
> against the issuer's `db_roles` binding) and forwards it to OPA as
> `input.db_role`; OPA passes it to the PostgREST reader as `X-Authz-Role`,
> where `authz._pre_request_reader()` validates it (member of `authz_reader`,
> not admin-capable, fail closed) and `SET LOCAL ROLE`s to it. In token-mode
> OPA deployments (`FORWARD_TOKEN_TO_OPA=true` + OPA `DB_ROLE_CLAIM`), OPA
> re-derives the role from the verified claims and ignores `input.db_role`;
> the input field is honored only in trusted-PEP mode
> (`REQUIRE_TOKEN_FOR_READS=false`).

## Configuration

All configuration is via environment variables.

### Common (both services)

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | HTTP bind address |
| `BASE_URL` | auto-detect | Base URL for `.well-known` response |
| `JWKS_URL` | | URL to JWKS endpoint (required if `JWKS_FILE` not set) |
| `JWKS_FILE` | | Path to local JWKS file (required if `JWKS_URL` not set) |
| `JWT_ISSUER` | | Expected `iss` claim (optional) |
| `JWT_AUDIENCE` | | Expected `aud` claim (optional) |
| `JWT_ISSUERS` | | Additional trusted issuers: JSON array of `{issuer, audience, jwks_url, jwks_file, stores, db_roles, client_db_roles}`; `iss` selects the validator; `stores` / `db_roles` (anchored regex lists) bind the issuer to specific stores / per-app DB roles; `client_db_roles` maps this issuer's client ids to roles |
| `JWT_ROLES_CLAIM` | | Comma-separated dotted claim paths aggregated into the caller's roles (e.g. `realm_access.roles,resource_access.authz-api.roles`) |
| `SEARCH_REQUIRED_ROLE` | | If set, the `search/*` endpoints require this role (`403` otherwise); empty = search open to any authenticated caller |
| `DB_ROLE_CLAIM` | | Dot-separated claim path with the caller's per-app DB role for namespace enforcement (see [Per-App Namespace Enforcement](#per-app-namespace-enforcement)) |
| `CLIENT_DB_ROLES` | | JSON map client id (`azp`) → per-app DB role; fallback when `DB_ROLE_CLAIM` is unset/absent |
| `REQUIRED_SCOPE` | | Required scope in `scope` claim (optional) |
| `SUBJECT_ID_CLAIM` | `preferred_username` | JWT claim for subject ID |
| `SUBJECT_ID_FALLBACK_CLAIM` | `sub` | Fallback JWT claim for subject ID |
| `SUBJECT_TYPE_CLAIM` | `subject_type` | JWT claim for subject type |
| `SUBJECT_TYPE_DEFAULT` | `internal_user` | Default subject type if claim missing |
| `ALLOW_SUBJECT_OVERRIDE` | `false` | Allow a request-body subject to override the JWT subject (trusted PEP/PDP mode). Default false = token-only; a mismatched body subject is rejected with `403` |
| `DEFAULT_STORE` | `demo` | Default authorization store |
| `STORE_HEADER` | `X-AuthZ-Store` | HTTP header for store selection |
| `REQUIRE_STORE_BINDING` | `false` | Refuse to start unless **every** trusted issuer has a `stores` binding (recommended `true` for multi-tenant deployments); off = unbound issuers are unrestricted, with a startup warning when several issuers are configured |
| `REQUIRE_DB_ROLE_BINDING` | `false` | When role derivation is configured (`DB_ROLE_CLAIM` / `CLIENT_DB_ROLES`): refuse to start unless every issuer has a `db_roles` or `client_db_roles` binding (recommended `true` for multi-tenant deployments) |
| `LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warn`, `error`) |

### authzen-direct only

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | *required* | PostgreSQL connection string |
| `DB_POOL_MAX` | `25` | Connection pool size |
| `DB_ROLE_CACHE_TTL_SECONDS` | `60` | How long a per-app DB role validation result (allowed *or* denied) is cached before re-checking `pg_has_role`; `0` disables caching (re-validate every request) |

### authzen-opa only

| Variable | Default | Description |
|---|---|---|
| `OPA_URL` | *required* | OPA server base URL (e.g. `http://opa:8181`) |
| `OPA_PACKAGE` | `authz` | OPA Rego package name |
| `FORWARD_TOKEN_TO_OPA` | `false` | Forward the verified bearer token to OPA as `input.token` so OPA re-validates it — lets OPA run token-only (`REQUIRE_TOKEN_FOR_READS=true`) instead of trusting the forwarded subject. Leave off for trusted-PEP setups that check arbitrary subjects |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Application / Client                 │
│                    (Bearer JWT)                         │
└────────────┬───────────────────────────┬────────────────┘
             │                           │
     ┌───────▼────────┐        ┌─────────▼──────────┐
     │ authzen-direct │        │   authzen-opa      │
     │ (port 8090)    │        │   (port 8091)      │
     │                │        │                    │
     │ JWT → SQL      │        │ JWT → OPA → REST   │
     └───────┬────────┘        └─────────┬──────────┘
             │                           │
     ┌───────▼────────┐        ┌─────────▼──────────┐
     │  PostgreSQL    │        │   OPA (Rego)       │
     │  authz schema  │        │       │            │
     │                │        │       ▼            │
     │                │        │   PostgREST        │
     │                │        │       │            │
     │                │        │       ▼            │
     │                │        │   PostgreSQL       │
     └────────────────┘        └────────────────────┘
```

Both services implement the same `Backend` interface:

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
  Rego policies that in turn call PostgREST

## Project Structure

```
authzen/
├── cmd/
│   ├── authzen-direct/main.go    # Direct PostgreSQL entry point
│   └── authzen-opa/main.go       # OPA proxy entry point
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
# Build both binaries
go build ./cmd/authzen-direct
go build ./cmd/authzen-opa

# Docker (select binary via build arg)
docker build --build-arg BINARY=authzen-direct -t authzen-direct .
docker build --build-arg BINARY=authzen-opa -t authzen-opa .
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
