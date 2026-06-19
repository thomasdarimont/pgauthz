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

| JWT claim | Maps to | Default claim name |
|---|---|---|
| Subject ID | `subject.id` | `preferred_username` (fallback: `sub`) |
| Subject type | `subject.type` | `subject_type` (fallback: config default) |

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

Requests are scoped to an authorization store. The store is selected via:

1. The `X-AuthZ-Store` HTTP header (configurable name)
2. The `DEFAULT_STORE` environment variable (default: `demo`)

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
| `REQUIRED_SCOPE` | | Required scope in `scope` claim (optional) |
| `SUBJECT_ID_CLAIM` | `preferred_username` | JWT claim for subject ID |
| `SUBJECT_ID_FALLBACK_CLAIM` | `sub` | Fallback JWT claim for subject ID |
| `SUBJECT_TYPE_CLAIM` | `subject_type` | JWT claim for subject type |
| `SUBJECT_TYPE_DEFAULT` | `internal_user` | Default subject type if claim missing |
| `ALLOW_SUBJECT_OVERRIDE` | `false` | Allow a request-body subject to override the JWT subject (trusted PEP/PDP mode). Default false = token-only; a mismatched body subject is rejected with `403` |
| `DEFAULT_STORE` | `demo` | Default authorization store |
| `STORE_HEADER` | `X-AuthZ-Store` | HTTP header for store selection |
| `LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warn`, `error`) |

### authzen-direct only

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | *required* | PostgreSQL connection string |
| `DB_POOL_MAX` | `25` | Connection pool size |

### authzen-opa only

| Variable | Default | Description |
|---|---|---|
| `OPA_URL` | *required* | OPA server base URL (e.g. `http://opa:8181`) |
| `OPA_PACKAGE` | `authz` | OPA Rego package name |

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
