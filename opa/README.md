# OPA + PostgREST Integration

This document explains how Open Policy Agent (OPA) integrates with PostgREST
to provide a stateless HTTP authorization API backed by the PostgreSQL
Zanzibar engine.

---

## 1. Architecture Overview

The system has three components connected via a Docker network:

```
                     ┌─────────────────────┐
  Application ──────▶│   OPA  (:8181)      │
  (HTTP)             │   Rego policies     │
                     └────────┬────────────┘
                              │ http.send (internal)
                              ▼
                     ┌─────────────────────┐
                     │ PostgREST (:3000)   │
                     │ REST → SQL bridge   │
                     └────────┬────────────┘
                              │ SQL
                              ▼
                     ┌─────────────────────┐
                     │ PostgreSQL (:5432)  │
                     │ authz schema        │
                     │ Zanzibar engine     │
                     └─────────────────────┘
```

- **OPA** is the only externally exposed service (port 8181). It receives
  authorization queries as JSON, evaluates Rego policies, and returns decisions.
- **PostgREST** is internal only (no host port). It exposes the `authz` schema's
  SQL functions as a REST API. OPA calls it via the Docker network.
- **PostgreSQL** stores all authorization data and runs the Zanzibar engine.
  The recursive access resolution happens entirely in SQL.

Applications never call PostgREST or PostgreSQL directly — OPA is the single
entry point. This gives you a clean separation between:

- **Policy logic** (Rego) — who can do what, under what conditions
- **Relationship resolution** (SQL) — graph traversal, tuple matching, condition evaluation
- **Authentication** (Rego) — JWT verification, subject extraction

---

## 2. How It Works

1. An application sends a POST request to OPA with an authorization question
   (e.g., "can Alice read document X?")
2. OPA evaluates the Rego policy, which extracts the subject, action, and
   resource from the input
3. The policy calls the Zanzibar client library, which makes an HTTP request
   to PostgREST (e.g., `POST /rpc/check_access`)
4. PostgREST translates the REST call into a SQL function call
   (`SELECT authz.check_access(...)`)
5. PostgreSQL evaluates the Zanzibar model — resolving direct tuples, computed
   relations, TTU chains, conditions, and wildcards
6. The boolean result flows back: PostgreSQL → PostgREST → OPA → application

For search queries (`list_objects`, `list_actions`), the flow is the same but
returns arrays instead of booleans.

---

## 3. Docker Compose Setup

The `compose.yml` defines all three services:

```yaml
services:
  authz-db:
    image: postgres:18.4
    environment:
      POSTGRES_USER: authz
      POSTGRES_PASSWORD: authz
      POSTGRES_DB: authz
    ports:
      - "55433:5432"        # Exposed for direct SQL access / debugging
    volumes:
      - authz-db-data:/var/lib/postgresql:z

  postgrest:
    image: postgrest/postgrest:v14.14
    environment:
      PGRST_DB_URI: postgres://authz:authz@authz-db:5432/authz
      PGRST_DB_ANON_ROLE: api_anon
      PGRST_DB_SCHEMAS: authz
    expose:
      - "3000"              # Internal only — no host port
    depends_on:
      authz-db:
        condition: service_healthy

  opa:
    image: openpolicyagent/opa:1.18.2
    command: run --server --watch --addr :8181 --authentication=token --authorization=basic /policies /data
    ports:
      - "8181:8181"         # The only externally exposed port
    volumes:
      - ./opa/policies:/policies:ro
      - ./opa/data:/data:ro
    depends_on:
      - postgrest
```

Key design decisions:

- **PostgREST has no host port** — it is only reachable by OPA via the Docker
  network (`http://postgrest:3000`). This prevents clients from bypassing
  OPA's policy layer.
- **OPA watches for policy changes** (`--watch`) — edit a `.rego` file and
  OPA reloads it automatically, no restart needed.
- **OPA mounts two directories**: `/policies` for Rego files and `/data` for
  static data (JWKS keys). OPA merges JSON files in `/data` into its data
  document at the root.

### Starting the stack

```bash
docker compose up -d
./bootstrap.sh          # Loads schema, functions, demo model, seed data, roles
```

`bootstrap.sh` runs `init.sh` (loads SQL), `tests/test.sh` (SQL tests),
`tests/test-opa.sh` (OPA integration tests), and `tests/test-authzen.sh`
(AuthZEN API tests).

---

## 4. PostgREST Configuration

PostgREST connects as the `authz` superuser and impersonates `api_anon` for
anonymous requests. The role grants are:

| Role | Capabilities |
|---|---|
| `api_anon` | Inherits `authz_reader` — can call `check_access`, `list_objects`, `list_actions`, `explain_access`, etc. |
| `authz_reader` | Access checks, search queries, condition validation |

All functions are `SECURITY DEFINER` (run as `authz`), so `api_anon` needs
no direct table access — it can only interact through the function API.

PostgREST exposes every function in the `authz` schema that the anonymous
role has `EXECUTE` on. OPA calls these as `POST /rpc/<function_name>` with
JSON bodies mapping parameter names to values.

---

## 5. OPA Policy Structure

The policy files are organized under `opa/policies/`:

```
opa/policies/
├── pgauthz_config.rego  # PostgREST URL, cache TTLs, default store
├── pgauthz.rego         # Client library: calls PostgREST functions
├── policy.rego          # Application policy: allow, accessible_objects, permitted_actions
├── authn.rego           # JWT verification and subject extraction
├── authn_config.rego    # Required issuer and audience for JWT validation
└── system_authz.rego    # OPA API access control (public vs admin endpoints)
```

### pgauthz Client Library (`pgauthz.rego`)

`package authz.pgauthz` — a reusable library that wraps every authorization
function as an OPA rule calling PostgREST via `http.send`.

Available functions:

| Rego Function | PostgREST Endpoint | Returns |
|---|---|---|
| `check_access(store, subject_type, subject_id, relation, object_type, object_id)` | `/rpc/check_access` | `true` / `false` |
| `check_access_with_context(... , ctx)` | `/rpc/check_access_with_context` | `true` / `false` |
| `check_access_with_contextual_tuples(... , ctx_tuples)` | `/rpc/check_access_with_contextual_tuples` | `true` / `false` |
| `check_access_with_contextual_tuples_ctx(... , ctx, ctx_tuples)` | `/rpc/check_access_with_contextual_tuples` | `true` / `false` |
| `list_objects(store, subject_type, subject_id, relation, object_type)` | `/rpc/list_objects` | `set{object_id}` |
| `list_objects_with_context(... , ctx)` | `/rpc/list_objects` | `set{object_id}` |
| `list_objects_page(... , limit, offset)` | `/rpc/list_objects` | `[object_id]` (ordered, offset) |
| `list_objects_page_with_context(... , ctx, limit, offset)` | `/rpc/list_objects` | `[object_id]` (ordered, offset) |
| `list_objects_page_after(... , limit, after)` | `/rpc/list_objects` | `[object_id]` (ordered, keyset) |
| `list_objects_page_after_with_context(... , ctx, limit, after)` | `/rpc/list_objects` | `[object_id]` (ordered, keyset) |
| `list_subjects(store, subject_type, relation, object_type, object_id)` | `/rpc/list_subjects` | `set{subject_id}` |
| `list_subjects_page(... , limit, offset)` | `/rpc/list_subjects` | `[subject_id]` (ordered, offset) |
| `list_subjects_page_after(... , limit, after)` | `/rpc/list_subjects` | `[subject_id]` (ordered, keyset) |
| `list_actions(store, subject_type, subject_id, object_type, object_id)` | `/rpc/list_actions` | `set{action}` |
| `list_actions_with_context(... , ctx)` | `/rpc/list_actions` | `set{action}` |

Each function:
1. Builds a JSON body with named parameters (`p_store`, `p_user_type`, etc.)
2. Sends a POST to `config.postgrest_url + "/rpc/<function>"`
3. Checks for `status_code == 200`
4. Extracts the result (boolean for checks, set comprehension for searches)
5. Uses `force_cache` with a configurable TTL

Example — how `check_access` calls PostgREST:

```rego
check_access(store, subject_type, subject_id, relation, object_type, object_id) := response.body if {
    response := http.send({
        "method": "POST",
        "url": concat("", [config.postgrest_url, "/rpc/check_access"]),
        "headers": {"Content-Type": "application/json"},
        "body": {
            "p_store": store,
            "p_user_type": subject_type,
            "p_user_id": subject_id,
            "p_relation": relation,
            "p_object_type": object_type,
            "p_object_id": object_id,
        },
        "raise_error": false,
        "force_cache": true,
        "force_cache_duration_seconds": _cache_ttl(store, object_type),
    })
    response.status_code == 200
}
```

### Configuration (`pgauthz_config.rego`)

`package authz.pgauthz.config` — centralizes runtime configuration:

```rego
# Default store used by the policy layer.
default_store := "demo"

# PostgREST base URL — resolves via Docker network.
postgrest_url := "http://postgrest:3000"

# Default cache TTL for http.send responses (seconds). 0 = no caching.
default_cache_ttl_seconds := 0

# Per-store, per-object-type overrides.
cache_ttl_seconds := {}
```

Cache TTL resolution order:
1. `cache_ttl_seconds[store][object_type]` — exact match
2. `cache_ttl_seconds[store]["_default"]` — store-level fallback
3. `default_cache_ttl_seconds` — global fallback

### Policy Layer (`policy.rego`)

`package authz` — the application-facing policy that defines the
authorization API. This is where you define your business-level rules.

The policy exposes three rules:

**`allow`** — default deny, grants access when the Zanzibar engine confirms it:

```rego
default allow := false

# Access check without context.
allow if {
    _subject_valid
    not input.context
    not input.contextual_tuples
    pgauthz.check_access(store, subject_type, subject_id,
        input.action, input.resource.type, input.resource.id)
}

# Access check with context (for conditions/ABAC).
allow if {
    _subject_valid
    input.context
    not input.contextual_tuples
    pgauthz.check_access_with_context(store, subject_type, subject_id,
        input.action, input.resource.type, input.resource.id, input.context)
}

# Access check with contextual tuples.
allow if {
    _subject_valid
    input.contextual_tuples
    not input.context
    pgauthz.check_access_with_contextual_tuples(store, subject_type, subject_id,
        input.action, input.resource.type, input.resource.id, input.contextual_tuples)
}

# Access check with both context and contextual tuples.
allow if {
    _subject_valid
    input.contextual_tuples
    input.context
    pgauthz.check_access_with_contextual_tuples_ctx(store, subject_type, subject_id,
        input.action, input.resource.type, input.resource.id,
        input.context, input.contextual_tuples)
}
```

OPA evaluates all `allow` rules — if any one matches, the result is `true`.
The four variants handle every combination of context and contextual tuples
so the correct PostgREST endpoint is always called.

**`accessible_objects`** — returns the set of object IDs the subject can access:

```rego
accessible_objects := pgauthz.list_objects(store, subject_type, subject_id,
    input.action, input.resource.type) if {
    _subject_valid
    not input.context
}
```

**`permitted_actions`** — returns the set of actions the subject has on a resource:

```rego
permitted_actions := pgauthz.list_actions(store, subject_type, subject_id,
    input.resource.type, input.resource.id) if {
    _subject_valid
    not input.context
}
```

**Subject resolution** — the policy supports two modes:

1. **JWT token** — subject extracted from verified token claims
2. **Explicit subject** — `input.subject.type` and `input.subject.id`

```rego
subject_type := authn.subject_type if { input.token }
subject_type := input.subject.type if { not input.token }

subject_id := authn.subject_id if { input.token }
subject_id := input.subject.id if { not input.token }
```

**Store selection** — from input or falling back to the configured default:

```rego
store := input.store if { input.store }
store := config.default_store if { not input.store }
```

### Authentication (`authn.rego`)

`package authn` — JWT verification and claim extraction.

Loads a static JWKS file from `opa/data/jwks.json` (mounted as OPA data).
Verifies the token against the configured issuer and audience:

```rego
_token_data := io.jwt.decode_verify(input.token, {
    "cert": json.marshal(jwks),
    "iss": authn_config.required_issuer,
    "aud": authn_config.required_audience,
})
```

Expected JWT claims:

| Claim | Usage | Default |
|---|---|---|
| `sub` | Subject identifier (fallback) | required |
| `preferred_username` | Subject ID (preferred) | falls back to `sub` |
| `subject_type` | Authz user type (`internal_user`, `client_user`) | `"internal_user"` |
| `roles` | Array of role names (exposed via `identity`) | `[]` |

The `authn_config.rego` file sets the required issuer and audience:

```rego
required_issuer := "https://auth.example.com"
required_audience := "authz-api"
```

---

## 6. API Endpoints

All requests are POST to OPA's Data API at `http://localhost:8181/v1/data/`.

> **Read mode.** The tokenless `input.subject` examples below require
> `REQUIRE_TOKEN_FOR_READS=false` (the base/test stack — `env.sh` exports it;
> safe **only** behind a trusted PEP). The keycloak/playground overlay pins the
> secure token-only mode (`REQUIRE_TOKEN_FOR_READS=true`), where these return
> `{"result": false}` — use the `input.token` variants there (the playground's
> AuthZEN path works because `authzen-opa` forwards the verified token,
> `FORWARD_TOKEN_TO_OPA=true`). See §7.

### Access Check (`allow`)

**Endpoint:** `POST /v1/data/authz/allow`

Check whether a subject has a specific action/relation on a resource.

**Without JWT (explicit subject):**

```json
{
  "input": {
    "subject":  { "type": "internal_user", "id": "alice" },
    "action":   "can_read",
    "resource": { "type": "document", "id": "doc_payroll_001" }
  }
}
```

**Response:**

```json
{ "result": true }
```

**With JWT token:**

```json
{
  "input": {
    "token":    "eyJhbGciOi...",
    "action":   "can_read",
    "resource": { "type": "document", "id": "doc_payroll_001" }
  }
}
```

The subject type and ID are extracted from token claims automatically.

**With a specific store** (default: `"demo"`):

```json
{
  "input": {
    "store":    "production",
    "subject":  { "type": "internal_user", "id": "alice" },
    "action":   "can_read",
    "resource": { "type": "document", "id": "doc_payroll_001" }
  }
}
```

### Resource Search (`accessible_objects`)

**Endpoint:** `POST /v1/data/authz/accessible_objects`

Returns the set of object IDs the subject can access for a given action and
object type. Note: `resource.id` is omitted since we're searching for it.

```json
{
  "input": {
    "subject":  { "type": "internal_user", "id": "bob" },
    "action":   "can_read",
    "resource": { "type": "document" }
  }
}
```

**Response:**

```json
{ "result": ["doc_acc_001", "doc_folder_payroll_q1_001", "doc_folder_tax_001",
             "doc_payroll_001", "doc_tax_001"] }
```

(Bob's 3 engagement documents as advisor, plus the 2 documents in the
`workpapers` folder tree he owns — folder grants inherit down to contained
documents.)

### Resource Search with Pagination (`accessible_objects_page`)

**Endpoint:** `POST /v1/data/authz/accessible_objects_page`

Returns an ordered array (not a set) for stable pagination. Supports two paging
modes via `page`:

- **Offset** — `{ "limit": 10, "offset": 0 }`; fetch the next page with
  `"offset": 10`.
- **Keyset (cursor)** — `{ "limit": 10, "after": "<last id of previous page>" }`;
  preferred for large result sets. Offset paging re-runs the per-candidate
  access check on every object of every earlier page (O(offset) wasted checks);
  keyset prunes those candidates before the check runs. When both are present,
  `after` wins.

```json
{
  "input": {
    "subject":  { "type": "internal_user", "id": "bob" },
    "action":   "can_read",
    "resource": { "type": "document" },
    "page":     { "limit": 10, "after": "doc_payroll_001" }
  }
}
```

**Response** (only the ids sorting after the `doc_payroll_001` cursor):

```json
{ "result": ["doc_tax_001"] }
```

When the result array is shorter than `limit`, you've reached the last page.
For keyset paging, the cursor for the next page is the last id of this one.

### Subject Search (`accessible_subjects`)

**Endpoint:** `POST /v1/data/authz/accessible_subjects`

Returns the set of subject IDs that have a given action on a resource.

```json
{
  "input": {
    "subject_type": "internal_user",
    "action":       "can_read",
    "resource":     { "type": "document", "id": "doc_payroll_001" }
  }
}
```

**Response:**

```json
{ "result": ["alice", "bob"] }
```

Pagination is available via `accessible_subjects_page` with `input.page`.

### Action Search (`permitted_actions`)

**Endpoint:** `POST /v1/data/authz/permitted_actions`

Returns the set of actions the subject has on a specific resource.

```json
{
  "input": {
    "subject":  { "type": "internal_user", "id": "alice" },
    "resource": { "type": "document", "id": "doc_payroll_001" }
  }
}
```

**Response:**

```json
{ "result": ["can_read", "can_edit"] }
```

### Identity (debugging)

**Endpoint:** `POST /v1/data/authz/identity`

When a valid JWT is provided, returns the decoded identity:

```json
{
  "input": { "token": "eyJhbGciOi..." }
}
```

**Response:**

```json
{
  "result": {
    "subject_type": "internal_user",
    "subject_id": "alice",
    "roles": ["admin"],
    "token_valid": true
  }
}
```

---

## 7. Authentication: JWT Support

The policy supports two authentication modes:

### Mode 1: Explicit Subject (no authentication)

Pass `subject.type` and `subject.id` directly. Useful for:
- Service-to-service calls from trusted backends
- Testing and development
- Systems that handle authentication separately

> **Disabled by default.** This mode lets the caller name any subject, so it is
> rejected unless `REQUIRE_TOKEN_FOR_READS=false` — set that **only** behind a
> trusted PEP that authenticates callers (the demo opts in via `env.sh`). In the
> default token-only mode, requests without a valid `token` are denied. See
> [PRODUCTION.md → OPA read subject policy](../docs/PRODUCTION.md#opa-read-subject-policy-require_token_for_reads).

```json
{
  "input": {
    "subject":  { "type": "internal_user", "id": "alice" },
    "action":   "can_read",
    "resource": { "type": "document", "id": "doc_001" }
  }
}
```

### Mode 2: JWT Token

Pass a `token` field. OPA verifies the JWT against the static JWKS, then
extracts the subject from claims.

```json
{
  "input": {
    "token":    "eyJhbGciOi...",
    "action":   "can_read",
    "resource": { "type": "document", "id": "doc_001" }
  }
}
```

**JWKS configuration:** Place the public keys in `opa/data/jwks.json`. OPA
loads this file automatically on startup (merged into the data document).
The file format is standard JWKS:

```json
{
  "keys": [
    {
      "kty": "EC",
      "use": "sig",
      "crv": "P-256",
      "kid": "my-kid",
      "x": "...",
      "y": "...",
      "alg": "ES256"
    }
  ]
}
```

**Issuer and audience** are configured in `authn_config.rego`:

```rego
required_issuer := "https://auth.example.com"
required_audience := "authz-api"
```

Update these to match your identity provider (e.g., Keycloak).

**Using a JWKS URL instead of a static file:** In production with Keycloak
or another IdP, you can fetch the JWKS dynamically instead of mounting a
static file. Modify `authn.rego` to fetch from the IdP's JWKS endpoint:

```rego
# Fetch JWKS from Keycloak (cached by OPA's http.send)
jwks_response := http.send({
    "method": "GET",
    "url": "https://keycloak.internal/realms/my-realm/protocol/openid-connect/certs",
    "force_cache": true,
    "force_cache_duration_seconds": 3600,
})

jwks := jwks_response.body if { jwks_response.status_code == 200 }
```

This eliminates the need to manage `opa/data/jwks.json` and automatically
picks up key rotations (within the cache TTL).

### Generating Test Tokens

The `opa/keys/` directory contains demo keys for testing:

| File | Purpose |
|---|---|
| `demo.key.txt` | Private key (ES256) for signing test JWTs |
| `demo_keys.jwks` | Full JWKS (private + public) |
| `demo_pub_keys.jwks` | Public-only JWKS |

The `opa/http-client.env.json` file contains pre-signed test tokens for
Alice, Bob, and Carol, usable with HTTP client tools (e.g., IntelliJ HTTP
Client, VS Code REST Client):

```json
{
  "dev": {
    "base_url": "http://localhost:8181/v1/data",
    "access_token_alice": "eyJhbGciOi...",
    "access_token_bob": "eyJhbGciOi...",
    "access_token_carl": "eyJhbGciOi..."
  }
}
```

---

## 8. Conditions and Context

When the authorization model uses conditions (ABAC), pass request-time
context via the `context` field. OPA forwards it to the PostgreSQL condition
engine for evaluation.

```json
{
  "input": {
    "subject":  { "type": "internal_user", "id": "alice" },
    "action":   "can_read",
    "resource": { "type": "document", "id": "doc_payroll_001" },
    "context":  { "current_time": "2026-03-12T10:00:00Z" }
  }
}
```

When `context` is present, the policy automatically routes to
`check_access_with_context` (or `list_objects_with_context` /
`list_actions_with_context` for search queries).

When `context` is absent, the plain `check_access` is used. Conditional
tuples (tuples with a condition attached) will not match without context.

---

## 9. Contextual Tuples

Contextual tuples are ephemeral relationships that exist only for the
duration of a single access check. They are useful for runtime state that
shouldn't be persisted (e.g., "the user is currently the on-call engineer").

Pass them via the `contextual_tuples` field:

```json
{
  "input": {
    "subject":  { "type": "internal_user", "id": "frank" },
    "action":   "can_read",
    "resource": { "type": "document", "id": "doc_client_001" },
    "contextual_tuples": [
      {
        "user_type":     "internal_user",
        "user_id":       "frank",
        "user_relation": null,
        "relation":      "viewer",
        "object_type":   "document",
        "object_id":     "doc_client_001"
      }
    ]
  }
}
```

This grants Frank `viewer` access to `doc_client_001` for this request only.
The tuple is never written to the database or audit log.

You can combine `context` and `contextual_tuples` in the same request —
the policy handles all four combinations automatically.

---

## 10. Caching

OPA's `http.send` supports response caching via `force_cache` and
`force_cache_duration_seconds`. The Zanzibar client library uses these to
cache PostgREST responses.

### Configuration

In `pgauthz_config.rego`:

```rego
# Global default: 0 = no caching
default_cache_ttl_seconds := 0

# Per-store, per-object-type overrides
cache_ttl_seconds := {
    "demo": {
        "_default": 5,       # All demo object types: 5 seconds
        "document": 10,      # Documents cached longer (less volatile)
        "team": 30,          # Team membership changes rarely
    },
}
```

### TTL Resolution

The cache TTL for a given `(store, object_type)` is resolved in order:

1. `cache_ttl_seconds[store][object_type]` — exact match
2. `cache_ttl_seconds[store]["_default"]` — store-level default
3. `default_cache_ttl_seconds` — global default

### Trade-offs

| TTL | Latency | Consistency | Use case |
|---|---|---|---|
| 0 (default) | Every check hits PostgREST | Always fresh | Low volume, security-critical |
| 1–5 seconds | Reduced load | Slight lag | Medium volume, acceptable staleness |
| 30+ seconds | Minimal load | Noticeable lag | High volume, rarely-changing data |

**Important:** OPA's `http.send` cache is keyed on the full request
(URL + body). Different inputs produce different cache entries. Caching
is most effective when the same user checks the same resource repeatedly
(e.g., page loads, API rate limiting).

---

## 11. Extending the Policy Layer

The three-layer architecture makes it easy to add business logic in OPA
without modifying the SQL engine.

### Adding application-specific rules

Edit `policy.rego` (or create a new policy file) to combine Zanzibar checks
with custom logic:

```rego
# Admins bypass all authorization checks
allow if {
    _subject_valid
    input.token
    "admin" in authn.roles
}

# Business hours restriction (enforced in OPA, not SQL)
allow if {
    _subject_valid
    input.action == "can_approve"
    time.clock(time.now_ns())[0] >= 9
    time.clock(time.now_ns())[0] < 18
    pgauthz.check_access(store, subject_type, subject_id,
        input.action, input.resource.type, input.resource.id)
}
```

### Adding a new store

1. Create the store and model in PostgreSQL (see MODEL_DESIGN.md)
2. Set `default_store` in `pgauthz_config.rego`, or pass `input.store` per request
3. No changes needed to `pgauthz.rego` — it accepts any store name

### Using OPA for multi-service authorization

Multiple applications can share the same OPA instance. Create separate
policy packages per application:

```
opa/policies/
├── pgauthz.rego         # Shared pgauthz client library
├── pgauthz_config.rego  # PostgREST URL, cache TTLs, default store
├── app_portal/          # Portal-specific policies
│   └── policy.rego      # package portal.authz
└── app_backend/         # Backend-specific policies
    └── policy.rego      # package backend.authz
```

Each policy package imports the shared pgauthz client and adds its own
business rules.

---

## 12. Testing

### OPA integration tests

`tests/test-opa.sh` runs end-to-end tests against the running stack:

```bash
./tests/test-opa.sh
```

It verifies:
- 11 access checks (`allow`) covering team membership, advisor roles,
  client access, cross-team denial
- 1 resource search (`accessible_objects`) verifying result count
- 1 action search (`permitted_actions`) verifying result count

Each test sends a curl POST to OPA and compares `jq '.result'` against
the expected value.

### HTTP client file

`opa/requests-check-access.http` contains annotated request examples for use with IDE
HTTP clients (IntelliJ, VS Code REST Client). It covers:

- Access checks with explicit subjects
- Access checks with JWT tokens
- Context-based checks (ABAC/conditions)
- Contextual tuples
- Resource and action searches

Select the `dev` environment to use the pre-configured base URL and test
tokens from `opa/http-client.env.json`.

### Running the full test suite

```bash
./bootstrap.sh              # init + SQL tests + OPA tests + AuthZEN tests
# or individually:
./init.sh                   # Load schema and data
./tests/test.sh             # SQL unit tests only
./tests/test-opa.sh         # OPA integration tests only
./tests/test-authzen.sh     # AuthZEN API tests only
```

---

## 13. Security

- **Read PostgREST must not be exposed externally.** It runs as
  `api_anon` (inheriting `authz_reader`) and has no authentication
  layer of its own. Keep it internal to the Docker network — OPA is
  the security boundary for all read-path access checks.
- **Write PostgREST is fronted by OPA, not exposed.** The writer has no host
  port and does **no** JWT verification of its own — it runs as a fixed
  `authz_writer` role and is reachable only by OPA, which verifies the token,
  requires the configured writer role, and forwards the write. See
  [DEVELOPMENT.md → Write API](../docs/DEVELOPMENT.md#write-api-opa-fronted).
- **JWKS rotation:** Replace `opa/data/jwks.json` with your identity
  provider's JWKS endpoint, or mount the file from a secrets manager.
  OPA reloads data files automatically when they change (with `--watch`).

### Restricting OPA's API endpoints

By default OPA exposes **writable** endpoints that allow anyone with network
access to push arbitrary policies, overwrite data (including JWKS keys), or
read your policy source and running configuration:

| Endpoint | Methods | Risk |
|---|---|---|
| `POST /v1/data/{path}` | POST | Safe — policy evaluation |
| `PUT/PATCH/DELETE /v1/data/{path}` | PUT, PATCH, DELETE | **Can inject/modify/delete data** |
| `GET /v1/policies` | GET | **Leaks policy source code** |
| `PUT/DELETE /v1/policies/{id}` | PUT, DELETE | **Can inject/remove policies** |
| `GET /v1/config` | GET | **Leaks service URLs and credentials** |
| `GET /health`, `GET /v1/status` | GET | Safe |

Use OPA's built-in authorization policy (`--authorization=basic`) to lock
down write access. This evaluates a system policy on every API request
before processing it.

#### Step 1: Create the system authorization policy

The system authorization policy is at `opa/policies/system_authz.rego`. It
implements three layers of protection:

**Public access (no token):**
- `POST /v1/data/authz/<endpoint>` — policy evaluation, restricted to an
  **exact allowlist** of the client-facing endpoints (`allow`, `evaluations`,
  `accessible_objects[_page]`, `accessible_subjects[_page]`, `permitted_actions`,
  `identity`, `write`). Package-prefix matching is **unsafe** — it would expose
  internal rules such as the admin token under `data.system.authz` — so only
  exact paths are public.
- `GET /health` and `GET /v1/status` — health checks and monitoring.

**Admin access (bearer token required):**
- `GET/PUT/DELETE /v1/policies/*` — policy management.
- `GET /v1/data/*` — raw data reads (for debugging).
- `GET /v1/config` — running configuration.

**Always denied (even for admins):**
- `PUT/PATCH/DELETE /v1/data/*` — data writes are blocked entirely. JWKS
  keys and other data must be managed via file mounts or signed bundles,
  never via the REST API. This prevents a compromised admin token from
  being used to inject malicious JWKS keys.

The admin token is read exclusively from the `OPA_ADMIN_TOKEN` environment
variable via `opa.runtime().env`. Environment variables **cannot** be read
via OPA's REST API — there is no endpoint that exposes them to external
callers. No secrets are stored in files.

#### Step 2: Configure OPA with authentication and authorization

```yaml
# compose-production.yml (excerpt)
opa:
  image: openpolicyagent/opa:1.18.2
  command:
    - run
    - --server
    - --addr=:8181
    - --authentication=token
    - --authorization=basic
    - /policies
    - /data
  environment:
    OPA_ADMIN_TOKEN: "${OPA_ADMIN_TOKEN}"  # Set in .env or secrets manager
  volumes:
    - ./opa/policies:/policies:ro
    - ./opa/data:/data:ro
```

The flags:
- `--authentication=token` — extracts a bearer token from the
  `Authorization` header and passes it as `input.identity` to the system
  authorization policy.
- `--authorization=basic` — evaluates `system.authz.allow` on every API
  request. If it returns false, OPA responds with 403.

#### Step 4: Use the admin token for management operations

```bash
# Push a policy update (requires admin token)
curl -X PUT http://localhost:8181/v1/policies/policy \
  -H "Authorization: Bearer your-secret-admin-token-here" \
  --data-binary @opa/policies/policy.rego

# Read running config (requires admin token)
curl http://localhost:8181/v1/config \
  -H "Authorization: Bearer your-secret-admin-token-here"

# Policy evaluation (no token needed — open to all)
curl -X POST http://localhost:8181/v1/data/authz/allow \
  -H "Content-Type: application/json" \
  -d '{"input": {"subject": {"type": "internal_user", "id": "alice"}, ...}}'
```

#### What gets blocked

| Request | No token | Admin token |
|---|---|---|
| `POST /v1/data/authz/allow` | Allowed | Allowed |
| `GET /health` | Allowed | Allowed |
| `GET /v1/status` | Allowed | Allowed |
| `POST /v1/data/keys` | **401** (not in the endpoint allowlist) | **401** |
| `GET /v1/data/keys` | **401** (would leak JWKS) | Allowed |
| `PUT /v1/data/keys` | **401** | **401** (data writes always denied) |
| `GET /v1/policies` | **401** (would leak source) | Allowed |
| `PUT /v1/policies/...` | **401** | Allowed |
| `GET /v1/config` | **401** (would leak URLs) | Allowed |

> **Note:** OPA's `--authorization=basic` returns HTTP 401 (not 403) for all
> denied requests, regardless of whether a token was provided.

#### Alternative: Reverse proxy

If you already have an Nginx or Caddy instance in front of OPA, you can
block dangerous endpoints at the proxy level instead of (or in addition to)
using OPA's built-in authorization:

```nginx
# nginx.conf — OPA reverse proxy
server {
    listen 8181;

    # Health checks — open
    location /health {
        proxy_pass http://opa:8181;
    }

    # Bundle status — open (monitoring)
    location /v1/status {
        proxy_pass http://opa:8181;
    }

    # Policy evaluation — only POST allowed
    location /v1/data/ {
        limit_except POST {
            deny all;
        }
        proxy_pass http://opa:8181;
    }

    # Block everything else: /v1/policies, /v1/config, /v1/compile
    location / {
        return 403;
    }
}
```

This is simpler than the authorization policy approach but less flexible —
there's no way to grant admin access with a token. Use it when you manage
policies exclusively via file mounts or bundles and never need the Policy
API at runtime.

#### Alternative: Separate admin and application addresses

OPA supports binding to multiple addresses. Use `--addr` for the
application-facing API and `--diagnostic-addr` for health/metrics. Combine
this with network-level isolation (firewall rules, Docker network
segmentation) to restrict which hosts can reach which port:

```yaml
# compose-production.yml (excerpt)
opa:
  image: openpolicyagent/opa:1.18.2
  command:
    - run
    - --server
    - --addr=:8181              # Application API — exposed to app network
    - --diagnostic-addr=:8282   # Diagnostics — exposed to monitoring network only
    - --authorization=basic     # Still use the system authz policy
    - /policies
    - /data
  ports:
    - "8181:8181"     # Application network
  expose:
    - "8282"          # Internal only — monitoring tools access via Docker network
```

The diagnostic address serves `/health` and `/metrics` but not the Data or
Policy APIs. This keeps health probes working even if you fully lock down
the main address.

#### Comparison

| Approach | Pros | Cons |
|---|---|---|
| **OPA authorization policy** | Self-contained, token-based admin access, no extra infra | Must maintain a system policy; token management |
| **Reverse proxy** | Simple, no OPA config changes, familiar tooling | No admin API access at all; extra service to maintain |
| **Network isolation** | Defense in depth, works with any approach above | Requires network-level controls (firewalls, Docker networks) |

**Recommendation:** Use the OPA authorization policy as the primary control,
and add network isolation as defense in depth. The reverse proxy is useful
if you already have one in the request path.

### Policy reload safety

OPA's `--watch` flag (used in the dev compose setup) automatically reloads
policies when files change on disk. If a reloaded file has a syntax or
compile error, **OPA rejects it and keeps the previous valid version**. A
typo in a `.rego` file will never replace working policies — OPA logs the
error and continues serving with the last good state.

**For production**, remove `--watch` and use OPA's Bundle API to trigger
reloads explicitly after validation:

```yaml
# compose-production.yml (excerpt)
opa:
  image: openpolicyagent/opa:1.18.2
  command: run --server --addr :8181 --authentication=token --authorization=basic /policies /data
  environment:
    OPA_ADMIN_TOKEN: "${OPA_ADMIN_TOKEN}"
  # No --watch — policies are reloaded via the Policy API or bundles
```

**Manual reload via the Policy API:**

OPA exposes a REST API for pushing policy updates. Replace policies
atomically by PUTting the new content. The admin token is required (see
[Restricting OPA's API Endpoints](#restricting-opas-api-endpoints)):

```bash
# Validate locally before pushing
opa check opa/policies/

# Push a single policy file
curl -X PUT http://localhost:8181/v1/policies/policy \
  -H "Authorization: Bearer $OPA_ADMIN_TOKEN" \
  --data-binary @opa/policies/policy.rego

# Push all policies (script)
for f in opa/policies/*.rego; do
  name="$(basename "$f" .rego)"
  curl -sf -X PUT "http://localhost:8181/v1/policies/$name" \
    -H "Authorization: Bearer $OPA_ADMIN_TOKEN" \
    --data-binary @"$f" || { echo "FAILED: $f"; exit 1; }
done
```

If the PUT payload fails to compile, OPA returns HTTP 400 with the error
and the running policy is unchanged.

**Pre-deployment validation with `opa check`:**

Run `opa check` in CI or before deployment to catch errors early:

```bash
# Syntax and type check all policies
opa check opa/policies/

# With strict mode (catches unused variables, shadowed imports)
opa check --strict opa/policies/
```

**Recommended production workflow:**

1. Edit policies in version control
2. CI runs `opa check --strict opa/policies/` — fail the build on errors
3. Deploy: push validated policies via the Policy API (or mount a new
   volume and restart OPA)
4. Verify: hit the health endpoint and run a smoke test

### Signed policy bundles (recommended for production)

For production environments where policy integrity and supply-chain security
matter, OPA supports **signed bundles**. A bundle is a `.tar.gz` archive
containing policies and data, signed with a private key. OPA verifies the
signature before loading — if the signature is invalid or missing, the
bundle is rejected and the previous valid bundle remains active.

This provides stronger guarantees than the Policy API approach:

| Concern | Policy API | Signed bundles |
|---|---|---|
| Syntax validation | Yes (400 on compile error) | Yes (rejected before load) |
| Tamper detection | No — anyone with API access can push | Yes — cryptographic signature |
| Supply chain | Trust the pusher | Trust the signing key |
| Atomic updates | Per-file | Entire bundle (policies + data) |
| Audit trail | API logs | Bundle revision ID + signature |

#### Step 1: Generate a signing key pair

```bash
# Generate an RSA key pair for bundle signing
openssl genrsa -out opa/keys/bundle_signing.pem 2048
openssl rsa -in opa/keys/bundle_signing.pem -pubout -out opa/keys/bundle_verification.pem

# IMPORTANT: bundle_signing.pem is the private key — keep it in CI secrets only.
# bundle_verification.pem is the public key — mounted into OPA containers.
```

#### Step 2: Build and sign the bundle in CI

```bash
# 1. Validate policies
opa check --strict opa/policies/

# 2. Build the bundle (policies + data in a single archive)
opa build \
  -b opa/policies/ \
  -b opa/data/ \
  --signing-key opa/keys/bundle_signing.pem \
  --signing-alg RS256 \
  --revision "$(git rev-parse --short HEAD)" \
  -o bundle.tar.gz

# 3. Upload to the bundle server (Nginx, internal HTTP server, etc.)
cp bundle.tar.gz /path/to/bundle-server/authz/bundle.tar.gz
```

The `opa build` command:
- Compiles and validates all `.rego` files
- Packages policies and data into a `.tar.gz`
- Signs the bundle with the private key and embeds the signature
- Embeds the git revision for traceability

#### Step 3: Configure OPA to pull signed bundles

Replace the file-based policy loading with bundle polling:

```yaml
# compose-production.yml
opa:
  image: openpolicyagent/opa:1.18.2
  command:
    - run
    - --server
    - --addr=:8181
    - --config-file=/config/opa-config.yaml
  volumes:
    - ./opa/keys/bundle_verification.pem:/keys/bundle_verification.pem:ro
    - ./opa/opa-config.yaml:/config/opa-config.yaml:ro
  # No policy or data mounts — everything comes from the bundle
```

```yaml
# opa/opa-config.yaml
services:
  bundle-server:
    url: http://bundle-server

bundles:
  authz:
    service: bundle-server
    resource: authz/bundle.tar.gz
    polling:
      min_delay_seconds: 30
      max_delay_seconds: 120

keys:
  bundle_key:
    key: /keys/bundle_verification.pem
    algorithm: RS256

decision_logs:
  console: true
```

OPA polls the bundle server at the configured interval. When a new bundle
is available:

1. OPA downloads it
2. Verifies the signature against `bundle_verification.pem`
3. If valid, atomically replaces all policies and data
4. If invalid (bad signature, corrupt archive), rejects and logs an error

#### Step 4: CI/CD pipeline

```
  git push
    │
    ▼
  CI: opa check --strict
    │
    ▼
  CI: opa build --signing-key ... --revision $(git rev-parse --short HEAD)
    │
    ▼
  CI: copy bundle.tar.gz to bundle server
    │
    ▼
  OPA polls bundle server (30–120s)
    │
    ▼
  OPA verifies signature → loads new policies atomically
```

#### Bundle server

Serve bundles from Nginx on the internal network:

```yaml
# compose-production.yml — add a bundle server
bundle-server:
  image: nginx:alpine
  volumes:
    - ./bundles:/usr/share/nginx/html:ro
  expose:
    - "80"
```

```yaml
# opa-config.yaml — point to the local server
services:
  bundle-server:
    url: http://bundle-server
```

Deploy new bundles by copying `bundle.tar.gz` into the `bundles/` directory.

#### Verifying the active bundle

```bash
# Check which bundle revision OPA is currently running
curl -s http://localhost:8181/v1/status | jq '.bundles.authz'
```

Returns the revision, last download time, and activation status:

```json
{
  "name": "authz",
  "active_revision": "a1b2c3d",
  "last_successful_download": "2026-03-15T10:30:00Z",
  "last_successful_activation": "2026-03-15T10:30:01Z"
}
```

---

## 14. Production Considerations

### Scaling

All three components (OPA, PostgREST, PostgreSQL) run co-located on a
single VM. To scale out, deploy multiple such stacks — each VM runs its
own OPA + PostgREST + PostgreSQL read replica. A load balancer distributes
authorization requests across the stacks.

```
                           VM 1                          VM 2
                    ┌─────────────────┐           ┌─────────────────┐
                    │ OPA             │           │ OPA             │
  Application ─────│ PostgREST        │           │ PostgREST       │
       │            │ PG replica  ◀──WAL──┐       │ PG replica  ◀──WAL──┐
       │            └─────────────────┘   │       └─────────────────┘   │
       │                                  │                             │
       ▼                                  │                             │
  Load Balancer ──────────────────────────┼─────────────────────────────┘
       │                                  │
       │            VM 0 (primary)        │
       │            ┌─────────────────┐   │
       └───writes──▶│ PG primary ─────┼───┘
                    └─────────────────┘
```

**Why this works:**
- **OPA is stateless** — any instance can handle any request. No session
  stickiness required.
- **PostgREST is stateless** — each instance maintains its own connection
  pool to the local PostgreSQL replica.
- **No shared state between VMs** — each stack is self-contained. The
  only coordination is PostgreSQL streaming replication from the primary.

#### Load balancer configuration

Use any L4 (TCP) or L7 (HTTP) load balancer (HAProxy, Nginx, cloud LB).
Round-robin or least-connections are both fine since all instances are
equivalent.

**Health checks** should verify the full stack, not just OPA. A simple
POST through OPA that reaches PostgREST and PostgreSQL catches failures
at any layer:

```
# Load balancer health check
POST /v1/data/authz/allow
Content-Type: application/json

{"input":{"subject":{"type":"__probe__","id":"__probe__"},"action":"__probe__","resource":{"type":"__probe__","id":"__probe__"}}}
```

A healthy stack returns HTTP 200 with `{"result": false}`. Any other
response (connection refused, 500, timeout) means the stack is unhealthy.

**Nginx example:**

```nginx
upstream authz {
    least_conn;
    server vm1:8181 max_fails=3 fail_timeout=10s;
    server vm2:8181 max_fails=3 fail_timeout=10s;
}

server {
    listen 8181;

    location / {
        proxy_pass http://authz;
        proxy_connect_timeout 2s;
        proxy_read_timeout 10s;
    }
}
```

#### Replication lag

A tuple written to the primary may not be visible on a replica for a few
milliseconds (streaming replication lag is typically <10ms). This means a
permission grant followed by an immediate access check could return
`false` if the check hits a replica that hasn't caught up yet.

For most workloads this is invisible. If your application requires
read-after-write consistency for permission changes, route the
confirming access check to the primary (or add a short delay after the
write).

You can monitor replication lag on each replica:

```sql
-- On the replica: current lag behind primary
SELECT now() - pg_last_xact_replay_timestamp() AS replication_lag;
```

#### Writes go to the primary

Tuple management (creating/deleting relationships, importing models) must
target the primary PostgreSQL instance directly — not through the
OPA/PostgREST read path. Your application backend connects to the primary
for writes while authorization checks go through the load balancer.

### Connection limits and concurrency

Each authorization check flows through three components, each with its own
concurrency model:

```
  Client ──▶ OPA ──▶ PostgREST ──▶ PostgreSQL
          (unlimited)  (pooled)     (max_connections)
```

**OPA** handles concurrent requests via Go goroutines — there is no
configurable limit. Each `http.send` call opens a **new TCP connection**
to PostgREST (OPA disables keep-alive). Under load, OPA can open as many
outbound connections as there are concurrent policy evaluations.

**PostgREST** maintains a fixed-size **connection pool** to PostgreSQL.
When the pool is exhausted, requests queue until a connection becomes
available or the acquisition timeout expires (HTTP 504).

**PostgreSQL** enforces a hard `max_connections` limit. Connections beyond
this are rejected.

#### Current settings

| Component | Setting | Value | Purpose |
|---|---|---|---|
| PostgreSQL | `max_connections` | 250 | Hard connection limit |
| PostgREST | `PGRST_DB_POOL` | 100 | Pooled connections to PostgreSQL |
| PostgREST | `PGRST_DB_POOL_ACQUISITION_TIMEOUT` | 10s | Max wait for a free connection |
| OPA | `default_cache_ttl_seconds` | 1 | Cache `http.send` responses (seconds) |

The PostgREST pool (100) is sized below PostgreSQL's limit (250), leaving
150 connections for direct access (migrations, admin tools, monitoring,
other services).

#### Tuning guidelines

- **PostgREST pool too small** → 504 errors under load. Increase
  `PGRST_DB_POOL` (but stay below `max_connections`).
- **PostgREST pool too large** → wastes PostgreSQL memory (~10 MB per
  connection). Size it to your actual peak concurrency.
- **OPA cache TTL** reduces outbound connections significantly. With a
  1-second TTL, repeated checks for the same user+resource within that
  window are served from OPA's in-memory cache without hitting PostgREST.
  Increase the TTL per-store/per-object-type in `pgauthz_config.rego` for
  less-volatile data (e.g., team memberships).
- **Multiple PostgREST instances** — if a single PostgREST pool isn't
  enough, run multiple instances. Each maintains its own pool.

### Monitoring

- **OPA health:** `GET http://localhost:8181/health`
- **OPA metrics:** `GET http://localhost:8181/v1/data/system/health`
  (when configured with `--set=decision_logs.console=true`)
- **PostgREST health:** Not externally exposed — check via OPA by sending
  a probe query (as `tests/test-opa.sh` does)

### Cache tuning

The default cache TTL is 1 second (`default_cache_ttl_seconds := 1` in
`pgauthz_config.rego`). Override per-store/per-object-type for longer TTLs on
less-volatile data. Set to 0 to disable caching entirely. Monitor for
stale decisions after permission changes — the cache TTL is the maximum
staleness window.

### Linux and Docker host tuning

All three components (OPA, PostgREST, PostgreSQL) run on the same server.
The typical deployment pattern is multiple such stacks on separate VMs,
each PostgreSQL instance configured as a streaming replica.

Since OPA creates a **new TCP connection per `http.send` call** (no
keep-alive), the most critical concern is ephemeral port exhaustion on
localhost. At sustained load, closed connections accumulate in `TIME_WAIT`
state (60 seconds by default), consuming ephemeral ports.

#### Kernel parameters (`/etc/sysctl.d/authz.conf`)

```ini
# -- Network: ephemeral port exhaustion --
# Default range is 32768–60999 (~28k ports). At 500 req/s with 60s
# TIME_WAIT, that's 30k sockets — exceeding the default range.
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15

# -- Network: connection backlog --
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_max_orphans = 32768

# -- PostgreSQL: shared memory --
# Adjust kernel.shmmax to at least your shared_buffers setting.
kernel.shmmax = 1073741824
kernel.shmall = 262144

# -- PostgreSQL: OOM prevention --
vm.overcommit_memory = 2
vm.overcommit_ratio = 80

# -- PostgreSQL: WAL write performance --
vm.dirty_ratio = 10
vm.dirty_background_ratio = 3
```

Apply with `sysctl --system` or on reboot.

#### Transparent Huge Pages

Disable THP — it causes latency spikes with PostgreSQL:

```bash
echo never > /sys/kernel/mm/transparent_hugepage/enabled
echo never > /sys/kernel/mm/transparent_hugepage/defrag
```

Persist via a systemd unit or `/etc/rc.local`.

#### File descriptor limits

The default `ulimit -n` (often 1024) is too low for high concurrency.

```ini
# /etc/security/limits.d/authz.conf
*  soft  nofile  65536
*  hard  nofile  65536
```

#### Docker-specific tuning

**Use host networking** to eliminate Docker's NAT overhead (iptables
rules, conntrack table) and avoid double port-range pressure. Since all
three services run on the same host, container isolation adds latency
without benefit:

```yaml
# compose-production.yml (excerpt)
services:
  authz-db:
    network_mode: host
    # PostgreSQL listens on 127.0.0.1:5432 (not exposed externally)
    command:
      - postgres
      - -c
      - listen_addresses=127.0.0.1
      # ...

  postgrest:
    network_mode: host
    environment:
      PGRST_DB_URI: postgres://authz:authz@127.0.0.1:5432/authz
      PGRST_SERVER_PORT: "3000"
      # ...

  opa:
    network_mode: host
    # ...
```

If host networking is not an option, tune Docker's userland proxy and
kernel settings instead:

```yaml
# /etc/docker/daemon.json
{
  "default-ulimits": {
    "nofile": { "Name": "nofile", "Hard": 65536, "Soft": 65536 }
  }
}
```

**Container resource limits** — prevent one component from starving the
others:

```yaml
services:
  authz-db:
    deploy:
      resources:
        limits:
          cpus: "4"
          memory: 2G
        reservations:
          cpus: "2"
          memory: 1G

  postgrest:
    deploy:
      resources:
        limits:
          cpus: "2"
          memory: 512M

  opa:
    deploy:
      resources:
        limits:
          cpus: "2"
          memory: 512M
```

Adjust based on your VM size. PostgreSQL should get the largest share
(it benefits most from memory for shared_buffers and OS page cache).

**PostgreSQL data volume** — use a named volume or bind mount on fast
storage. Avoid overlayfs for the data directory:

```yaml
volumes:
  - /data/postgresql:/var/lib/postgresql:z
```

**Logging driver** — the default `json-file` driver can become a
bottleneck under high throughput. Use `local` or `journald`:

```yaml
services:
  opa:
    logging:
      driver: local
      options:
        max-size: "50m"
        max-file: "5"
```

### Policy version control

Keep `opa/policies/` in version control alongside the SQL model. The policy
and model should evolve together — a new relation in the SQL model may
require a corresponding policy update in OPA.
