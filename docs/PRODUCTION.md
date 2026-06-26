# Production Hardening

A checklist and role-recipe guide for running pgauthz outside the demo. The
demo defaults favor convenience; this page is what to change before exposing
the engine to real traffic. Deeper background is in
[ARCHITECTURE.md](ARCHITECTURE.md) (security model, deployment topologies),
[DEVELOPMENT.md](DEVELOPMENT.md) (JWT/PostgREST/operations), and
[DESIGN.md](DESIGN.md) (rationale).

## Configuration

Customize the deployment through a `.env` file rather than editing the compose
files or SQL — copy the template and edit:

```bash
cp .env.example .env
# edit .env: passwords, JWT, condition timeout, ...
docker compose down -v && ./init.sh   # fresh DB so initdb applies the passwords
```

`docker compose` reads `.env` automatically, and the helper scripts (`env.sh`,
`init.sh`) source it too. The real `.env` is **gitignored** — keep secrets out
of version control, and prefer a secret manager in real production. Every knob
defaults to the demo value, so an unset variable is never a surprise. Each
setting and its default is documented in
[`.env.example`](../.env.example); the relevant ones are called out in the
sections below.

Two things flow at *different* times: service-role **passwords** are applied
when the database is first initialized (so set them before the first
`./init.sh`; to rotate, recreate with `down -v`), while the condition
`statement_timeout` and an optional `authz_contextual_reader` grant are applied
by `init.sh` on every run.

## Before-production checklist

- [ ] **Configure via `.env`** (copy `.env.example` → `.env`) rather than
      editing files. `docker compose` and the helper scripts read it; the real
      `.env` is gitignored. See [Configuration](#configuration).
- [ ] **Change every default password** in `.env`: `PG_PASSWORD` (superuser),
      `AUTHZ_AUTHENTICATOR_PASSWORD`, `AUTHZEN_DIRECT_PASSWORD`. The service-role
      passwords are applied at first DB init, so set them before the first
      `./init.sh` (to change them later: `docker compose down -v && ./init.sh`).
- [ ] **Never host-expose either PostgREST instance.** The reader (`api_anon`)
      is a full reader and the writer runs as `authz_writer`; OPA is the
      mandatory front door, and only OPA should reach PostgREST. See
      [Network exposure](#network-exposure).
- [ ] **Decide the AuthZEN subject policy.** Keep `ALLOW_SUBJECT_OVERRIDE=false`
      (token-only) unless the caller is a trusted PEP. See [AuthZEN subject policy](#authzen-subject-policy).
- [ ] **Keep OPA reads token-only.** Leave `REQUIRE_TOKEN_FOR_READS=true`
      (default) unless OPA sits behind a trusted PEP; otherwise any caller could
      ask for an arbitrary subject. See [OPA read subject policy](#opa-read-subject-policy-require_token_for_reads).
- [ ] **Grant `authz_contextual_reader` only to trusted callers** (it lets a
      caller inject ephemeral tuples into a decision). It is granted to no one
      by default. See [Role recipes](#role-recipes).
- [ ] **Set a real JWKS / JWT issuer / audience** (`JWKS_URL`, `JWT_ISSUER`,
      `JWT_AUDIENCE`) for OPA and the AuthZEN services.
- [ ] **Schedule audit-partition maintenance and retention.** See
      [Audit retention](#audit-retention).
- [ ] **Tune the condition `statement_timeout`** for your slowest legitimate
      operation. See [Condition (ABAC) policy](#condition-abac-policy).
- [ ] **Decide your replica-consistency policy** (which checks must hit the
      primary). See [Replica consistency](#replica-consistency).
- [ ] **Review namespace grants.** If you use namespaces, grant
      `namespace_access` per type so reads/writes are scoped. For per-app
      isolation over the OPA write path, issue per-app DB roles and set
      `WRITER_DB_ROLE_CLAIM` (the writer's `_pre_request` hook assumes the role
      from the JWT) — see [DEVELOPMENT.md → Per-app namespace isolation](DEVELOPMENT.md#per-app-namespace-isolation-over-the-opa-write-path).

## Role recipes

All application access goes through `SECURITY DEFINER` functions owned by the
non-superuser `authz_owner`; app roles never touch tables directly. Roles are
created and granted in `db/security/roles.sql`.

**Application roles (NOLOGIN — used via `SET ROLE` or inheritance):**

| Role | Grants | Inherits |
|---|---|---|
| `authz_reader` | `check_access`, `check_access_with_context`, `list_objects/subjects/actions`, batch checks, `validate_condition`, `explain_access` | — |
| `authz_contextual_reader` | `check_access_with_contextual_tuples*` (inject ephemeral tuples) | — |
| `authz_auditor` | `audit_check_access`, `audit_list_*` | `authz_reader` |
| `authz_writer` | `write_tuple`/`delete_tuple` + batch ops | `authz_reader` |
| `authz_admin` | store/model/namespace management, `ensure_audit_partitions`, `find_redundant_tuples` | `authz_writer`, `authz_auditor` |
| `api_anon` | (none of its own) | `authz_reader` |
| `authz_owner` | owns the schema + objects (definer context) | — |
| `authz_eval` | **zero grants** — the condition-evaluation sandbox | — |

**Connection (LOGIN) roles** — what each component authenticates as:

| Component | Connects as | Effective role(s) | Notes |
|---|---|---|---|
| OPA → PostgREST (reader, :3000) | `authz_authenticator` | `SET ROLE` → `api_anon` (or a JWT-claimed role) | `authz_authenticator` is `LOGIN NOINHERIT`; it can `SET ROLE` to any app role. Reader serves anonymous reads as `api_anon`. |
| PostgREST writer (internal) | `authz_authenticator` | `SET ROLE` → `authz_writer` (fixed anon role) | **No JWT verification** — OPA is the front door (verifies the token + writer role, then forwards). Reachable only by OPA; no host port. |
| AuthZEN-direct (Go, :8090) | `authzen_direct` | inherits `authz_reader` | Read-only; no `SET ROLE`. Dedicated non-superuser login. |
| AuthZEN-opa (Go, :8091) | — (no DB connection) | — | Calls OPA → PostgREST. |
| Backend writers (your app) | a login role granted `authz_writer` (or the writer API with a `role=authz_writer` JWT) | `authz_writer` | |
| Admin tooling | a login role granted `authz_admin` | `authz_admin` | Store/model/namespace changes. |

**When to grant `authz_contextual_reader`.** Contextual-tuple checks let the
caller inject the very grant being tested, so the privilege is separate. Grant
it **only** to a trusted PDP/backend role that constructs contextual tuples
from legitimate request context — e.g. a backend that already authenticates
its callers. **Never** grant it to `api_anon`, `authzen_direct`, or any role
reachable by untrusted clients. Set `AUTHZ_CONTEXTUAL_READER_GRANTEE` in `.env`
and `init.sh` applies the grant, or do it manually:

```sql
GRANT authz_contextual_reader TO <your_trusted_backend_role>;
```

## Network exposure

- **OPA is the only front door** — for reads *and* writes. Neither PostgREST
  instance has per-request authn of its own; keep both on an internal network
  and expose only OPA (`:8181`).
- **Reader and writer are isolated by DB role.** The reader runs as
  `api_anon`/`authz_reader` (no write grants — structurally cannot mutate); the
  writer runs as the fixed `authz_writer` and is reachable only by OPA. A bug in
  the read policy therefore cannot escalate to a write.
- **Read-only deployments:** omit `postgrest-writer` and leave
  `POSTGREST_WRITER_URL` unset — OPA's write rule returns
  `{"allowed": false, "error": "writes_disabled"}`.
- See [ARCHITECTURE.md → Deployment View](ARCHITECTURE.md#7-deployment-view).

### Edge proxy / mTLS in front of OPA

OPA exposes plain HTTP and its `/v1/data` API reads the JWT from the request
**body** (`input.token`) — it does not consume the `Authorization` header or any
TLS client identity (that header feeds only OPA's own admin gating). For
production, put a TLS-terminating reverse proxy in front of OPA and stop
publishing OPA's port to the host, so the proxy is the only entry point.

This cleanly separates two concerns:

- **Transport / caller authentication at the edge** — TLS, and optionally
  **X.509 client certificates (mTLS)** to gate *which callers* (trusted
  PEPs/backends) may reach OPA at all. Also the place for rate limiting and IP
  allow-lists.
- **Per-user authorization in OPA** — the application JWT in the body
  (`input.token`) identifies the end user; OPA's policy decides what they may do.

A ready template is in [`gateway/nginx.conf`](../gateway/nginx.conf) (TLS +
optional mTLS → `opa:8181`). It is **default-deny**: only `/health` and the
application decision API (`POST /v1/data/authz/*`) are forwarded, so OPA's
management surface (`/v1/policies`, `/v1/config`, raw `/v1/data`,
`/v1/data/system`, `/v1/data/keys`) is unreachable through the edge — a second
layer on top of `system_authz.rego`. It is intentionally **not** wired into the
default compose — supply `server.crt`/`server.key` and a `client-ca.crt`, mount
them at `/certs`, run it in front of OPA, and remove OPA's host port. Note that
mTLS authenticates the caller, not the end user — the JWT still does per-user
authz.

## Secrets, passwords, and JWT

- Replace all `authz` dev passwords via `.env` (`PG_PASSWORD`,
  `AUTHZ_AUTHENTICATOR_PASSWORD`, `AUTHZEN_DIRECT_PASSWORD`) — see
  [Configuration](#configuration). Store secrets in your platform's secret
  manager, not in committed files.
- Configure JWT verification on OPA and the AuthZEN services: `JWKS_URL` (or
  `JWKS_FILE`), `JWT_ISSUER`, `JWT_AUDIENCE`, and optionally `REQUIRED_SCOPE`.
  See [DEVELOPMENT.md → JWT](DEVELOPMENT.md#jwt-secret--jwks).

### JWT signature verification (asymmetric / JWKS)

Real issuers sign tokens with a private key and publish the public key at a
`jwks_uri`. Each component verifies tokens independently:

**OPA verifies every token** — for reads and writes alike. The demo ships a
static `opa/data/jwks.json` ES256 key; in production point OPA at your issuer,
which can fetch and cache a remote `jwks_uri`. The AuthZEN services verify
independently via `JWKS_URL` or `JWKS_FILE`.

Because OPA fronts the writer (it forwards authorized writes to a fixed-role
writer that does **no** JWT verification of its own), there is a single place
that handles tokens and `jwks_uri` rotation — no JWKS to sync into PostgREST,
and PostgREST's inability to fetch a remote `jwks_uri` is no longer a concern.

**Write authorization** is a faithful port of the old role-claim model into OPA,
made configurable for any issuer:

- `JWT_ROLES_CLAIM` — comma-separated list of dotted paths to roles arrays;
  roles are aggregated (set-union) across all of them, default `roles`. For
  Keycloak, roles split across realm and client claims:
  `realm_access.roles,resource_access.authz-api.roles`.
- `WRITER_ROLE` — the role value that authorizes tuple writes (matched in any
  configured claim), default `authz_writer`.

OPA verifies the token, requires `WRITER_ROLE` within the configured claim, then
forwards `write`/`delete` to the writer — recording the authenticated subject as
the audit author (`performed_by`). The writer always runs as `authz_writer`
regardless of token contents, so a forged or over-scoped role claim cannot reach
admin operations. Admin/model management is intentionally **out of** the
OPA-fronted write path — perform it via a separate `authz_admin` channel.

## AuthZEN subject policy

`ALLOW_SUBJECT_OVERRIDE` controls whether a request-body subject may override
the JWT-derived subject:

- **`false` (default, token-only):** the JWT subject is authoritative; a
  differing body subject is rejected with `403`. Use this for **user-facing**
  deployments where the JWT identifies the end user.
- **`true` (trusted PEP/PDP):** the body subject is authoritative (JWT as
  fallback) — required for batch evaluations with per-evaluation subjects. Set
  this **only** when the caller is a trusted enforcement point.

The compose file defaults to `false`; the demo/test stack opts into `true`
via `env.sh`, so the shipped compose is safe to copy to production as-is.

### OPA read subject policy (`REQUIRE_TOKEN_FOR_READS`)

OPA's read/evaluation policy has the same concern: for backward compatibility it
can derive the subject from an explicit `input.subject` when no JWT is present.
`REQUIRE_TOKEN_FOR_READS` gates that:

- **`true` (default, token-only):** a request with `input.subject` but no
  `input.token` is rejected (the decision is deny). The verified JWT is the only
  trusted identity — use this whenever OPA is reachable by anything but a trusted
  PEP, since OPA's `:8181` and the public `data.authz.*` endpoints would
  otherwise let any caller ask "can subject X do Y?" for an arbitrary X.
- **`false` (trusted PEP):** explicit-subject requests are accepted. Set this
  **only** when OPA sits behind a PEP that authenticates callers and passes the
  subject (and ideally the mTLS edge, see [Network exposure](#network-exposure)).

Like `ALLOW_SUBJECT_OVERRIDE`, `compose.yml` defaults to the safe value (`true`)
and the demo opts into `false` via `env.sh`.

## Condition (ABAC) policy

Condition expressions are arbitrary SQL run in a sandbox (`_exec_condition` as
the zero-privilege `authz_eval` role). Layered defenses (in `roles.sql`):

- **Capability sandbox:** `authz_eval` has zero table/function grants — no
  data, file, or host access.
- **`statement_timeout`** on the service login roles (default `60s`) bounds
  evaluation time; a timed-out condition fails closed. **It applies to every
  statement on those connections** (checks, listings, time-travel), so size it
  above your slowest legitimate operation — set `CONDITION_STATEMENT_TIMEOUT`
  in `.env`.
- **`pg_sleep*` revoked from `PUBLIC`** so the sandbox can't hang on it.
- **Write-time validation:** a malformed condition expression is rejected at
  `INSERT`/`UPDATE`, not stored and silently denied.

Treat condition expressions as **admin-authored** (end users supply only
context *values*, passed as bound parameters — they cannot inject SQL). See
[DESIGN.md → Condition expression sandboxing](DESIGN.md#condition-expression-sandboxing).

## Replica consistency

Reads on the primary are read-your-writes (MVCC); read replicas are eventually
consistent (sub-second lag). The risk is a **stale allow after a revoke**.

- Route security-critical checks — especially the confirming check right after
  a **revoke** — to the **primary**.
- Accept bounded staleness for the high-volume common case.
- `synchronous_commit = remote_apply` makes replicas strongly consistent at a
  write-latency cost.

A practical way to operationalise this is to classify each decision and pin its
read path:

| Decision class | Examples | Read path |
|---|---|---|
| **Critical** | revoke admin, payment approval, the confirming check after a write | **Primary** (read-your-writes) |
| **Normal** | viewing a document, listing resources | Replica or embedded read-only engine (bounded staleness) |
| **Analytical** | access reviews, historical / audit reporting | Dedicated replica |

Application roles should get only runtime reader/writer roles; model
administration, condition management, and namespace grants belong to a separate
control plane (`db/security/roles.sql`).

There is no revision-token (zookie) API; see
[ARCHITECTURE.md → Consistency tokens](ARCHITECTURE.md#consistency-tokens-zookies-why-not-yet)
and the README "Consistency model" section.

## Audit retention

The audit trail (`tuples_audit`) is monthly `RANGE`-partitioned; model and
condition history (`models_audit`, `conditions_audit`) are append-only logs.

- **Create partitions ahead of time.** Schedule
  `SELECT authz.ensure_audit_partitions()` (e.g. a nightly cron or `pg_cron`)
  so rows always land in a real monthly partition, not the default fail-safe
  partition.
- **Retention is a cheap partition drop:** `DROP TABLE authz.tuples_audit_YYYY_MM`
  (or `DETACH` + archive) for months past your retention window.
- The audit trail is append-only (a trigger blocks `UPDATE`/`DELETE` outside
  the sanctioned maintenance window). `delete_store(..., p_purge_audit => true)`
  removes a store's audit rows.

See [DEVELOPMENT.md → Audit partition maintenance](DEVELOPMENT.md#audit-partition-maintenance).

## Further reading

- [ARCHITECTURE.md](ARCHITECTURE.md) — security model (defense in depth),
  deployment topologies, decision records
- [DEVELOPMENT.md](DEVELOPMENT.md) — JWT/PostgREST setup, partition
  management, operational tasks
- [DESIGN.md](DESIGN.md) — design rationale (sandboxing, reverse expansion,
  transactional versioning)
