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
- [ ] **Never host-expose the read PostgREST (`api_anon`).** `api_anon` is a
      full reader; OPA is the mandatory front door. Only OPA (and the Nginx
      writer gateway) should reach PostgREST. See [Network exposure](#network-exposure).
- [ ] **Decide the AuthZEN subject policy.** Keep `ALLOW_SUBJECT_OVERRIDE=false`
      (token-only) unless the caller is a trusted PEP. See [AuthZEN subject policy](#authzen-subject-policy).
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
      `namespace_access` per type so reads/writes are scoped.

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
| PostgREST writer (:3001, behind Nginx) | `authz_authenticator` | `SET ROLE` → `authz_writer` / `authz_admin` (from the JWT `role` claim) | Only `POST /rpc/*` is forwarded by the gateway. |
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

- **OPA is the only front door for reads.** The reader PostgREST (`api_anon`)
  must not be reachable from the network — it has no per-request authn of its
  own. Keep it on an internal network; expose only OPA (`:8181`).
- **The writer is fronted by the Nginx gateway**, which forwards only
  `POST /rpc/*` and returns a generic 404 for everything else (no schema
  leakage). The writer PostgREST itself is not host-exposed.
- See [ARCHITECTURE.md → Deployment View](ARCHITECTURE.md#7-deployment-view).

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

- **OPA** and the **AuthZEN services** verify against a JWKS (the demo ships a
  static `opa/data/jwks.json` ES256 key). In production, point them at your
  issuer — OPA can fetch and cache a remote `jwks_uri`; the AuthZEN services
  take `JWKS_URL` or `JWKS_FILE`.
- The **PostgREST writer** verifies the token itself (to map the Postgres role
  from a JWT claim). It uses a **static** JWK/JWKS via `PGRST_JWT_SECRET`
  (`@/path/to/jwks.json` or the JSON inline) — the demo points it at the same
  public JWKS. **PostgREST does NOT fetch a remote `jwks_uri`**, so for a
  rotating issuer key you need one of:
  1. **Front the writer with OPA** (as the read path is) — OPA owns JWT
     verification and `jwks_uri` rotation; the writer no longer verifies JWTs.
     *Recommended* — one place handles tokens, consistent with reads.
  2. **Sync the JWKS** — a sidecar/cron fetches the issuer's `jwks_uri`, writes
     the JWKS file the writer reads, and reloads PostgREST config
     (`NOTIFY pgrst, 'reload config'`) on rotation.
- Map the writer's role from your issuer's claim with `PGRST_JWT_ROLE_CLAIM_KEY`
  (e.g. `.realm_access.roles[0]`); the token's mapped role must be one
  `authz_authenticator` may `SET ROLE` to (`authz_writer` / `authz_admin`).

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
