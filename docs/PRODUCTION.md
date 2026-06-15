# Production Hardening

A checklist and role-recipe guide for running pgauthz outside the demo. The
demo defaults favor convenience; this page is what to change before exposing
the engine to real traffic. Deeper background is in
[ARCHITECTURE.md](ARCHITECTURE.md) (security model, deployment topologies),
[DEVELOPMENT.md](DEVELOPMENT.md) (JWT/PostgREST/operations), and
[DESIGN.md](DESIGN.md) (rationale).

## Before-production checklist

- [ ] **Change every default password.** The dev/test stack uses `authz` for
      `authz_authenticator`, `authzen_direct`, and the DB superuser. Replace
      them (`db/security/initdb`, `compose*.yml`, `env.sh`, your connection
      strings / secrets store).
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
reachable by untrusted clients:

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

- Replace all `authz` dev passwords (see the checklist). Store secrets in your
  platform's secret manager, not in compose files.
- Configure JWT verification on OPA and the AuthZEN services: `JWKS_URL` (or
  `JWKS_FILE`), `JWT_ISSUER`, `JWT_AUDIENCE`, and optionally `REQUIRED_SCOPE`.
  See [DEVELOPMENT.md → JWT](DEVELOPMENT.md#jwt-secret--jwks).

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
  above your slowest legitimate operation — tune in `roles.sql`.
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
