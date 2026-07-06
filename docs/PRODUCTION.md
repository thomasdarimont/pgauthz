# Production Hardening

A checklist and role-recipe guide for running pgauthz outside the demo. The
demo defaults favor convenience; this page is what to change before exposing
the engine to real traffic. Deeper background is in
[ARCHITECTURE.md](ARCHITECTURE.md) (security model, deployment topologies),
[DEVELOPMENT.md](DEVELOPMENT.md) (JWT/operations), and
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
      `AUTHZEN_DIRECT_PASSWORD`, `PGAUTHZD_RW_PASSWORD`. The service-role
      passwords are applied at first DB init, so set them before the first
      `./init.sh` (to change them later: `docker compose down -v && ./init.sh`).
- [ ] **Never host-expose pgauthzd's internal callback listeners.** pgauthzd is
      the external front door; the read callback runs a full reader role and the
      write callback runs as `authz_writer`, and both are reached **only** by
      OPA's callback (service token + optional mTLS, no host port). See
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
      `JWT_AUDIENCE`) for OPA and the AuthZEN services. The AuthZEN services can
      trust several issuers at once via `JWT_ISSUERS` (JSON array of
      `{issuer, audience, jwks_url|jwks_file}`; the token's `iss` selects the
      validator — legacy single-issuer envs still work).
- [ ] **Bind every issuer to its stores and roles** (multi-tenant AuthZEN).
      An issuer without a `stores` binding can reach **every** store; without a
      `db_roles`/`client_db_roles` binding it can claim any reader role. Set
      the bindings per issuer in `JWT_ISSUERS` and enforce completeness with
      `REQUIRE_STORE_BINDING=true` and `REQUIRE_DB_ROLE_BINDING=true` — the
      service then refuses to start with an unbound issuer instead of running
      unrestricted. See [authzen/README.md → Multi-Store](../authzen/README.md).
- [ ] **Configure per-app DB roles on both AuthZEN services** (multi-tenant).
      Both services enforce database-level per-application namespace isolation
      on reads: `pgauthzd-decision` assumes the derived role itself
      (`DB_ROLE_CLAIM` / `CLIENT_DB_ROLES` → `SET LOCAL ROLE`), and
      `pgauthzd-opa` forwards it to OPA (`input.db_role`), which passes it to
      the pgauthzd read callback as `X-Authz-Role`; pgauthzd validates it and
      `SET LOCAL ROLE`s to it for the request. For the OPA path, also set
      `DB_ROLE_CLAIM` on the **OPA**
      service so token-mode requests derive the role from verified claims.
      With no role configured, reads run as the fixed full-reader role.
- [ ] **Gate the AuthZEN reverse-search endpoints.**
      `search/subject|resource|action` enumerate the access graph ("who can
      access X?"), which is strictly more than "can *I* access X?". Set
      `SEARCH_REQUIRED_ROLE` (with `JWT_ROLES_CLAIM` for the claim paths) so only
      auditor-grade callers may use them; left unset, search is open to any
      authenticated caller.
- [ ] **Schedule audit-partition maintenance and retention.** See
      [Audit retention](#audit-retention).
- [ ] **Schedule `cleanup_expired_tuples` if you use tuple expiry.** Expired
      grants stop granting instantly (RLS-enforced) but occupy storage until
      garbage-collected; the cleanup is audited and time-travel stays exact.
      A daily run with a small grace (e.g. `SELECT
      authz.cleanup_expired_tuples(NULL, '1 day')`) keeps recent expiries
      inspectable in the live table.
- [ ] **Tune the condition `statement_timeout`** for your slowest legitimate
      operation. See [Condition (ABAC) policy](#condition-abac-policy).
- [ ] **Decide your replica-consistency policy** (which checks must hit the
      primary). See [Replica consistency](#replica-consistency).
- [ ] **Run >= 2 database instances and pick a failover RPO.** Automatic
      failover needs a standby; synchronous replication avoids losing an acked
      grant/revoke. Ensure clients retry writes during promotion. See
      [High availability & failover](#high-availability--failover-the-write-path).
- [ ] **Review namespace grants.** If you use namespaces, grant
      `namespace_access` per type so reads/writes are scoped. For per-app
      isolation over the pgauthzd write path, issue per-app DB roles and set
      `DB_ROLE_CLAIM` (pgauthzd validates the role and `SET LOCAL ROLE`s to it
      per request) — see [DEVELOPMENT.md → Per-app namespace isolation](DEVELOPMENT.md#per-app-namespace-isolation-over-the-pgauthzd-write-path).

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
| `authz_owner` | owns the schema + objects (definer context) | — |
| `authz_eval` | **zero grants** — the condition-evaluation sandbox | — |

**Connection (LOGIN) roles** — what each component authenticates as:

| Component | Connects as | Effective role(s) | Notes |
|---|---|---|---|
| pgauthzd-decision (Go, :8090, `decision-only`) | `authzen_direct` | inherits `authz_reader` (optional `SET LOCAL ROLE` to a per-app role) | Read-only front door; direct pgx, no OPA. Dedicated non-superuser login. |
| pgauthzd-opa (Go, :8091, OPA-fronted — `OPA_URL` set) | `authzen_direct` | `authz_reader` default (`SET LOCAL ROLE` per-app) | Front door that consults its OPA sidecar; also hosts the internal read callback OPA calls back into for the graph. |
| pgauthzd-full write callback (internal, `full`) | `pgauthzd_rw` | inherits `authz_writer` (per-app `SET LOCAL ROLE`) | Writer instance; applies writes natively via pgx (no authenticator / `SET ROLE` dance — it connects directly as its writer role). The **callback listener** does no JWT verification of its own — it trusts OPA (its upstream policy sidecar) over the shared service token + `X-Authz-Role`. Internal-only, no host port. (pgauthzd is the external front door; its `/pgauthz/v1/write` API validates the JWT + writer role.) |
| Backend writers (your app) | a login role granted `authz_writer` (or the writer API with a `role=authz_writer` JWT) | `authz_writer` | |
| Admin tooling | a login role granted `authz_admin` | `authz_admin` | Store/model/namespace changes. |

**When to grant `authz_contextual_reader`.** Contextual-tuple checks let the
caller inject the very grant being tested, so the privilege is separate. Grant
it **only** to a trusted PDP/backend role that constructs contextual tuples
from legitimate request context — e.g. a backend that already authenticates
its callers. **Never** grant it to `authz_reader`, `authzen_direct`, or any role
reachable by untrusted clients. Set `AUTHZ_CONTEXTUAL_READER_GRANTEE` in `.env`
and `init.sh` applies the grant, or do it manually:

```sql
GRANT authz_contextual_reader TO <your_trusted_backend_role>;
```

## Network exposure

- **pgauthzd is the external front door** — for reads *and* writes; it validates
  the JWT. OPA is an **internal policy sidecar** reachable only by pgauthzd (and
  pgauthzd's own callback listeners, which OPA calls back into, have no host
  port). Expose pgauthzd's front-door ports; keep OPA and the callback listeners
  on an internal network. An external Nginx/LB may front pgauthzd itself.
- **Read and write callbacks are isolated by DB role.** The read callback runs a
  read-only role (`authz_reader`; no write grants — structurally cannot mutate);
  the write callback runs as `authz_writer` and is reachable only by OPA's
  callback. A bug in the read policy therefore cannot escalate to a write.
- **Read-only deployments:** omit the `full`/writer instance and leave
  `NATIVE_WRITE_URL` unset — OPA's write rule returns
  `{"allowed": false, "error": "writes_disabled"}`.
- See [ARCHITECTURE.md → Deployment View](ARCHITECTURE.md#7-deployment-view).

### Edge proxy / mTLS

In the default topology **pgauthzd is the front door** and OPA is an internal
sidecar — clients never reach OPA directly, so **stop publishing OPA's port to
the host** and keep it on an internal network. Front **pgauthzd** with a
TLS-terminating reverse proxy / load balancer for transport security at the edge.

The proxy template below (in `gateway/`) is for the optional/legacy topology that
exposes OPA's decision API directly: OPA serves plain HTTP and its `/v1/data` API
reads the JWT from the request **body** (`input.token`) — it does not consume the
`Authorization` header or any TLS client identity (that header feeds only OPA's
own admin gating). The same TLS / mTLS pattern also protects the internal
pgauthzd↔OPA↔callback hops (prefer mesh-provided mTLS, or the callback listeners'
built-in `INTERNAL_TLS_*` options, where available).

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
  `AUTHZEN_DIRECT_PASSWORD`, `PGAUTHZD_RW_PASSWORD`) — see
  [Configuration](#configuration). Store secrets in your platform's secret
  manager, not in committed files.
- Configure JWT verification on OPA and the AuthZEN services: `JWKS_URL` (or
  `JWKS_FILE`), `JWT_ISSUER`, `JWT_AUDIENCE`, and optionally `REQUIRED_SCOPE`.
  See [DEVELOPMENT.md → JWT](DEVELOPMENT.md#jwt-secret--jwks).

### JWT signature verification (asymmetric / JWKS)

Real issuers sign tokens with a private key and publish the public key at a
`jwks_uri`. Each component verifies tokens independently:

**pgauthzd verifies the JWT** — for reads and writes alike; it is the front
door. Multi-issuer via `JWT_ISSUERS` (the token's `iss` selects the validator;
legacy single-issuer `JWKS_URL`/`JWKS_FILE` still work), so `jwks_uri` rotation
lives in one place. When policy enrichment is enabled (`OPA_URL` set), pgauthzd
forwards the verified token to OPA (`FORWARD_TOKEN_TO_OPA`) and OPA re-validates
it — defense in depth. The demo ships a static `opa/data/jwks.json` ES256 key;
in production point pgauthzd (and OPA, when enriching) at your issuer's remote
`jwks_uri`.

Because pgauthzd is the single front door that validates tokens — and the
internal **write callback** trusts OPA over the shared service token, doing
**no** JWT verification of its own — there is one place that handles tokens and
`jwks_uri` rotation.

**Write authorization.** pgauthzd's writer is the front door: it validates the
JWT + writer role itself and applies the write via pgx — no OPA on the write
path. (With the opt-in OPA overlay, the equivalent write policy-as-code is OPA's
`write.rego`.) The role-claim model is configurable for any issuer:

- `JWT_ROLES_CLAIM` — comma-separated list of dotted paths to roles arrays;
  roles are aggregated (set-union) across all of them, default `roles`. For
  Keycloak, roles split across realm and client claims:
  `realm_access.roles,resource_access.authz-api.roles`.
- `WRITER_ROLE` — the role value that authorizes tuple writes (matched in any
  configured claim), default `authz_writer`.

OPA (the write-authz decision) requires `WRITER_ROLE` within the configured
claim and authorizes `write`/`delete` — the authenticated subject is recorded as
the audit author (`performed_by`). The writer always runs as `authz_writer`
regardless of token contents, so a forged or over-scoped role claim cannot reach
admin operations. Admin/model management is intentionally **out of** the
write path — perform it via a separate `authz_admin` channel.

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

**Avoiding `false` altogether with token-forwarding.** When the PEP in front of
OPA is `pgauthzd-opa`, prefer `FORWARD_TOKEN_TO_OPA=true` on it: the service then
forwards the verified bearer token to OPA as `input.token`, OPA re-validates it,
and `REQUIRE_TOKEN_FOR_READS` can stay **`true`** — no tokenless subject-trust
anywhere (defense in depth; the playground stack runs this way). The tokenless
`false` mode remains necessary only for trusted PEPs that evaluate access for
**arbitrary subjects** on behalf of others (there is no token for "can *bob*
read this?" when *alice's* service asks).

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
- **Context size cap:** a request/stored context JSONB larger than
  `authz._max_context_bytes()` (default **256 KiB**) is rejected before
  evaluation with a clear error, bounding memory pressure from an oversized
  context. Tune per session/database via the GUC, e.g.
  `ALTER DATABASE authz SET authz.max_context_bytes = '524288';`.
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
  write-latency cost — see the next section for the shipped setup.

A practical way to operationalise this is to classify each decision and pin its
read path:

| Decision class | Examples | Read path |
|---|---|---|
| **Critical** | revoke admin, payment approval, the confirming check after a write | **Primary** (read-your-writes) |
| **Normal** | viewing a document, listing resources | Replica or embedded read-only engine (bounded staleness) |
| **Analytical** | access reviews, historical / audit reporting | Dedicated replica |

Application roles should get only runtime reader/writer roles; model
administration, condition management, and namespace grants belong to a separate
control plane (`db/security/roles.sql`). Product teams adding their own OPA
policies on top of the platform stack: see
[opa/README.md → Product-team policies](../opa/README.md#product-team-policies-platform-engineering-model)
(per-team packages + the `system_authz.rego` allowlist as the review
choke-point, or team-owned sidecar OPAs against the decision API).

There is no revision-token (zookie) API; see
[ARCHITECTURE.md → Consistency tokens](ARCHITECTURE.md#consistency-tokens-zookies-why-not-yet)
and the README "Consistency model" section.

### Strict revocation: synchronous apply on the write path

The pgauthzd `full`/writer instance connects with
**`synchronous_commit = remote_apply`** (connection-scoped in its
`DATABASE_URL`; Helm: `writer.synchronousCommit`). With `synchronous_standby_names`
configured, a grant/revoke is only **acknowledged once every synchronous
standby has applied it** — after the ack, no replica in the set can serve a
stale allow. Without synchronous standbys it is a no-op. In one sentence:
*"revoked" is only reported once it is true everywhere reads are served — and
only replicas where that is guaranteed may serve reads.*

Operational contract (decide these explicitly, don't discover them in an
incident):

- **The invariant:** every replica serving reads must be in the synchronous
  set. Platform readiness ("is it up") does NOT imply caught-up — a replica
  evicted from the sync set must simultaneously stop receiving read traffic
  (lag-gated `-ro` membership), or choose `required` durability so writes
  block instead.
- **When a sync standby doesn't answer, the commit BLOCKS** (indefinitely —
  that blocking is the fail-closed behavior). The dangerous paths are the
  silent ones: a **client cancel** leaves the transaction *committed locally*
  ("canceling wait … transaction has already committed locally") and
  replicating asynchronously — surface it as "revocation pending", never as
  success or failure; and a **quorum shrink without read eviction** reopens
  the stale-allow hole.
- **Per-write consistency modes.** The connection default is the *policy*;
  individual writes override it via the `consistency` field on the write request,
  which pgauthzd maps to a per-transaction `SET LOCAL synchronous_commit`:
  `applied` (remote_apply — strict revocation) · `durable` (flushed on sync
  standbys) · `eventual` (primary-only; the opt-down for bulk/latency-tolerant
  grants). Unknown values fail closed. Direct-SQL callers do the same with
  `SET LOCAL synchronous_commit = …` in their own transaction. Keeping the
  default at `remote_apply` means a *forgotten* mode yields a slow write, not
  a silent stale-allow window — secure by default, fast by explicit opt-down.
- **Bulk loads / imports** should bypass the wait: run them on a separate
  channel (direct SQL) with `synchronous_commit = local`, or send
  `consistency: "eventual"` through the write API.
- **Caches — the end-to-end staleness bound.** `remote_apply` bounds *database*
  staleness, not the OPA decision cache above it. After an acknowledged revoke,
  the worst-case window in which a stale allow can still be served is:
  `replication staleness (0 on the synchronous set with remote_apply) + the
  decision-cache TTL for that (store, object type)`. Choose TTLs per object
  type with that formula in mind (`CACHE_TTL_SECONDS` — sensitive types can run
  at `0`), and for individual revocation-sensitive checks bypass the
  cache for that one decision: `"no_cache": true` on the OPA read input, or
  the standard `Cache-Control: no-cache` header on the AuthZEN API. Cache entries are keyed on the full request (store, subject,
  per-app role header included), so the TTL bounds only *temporal* staleness —
  never cross-tenant or cross-role reuse. Revision-keyed cache entries (a
  store watermark in the key, invalidated via the watch changefeed) are the
  roadmap refinement for high-TTL deployments.

The scaling suite carries the regression test: a revoke acknowledged under
`remote_apply` is denied on the replica immediately, over repeated
grant/revoke cycles (`tests/test-scaling.sh`).

## High availability & failover (the write path)

[Replica consistency](#replica-consistency) is about the **read** path; this is
about keeping **writes** available when the primary dies. pgauthz is
**single-primary** — PostgreSQL has no native multi-master, so a hot standby is
read-only *until it is promoted*. High availability here means **automatic
failover** (promote a standby to primary), not two simultaneously-writable nodes.

On the Helm/CloudNativePG deployment this is **already handled** when
`database.instances >= 2`:

- CNPG monitors the primary and, on failure, **promotes the most-advanced
  standby** and **repoints the `-rw` Service** to it.
- Everything that writes connects to that `-rw` name — the migrations Job and
  the pgauthzd `full`/writer instance — so after failover they reconnect to the
  **same DNS name** and land on the new primary. No redeploy, no config change.
- The `-ro`/`-r` read Services drop the dead node from rotation automatically.

**The application must retry writes.** During the promotion window (seconds to
tens of seconds) the old primary is gone and the new one is not yet writable, so
in-flight writes fail. Clients should retry on connection drop / `57P01`
(admin shutdown) / `25006` (read-only transaction — seen briefly mid-promotion).
pgauthz writes are retry-friendly: `write_tuples_checked` uses optimistic
concurrency / preconditions, so a retried conditional write re-validates rather
than blindly double-applying.

### Data-loss guarantee (RPO): synchronous vs. asynchronous

Failover *promotes* a standby; whether the promoted node has **all** acknowledged
commits depends on the replication mode:

| Mode | On primary failure | Write cost | Chart setting |
|---|---|---|---|
| **Asynchronous** (default) | commits not yet shipped to a standby are lost (small RPO > 0) | none | `database.replication.synchronous.enabled: false` |
| **Synchronous** | an acked commit is guaranteed on a standby → **RPO 0** | each commit waits for a standby ack | `enabled: true` (see [`values-ha.yaml`](../deploy/helm/pgauthz/values-ha.yaml)) |

For an **authorization** store, losing an acknowledged grant/revoke on failover
can resurrect a revoked permission, so **synchronous replication is the
conservative choice**. With `instances: 3` and `maxSyncReplicas: 1`, a commit
waits for **any 1 of the 2 standbys** → RPO 0, and a single node loss still
leaves a sync candidate so writes keep flowing. `minSyncReplicas: 0` keeps writes
available (async fallback) if **all** standbys are down; set it to `1` for
**strict** RPO 0 (writes block rather than ack un-replicated data) — an
availability-vs.-zero-loss choice for your environment. Equivalent on a
hand-rolled cluster: `synchronous_commit = remote_apply` /
`remote_write` + `synchronous_standby_names`.

> Failover and backups are complementary: failover survives **node loss**,
> continuous backups (`database.backup` / Barman, or external WAL archiving)
> survive **corruption and operator error**. Run both. The memo's per-session
> temp tables and the audit log need no special handling — connections re-open
> against the new primary and rebuild session state; audit partitions stream
> across with the rest of the data.

**Run a failover game-day** before you rely on it — verify auto-promotion, the
`-rw` repoint, and that an acked write survives (RPO 0). The chart README has a
copy-paste drill (planned `cnpg promote` switchover and an unplanned
pod-kill, plus the single-node-k3d stuck-`Terminating` gotcha): see
[deploy/helm/pgauthz/README.md → Testing failover](../deploy/helm/pgauthz/README.md#testing-failover-game-day).

## Reference configuration: single region, multi-AZ (SaaS)

The validated sweet spot — one region, instances spread across 3
availability zones, strict revocation, zero-RPO failover. Concrete Helm
setup:

```yaml
# values-prod-multiaz.yaml (layer on values.yaml + values-ha.yaml)
database:
  instances: 3                       # 1 primary + 2 standbys, one per AZ
  affinity:                          # spread across zones (AZ loss ⇒ 1 instance)
    enablePodAntiAffinity: true
    topologyKey: topology.kubernetes.io/zone
    podAntiAffinityType: required
  replication:
    synchronous:
      enabled: true
      maxSyncReplicas: 2             # BOTH standbys ack ⇒ every serving
                                     # replica is guaranteed (all-serving sync)
      minSyncReplicas: 1             # keep RPO 0 even with one standby down
  # backup: ...                      # always pair HA with backups

writer:
  synchronousCommit: remote_apply    # (default) strict revocation on ack
```

Why these choices, and what they give you:

- **`maxSyncReplicas: 2` (= all standbys) rather than 1.** With `ANY 1`
  quorum, the acking standby varies per commit — neither replica is
  individually guaranteed, so strict reads would have to hit the primary.
  With **both** standbys synchronous, every `-ro` member is covered: the
  `serving(-ro) ⊆ sync set` invariant holds **by construction**. In-region
  AZ round-trips are ~1 ms, so the write-latency cost is negligible —
  this trade only gets hard across regions.
- **Self-enforcing invariant.** With all standbys sync + `remote_apply`,
  an alive-but-lagging replica **blocks revokes** (visible, pageable)
  instead of silently serving stale allows; a *dead* replica drops out of
  both the sync set and `-ro` via readiness. The dangerous
  quorum-shrink-while-still-serving gap doesn't exist in this shape.
- **`minSyncReplicas: 1`** keeps writes flowing (still RPO 0) when one
  standby is down; set `2` if you prefer revokes to block until full
  redundancy is restored.
- **Stateless tier per AZ.** Run ≥ 2 replicas of pgauthzd (reader/writer/
  AuthZEN) + OPA spread across zones (standard deployment spread). Reads via the
  `-ro` Service cross AZs freely (~1 ms); if you want AZ-local reads, set
  the Service's `trafficDistribution: PreferClose` (K8s ≥ 1.31).
- **Write path** stays on the global `-rw` name — CNPG repoints it on
  failover (validated ~5 s switchover); clients retry per the
  [HA section](#high-availability--failover-the-write-path).
- **Per-write modes** ride on top: `consistency: eventual` for bulk
  imports/latency-tolerant grants, the `applied` default for everything
  else. OPA's decision cache stays at a small TTL
  (`DEFAULT_CACHE_TTL_SECONDS`); revocation-sensitive checks bypass it.

Failure drill this configuration survives (test it, don't trust it):
kill any single instance or a whole AZ → automatic promotion / continued
service, RPO 0, and no window in which a serving replica returns a
revoked permission.

### Variant: on-prem datacenter

**With three (or more) nodes — prefer this.** Three nodes give you quorum
locally: run k3s (3 control-plane nodes) + CNPG, and the
[multi-AZ reference configuration](#reference-configuration-single-region-multi-az-saas)
applies verbatim with `topologyKey: kubernetes.io/hostname` instead of the
zone key — `instances: 3`, both standbys synchronous, **safe automatic
failover** (the third node is the tiebreaker; no split-brain, no human in
the loop), validated ~seconds switchover semantics. If you can rack a third
node — even a modest one — this is strictly better than the two-node
variant below.

**With exactly two nodes:** primary + full stateless tier on node 1, synchronous standby +
stateless tier on node 2; a VIP (keepalived) or LB in front of OPA/AuthZEN.
Reads are node-local; writes cross to the primary. The consistency story
*simplifies* here: with one standby, `maxSyncReplicas: 1` makes it the entire
sync set (the serving ⊆ sync-set invariant holds by construction), an
alive-but-lagging standby **blocks revokes visibly**, and a *dead* standby
serves nothing — so `minSyncReplicas: 0` (async fallback) has no stale-allow
hole on this shape.

**Failover is operator-driven — deliberately.** Two nodes cannot distinguish
"peer died" from "link died"; automatic promotion without a third-party
witness eventually split-brains, and two primaries accepting authz writes is
the worst failure an authorization store can have. Monitoring alerts, a human
decides. (Want automatic? Add a small witness node — even a VM elsewhere —
and run k3s + CNPG or Patroni + etcd with three control-plane members; then
the multi-AZ reference config applies with
`topologyKey: kubernetes.io/hostname`.)

**Promotion runbook** (the three easy-to-miss steps are marked ⚠):

1. **Verify, don't guess:** confirm the primary is actually dead
   (`pg_isready` from *both* the standby and a third vantage point if you
   have one), not just unreachable from one side.
2. ⚠ **Fence the old primary first** — stop the service / power it off /
   drop it from the VIP — *before* promoting. If it comes back writable
   later, you have two primaries.
3. **Promote:** `SELECT pg_promote();` on the standby.
4. ⚠ **Clear the sync requirement on the new primary:**
   `ALTER SYSTEM RESET synchronous_standby_names; SELECT pg_reload_conf();`
   — the new primary has no standby yet, and with sync names set + the
   writer's `remote_apply`, **every write would block** until the peer
   rejoins. (Window is safe: the only replica is down, nothing can serve
   stale reads.)
5. **Repoint writes:** flip the VIP / the `authz-primary` DNS or network
   alias so the writer's `DATABASE_URL` resolves to the new primary.
   pgauthzd reconnects on its own; clients retry per the
   [HA section](#high-availability--failover-the-write-path).
6. ⚠ **Rejoin the old node as the new standby — never restart it as-is:**
   its timeline has diverged (it may hold *unacked* local commits — losing
   those is correct, they were never acknowledged). Fast path
   `pg_rewind --target-pgdata=... --source-server=...`; the always-works
   path is a fresh `pg_basebackup` clone. Then restore
   `synchronous_standby_names` on the new primary and confirm
   `pg_stat_replication.sync_state = 'sync'` — the strict-revocation
   guarantee is back.

**What monitoring must alert on** (each maps to a runbook step):
primary down (`pg_isready`), standby down or `pg_stat_replication` empty on
the primary, replication lag above threshold, and **commits blocked in sync
wait** (`pg_stat_activity.wait_event = 'SyncRep'`) — that last one is the
lagging-standby-blocks-revokes signal, which is the guarantee working as
designed, but an operator needs to know.

**RPO note:** with `remote_apply`, no *acknowledged* grant/revoke is ever
lost in this flow — the standby had applied everything acked before it could
be promoted. In-flight writes that were never acked may be lost; that is the
contract.

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
- **Retire stores; don't delete them, where audit history matters.** Use
  `authz.retire_store('mystore')` — a soft-delete that drops only the live
  tuples (reclaiming their partitions) and marks the store retired
  (`stores.deleted_at`), while **keeping** its dictionary
  (`types`/`relations`/`models`/`conditions`) and full audit log. The
  historical API (`audit_check_access`, `audit_list_*`) still resolves a retired
  store **by name**, so "could user X do Y at time T?" keeps working long after
  it stops serving live checks; the live APIs reject it, and its name stays
  reserved (no by-name ambiguity with the preserved history). Retirement is a
  **metadata operation** — it drops partitions (DDL) and writes the `deleted_at`
  marker, so it stays cheap (`O(partitions)`) and generates **no** per-tuple
  audit rows even for a store with millions of tuples; time-travel as of `>=`
  the retirement instant denies everything, and earlier instants resolve from
  the kept history.
- **Audit timestamps are *effective transaction* timestamps, not commit
  timestamps.** Every audit event (and the `deleted_at` retirement marker) is
  stamped with `transaction_timestamp()` — the time the writing transaction
  *started*, not when it committed and became visible. This is deliberate (every
  change in one transaction shares one instant, so time-travel sees a
  transaction's effect atomically), but it means a long-running transaction's
  recorded "instant" can precede the moment its changes actually became visible.
  Treat the audit clock as an effective-transaction-time ordering, not an
  authoritative commit-time one. (A future monotonic per-store revision counter
  would give a cleaner total order; see the roadmap.)

  `delete_store` is the *physical* removal (right-to-be-forgotten / erasure)
  path: it drops the dictionary rows, so even with audit rows preserved
  (`p_purge_audit => false`) their `store_id` / `object_type` / `relation` IDs
  become name-unresolvable and the historical API can no longer query that
  store. Reserve it for non-audited / test stores or deliberate erasure; a
  retired store can later be purged with `delete_store` when its retention
  window expires.

See [DEVELOPMENT.md → Audit partition maintenance](DEVELOPMENT.md#audit-partition-maintenance).

## Scale & supported limits

pgauthz targets **bounded** relationship graphs with a fairly fixed set of
models. Know these limits before sizing a deployment:

- **Identifier space (`integer`).** Stores, types, relations, models, and
  conditions use `integer GENERATED ALWAYS AS IDENTITY` keys (≈**2.1 billion**).
  IDENTITY **never reuses** a value, so the bound is on the *cumulative number
  ever created*, not the live count — but at 2.1 B that is not a practical limit
  even for churny environments that create-and-delete many stores/types/relations
  over time. (These IDs were `smallint`, capped at 32,767, before **v0.2.0**;
  widening to `integer` is a breaking re-baseline — see the CHANGELOG.)
- **Partition growth.** `authz.tuples` has one LIST partition per object *type*
  (hash sub-partitioned for high-cardinality types); `authz.tuples_audit` has one
  RANGE partition per month. Both grow the partition/catalog count — keep the type
  count bounded and prune old audit partitions (above). Thousands of partitions
  are fine; tens of thousands begin to pressure planning and the catalog.
- **Search result size.** `check_access` is bounded by graph depth/fan-out;
  `list_objects` / `list_subjects` are bounded by the **reachable set**, not the
  store size (see [BENCHMARKS.md](BENCHMARKS.md)). A query whose answer is large
  (e.g. a document readable by a whole org) is correspondingly expensive —
  paginate, and route large listings to a dedicated replica.
- **Tuple volume / concurrency — not yet measured.** Published benchmarks cover
  tens of thousands of tuples on a laptop. Capacity at 1M–100M tuples, under
  concurrent reads/writes, cold cache, skewed fan-out, and replica failover is
  **not yet characterized** — validate against your own data shape before relying
  on it at scale.

## Upgrades & migrations

Schema **structure** is versioned as forward-only migrations in `db/migrations/`,
applied by `sqlx migrate run` and tracked in `public._sqlx_migrations`; engine
**code** (functions/views/triggers) is idempotent and reloaded on top. There is
no `DROP SCHEMA` install path — installing and upgrading are the same operation
(only pending migrations run). See
[ADR 0001](adr/0001-schema-migrations.md).

- **Take a backup before upgrading.** Migrations are forward-only — there are no
  `down` scripts. Rollback = restore from backup / PITR. A logical
  `pg_dump -n authz` (or your usual base backup + WAL) immediately before
  applying a new release is the supported rollback path.
- **`public._sqlx_migrations` is per-database and must not be replicated.** Each
  replica / embedded read-only engine runs its own migrations to build structure;
  publications cover only `authz.*`, so the ledger is naturally excluded — keep
  it that way.
- **Apply migrations once, ahead of code.** On CloudNativePG the migration image
  ([`deploy/migrations/`](../deploy/migrations/)) does `sqlx migrate run` then
  loads the engine code in a single `SET ROLE authz` session; run it from an
  install/upgrade hook (it is safe to re-run — idempotent).
- A structural change requiring `CREATE INDEX CONCURRENTLY` (to avoid locking a
  large `authz.tuples`) ships as a `-- no-transaction` migration; schedule those
  during low-write windows.

## Further reading

- [ARCHITECTURE.md](ARCHITECTURE.md) — security model (defense in depth),
  deployment topologies, decision records
- [DEVELOPMENT.md](DEVELOPMENT.md) — JWT setup, partition
  management, operational tasks
- [DESIGN.md](DESIGN.md) — design rationale (sandboxing, reverse expansion,
  transactional versioning)
