# Security self-audit

A first-party review of the pgauthz engine's security posture: a threat model,
the mechanisms that enforce it (verified against the code), and findings with
severities. It is **preparation for an external review, not a substitute** for
one — no independent party has attested to these claims.

- **Scope:** the SQL engine (`db/engine/`, `db/security/`, `db/migrations/`) and
  its trust boundaries, **plus** the tiers that now carry security logic: the
  AuthZEN Go services (multi-issuer routing, per-app role switching, token
  forwarding), the OPA front-door policies (public-path allowlist, read/write
  role forwarding), and the model registry. The playground BFF is reviewed as a
  dev-only tool (out of the deployable engine).
- **Method:** the original four engine passes (SECURITY DEFINER + roles; the
  condition sandbox; multi-tenant isolation; fail-closed + write validation +
  audit), plus a **2026-07 refresh** covering the surfaces added since v0.1.x:
  multi-issuer JWT routing + store/role bindings, the three `SET LOCAL ROLE`
  paths (writer + reader hooks, authzen-direct in-service), token forwarding and
  the trusted-PEP `input.db_role` path, the per-role OPA cache partitioning, the
  model registry as a cross-store propagation path, and the team-Rego governance
  chokepoint. Each finding re-verified against the source; file:line citations
  point at the current tree.
- **Date / version:** engine passes 2026-06-29 (~v0.1.4); refresh 2026-07-05
  (~v0.6); **v0.7 delta 2026-07-05** (rich decisions, native expiry, cache
  bypass, authzctl) — found one High fail-open (F11, open with a designed
  fix). This is the first non-Info finding in the engine code.
- **Companion docs:** [`SECURITY.md`](../SECURITY.md) (reporting / supported
  line), [`PRODUCTION.md`](PRODUCTION.md) (hardening), [`ARCHITECTURE.md`](ARCHITECTURE.md)
  (defense-in-depth).

## Threat model

**Assets.** The authorization tuples + models (who-can-do-what), the audit trail
(system of record), and the correctness of every decision (a wrong *allow* is
the worst outcome).

**Trust boundaries.**

```
 untrusted          trusted PEP            engine boundary
 client  ──JWT──▶  OPA  ──▶ PostgREST ──SET ROLE──▶ authz.* SECURITY DEFINER fns
                   (authn,   (api_anon /   ▲                   │ run as authz_owner
                    policy)   authz_writer,│        ┌──────────┴─────────────┐
                              or per-app   │        │ base tables (no direct │
                              role via     │        │ grant to app roles)    │
                              X-Authz-Role)│        └────────────────────────┘
                       reader + writer hooks validate: tier member, not admin
 condition expr ───────────────────────────▶ authz_eval (zero-privilege sandbox)
```

**Actors & assumed capabilities.**

| Actor | Can | Must not be able to |
|---|---|---|
| Unauthenticated client | Reach OPA only | Reach PostgREST/Postgres directly |
| Authenticated app (PEP-fronted) | Checks + writes within its store/namespace | Read/write another tenant's tuples |
| A model/condition author (admin) | Define models + conditions; publish/apply registry models | Make a condition that reads tables or runs code |
| A direct-SQL service role | Call `authz.*` for its tier | Reach base tables; widen its own grants |
| Malicious condition expression | Be evaluated | Read data, call functions, escalate, or run unbounded |
| A tenant's IdP (one of several issuers) | Mint tokens for its bound stores/roles | Access another issuer's stores or claim another tenant's DB role |

**Out of scope of the *engine*'s guarantees (deployment's job):** TLS, network
isolation of the internal tiers, JWT key management, secret rotation, restricting
superuser logins, and OPA policy correctness. These are the load-bearing
*operational* assumptions — see [Findings → Operational](#operational--deployment).

## Mechanisms (verified)

Defense-in-depth, each layer checked against the source:

1. **Function-only access; no table grants.** App roles get `EXECUTE` on the
   `authz.*` API and nothing else — no `SELECT/INSERT/...` on `authz.tuples` etc.
   (`db/security/roles.sql`; "No direct table grants" at roles.sql:201). PostgREST
   therefore cannot expose table endpoints.
2. **SECURITY DEFINER, owned by a non-superuser.** All 59 public functions are
   `ALTER … SECURITY DEFINER` (roles.sql) and owned by **`authz_owner`**,
   a `NOLOGIN` non-superuser (roles.sql ownership transfer) — a bug in a
   definer function cannot reach superuser. The `search_path` pinning (mechanism 3)
   runs dynamically over `pg_proc.prosecdef`, so the registry and reader-hook
   functions added since are covered without editing the list.
3. **search_path pinned against hijacking.** A dynamic block pins
   `search_path = pg_catalog, authz, pg_temp` on **every** `prosecdef` function
   (roles.sql:298-303), so a caller's `search_path` can't redirect name resolution
   — the classic SECURITY DEFINER attack. New definer functions are covered
   automatically (it filters `pg_proc.prosecdef`).
4. **Condition sandbox = zero-privilege role.** Condition expressions run via
   `_exec_condition`, which is **owned by `authz_eval`** (a `NOLOGIN` role with no
   table and no function grants) (conditions.sql; baseline.sql:22-28). A malicious
   SQL condition cannot `SELECT` tuples or `pg_authid`, call `pg_read_file` /
   `dblink` / `lo_*`, write, or escalate — it has no capabilities. `pg_sleep*` is
   revoked from `PUBLIC` (roles.sql:137-139), and `statement_timeout` bounds cost.
   The CEL path (`extensions/pg-cel`, Rust/pgrx) is a pure expression evaluator
   (no I/O), with non-boolean / error → deny.
5. **Fail-closed decisions.** On the decision path, `query_canceled` (timeout) is
   **re-raised** so a check can't outlive its budget, and every other error →
   `RETURN false` (deny) — `conditions.sql:140-146`. Missing rule/condition and
   NULLs resolve to deny.
6. **Bounded recursion.** Graph traversal is capped at `_max_depth()` (default 32,
   GUC `authz.max_depth`; core_internal.sql:253-255, access_internal.sql:683) with
   **cycle detection** (`v_key = ANY(p_path)` → false; access_internal.sql:704), so
   cyclic models or deep chains terminate.
7. **Store + namespace isolation.** Every query filters `store_id`
   (resolved by `_s()`); namespace-restricted types gate read/write by DB-role
   membership via `_check_namespace_access` / `pg_has_role` (core_internal.sql:179-225),
   enforced on all read and write paths. Object wildcards (`object_id='*'`) require
   an explicit `allow_object_wildcard` rule (tuples.sql:56-66); contextual ("what-if")
   tuples sit behind a separate `authz_contextual_reader` role (roles.sql:160-172).
8. **Append-only audit.** `_audit_block_dml` blocks `UPDATE`/`DELETE` on the audit
   tables unless a **transaction-local** `authz.audit_maintenance` GUC is set
   (audit_triggers.sql:88-97), which only the sanctioned partition/purge paths set
   and immediately reset. `performed_by` comes from a session var set by the API.
9. **No SQL injection surface found.** Identifiers use `%I` or are reduced to
   smallint IDs before use; literals use `%L`; partition names are
   `regexp_replace('[^a-zA-Z0-9]','_')`-sanitized; condition expressions run as data
   under the zero-privilege role. The role-switch hooks quote the requested role
   with `format('SET LOCAL ROLE %I', …)` (core_internal.sql:208, 255) and the
   AuthZEN direct backend uses `pgx.Identifier{role}.Sanitize()`
   (pgbackend/backend.go:69) — caller-derived role names are never concatenated raw.

### Multi-tenant / front-door surface (2026-07 refresh)

10. **Symmetric per-app role switching, both read and write, fail-closed.** OPA
    forwards the caller's per-app DB role as `X-Authz-Role`; the writer's
    `_pre_request` and the reader's `_pre_request_reader` (core_internal.sql)
    each validate it — the role must exist, be a member of the tier role
    (`authz_writer` / `authz_reader`), and **not** be admin-capable — then
    `SET LOCAL ROLE` (transaction-scoped, no pool leak). An unknown, over-scoped,
    or admin role raises `insufficient_privilege`. `_check_namespace_access` then
    enforces per app on both paths. `authzen-direct` applies the same discipline
    in-process (`withRole`/`checkRole`, pgbackend/backend.go).
11. **Cross-issuer isolation.** The AuthZEN services trust several issuers; the
    token's `iss` selects the validator (signature verified against *that*
    issuer's JWKS — an unknown `iss` is rejected). A verified token is then
    bound: `storeChecked` rejects a store outside the issuer's `stores`
    patterns, and `dbRoleAllowed` rejects a DB role outside its `db_roles`
    patterns — both **anchored** regexes (`^(?:…)$`, compile-checked at load),
    both `403` on violation, never a silent downgrade (handler.go, middleware.go).
    `REQUIRE_STORE_BINDING` / `REQUIRE_DB_ROLE_BINDING` turn an unbound issuer
    from a warning into a startup error.
12. **Per-role decision-cache partitioning.** OPA's read `http.send` calls carry
    the role header, and the header is part of the `force_cache` request key
    (pgauthz.rego `_read_headers`), so a cached allow for app A can never be
    served to app B — isolation holds through the cache, not just at the DB.
13. **Registry propagation is validated + admin-gated.** `apply_model` reuses the
    ordinary model API (`model_add_rule`, `create_condition` — which fires the
    write-time validation trigger), records every change to `models_audit`, and
    self-verifies by checksum after applying. `publish_model`/`apply_model` are
    `authz_admin`-only (`export_model`/status are reader). Propagated condition
    expressions still run in the zero-privilege sandbox at eval time (mechanism 4).

## Findings

Severities reflect **code-verified** impact. (Note: an initial pass over-rated the
SECURITY DEFINER-consistency item as High; verifying the function bodies showed
they only delegate, so it is Low — recorded here for transparency.)

| # | Sev | Finding | Status |
|---|---|---|---|
| F1 | Low | `check_access_with_contextual_tuples_jsonb` and `check_access_batch_typed_jsonb` were `plpgsql`, granted `EXECUTE`, but **not** `SECURITY DEFINER` — they ran as the caller, though they only `_validate_tuple_jsonb` (pure) and **delegate** to the SECURITY DEFINER variants, so there was no breakage or escalation. **Fixed:** both are now `SECURITY DEFINER` (roles.sql), so the public API is uniformly definer and they pick up search_path pinning. | ✅ Fixed |
| F2 | Low | `create_condition_sql` / `create_condition_cel` were `LANGUAGE sql` wrappers (inlined) over `create_condition` (SECURITY DEFINER). **Fixed:** marked `SECURITY DEFINER` (roles.sql) for API uniformity. | ✅ Fixed |
| F3 | Low | Partition DDL used `%s` for the (already `regexp_replace`-sanitized) table identifier — not injectable, but `%s` over a name is an anti-pattern. **Fixed:** `_ensure_tuple_partition` / `_ensure_audit_partition` now build the unqualified name and use `authz.%I` (core_internal.sql), matching `store.sql`. | ✅ Fixed |
| F4 | Info | `statement_timeout` is a **role-level** setting (roles.sql:126-127), so it bounds *all* statements, not just condition evaluation. A per-statement `SET LOCAL statement_timeout` around condition eval would isolate the budget — but adds complexity; the role-level bound is a reasonable default. | Accepted (documented in PRODUCTION.md) |
| F5 | Info | No explicit size cap on the request/stored **context JSONB** — a huge context could pressure memory before `statement_timeout` / PG limits stop it. **Fixed:** `_eval_condition` rejects a context over `authz._max_context_bytes()` (default **256 KiB**, GUC `authz.max_context_bytes`) with a clear `program_limit_exceeded` error (re-raised, not a silent deny). | ✅ Fixed |
| F6 | Info | `required_context` documents a condition's keys but is **not** enforced as an allow-list at eval time, so an expression could read other keys present in context. Matters only if an *admin* is malicious; low value vs. cost. | Won't fix (by design) |

### Refresh findings (2026-07, multi-tenant / front-door)

| # | Sev | Finding | Status |
|---|---|---|---|
| F7 | Info | **Model registry amplifies admin trust.** `apply_model` lets an admin push a model — including SQL/CEL **condition expressions** — from an authoring store to many tenant stores in one call. This grants no capability beyond `authz_admin` (publish/apply are admin-only, propagation is validated + audited + checksum-verified, and expressions still run in the zero-privilege sandbox), but the *blast radius* of a malicious or compromised admin is now fleet-wide. Treat authoring-store admin as a fleet-privileged role; immutable versions + `models_audit` give the forensic trail. | Accepted (by design; documented) |
| F8 | Info | **Trusted-PEP mode extends to `input.db_role`.** In `REQUIRE_TOKEN_FOR_READS=false` (trusted-PEP) mode, OPA honors a request-body `input.db_role` for the read role switch (pgauthz.rego:33-36) — the same trust already extended to `input.subject` in that mode. A caller reaching OPA directly could then assert any DB role, but the reader hook still fail-closes to reader-only, non-admin roles that are `GRANT`ed to the authenticator, so it cannot escalate — at most it selects another *reader* namespace. The default `REQUIRE_TOKEN_FOR_READS=true` derives the role from verified claims and ignores `input.db_role`. Keep OPA reachable only by a trusted PEP whenever this mode is on. | Accepted (mirrors `X-Authz-Role`; operational control) |
| F9 | Low | **403s echo the attempted store/role name.** The issuer-binding rejections include the requested store / DB role in the error string (handler.go, middleware.go). The caller already knows the value it sent, so this leaks nothing to *that* caller; the minor concern is these strings reaching shared logs. Optional: drop the value from the message. | Won't fix (low value) |
| F10 | Info | **Negative role-validation cache in authzen-direct.** `checkRole` caches *denied* as well as allowed results for `DB_ROLE_CACHE_TTL_SECONDS` (default 60; pgbackend/backend.go). A role newly granted its membership is not honored until the entry expires — a fail-*closed* staleness (availability, not a security gap). Unknown-role lookups are never cached. Set the TTL to `0` to re-validate every request. | Accepted (bounded; documented) |

No High/Critical **code** findings in the refresh. Cross-issuer isolation is
enforced with anchored patterns and 403-not-downgrade semantics; the two new
role-switch hooks share the writer's fail-closed discipline and identifier
quoting; registry propagation adds reach, not privilege. The engine remains
fail-closed, the privileged surface small and consistently owned, and the
condition sandbox a genuine capability sandbox.

### Delta findings (2026-07, v0.7 — rich decisions, expiry, cache bypass)

An adversarial pass over the surface added since the refresh — native tuple
expiry (`expires_at` + row-level security), `check_access_detailed` /
`allow_detailed`, the `no_cache` cache bypass, and `authzctl` — surfaced one
real fail-open in the expiry enforcement.

| # | Sev | Finding | Status |
|---|---|---|---|
| F11 | **High** | **The tuple-expiry RLS escape is a caller-settable GUC (fail-open).** Native expiry hides expired tuples via a row-level-security `SELECT` policy on `authz.tuples`; the sanctioned write/delete/cleanup paths reveal expired rows by arming a transaction-local GUC, `authz.tuples_include_expired`, that the policy honors (migration 0005). But a **custom GUC is settable by any role**, and expiry is read *inside* the `SECURITY DEFINER` functions that app roles legitimately invoke (`check_access`, `list_*`). A direct `authz_reader` connection can therefore `SET authz.tuples_include_expired = 'on'` and make **expired grants grant again** — the exact fail-open expiry was meant to prevent. No policy predicate can distinguish a legitimate arming from a forged one (at evaluation time both are "GUC on, `current_user = authz_owner`"). **Verified** with a live `SET ROLE authz_reader` reproduction (expired check flipped `false → true`). **Exploitability boundary:** *not* reachable through the OPA/PostgREST/AuthZEN front door, which exposes only RPC calls, never raw SQL — so no unauthenticated or HTTP-only caller can trigger it. It is a **direct-SQL trust-tier** hole: it matters for services that connect to Postgres directly as a reader role (`authzen-direct` → `authz_reader`, direct-SQL integrations, or a SQL-injection foothold in a reader-privileged path — none found). **Fix designed, not yet landed** (see below): the GUC escape cannot be made safe (a SET-ROLE alternative is rejected by Postgres inside `SECURITY DEFINER` functions), so the escape must become a dedicated `BYPASSRLS` role that only the sanctioned paths enter via `SECURITY DEFINER` helper functions **owned by** that role, with the policy carrying no GUC escape at all. This touches the ownership-transfer machinery (roles.sql) and the write path, so it is scoped as its own change rather than rushed. | 🔴 **Open — fix designed** |

The audit tables' analogous GUC (`authz.audit_maintenance`) is **not**
vulnerable in the same way: app roles hold no direct `UPDATE`/`DELETE` grant
on the audit tables, so even with that GUC armed they cannot issue the DML —
the function-only-access layer (mechanism 1) is the second gate that expiry
reads lack. The other v0.7 additions reviewed clean:

- **`check_access_detailed` / `allow_detailed`** run `SECURITY DEFINER`,
  reader-granted, and expose only what `explain_access` already does
  (decision reason + missing condition-context keys) — no tuple/subject
  identifiers beyond the caller's own query. The AuthZEN `X-Authz-Detail`
  path is opt-in and additive; without the header the response is the plain
  boolean.
- **`no_cache` / `Cache-Control: no-cache`** only shortens a cache TTL for
  one decision; it cannot change a decision or amplify load beyond the
  cache-busting an authenticated caller already had (F-none; documented in
  opa/README).
- **`authzctl`** is an operator/CI tool in the psql trust tier (direct DSN,
  admin for writes); it introduces no new engine surface — it drives the
  existing registry/import API. Its OpenFGA-DSL `condition` blocks are
  parsed-not-imported (vocabulary mismatch), so no untranslated CEL reaches
  the sandbox.

**Playground BFF (dev-only, out of the deployable engine).** The playground is
an opt-in overlay (`PGAUTHZ_PLAYGROUND=1`), absent from base `compose.yml` and
the Helm chart, with no host port (proxy-only) and an OIDC session on every
endpoint. It connects as a dedicated read-only `authz_metadata` role (inherits
`authz_reader` + direct `SELECT` on metadata tables only; `statement_timeout`
armed). Its one posture note (**P1, Medium if misdeployed**): with
`PLAYGROUND_EXPLORE_ENABLED=true` and **no** `PLAYGROUND_EXPLORE_ROLE`, any
authenticated user can run arbitrary-subject checks — intended for a playground,
but set `PLAYGROUND_EXPLORE_ROLE` before exposing it beyond a dev box (it stays
read-only via `authz_metadata` regardless). Don't copy `compose-playground.yml`
to production.

### Operational / deployment

These are where real compromise would come from — they are assumptions the engine
*relies on*, not flaws in it. They belong in the deploy checklist, not the code.

| Risk | Why it matters | Control |
|---|---|---|
| Internal tiers exposed (PostgREST/Postgres reachable beyond OPA) | The read API is unauthenticated (`api_anon`) by design; exposure = tuple disclosure | Network isolation / no host ports (compose & chart already do this); verify in your env |
| `X-Authz-Role` header is **trusted, not signed** (read *and* write) | Both PostgREST instances assume only OPA sets it; the `_pre_request` / `_pre_request_reader` hooks validate the role is a member of the tier role and not admin (core_internal.sql), but cannot prove OPA's authority | Keep both PostgREST instances reachable only by OPA; mTLS/network policy |
| `input.db_role` honored in trusted-PEP mode | With `REQUIRE_TOKEN_FOR_READS=false`, a caller can assert the read role (bounded to reader-only, non-admin, granted roles — see F8) | Keep the default `REQUIRE_TOKEN_FOR_READS=true`, or keep OPA reachable only by a trusted PEP |
| Issuer without a `stores` / `db_roles` binding | An unbound issuer's tokens can reach every store / claim any reader role | Set per-issuer bindings; enable `REQUIRE_STORE_BINDING` / `REQUIRE_DB_ROLE_BINDING` (startup error on an unbound issuer) |
| Model-registry authoring store is fleet-privileged | An admin on the authoring store can push models + conditions to every tenant store (F7) | Restrict `authz_admin` on the authoring store; review `models_audit` + registry versions |
| OPA compromise / wrong policy | OPA is the PEP — a bad policy or breach bypasses authn/authz. Team-added Rego packages need an explicit line in the `system_authz` public-path allowlist, so that file is the governance chokepoint | Review Rego; pin/version OPA; gate `system_authz.rego` edits in CI/CODEOWNERS; treat policies as security-critical |
| Playground deployed beyond dev | Arbitrary-subject probing if `PLAYGROUND_EXPLORE_ROLE` unset (read-only; P1) | Keep it opt-in/dev-only; set `PLAYGROUND_EXPLORE_ROLE`; never host-expose |
| `authz_contextual_reader` granted too broadly | "What-if" tuple injection can probe for unpublished grants | Grant only to trusted backends (default: not granted to `api_anon`/`authz_reader`) |
| Dev secrets shipped (`authz` passwords, `opaAdminToken`) | Defaults are DEV ONLY | Override every secret; use a secret store (see PRODUCTION.md) |
| Superuser can bypass audit triggers | `session_replication_role` defeats any trigger (inherent to PostgreSQL) | Restrict superuser logins administratively |
| **A direct reader can bypass tuple expiry (F11)** until the fix lands | `SET authz.tuples_include_expired='on'` reveals expired grants — but only over a direct SQL connection as `authz_reader`, never through OPA/PostgREST | Do not expose a direct reader connection beyond trusted services; the front door is unaffected. Fix tracked below |

## Hardening checklist

Deploy-time (most are in [`PRODUCTION.md`](PRODUCTION.md) — this cross-checks them):

- [ ] PostgREST (read + write) and Postgres have **no host ports**; only OPA is reachable.
- [ ] Every secret overridden; `opa.requireTokenForReads=true` unless a trusted PEP fronts reads.
- [ ] `authz_contextual_reader` granted only to trusted services (and only if used).
- [ ] JWT verified against your IdP's JWKS; role claim (`DB_ROLE_CLAIM`) mapping reviewed.
- [ ] **Multi-tenant AuthZEN:** every issuer bound to its `stores` + `db_roles`; `REQUIRE_STORE_BINDING` / `REQUIRE_DB_ROLE_BINDING` on.
- [ ] **Per-app namespace isolation on reads:** app roles are `GRANT`ed to `authz_authenticator` (so the reader can `SET ROLE`) and to the namespace with `can_read`.
- [ ] **Model registry:** authoring-store `authz_admin` treated as fleet-privileged; rollout via canary → fleet.
- [ ] `statement_timeout` tuned for your slowest legitimate op (large `list_*`, time-travel).
- [ ] Superuser logins restricted; `authz_owner` stays non-superuser.
- [ ] Audit retention + partition maintenance scheduled; backups before upgrades.
- [ ] If `pg_cel` is used: pin the extension version; review before upgrading.
- [ ] Playground overlay **not** deployed to production; if used elsewhere, `PLAYGROUND_EXPLORE_ROLE` set.

Code hardening F1/F2 (uniform `SECURITY DEFINER`), F3 (`%I` in partition DDL),
and F5 (256 KiB context-size cap) are **done**. F4/F6 and the refresh findings
F7/F8/F9/F10 are accepted as-is (operational controls, not code fixes).

## For an external auditor

Highest-value targets, in order: (1) the **condition sandbox** — try to make a
SQL/CEL condition read data, call a function, or escape `authz_eval`; (2)
**cross-tenant isolation** — find any decision/search path that returns another
store's tuples, a namespace bypass, or a way for one issuer's token to reach
another issuer's stores/DB roles despite the anchored bindings; (3) **fail-open**
— any error/NULL/timeout path that yields *allow*; (4) the **OPA→PostgREST trust
boundary** — forge or replay `X-Authz-Role` on the reader *or* writer, or smuggle
`input.db_role` past `REQUIRE_TOKEN_FOR_READS`; (5) the **role-switch hooks** —
find a role that passes `_pre_request` / `_pre_request_reader` yet is
admin-capable or not GRANT-restricted; (6) **tuple expiry** — bypass the RLS `SELECT` policy (F11 is the known one via
the escape GUC; look for others — index-only scans, `COPY`, partition-direct
DML); (7) the **model registry** — make
`apply_model` land a model whose live checksum differs from the registry
(defeating the self-check), or propagate a condition that escapes the sandbox on
a target store. The SQL test suites (`tests/sql/`, incl. `tests_model_registry`
and `tests_pre_request_reader`) and `bench/` model fixtures are useful starting
corpora.
