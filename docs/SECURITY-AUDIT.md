# Security self-audit

A first-party review of the pgauthz engine's security posture: a threat model,
the mechanisms that enforce it (verified against the code), and findings with
severities. It is **preparation for an external review, not a substitute** for
one — no independent party has attested to these claims.

- **Scope:** the SQL engine (`db/engine/`, `db/security/`, `db/migrations/`) and
  its trust boundaries, **plus** the tiers that now carry security logic: the
  AuthZEN Go services (multi-issuer routing, per-app role switching, token
  forwarding), the OPA sidecar policies (public-path allowlist, read/write
  role forwarding), and the model registry. The playground BFF is reviewed as a
  dev-only tool (out of the deployable engine).
- **Method:** the original four engine passes (SECURITY DEFINER + roles; the
  condition sandbox; multi-tenant isolation; fail-closed + write validation +
  audit), plus a **2026-07 refresh** covering the surfaces added since v0.1.x:
  multi-issuer JWT routing + store/role bindings, the three `SET LOCAL ROLE`
  paths (writer + reader hooks, pgauthzd-decision in-service), token forwarding and
  the trusted-PEP `input.db_role` path, the per-role OPA cache partitioning, the
  model registry as a cross-store propagation path, and the team-Rego governance
  chokepoint. Each finding re-verified against the source; file:line citations
  point at the current tree.
- **Date / version:** engine passes 2026-06-29 (~v0.1.4); refresh 2026-07-05
  (~v0.6); **v0.7 delta 2026-07-05** (rich decisions, native expiry, cache
  bypass, pgauthzctl) — found one High fail-open (F11), **fixed** in migration 0006 — the first
  non-Info engine finding, found and closed within the same delta; **v0.8/v0.9
  delta 2026-07-06** (pgauthzd consolidation — the native `/pgauthz/v1` callback
  listener behind a service token + optional mTLS; freshness tokens with HMAC
  signing + transparent primary fallback; the `:9090` metrics listener) — found
  one Medium freshness fail-open (F12, a promoted-primary false-allow after a
  lossy failover), **fixed** in the same delta by timeline-guarding the reader
  guard on the primary too.
- **Independence.** Still a **first-party** review — no independent party has
  attested to these claims; it remains preparation for an external review, not a
  substitute. It is now *informed by* external reviews of the v0.6–v0.8 tree
  (competitive / architecture passes, and a v0.8.0 freshness review that surfaced
  F12), but those are design and roadmap critiques, **not** a security
  attestation. The "for an external auditor" section below is the standing ask.
- **Companion docs:** [`SECURITY.md`](../SECURITY.md) (reporting / supported
  line), [`PRODUCTION.md`](PRODUCTION.md) (hardening), [`ARCHITECTURE.md`](ARCHITECTURE.md)
  (defense-in-depth).

## Threat model

**Assets.** The authorization tuples + models (who-can-do-what), the audit trail
(system of record), and the correctness of every decision (a wrong *allow* is
the worst outcome).

**Trust boundaries.**

```
 untrusted        front door       policy sidecar       engine boundary
 client ──JWT──▶ pgauthzd ─────▶ OPA ──native cb──▶ authz.* SECURITY DEFINER fns
                 (validates      (authn,  (trusted     ▲                   │ run as authz_owner
                  the JWT)        policy)   upstream    │        ┌──────────┴─────────────┐
                                            of the      │        │ base tables (no direct │
                                            callback;   │        │ grant to app roles)    │
                                            X-PGAuthz-Role│        └────────────────────────┘
                                            reader/writer)│
                  pgauthzd validates the forwarded X-PGAuthz-Role: tier member, not admin
 condition expr ───────────────────────────▶ authz_eval (zero-privilege sandbox)
```

> *Architecture note (post-audit).* This audit was originally performed against
> a PostgREST read/write bridge. PostgREST has since been **removed** — pgauthzd
> is now the external **front door** (validates the JWT), and OPA is an internal
> policy sidecar that calls **back** into pgauthzd's native `/pgauthz/v1`
> callback (service-token gated, optional mTLS). The trust boundary keeps the
> same shape: a bridge OPA calls, still asserting `X-PGAuthz-Role`. The old
> PostgREST authenticator-role + `SET ROLE` dance **and** the SQL
> `_pre_request` / `_pre_request_reader` hooks are gone — pgauthzd connects
> directly as its reader/writer role and now validates the forwarded
> `X-PGAuthz-Role` (tier member, not admin) and applies `SET LOCAL ROLE` in Go
> (per-app role via `X-PGAuthz-Role` / `DB_ROLE_CLAIM`). The findings below are
> preserved as recorded.

**Actors & assumed capabilities.**

| Actor | Can | Must not be able to |
|---|---|---|
| Unauthenticated client | Reach pgauthzd's public front door (rejected without a valid JWT) | Reach the OPA sidecar, pgauthzd's internal callback, or Postgres directly |
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
   (`db/security/roles.sql`; "No direct table grants" at roles.sql:201). An HTTP
   bridge (pgauthzd's callback, or the former PostgREST reader) therefore cannot
   expose table endpoints.
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
    forwards the caller's per-app DB role as `X-PGAuthz-Role`; the writer's
    `_pre_request` and the reader's `_pre_request_reader` (core_internal.sql)
    each validate it — the role must exist, be a member of the tier role
    (`authz_writer` / `authz_reader`), and **not** be admin-capable — then
    `SET LOCAL ROLE` (transaction-scoped, no pool leak). An unknown, over-scoped,
    or admin role raises `insufficient_privilege`. `_check_namespace_access` then
    enforces per app on both paths. `pgauthzd-decision` applies the same discipline
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

### pgauthzd consolidation / freshness surface (v0.8/v0.9)

14. **The native callback listener is dual-authenticated + non-public.** OPA calls
    back into pgauthzd's native `/pgauthz/v1` API on a **separate listener**
    (`INTERNAL_LISTEN_ADDR`, no host port), gated by a shared service token
    (`INTERNAL_SERVICE_TOKEN` on pgauthzd / `NATIVE_SERVICE_TOKEN` on OPA) and,
    when configured, **mTLS** (`tls.Config{ClientAuth: RequireAndVerifyClientCert}`
    against a pinned client CA). It deliberately does **not** re-verify the
    end-user JWT — pgauthzd is the front door; the callback trusts its OPA
    upstream (see the trust-boundary note). Reader vs. writer capability is the
    connecting **DB role** (`decision-only` → reader, `full` → writer), not a Go
    flag. The public native surface is exposed only when *not* fronting OPA.
15. **Freshness tokens are signed assertions, fail-closed, and grant nothing.**
    A freshness token is `{epoch=timeline, lsn}` **HMAC-SHA256 signed** (server
    key, base64url; authz/freshness.go) — it is a read-your-writes *assertion*,
    not a capability, so the signature exists only to stop a client fabricating a
    future WAL position. Every guard path fail-closes: a bad/tampered signature or
    an `at_least_as_fresh` request with **no** token → **400** (never a silent
    downgrade to a low-latency read); `stale`/`wrong_epoch`/`unknown` → **409**
    (or transparent primary re-check, mechanism 16). The reader guard derives
    **this node's** own `(timeline, position)` and applies the same verdict on a
    standby *and* a promoted primary — there is no "primary is always fresh"
    shortcut (that shortcut was F12, now removed): a promoted primary on a new
    timeline returns `wrong_epoch`, closing the lossy-failover false-allow.
16. **Transparent primary fallback re-validates, never assumes.** With
    `FRESHNESS_PRIMARY_URL` set (decision-only + non-OPA only), a reader holds a
    **second pgx pool to the primary** as the *same reader role* (no privilege
    change — read-only DSN). On a not-fresh replica verdict it **re-runs
    `assert_fresh` against the primary** and routes the read there only on a
    `fresh` verdict (`X-PGAuthz-Served-By: primary`); any other primary verdict
    fails closed to 409. The fallback cannot serve a write role or a lost write.
17. **The metrics listener is non-public and content-free.** Prometheus metrics
    are served on a separate `METRICS_LISTEN_ADDR` (`:9090`, no host port in
    compose/chart). Labels are **fixed-cardinality** (bucketed store tail;
    `api ∈ {native, authzen}`; pool `∈ {primary, replica, fallback}`) — no
    model-defined type/action and no tuple/subject content — so the surface
    exposes rates, latencies, and gauges, never authorization data.

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
| F8 | Info | **Trusted-PEP mode extends to `input.db_role`.** In `REQUIRE_TOKEN_FOR_READS=false` (trusted-PEP) mode, OPA honors a request-body `input.db_role` for the read role switch (pgauthz.rego:33-36) — the same trust already extended to `input.subject` in that mode. A caller reaching OPA directly could then assert any DB role, but the reader hook still fail-closes to reader-only, non-admin roles that are `GRANT`ed to the authenticator, so it cannot escalate — at most it selects another *reader* namespace. The default `REQUIRE_TOKEN_FOR_READS=true` derives the role from verified claims and ignores `input.db_role`. Keep OPA reachable only by a trusted PEP whenever this mode is on. | Accepted (mirrors `X-PGAuthz-Role`; operational control) |
| F9 | Low | **403s echo the attempted store/role name.** The issuer-binding rejections include the requested store / DB role in the error string (handler.go, middleware.go). The caller already knows the value it sent, so this leaks nothing to *that* caller; the minor concern is these strings reaching shared logs. Optional: drop the value from the message. | Won't fix (low value) |
| F10 | Info | **Negative role-validation cache in pgauthzd-decision.** `checkRole` caches *denied* as well as allowed results for `DB_ROLE_CACHE_TTL_SECONDS` (default 60; pgbackend/backend.go). A role newly granted its membership is not honored until the entry expires — a fail-*closed* staleness (availability, not a security gap). Unknown-role lookups are never cached. Set the TTL to `0` to re-validate every request. | Accepted (bounded; documented) |

No High/Critical **code** findings in the refresh. Cross-issuer isolation is
enforced with anchored patterns and 403-not-downgrade semantics; the two new
role-switch hooks share the writer's fail-closed discipline and identifier
quoting; registry propagation adds reach, not privilege. The engine remains
fail-closed, the privileged surface small and consistently owned, and the
condition sandbox a genuine capability sandbox.

### Delta findings (2026-07, v0.7 — rich decisions, expiry, cache bypass)

An adversarial pass over the surface added since the refresh — native tuple
expiry (`expires_at` + row-level security), `check_access_detailed` /
`allow_detailed`, the `no_cache` cache bypass, and `pgauthzctl` — surfaced one
real fail-open in the expiry enforcement.

| # | Sev | Finding | Status |
|---|---|---|---|
| F11 | **High** | **The tuple-expiry RLS escape is a caller-settable GUC (fail-open).** Native expiry hides expired tuples via a row-level-security `SELECT` policy on `authz.tuples`; the sanctioned write/delete/cleanup paths reveal expired rows by arming a transaction-local GUC, `authz.tuples_include_expired`, that the policy honors (migration 0005). But a **custom GUC is settable by any role**, and expiry is read *inside* the `SECURITY DEFINER` functions that app roles legitimately invoke (`check_access`, `list_*`). A direct `authz_reader` connection can therefore `SET authz.tuples_include_expired = 'on'` and make **expired grants grant again** — the exact fail-open expiry was meant to prevent. No policy predicate can distinguish a legitimate arming from a forged one (at evaluation time both are "GUC on, `current_user = authz_owner`"). **Verified** with a live `SET ROLE authz_reader` reproduction (expired check flipped `false → true`). **Exploitability boundary:** *not* reachable through the pgauthzd/OPA/AuthZEN front door, which exposes only RPC calls, never raw SQL — so no unauthenticated or HTTP-only caller can trigger it. It is a **direct-SQL trust-tier** hole: it matters for services that connect to Postgres directly as a reader role (`pgauthzd-decision` → `authz_reader`, direct-SQL integrations, or a SQL-injection foothold in a reader-privileged path — none found). **Fixed (migration 0006):** the SELECT policy carries **no GUC escape** — reads are expiry-honest for every role, unbypassable by any caller value. The two operations that must see expired rows (the reactivating `ON CONFLICT` upsert and cleanup) run in `SECURITY DEFINER` helpers (`authz._rls_*`) **owned by** a dedicated `BYPASSRLS` role, `authz_rls_bypass`, called normally — Postgres forbids `SET ROLE` inside a definer function, so ownership is the mechanism (not a caller-settable GUC or role switch). `EXECUTE` is granted only to `authz_owner`; **no LOGIN role can reach the bypass role** (verified: `pg_has_role` false for `authz_authenticator`/`authzen_direct`/`api_anon`/`authz_metadata`). Re-verified closed: the `SET authz.tuples_include_expired='on'` reproduction now returns `false`; a direct `_rls_*` call as `authz_reader` is denied (no `EXECUTE`). roles.sql excludes `authz._rls_%` from the blanket owner-transfer loop and re-owns them dynamically — else a definer helper could end up superuser-owned. | ✅ **Fixed** |

The audit tables' analogous GUC (`authz.audit_maintenance`) is **not**
vulnerable in the same way: app roles hold no direct `UPDATE`/`DELETE` grant
on the audit tables, so even with that GUC armed they cannot issue the DML —
the function-only-access layer (mechanism 1) is the second gate that expiry
reads lack. The other v0.7 additions reviewed clean:

- **`check_access_detailed` / `allow_detailed`** run `SECURITY DEFINER`,
  reader-granted, and expose only what `explain_access` already does
  (decision reason + missing condition-context keys) — no tuple/subject
  identifiers beyond the caller's own query. The AuthZEN `X-PGAuthz-Detail`
  path is opt-in and additive; without the header the response is the plain
  boolean.
- **`no_cache` / `Cache-Control: no-cache`** only shortens a cache TTL for
  one decision; it cannot change a decision or amplify load beyond the
  cache-busting an authenticated caller already had (F-none; documented in
  opa/README).
- **`pgauthzctl`** is an operator/CI tool in the psql trust tier (direct DSN,
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

### Delta findings (2026-07, v0.8/v0.9 — pgauthzd consolidation, freshness, metrics)

An adversarial pass over the surface added by the pgauthzd consolidation — the
native `/pgauthz/v1` callback listener, freshness tokens (HMAC mint + reader
guard + transparent primary fallback), and the metrics listener — surfaced one
Medium fail-open in the freshness guard (found by an external v0.8.0 review),
fixed in the same delta.

| # | Sev | Finding | Status |
|---|---|---|---|
| F12 | **Medium** | **Promoted-primary freshness false-allow (fail-open, narrow).** v0.8.0's reader guard shortcut treated *any* primary as unconditionally `fresh` — `assert_fresh` returned `'fresh'` without deriving the node's own timeline. After a **lossy failover**, a node promoted onto a **new** timeline would confirm a token minted on the **old** timeline whose write it had lost — a stale *allow* (the "new enemy" the token exists to prevent). Reachable only when freshness tokens are enabled (`FRESHNESS_TOKEN_KEY` set) *and* a lossy promotion has occurred *and* a caller replays an old-timeline `at_least_as_fresh` token; the default `minimize_latency` path is unaffected. **Fixed (v0.9.0):** `assert_fresh` now derives the node's own `(timeline, position)` on the primary too — `pg_walfile_name(pg_current_wal_insert_lsn())` for the timeline (never `pg_control_checkpoint().timeline_id`, which lags promotion until a checkpoint → a second false-allow window the prototype reproduced) — and applies the same `_freshness_verdict` as a standby, so a cross-timeline token yields `wrong_epoch` → 409. The transparent fallback was hardened in the same change: it **re-runs the verdict on the primary** and serves only on `fresh`, so it can't paper over the gap. Verified: `tests_freshness.sql` 12/12 (incl. `primary_wrong_epoch`, `primary_future_lsn_stale`), and Go guard/fallback tests (`TestFreshnessFallbackPrimaryAlsoStale`, `TestFreshnessMissingTokenIs400`). | ✅ **Fixed** |
| F13 | Info | **Single freshness HMAC key, no rotation yet.** The token signature uses one server-side key (`FRESHNESS_TOKEN_KEY`); there is no `kid` overlap window, so rotating the key invalidates every outstanding token at once (in-flight `at_least_as_fresh` reads 400 → clients re-mint on their next write). Because a token is a freshness assertion that **grants nothing**, a leaked key lets an attacker at most forge a *future* position (a self-inflicted stale-deny / extra primary hop), never an allow — impact is availability, not authorization. **Fixed:** the signing config is now an ordered keyring, `FRESHNESS_TOKEN_KEYS` — the **first** key mints, **every** key verifies — and each token embeds a derived key id (`base64url(sha256(secret)[:4])`, covered by the MAC, so a token cannot be re-labelled to another key). Rotation is a zero-downtime three-phase overlap (`"old,new"` → `"new,old"` → `"new"`; runbook in PRODUCTION.md), with a per-kid verification counter (`pgauthzd_freshness_key_verifications_total`, keyring-bounded labels) as the drain signal for dropping the old key. An unknown/retired kid fails with the same opaque `ErrBadToken` as a forgery (fail closed, no oracle). | ✅ **Fixed** |
| F14 | Info | **Primary-fallback pool widens reader reach, not privilege.** `FRESHNESS_PRIMARY_URL` gives a decision-only reader a second pool to the primary. It connects as the **same read-only role** and re-validates freshness before serving, so it grants no new capability — but it does make the primary reachable from a reader tier that otherwise only touched a replica. Point it at a **reader-role DSN** (never the writer), keep it reader→primary-network-scoped, and it stays gated to `decision-only` + non-OPA instances. | Accepted (operational; reader DSN only) |
| F15 | Info | **Metrics endpoint is unauthenticated (by design).** The `:9090` metrics listener has no auth (standard Prometheus scrape model). It exposes no authorization content — labels are fixed-cardinality (bucketed store tail, `api`/`pool` enums), values are rates/latencies/gauges — but store-activity *volumes* and pool health are observable. Keep it on a non-public address / scrape-only network (compose & chart give it no host port); a `NetworkPolicy` restricts ingress to the Prometheus scraper. | Accepted (operational; keep non-public) |

No High/Critical **code** findings in this delta. The one fail-open (F12) was
found and closed in the same release; the callback listener adds a service-token
+ optional-mTLS gate on a non-public address; freshness tokens are signed,
grant nothing, and fail closed on every ambiguous verdict; the metrics surface
is content-free. The remaining v0.8/v0.9 items are operational controls.

### Operational / deployment

These are where real compromise would come from — they are assumptions the engine
*relies on*, not flaws in it. They belong in the deploy checklist, not the code.

| Risk | Why it matters | Control |
|---|---|---|
| Internal tiers exposed (pgauthzd's internal callback / Postgres reachable beyond the front door) | The callback listener does not re-verify the end-user JWT (it trusts the OPA sidecar); exposure = tuple disclosure | Network isolation / no host ports (compose & chart already do this); verify in your env |
| `X-PGAuthz-Role` header is **trusted, not signed** (read *and* write) | Both pgauthzd callback instances (reader + writer) assume only OPA sets it; pgauthzd validates the role is a member of the tier role and not admin (in Go, then `SET LOCAL ROLE`), but cannot prove OPA's authority | Keep both pgauthzd callback listeners reachable only by OPA; service token + mTLS/network policy |
| `input.db_role` honored in trusted-PEP mode | With `REQUIRE_TOKEN_FOR_READS=false`, a caller can assert the read role (bounded to reader-only, non-admin, granted roles — see F8) | Keep the default `REQUIRE_TOKEN_FOR_READS=true`, or keep OPA reachable only by a trusted PEP |
| Native callback service token / mTLS not set | The callback listener trusts its OPA upstream and does not re-verify the JWT; without the token (and ideally mTLS) anyone who reaches it can assert `X-PGAuthz-Role` (F14/mechanism 14) | Set `INTERNAL_SERVICE_TOKEN`/`NATIVE_SERVICE_TOKEN`; enable mTLS in untrusted networks; keep the internal listener non-public |
| Freshness HMAC key weak / shared / unrotated | A leaked freshness key lets an attacker forge a *future* position (stale-deny / extra primary hop — never an allow, F13) | Set strong per-deployment `FRESHNESS_TOKEN_KEYS`; rotate via the keyring overlap (F13, runbook in PRODUCTION.md) — or drop-and-replace on suspicion (outstanding tokens 400; clients re-mint) |
| Primary-fallback DSN points at the writer | `FRESHNESS_PRIMARY_URL` as a writer DSN would give a reader tier write reach (F14) | Use a **reader-role** DSN; scope reader→primary network; gated to decision-only + non-OPA |
| Metrics endpoint exposed publicly | `:9090` is unauthenticated; leaks store-activity volumes / pool health (no authz content, F15) | Keep `METRICS_LISTEN_ADDR` non-public; scrape-only network / `NetworkPolicy` (chart ships one) |
| Issuer without a `stores` / `db_roles` binding | An unbound issuer's tokens can reach every store / claim any reader role | Set per-issuer bindings; enable `REQUIRE_STORE_BINDING` / `REQUIRE_DB_ROLE_BINDING` (startup error on an unbound issuer) |
| Model-registry authoring store is fleet-privileged | An admin on the authoring store can push models + conditions to every tenant store (F7) | Restrict `authz_admin` on the authoring store; review `models_audit` + registry versions |
| OPA compromise / wrong policy | OPA is the PEP — a bad policy or breach bypasses authn/authz. Team-added Rego packages need an explicit line in the `system_authz` public-path allowlist, so that file is the governance chokepoint | Review Rego; pin/version OPA; gate `system_authz.rego` edits in CI/CODEOWNERS; treat policies as security-critical |
| Playground deployed beyond dev | Arbitrary-subject probing if `PLAYGROUND_EXPLORE_ROLE` unset (read-only; P1) | Keep it opt-in/dev-only; set `PLAYGROUND_EXPLORE_ROLE`; never host-expose |
| `authz_contextual_reader` granted too broadly | "What-if" tuple injection can probe for unpublished grants | Grant only to trusted backends (default: not granted to `authz_reader`) |
| Dev secrets shipped (`authz` passwords, `opaAdminToken`) | Defaults are DEV ONLY | Override every secret; use a secret store (see PRODUCTION.md) |
| Superuser can bypass audit triggers | `session_replication_role` defeats any trigger (inherent to PostgreSQL) | Restrict superuser logins administratively |

## Hardening checklist

Deploy-time (most are in [`PRODUCTION.md`](PRODUCTION.md) — this cross-checks them):

- [ ] pgauthzd's internal callback listeners (read + write) and Postgres have **no host ports**; only OPA reaches the callback, and only pgauthzd reaches OPA.
- [ ] Native callback authenticated: `INTERNAL_SERVICE_TOKEN`/`NATIVE_SERVICE_TOKEN` set; mTLS enabled where the callback network isn't fully trusted.
- [ ] **Freshness (if enabled):** strong per-deployment `FRESHNESS_TOKEN_KEYS`; rotation via the three-phase keyring overlap (PRODUCTION.md); `FRESHNESS_PRIMARY_URL` (if used) is a **reader-role** DSN, decision-only + non-OPA.
- [ ] **Metrics:** `METRICS_LISTEN_ADDR` non-public; scrape restricted to Prometheus (chart `NetworkPolicy` / no host port).
- [ ] Every secret overridden; `opa.requireTokenForReads=true` unless a trusted PEP fronts reads.
- [ ] `authz_contextual_reader` granted only to trusted services (and only if used).
- [ ] JWT verified against your IdP's JWKS; role claim (`DB_ROLE_CLAIM`) mapping reviewed.
- [ ] **Multi-tenant AuthZEN:** every issuer bound to its `stores` + `db_roles`; `REQUIRE_STORE_BINDING` / `REQUIRE_DB_ROLE_BINDING` on.
- [ ] **Per-app namespace isolation on reads:** app roles are `GRANT`ed to the reader's login role `authzen_direct` (so pgauthzd can `SET LOCAL ROLE`) and to the namespace with `can_read`.
- [ ] **Model registry:** authoring-store `authz_admin` treated as fleet-privileged; rollout via canary → fleet.
- [ ] `statement_timeout` tuned for your slowest legitimate op (large `list_*`, time-travel).
- [ ] Superuser logins restricted; `authz_owner` stays non-superuser.
- [ ] Audit retention + partition maintenance scheduled; backups before upgrades.
- [ ] If `pg_cel` is used: pin the extension version; review before upgrading.
- [ ] Playground overlay **not** deployed to production; if used elsewhere, `PLAYGROUND_EXPLORE_ROLE` set.

Code hardening F1/F2 (uniform `SECURITY DEFINER`), F3 (`%I` in partition DDL),
F5 (256 KiB context-size cap), F11 (expiry RLS escape, migration 0006), F12
(promoted-primary freshness guard, v0.9.0), and F13 (freshness keyring rotation)
are **done**. F4/F6, the refresh findings F7/F8/F9/F10, and the v0.8/v0.9
findings F14/F15 are accepted as-is (operational controls, not code fixes).

## For an external auditor

Highest-value targets, in order: (1) the **condition sandbox** — try to make a
SQL/CEL condition read data, call a function, or escape `authz_eval`; (2)
**cross-tenant isolation** — find any decision/search path that returns another
store's tuples, a namespace bypass, or a way for one issuer's token to reach
another issuer's stores/DB roles despite the anchored bindings; (3) **fail-open**
— any error/NULL/timeout path that yields *allow*; (4) the **OPA→pgauthzd callback
trust boundary** — forge or replay `X-PGAuthz-Role` on the reader *or* writer, or smuggle
`input.db_role` past `REQUIRE_TOKEN_FOR_READS`; (5) **pgauthzd's role
validation** — find a role that passes pgauthzd's `X-PGAuthz-Role` check (Go:
member of the tier role, not admin) yet is admin-capable or not
GRANT-restricted; (6) **tuple expiry** — bypass the RLS `SELECT` policy (F11, the escape-GUC path, is now fixed via a
BYPASSRLS-owned helper; look for others — index-only scans, `COPY`, partition-direct
DML); (7) the **model registry** — make
`apply_model` land a model whose live checksum differs from the registry
(defeating the self-check), or propagate a condition that escapes the sandbox on
a target store; (8) **freshness tokens** — forge or replay a token to obtain a
stale *allow* (F12 closed the promoted-primary path; probe others — a clean
promotion, a timeline derived from the control file, a fallback that serves a
non-`fresh` primary verdict, or a paginated cursor that mixes pre-/post-revoke
pages); (9) the **native callback trust boundary** — reach `/pgauthz/v1` without
the service token / past mTLS, or assert `X-PGAuthz-Role` as a non-OPA caller.
The SQL test suites (`tests/sql/`, incl. `tests_model_registry` and
`tests_freshness`), pgauthzd's Go tests (`pgauthzd/internal/pgbackend/`,
`internal/api/` freshness guard/fallback), and `bench/` model fixtures are useful
starting corpora.
