# Security self-audit

A first-party review of the pgauthz engine's security posture: a threat model,
the mechanisms that enforce it (verified against the code), and findings with
severities. It is **preparation for an external review, not a substitute** for
one — no independent party has attested to these claims.

- **Scope:** the SQL engine (`db/engine/`, `db/security/`, `db/migrations/`) and
  its trust boundaries. The OPA/PostgREST/AuthZEN tiers are covered only where
  they bear on the engine's guarantees.
- **Method:** four focused passes (SECURITY DEFINER + roles; the condition
  sandbox; multi-tenant isolation; fail-closed + write validation + audit), each
  finding then re-verified against the source. File:line citations point at the
  current tree.
- **Date / version:** 2026-06-29, around v0.1.4.
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
                   (authn,   (api_anon /                       │ run as authz_owner
                    policy)   authz_writer)        ┌───────────┴────────────┐
                                                   │ base tables (no direct │
                                                   │ grant to app roles)    │
                                                   └────────────────────────┘
 condition expr ───────────────────────────▶ authz_eval (zero-privilege sandbox)
```

**Actors & assumed capabilities.**

| Actor | Can | Must not be able to |
|---|---|---|
| Unauthenticated client | Reach OPA only | Reach PostgREST/Postgres directly |
| Authenticated app (PEP-fronted) | Checks + writes within its store/namespace | Read/write another tenant's tuples |
| A model/condition author (admin) | Define models + conditions | Make a condition that reads tables or runs code |
| A direct-SQL service role | Call `authz.*` for its tier | Reach base tables; widen its own grants |
| Malicious condition expression | Be evaluated | Read data, call functions, escalate, or run unbounded |

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
2. **SECURITY DEFINER, owned by a non-superuser.** All 48 public functions are
   `ALTER … SECURITY DEFINER` (roles.sql:230-273) and owned by **`authz_owner`**,
   a `NOLOGIN` non-superuser (roles.sql ownership transfer ~:318-387) — a bug in a
   definer function cannot reach superuser.
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
   under the zero-privilege role.

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
| F5 | Info | No explicit size cap on the request/stored **context JSONB**. A huge context could pressure memory before `statement_timeout` / PG limits stop it. An explicit `pg_column_size` cap would harden the edge. | Optional hardening |
| F6 | Info | `required_context` documents a condition's keys but is **not** enforced as an allow-list at eval time, so an expression could read other keys present in context. Matters only if an *admin* is malicious; low value vs. cost. | Won't fix (by design) |

No High/Critical **code** findings. The engine is fail-closed, the privileged
surface is small and consistently owned, and the condition sandbox is a genuine
capability sandbox.

### Operational / deployment

These are where real compromise would come from — they are assumptions the engine
*relies on*, not flaws in it. They belong in the deploy checklist, not the code.

| Risk | Why it matters | Control |
|---|---|---|
| Internal tiers exposed (PostgREST/Postgres reachable beyond OPA) | The read API is unauthenticated (`api_anon`) by design; exposure = tuple disclosure | Network isolation / no host ports (compose & chart already do this); verify in your env |
| `X-Authz-Role` header is **trusted, not signed** | The writer assumes only OPA can set it; `_pre_request` validates the role is a writer and not admin (core_internal.sql:149-170), but cannot prove OPA's authority | Keep the writer reachable only by OPA; mTLS/network policy |
| OPA compromise / wrong policy | OPA is the PEP — a bad policy or breach bypasses authn/authz | Review Rego; pin/version OPA; treat policies as security-critical |
| `authz_contextual_reader` granted too broadly | "What-if" tuple injection can probe for unpublished grants | Grant only to trusted backends (default: not granted to `api_anon`/`authz_reader`) |
| Dev secrets shipped (`authz` passwords, `opaAdminToken`) | Defaults are DEV ONLY | Override every secret; use a secret store (see PRODUCTION.md) |
| Superuser can bypass audit triggers | `session_replication_role` defeats any trigger (inherent to PostgreSQL) | Restrict superuser logins administratively |

## Hardening checklist

Deploy-time (most are in [`PRODUCTION.md`](PRODUCTION.md) — this cross-checks them):

- [ ] PostgREST (read + write) and Postgres have **no host ports**; only OPA is reachable.
- [ ] Every secret overridden; `opa.requireTokenForReads=true` unless a trusted PEP fronts reads.
- [ ] `authz_contextual_reader` granted only to trusted services (and only if used).
- [ ] JWT verified against your IdP's JWKS; writer-role claim mapping reviewed.
- [ ] `statement_timeout` tuned for your slowest legitimate op (large `list_*`, time-travel).
- [ ] Superuser logins restricted; `authz_owner` stays non-superuser.
- [ ] Audit retention + partition maintenance scheduled; backups before upgrades.
- [ ] If `pg_cel` is used: pin the extension version; review before upgrading.

Code hardening: F1/F2 (uniform `SECURITY DEFINER`) and F3 (`%I` in partition DDL)
are **done**; F5 (context size cap) remains optional.

## For an external auditor

Highest-value targets, in order: (1) the **condition sandbox** — try to make a
SQL/CEL condition read data, call a function, or escape `authz_eval`; (2)
**cross-tenant isolation** — find any decision/search path that returns another
store's tuples, or a namespace bypass; (3) **fail-open** — any error/NULL/timeout
path that yields *allow*; (4) the **OPA→writer trust boundary** — forge or replay
`X-Authz-Role`. The SQL test suites (`tests/sql/`) and `bench/` model fixtures are
useful starting corpora.
