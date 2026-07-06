# ADR 0009 — Freshness tokens for read-your-writes (LSN watermark)

- **Status:** Proposed
- **Date:** 2026-07-06
- **Deciders:** maintainers
- **Relates to:** [0007](0007-pgauthzd-front-door.md) (pgauthzd owns the writer
  connection — the enabler), the shipped per-write `synchronous_commit` modes
  ("Layer B" strict revocation)

## Context

pgauthz's expected topology is a single write primary with read replicas serving
checks. Replicas are asynchronous (sub-second lag), so a check routed to a replica
immediately after a write can miss it. Two directions matter differently:

- A **stale deny after a grant** is an accepted availability hiccup.
- A **stale allow after a revoke** ("new enemy") is a correctness violation.

Two mechanisms already exist or were considered:

- **Layer B — per-write durability (shipped).** A write can request
  `applied | durable | eventual`, mapped to `synchronous_commit = remote_apply |
  on | local`. `applied` makes a revoke's ack wait until every *synchronous*
  replica has applied it. This is the t0 guarantee **within the synchronous set**,
  but it says nothing about a client reading its **own** recent write from an
  arbitrary (possibly async) replica, and it does not give a caller a handle to
  express "answer only if you're at least as fresh as my last write."

- **Route freshness-sensitive checks to the primary (current guidance).** Correct
  but coarse: it sends checks to the primary *always*, even when the replica is
  already fresh enough, forfeiting the read-scaling the replicas exist for.

What is missing is a **freshness token**: a write returns a small opaque handle,
and a later read can present it to demand read-your-writes, letting a replica
serve the read whenever it is provably caught up and fall back to the primary only
when it genuinely isn't. This is Zanzibar's *zookie* / OpenFGA's
`HIGHER_CONSISTENCY`, adapted to PostgreSQL.

This was previously parked (see the "consistency tokens" trail) for two reasons,
both now resolved:

1. *"Post-commit LSN capture is awkward."* Under the old PostgREST bridge, nothing
   owned the write transaction's connection, so capturing the commit's LSN meant a
   separate round trip through a component that couldn't see the tx. After
   [ADR 0007], **pgauthzd owns the writer connection** and can read the LSN on the
   same connection right after commit — the obstacle is gone.
2. *"Wait for PG19 `WAIT FOR LSN`."* PG19's primitive only optimizes the
   replica-side *wait*; the token mint, the freshness guard, and primary-fallback
   are all buildable today. PG19 later turns a short poll into a one-line preamble
   — an optimization, not a prerequisite.

### Substrate: LSN watermark, not a per-store revision counter

The earlier forward design proposed a per-store monotonic counter
(`store_revisions`, bumped `FOR UPDATE` inside each write). It is simple and
failover-robust, but the row lock **serializes all writes to a store across the
`remote_apply` commit wait** — a real throughput ceiling for a churny large tenant
on WAN-synchronous replication. An **LSN watermark** avoids the counter (and the
serialization) entirely: WAL position is already a global, monotonic,
commit-ordered clock.

A streaming-replication prototype validated the LSN approach and pinned down its
one sharp edge:

- **Watermark is sound.** A token minted from `pg_current_wal_insert_lsn()`
  *post-commit* is satisfied on a replica exactly when
  `pg_last_wal_replay_lsn() >= token.lsn` — which coincides with the write being
  visible (MVCC). No WAL detail leaks into the API beyond an opaque position.
- **The timeline (epoch) is the sharp edge.** LSNs are only comparable *within a
  timeline*. After a failover, the promoted node continues on a new timeline; a
  token minted on the old timeline must not be compared by LSN against the new one
  (a lossy failover can make the naive `lsn >= token.lsn` check **false-allow**
  against diverged/lost WAL — the prototype reproduced this). The guard is an
  **epoch = timeline id** carried in the token.
- **Read the timeline from the WAL position, never from the control file.** The
  prototype confirmed `pg_control_checkpoint().timeline_id` **lags** promotion
  (still reported the old timeline until the next checkpoint, while the node was
  already serving the new one) — using it for the epoch would open a false-allow
  window. Correct sources: on the **primary** (out of recovery)
  `pg_walfile_name(pg_current_wal_insert_lsn())`; on a **standby** (in recovery,
  where `pg_walfile_name()` errors) `pg_stat_wal_receiver.received_tli`.

## Decision

Adopt an **app-level LSN-watermark freshness token**, minted by the pgauthzd
writer and enforced by pgauthzd readers. No PostgreSQL version dependency.

### Token

An opaque, integrity-protected value:

```
token = { kid, epoch: <timeline_id>, lsn: <pg_lsn> }   -- HMAC-signed, base64url
```

- **Global**, not per-store — a replica replayed to LSN L has replayed *everything*
  ≤ L, so one watermark covers all stores. Slightly conservative (a token from
  store A also waits out unrelated writes), which is acceptable and far simpler
  than per-store keying.
- **HMAC-signed** with a server-side key so clients cannot forge a future position;
  readers reject a bad signature (fail closed). The token is a freshness assertion,
  not a capability — it grants nothing on its own.
- **Key-rotation-ready.** The signing config is an ordered keyring
  (`FRESHNESS_TOKEN_KEYS`): the **first** key mints, **every** key verifies. Each
  token embeds a key id (`kid = base64url(sha256(secret)[:4])` — derived, never
  configured) so the verifier picks the right key during an overlap; an unknown
  kid is rejected with the same opaque error as a forgery. Rotation is three
  rollouts, each safe under mid-rollout instance skew — a reader must accept a
  key *before* any writer mints with it: `"old,new"` → `"new,old"` → `"new"`,
  dropping the old key once its per-kid verification metric
  (`pgauthzd_freshness_key_verifications_total`) drains. A plain `KEY` +
  `KEY_PREVIOUS` pair was rejected because it cannot express the
  accept-before-mint phase.

### Scope: cooperative consistency, not global revocation enforcement

A token upgrades only the reads that *present* it; a default
(`minimize_latency`) read may still hit a lagging replica. Deployment-level
revocation visibility is Layer B's job (`remote_apply` + the serving ⊆
sync-set invariant); the token is the *causal read-your-writes* handle for
participating workflows. A PEP fronting end users must own consistency
selection (retain the newest observed token, never let clients weaken the
mode, cache-bypass after revokes) — see PRODUCTION.md.

### Mint (writer)

After the write transaction commits, on the **same** pgx connection:

```sql
SELECT pg_current_wal_insert_lsn(),
       pg_walfile_name(pg_current_wal_insert_lsn());  -- epoch = tli prefix
```

One extra cheap round trip. The writer returns the signed token in the native
write response (and an `X-PGAuthz-Revision` header on AuthZEN writes).

Minting is **best-effort but never silent**: the write has already committed,
so a mint failure must not fail the request — instead it is counted
(`pgauthzd_freshness_mint_failures_total`), logged, and reported to the caller
as `X-PGAuthz-Revision-Status: unavailable` (vs `issued` / `disabled`), so a
client that expected read-your-writes can tell a broken mint from a
switched-off feature.

### Read modes

A read carries an optional consistency mode (native field / `X-PGAuthz-Consistency`
already exists for writes; extended to reads):

- `minimize_latency` (default) — answer from the local replica, today's behavior.
- `at_least_as_fresh(token)` — the reader must satisfy the token (below) or route
  to the primary.
- `fully_consistent` — always answer from the primary.

### Reader guard — `assert_fresh(token)`

`assert_fresh` derives **this node's** `(timeline, WAL position)` and compares
them to the token — the *same* logic on a standby and a primary, so a **promoted
primary is guarded too** (there is deliberately **no** "primary is always fresh"
special case):

- **standby:** timeline = `pg_stat_wal_receiver.received_tli` (recovery-safe; NULL
  when not streaming / without `pg_read_all_stats`), position = `pg_last_wal_replay_lsn()`.
- **primary:** timeline = `pg_walfile_name(pg_current_wal_insert_lsn())`, position
  = `pg_current_wal_insert_lsn()`.

Verdict, at the guard (HTTP) then in the engine (`assert_fresh`):

1. Bad signature / unknown kid → **400**. `at_least_as_fresh` with **no token**
   → **400** — a missing token is a client error, never a silent downgrade to a
   low-latency read. The 400 message is one fixed opaque string for every
   bad-token cause: a probe must not be able to distinguish "key retired by
   rotation" from "forged" (**no oracle**); the operational detail (unknown kid
   vs signature vs malformed) goes to the server log only.
2. timeline unknown (empty `pg_stat_wal_receiver`) → **`unknown`** → route to primary.
3. `node_timeline != token.epoch` → **`wrong_epoch`** → route to primary. This is
   the lossy-failover guard: a promoted primary is on a **new** timeline, so an
   old-timeline token is rejected *here too* — not served as if fresh. Conservative
   (even a clean promotion forces a re-mint), which beats confirming a lost write.
4. `node_position < token.lsn` → **`stale`** → briefly wait / route to primary.
5. Otherwise → **`fresh`** → serve locally.

An unsatisfiable read returns a **structured 409** —
`{error: "freshness_constraint_unsatisfied", verdict, primary_consulted,
message}` plus `X-PGAuthz-Stale: <verdict>` — because the right recovery differs
by verdict:

| Verdict | Client action |
|---|---|
| `stale` | retry the primary / another replica, or wait |
| `unknown` | this node can't judge; retry the primary |
| `wrong_epoch` | **not retryable** — the token's timeline is gone (failover); re-mint via a new write or drop the constraint |
| bad token (400) | reject; do not retry |

`primary_consulted: true` means the transparent fallback already re-checked the
primary and it could not satisfy the token either — "retry the primary" is no
longer useful advice. (A future refinement could validate timeline *ancestry* +
the fork LSN to accept old-timeline tokens after a provably-lossless promotion;
conservative rejection is the deliberate choice today.)

### Pagination

Bind AuthZEN keyset cursors to the freshness token (embed `{epoch, lsn}` in the
cursor) so a paginated scan cannot silently mix pre- and post-revoke states across
pages; a page presented against a replica that can no longer satisfy the cursor's
token falls back like any other `at_least_as_fresh` read.

### Composition with Layer B

Orthogonal and complementary. Layer B (`applied`/`remote_apply`) is the **write
side** — it bounds *when a revoke is acknowledged*. Freshness tokens are the
**read side** — they let a caller *observe its own writes* on a replica without
pinning all sensitive reads to the primary. A deployment can use either or both.

## Consequences

- **No write serialization** — the LSN watermark needs no shared counter, so it
  does not add the per-store `FOR UPDATE` bottleneck the `store_revisions`
  substrate would have. This is the primary reason for the choice.
- **One extra round trip per write** (the post-commit LSN `SELECT`), on a
  connection pgauthzd already holds. Negligible next to the commit itself.
- **The freshness check needs no second pool** — it runs on the reader's existing
  replica connection (`pg_stat_wal_receiver` + `pg_last_wal_replay_lsn`). A pool to
  the primary is required only for *transparent* fallback (see open decision).
- **Failover-correct by construction** — the epoch guard rejects any cross-timeline
  token, closing the lossy-failover false-allow that a naive LSN compare permits.
  The correctness hinges on deriving the timeline from the WAL position (not the
  control file), per the prototype.
- **Global watermark is mildly conservative** — a token occasionally waits out
  unrelated writes to other stores. Acceptable; avoids reverse-closure keying.
- **OPA decision cache must bypass or key by token** for `at_least_as_fresh`
  reads, so a cached decision cannot mask a freshness requirement.
- **No PG19 dependency.** When PG19 lands, `WAIT FOR LSN` can replace the bounded
  poll in step 4 with a single replica-side preamble — a drop-in optimization; the
  token format and guard are unchanged.

## Stale-read routing shape (both shipped)

When a replica cannot satisfy an `at_least_as_fresh` token, the reader either:

- **(a) Retryable signal** (default) — return `409` + `X-PGAuthz-Stale` and let
  the gateway/client retry against the primary-connected instance. Single pool;
  turns "route sensitive reads to primary" from *always* into
  *only-when-actually-stale*.
- **(b) Transparent fallback** (opt-in, `FRESHNESS_PRIMARY_URL`) — the reader
  holds a second pool to the primary. It does **not** assume the primary is
  authoritative for the token: it **re-runs `assert_fresh` against the primary
  pool** and serves from the primary (`X-PGAuthz-Served-By: primary`) only on a
  `fresh` verdict. A promoted primary on a new timeline returns `wrong_epoch` →
  the guard fails closed (`409`) instead of serving a possibly-lost write. Adds
  connection management + a reader→primary reachability requirement.

## Alternatives considered

- **Per-store `store_revisions` counter** — simple and failover-robust, but
  serializes writes per store across `remote_apply`. Rejected as the substrate for
  that reason; the LSN watermark gives the same read-your-writes guarantee without
  the write ceiling.
- **Wait for PG19 `WAIT FOR LSN`** — defers a shippable feature for an optimization
  of one step. Rejected as a gate; adopted later as an enhancement.
- **Route all sensitive reads to the primary (status quo)** — correct but forfeits
  replica read-scaling even when the replica is already fresh. The token makes the
  primary hop rare instead of unconditional.
- **Regional bloom/watermark revocation filter** — a separate, composable
  optimization for *asynchronous* regions deliberately kept out of the sync set;
  narrows their staleness and makes primary-confirms rare. Out of scope here;
  builds on this token machinery when a multi-region deployment needs it.
