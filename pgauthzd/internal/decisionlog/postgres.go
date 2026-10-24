package decisionlog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The postgres sink (ADR 0015): decision lines land in a daily-partitioned
// table of a SINK database — never the engine's check path, never a
// replica — written by a background flusher in batches. The Logger keeps
// its one-line-per-call contract; this sink is the io.Writer under it.
//
// Durability is "refuse when down", not "fsync per line": a line is queued
// (bounded) and inserted within FlushInterval; a crash loses at most the
// queue. When an insert fails the sink is DOWN: every further Write reports
// the error (DECISION_LOG_REQUIRED then fails closed) and tries a
// synchronous flush, so the Logger's probe marker is also the recovery
// attempt. Retention is the sink's own: partitions older than
// RetentionDays are dropped once an hour.

// PostgresConfig configures the postgres sink.
type PostgresConfig struct {
	DSN           string
	RetentionDays int           // 0 = keep everything
	QueueSize     int           // lines held between flushes (default 10000)
	BatchSize     int           // lines per insert (default 500)
	FlushInterval time.Duration // default 1s
}

// Table is the sink table; Schema its schema.
const (
	Schema = "decisionlog"
	Table  = "decisions"
)

// DDL creates the schema and the partitioned table (idempotent; every
// instance runs it at start, the first one wins). The console reads the
// same table; keep its shape additive.
const DDL = `
CREATE SCHEMA IF NOT EXISTS decisionlog;
CREATE TABLE IF NOT EXISTS decisionlog.decisions (
    id            bigint GENERATED ALWAYS AS IDENTITY,
    ts            timestamptz NOT NULL,
    request_id    text,
    trace_id      text,
    span_id       text,
    listener      text NOT NULL,
    endpoint      text NOT NULL,
    via           text,
    store         text NOT NULL,
    subject_type  text,
    subject_id    text,
    action        text,
    resource_type text,
    resource_id   text,
    decision      boolean,
    state         text,
    reason        text,
    actor         text,
    client        text,
    issuer        text,
    latency_ms    real,
    error         text,
    line          jsonb NOT NULL
) PARTITION BY RANGE (ts);
CREATE TABLE IF NOT EXISTS decisionlog.decisions_default PARTITION OF decisionlog.decisions DEFAULT;
ALTER TABLE decisionlog.decisions ADD COLUMN IF NOT EXISTS trace_id text;
ALTER TABLE decisionlog.decisions ADD COLUMN IF NOT EXISTS span_id text;
ALTER TABLE decisionlog.decisions ADD COLUMN IF NOT EXISTS store_id integer;
CREATE INDEX IF NOT EXISTS decisions_store_trace ON decisionlog.decisions (store, trace_id) WHERE trace_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS decisions_store_ts ON decisionlog.decisions (store, ts DESC, id DESC);
CREATE INDEX IF NOT EXISTS decisions_store_subject_ts ON decisionlog.decisions (store, subject_type, subject_id, ts DESC);
CREATE INDEX IF NOT EXISTS decisions_store_resource_ts ON decisionlog.decisions (store, resource_type, resource_id, ts DESC);
CREATE INDEX IF NOT EXISTS decisions_id ON decisionlog.decisions (id);
CREATE TABLE IF NOT EXISTS decisionlog.erasures (
    store        text NOT NULL,
    subject_type text NOT NULL,
    subject_id   text NOT NULL,
    erased_at    timestamptz NOT NULL DEFAULT now(),
    erased_by    text,
    PRIMARY KEY (store, subject_type, subject_id, erased_at)
);
CREATE TABLE IF NOT EXISTS decisionlog.store_fences (
    store      text NOT NULL,
    store_id   integer NOT NULL,   -- the purged incarnation; 0 = lines without one
    purged_at  timestamptz NOT NULL,
    purged_by  text,
    PRIMARY KEY (store, store_id)
);
-- the predecessor table (store_purges, name-keyed): its fences carry over as
-- fences for lines without an id; the table itself stays until the fleet
-- has moved (an instance still writing it must not lose it)
DO $m$
BEGIN
    IF to_regclass('decisionlog.store_purges') IS NOT NULL THEN
        INSERT INTO decisionlog.store_fences (store, store_id, purged_at, purged_by)
        SELECT store, 0, purged_at, purged_by FROM decisionlog.store_purges
        ON CONFLICT (store, store_id) DO UPDATE SET purged_at = GREATEST(store_fences.purged_at, EXCLUDED.purged_at);
    END IF;
END
$m$;
`

// Erasure tombstones (review #21): a data-subject erasure deletes the
// persisted lines about a person, but a line the Logger accepted BEFORE the
// erasure may still sit in an instance's queue and flush afterwards. The
// erasing side writes a tombstone (store, subject, erased_at) into
// decisionlog.erasures; every batch this sink inserts is followed, in the
// same transaction, by a delete of the batch's rows that a tombstone
// covers — a line about the person decided at or before erased_at, on the
// subject or the resource side. Lines decided after the erasure are new
// data and stay. Tombstones are pruned with the retention window.
//
// Ordering (review #22): a batch and an erasure run in separate
// transactions, and under READ COMMITTED a batch that filtered before the
// tombstone committed could still commit after the erasure's delete. A
// transaction-level advisory lock orders them without serialising the
// sinks: every batch holds the lock SHARED for its transaction (batches
// never wait for each other), the erasure takes it EXCLUSIVE for an
// instant — after writing the tombstone, right before committing that tiny
// transaction — and runs its delete afterwards with no lock held. So a
// batch that filtered without seeing the tombstone has committed before
// the erasure's delete runs, and a batch that starts after the erasure's
// lock request filters after the tombstone is committed. The console's
// eraseDecisions mirrors erasureBarrierSQL; the key is hashtext of the
// tombstone table's name, the same on both sides of one database.
//
// Retention (dropping partitions, pruning tombstones) runs under the same
// lock, exclusive, in one transaction — so it cannot slip between a batch's
// age check and its commit (review #23) — and the age check is made inside
// the batch transaction, after the lock, on the database clock: one clock
// for every instance, read after any retention that ran before has
// committed. Dropping a partition takes an ACCESS EXCLUSIVE lock on the
// table anyway, so batches waited for retention before this; the advisory
// lock adds no new wait.
const (
	batchLockSQL      = `SELECT pg_advisory_xact_lock_shared(hashtext('decisionlog.erasures'))`
	erasureBarrierSQL = `SELECT pg_advisory_xact_lock(hashtext('decisionlog.erasures'))`
	// retentionCutoffSQL is the first day kept, on the database clock (UTC
	// midnight, retention days back) — the one boundary for dropping,
	// pruning and accepting.
	retentionCutoffSQL = `SELECT date_trunc('day', clock_timestamp(), 'UTC') - make_interval(days => $1)`
)

const applyErasuresSQL = `
DELETE FROM decisionlog.decisions d
 USING decisionlog.erasures e
 WHERE d.id > $1
   AND d.store = e.store
   AND d.ts <= e.erased_at
   AND ((d.subject_type = e.subject_type AND d.subject_id = e.subject_id)
     OR (d.resource_type = e.subject_type AND d.resource_id = e.subject_id))`

// Store fences: a store deleted with its decision log purged leaves a row
// per purged incarnation (store, store_id), written under the same
// exclusive barrier as a tombstone; every batch drops its lines of that
// incarnation, so a buffered line cannot outlive the purge (nor an erased
// subject's line come back once the tombstones went with the store). A
// store recreated under the name has a new id and is untouched. Lines
// without an id (OPA-fronted decisions, lines from before the id existed)
// fall back to the deletion time. Fences are pruned with retention.
const applyStoreFencesSQL = `
DELETE FROM decisionlog.decisions d
 USING decisionlog.store_fences f
 WHERE d.id > $1
   AND d.store = f.store
   AND (d.store_id = f.store_id OR (d.store_id IS NULL AND d.ts <= f.purged_at))`

var columns = []string{"ts", "request_id", "trace_id", "span_id", "listener", "endpoint", "via", "store", "store_id", "subject_type", "subject_id", "action",
	"resource_type", "resource_id", "decision", "state", "reason", "actor", "client", "issuer", "latency_ms", "error", "line"}

// row is one decision line as table columns.
type row struct {
	ts   time.Time
	vals []any
}

// store is what the sink needs from the database (a pool in production,
// a fake in tests).
type store interface {
	ensurePartitions(ctx context.Context, days []time.Time) error
	insert(ctx context.Context, rows []row, retentionDays int) (expired int, err error)
	retain(ctx context.Context, retentionDays int) (dropped int, err error)
	purgeStore(ctx context.Context, store string, storeID int32, by string, before time.Time) (int64, error)
	close()
}

// ErrQueueFull is returned by Write when the queue has no room (the line
// is dropped and counted by the Logger as an error).
var ErrQueueFull = errors.New("decision log queue full")

// PostgresSink is the io.Writer + io.Closer the Logger writes to.
type PostgresSink struct {
	cfg           PostgresConfig
	db            store
	q             chan []byte
	pending       bytes.Buffer // a partial line between Writes
	wmu           sync.Mutex   // Write
	fmu           sync.Mutex   // one flush at a time
	down          atomic.Bool
	lastErr       atomic.Pointer[error]
	ensured       sync.Map // day (YYYYMMDD) → true
	lastRetention time.Time
	stop          chan struct{}
	done          chan struct{}
	// OnFlush, when set, is called after every insert attempt with "ok" or
	// "error" and the number of lines (wired to metrics by the daemon).
	OnFlush func(result string, lines int)
	// OnDrop, when set, is called with the number of ACCEPTED lines a failed
	// batch could not keep (the queue was full when they were put back):
	// evidence that is gone, to be counted and alarmed on. Dropped is the
	// running total.
	OnDrop  func(lines int)
	Dropped atomic.Int64
	// OnExpired, when set, is called with the number of lines a batch
	// refused because they are older than the retention window (review
	// #22): such a line would recreate a dropped partition and could outlive
	// the erasure tombstone that covered it. Expired is the running total.
	OnExpired func(lines int)
	Expired   atomic.Int64
	// Queued reports the current queue length (metrics).
	Queued func() int
	// now is the local clock of the first-pass age check (tests skew it
	// against the database's).
	now func() time.Time
}

// OpenPostgres connects, creates the schema and table when missing, ensures
// today's and tomorrow's partitions, and starts the flusher.
func OpenPostgres(ctx context.Context, cfg PostgresConfig) (*PostgresSink, error) {
	if strings.TrimSpace(cfg.DSN) == "" {
		return nil, errors.New("decision log sink postgres: DECISION_LOG_DSN is required")
	}
	pc, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("decision log sink postgres: %w", err)
	}
	pc.MaxConns = 2
	pc.ConnConfig.RuntimeParams["application_name"] = "pgauthzd-decision-log"
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("decision log sink postgres: %w", err)
	}
	db := &pgStore{pool: pool}
	if err := db.init(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("decision log sink postgres: %w", err)
	}
	return newPostgresSink(cfg, db), nil
}

func newPostgresSink(cfg PostgresConfig, db store) *PostgresSink {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 10000
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 500
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = time.Second
	}
	s := &PostgresSink{cfg: cfg, db: db, q: make(chan []byte, cfg.QueueSize), stop: make(chan struct{}), done: make(chan struct{}), now: time.Now}
	s.Queued = func() int { return len(s.q) }
	go s.run()
	return s
}

// Write queues complete lines; a trailing partial line waits for the rest.
// Returns ErrQueueFull (the line dropped) when there is no room, and the
// last insert error while the sink is down — after trying a synchronous
// flush, which is how the sink recovers.
func (s *PostgresSink) Write(p []byte) (int, error) {
	s.wmu.Lock()
	s.pending.Write(p)
	var dropped bool
	for {
		b := s.pending.Bytes()
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			break
		}
		line := bytes.TrimSpace(b[:i])
		s.pending.Next(i + 1)
		if len(line) == 0 {
			continue
		}
		select {
		case s.q <- append([]byte(nil), line...):
		default:
			dropped = true
		}
	}
	s.wmu.Unlock()
	if dropped {
		return len(p), ErrQueueFull
	}
	if s.down.Load() {
		// Recovery attempt on the caller's thread (rate-limited by the
		// Logger's probe): the queue is flushed now; success clears down.
		if err := s.flushNow(context.Background()); err != nil {
			return len(p), err
		}
	}
	return len(p), nil
}

// Down reports whether the last insert failed.
func (s *PostgresSink) Down() bool { return s.down.Load() }

// run is the flusher: lines collect into a batch that is inserted when it
// reaches BatchSize or at the next tick (FlushInterval); retention runs
// once an hour on the tick.
func (s *PostgresSink) run() {
	defer close(s.done)
	ctx := context.Background()
	t := time.NewTicker(s.cfg.FlushInterval)
	defer t.Stop()
	var pending [][]byte
	for {
		select {
		case <-s.stop:
			if len(pending) > 0 {
				_ = s.flushMany(ctx, pending)
			}
			return
		case <-t.C:
			if len(pending) > 0 {
				_ = s.flushMany(ctx, pending)
				pending = nil
			}
			s.retention(ctx)
		case line := <-s.q:
			pending = append(pending, line)
			if len(pending) >= s.cfg.BatchSize {
				_ = s.flushMany(ctx, pending)
				pending = nil
			}
		}
	}
}

func (s *PostgresSink) drain(batch [][]byte, max int) [][]byte {
	for len(batch) < max+1 {
		select {
		case l := <-s.q:
			batch = append(batch, l)
		default:
			return batch
		}
	}
	return batch
}

// flushNow inserts everything queued, in batches, and returns the first error.
func (s *PostgresSink) flushNow(ctx context.Context) error {
	for {
		batch := s.drain(nil, s.cfg.BatchSize-1)
		if len(batch) == 0 {
			if s.down.Load() {
				// nothing to insert: probe with the pending state unchanged
				if e := s.lastErr.Load(); e != nil {
					return *e
				}
			}
			return nil
		}
		if err := s.flushMany(ctx, batch); err != nil {
			return err
		}
	}
}

// flushMany inserts one batch; on failure the lines are re-queued (what
// fits) and the sink is marked down.
func (s *PostgresSink) flushMany(ctx context.Context, batch [][]byte) error {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	rows := make([]row, 0, len(batch))
	days := map[string]time.Time{}
	var oldest time.Time
	if s.cfg.RetentionDays > 0 {
		// one day of grace: this pass runs on the local clock, and a clock
		// ahead of the database's must not discard a line the database
		// would still keep (review #24) — only the transaction's check
		// refuses for good. The grace bounds the tolerated skew: a local
		// clock more than a day ahead of the database's would still
		// discard the window's oldest day here.
		oldest = retentionCutoffAt(s.now(), s.cfg.RetentionDays+1)
	}
	expired := 0
	kept := make([][]byte, 0, len(batch)) // the lines behind rows, for re-queueing
	for _, line := range batch {
		r, err := parseRow(line)
		if err != nil {
			continue // not a decision line; skip, never block the stream
		}
		if !oldest.IsZero() && r.ts.Before(oldest) {
			// older than retention by more than a day: never accepted (see
			// OnExpired). This first pass, on the local clock, spares
			// ensurePartitions from recreating a dropped day; the binding
			// check is insert's, in the transaction, on the database clock
			// (a line in the grace day may recreate an empty partition that
			// the next retention run drops again — harmless).
			expired++
			continue
		}
		rows = append(rows, r)
		kept = append(kept, line)
		day := r.ts.UTC().Truncate(24 * time.Hour)
		if _, ok := s.ensured.Load(day.Format("20060102")); !ok {
			days[day.Format("20060102")] = day
		}
	}
	countExpired := func() {
		if expired == 0 {
			return
		}
		s.Expired.Add(int64(expired))
		slog.Warn("decision log: lines older than the retention window refused", "expired", expired, "total_expired", s.Expired.Load(), "retention_days", s.cfg.RetentionDays)
		if s.OnExpired != nil {
			s.OnExpired(expired)
		}
	}
	if len(rows) == 0 {
		countExpired()
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var err error
	if len(days) > 0 {
		list := make([]time.Time, 0, len(days))
		for _, d := range days {
			list = append(list, d)
		}
		if err = s.db.ensurePartitions(cctx, list); err == nil {
			for k := range days {
				s.ensured.Store(k, true)
			}
		}
	}
	if err == nil {
		var late int
		late, err = s.db.insert(cctx, rows, s.cfg.RetentionDays)
		if err == nil {
			expired += late
		}
	}
	countExpired()
	if err != nil {
		s.down.Store(true)
		s.lastErr.Store(&err)
		// keep the lines for the next attempt — what the queue can hold; the
		// rest is lost and said so (counted, logged): a line the Logger
		// accepted has no recoverable trail once the queue cannot take it back.
		dropped := 0
		for _, line := range kept {
			select {
			case s.q <- line:
			default:
				dropped++
			}
		}
		if dropped > 0 {
			s.Dropped.Add(int64(dropped))
			slog.Error("decision log: lines lost — the sink is down and the queue is full", "dropped", dropped, "total_dropped", s.Dropped.Load(), "queue", cap(s.q), "err", err)
			if s.OnDrop != nil {
				s.OnDrop(dropped)
			}
		}
		if s.OnFlush != nil {
			s.OnFlush("error", len(rows))
		}
		return err
	}
	s.down.Store(false)
	if s.OnFlush != nil {
		s.OnFlush("ok", len(rows))
	}
	return nil
}

// retentionCutoff is the local-clock twin of retentionCutoffSQL: the first
// day the sink keeps. flushMany uses it, one day wider, for the cheap first
// pass; the database's own answer decides inside the transactions.
func retentionCutoff(days int) time.Time { return retentionCutoffAt(time.Now(), days) }

func retentionCutoffAt(now time.Time, days int) time.Time {
	return now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -days)
}

// retention drops partitions older than RetentionDays, once an hour.
func (s *PostgresSink) retention(ctx context.Context) {
	if s.cfg.RetentionDays <= 0 {
		return
	}
	if time.Since(s.lastRetention) < time.Hour {
		return
	}
	s.lastRetention = time.Now()
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := s.db.retain(cctx, s.cfg.RetentionDays); err != nil {
		slog.Warn("decision log: retention failed; retried in an hour", "err", err)
	}
	// a dropped day must be re-ensured should a late line still name it
	s.ensured.Range(func(k, _ any) bool { s.ensured.Delete(k); return true })
}

// PurgeStore removes the lines of one deleted incarnation of a store
// (storeID, from the engine's deletion receipt) and the lines without an id
// decided at or before `before` (the receipt's deletion time), plus the
// store's tombstones up to then, behind the store fence. Idempotent.
func (s *PostgresSink) PurgeStore(ctx context.Context, store string, storeID int32, by string, before time.Time) (int64, error) {
	if storeID <= 0 {
		return 0, errors.New("decision log: a store purge names the deleted incarnation (store_id > 0)")
	}
	return s.db.purgeStore(ctx, store, storeID, by, before)
}

// Close stops the flusher, inserts what is queued and closes the pool.
func (s *PostgresSink) Close() error {
	close(s.stop)
	<-s.done
	err := s.flushNow(context.Background())
	s.db.close()
	return err
}

// parseRow turns a line into table columns. The JSON stays in `line`.
func parseRow(line []byte) (row, error) {
	var e Entry
	if err := json.Unmarshal(line, &e); err != nil {
		return row{}, err
	}
	if e.Time.IsZero() || e.Store == "" && e.Endpoint == "" {
		return row{}, errors.New("not a decision line")
	}
	var decision any
	if e.Decision != nil {
		decision = *e.Decision
	}
	return row{ts: e.Time, vals: []any{
		e.Time, nullable(e.RequestID), nullable(e.TraceID), nullable(e.SpanID), e.Listener, e.Endpoint, nullable(e.Via), e.Store, nullableID(e.StoreID),
		nullable(e.Subject.Type), nullable(e.Subject.ID), nullable(e.Action),
		nullable(e.Resource.Type), nullable(e.Resource.ID),
		decision, nullable(e.State), nullable(e.Reason), nullable(e.Actor), nullable(e.Client), nullable(e.Issuer),
		float32(e.LatencyMS), nullable(e.Error), line,
	}}, nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableID(id int32) any {
	if id == 0 {
		return nil
	}
	return id
}

// ── the real store ──────────────────────────────────────────────────────

type pgStore struct{ pool *pgxpool.Pool }

func (p *pgStore) init(ctx context.Context) error {
	if _, err := p.pool.Exec(ctx, DDL); err != nil && !isDuplicate(err) {
		return err
	}
	now := time.Now().UTC().Truncate(24 * time.Hour)
	return p.ensurePartitions(ctx, []time.Time{now, now.AddDate(0, 0, 1)})
}

func partitionName(day time.Time) string { return Table + "_" + day.UTC().Format("20060102") }

func (p *pgStore) ensurePartitions(ctx context.Context, days []time.Time) error {
	for _, d := range days {
		d = d.UTC().Truncate(24 * time.Hour)
		sql := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.%s PARTITION OF %s.%s FOR VALUES FROM ('%s') TO ('%s')`,
			Schema, partitionName(d), Schema, Table, d.Format("2006-01-02"), d.AddDate(0, 0, 1).Format("2006-01-02"))
		if _, err := p.pool.Exec(ctx, sql); err != nil && !isDuplicate(err) {
			return err
		}
	}
	return nil
}

// insert copies a batch in and, in the same transaction, removes the rows
// of that batch an erasure tombstone covers (see applyErasuresSQL); rows
// older than the retention window are refused (returned as expired).
func (p *pgStore) insert(ctx context.Context, rows []row, retentionDays int) (int, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	expired, err := insertTx(ctx, tx, rows, retentionDays)
	if err != nil {
		return 0, err
	}
	return expired, tx.Commit(ctx)
}

// insertTx is insert's body in a caller-owned transaction: the shared
// erasure lock first (held until the caller commits), then the age check
// on the database clock, then COPY, then the tombstone filter. Separate so
// the two-session tests can hold the transaction open at the point an
// erasure or a retention run may interleave.
func insertTx(ctx context.Context, tx pgx.Tx, rows []row, retentionDays int) (int, error) {
	if _, err := tx.Exec(ctx, batchLockSQL); err != nil {
		return 0, err
	}
	expired := 0
	if retentionDays > 0 {
		var cutoff time.Time
		if err := tx.QueryRow(ctx, retentionCutoffSQL, retentionDays).Scan(&cutoff); err != nil {
			return 0, err
		}
		live := rows[:0:0]
		for _, r := range rows {
			if r.ts.Before(cutoff) {
				expired++
				continue
			}
			live = append(live, r)
		}
		rows = live
	}
	if len(rows) == 0 {
		return expired, nil
	}
	src := make([][]any, len(rows))
	for i, r := range rows {
		src[i] = r.vals
	}
	var minID int64
	if err := tx.QueryRow(ctx, `SELECT coalesce(pg_sequence_last_value(pg_get_serial_sequence($1, 'id')::regclass), 0)`, Schema+"."+Table).Scan(&minID); err != nil {
		return 0, err
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{Schema, Table}, columns, pgx.CopyFromRows(src)); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, applyErasuresSQL, minID); err != nil {
		return 0, err
	}
	_, err := tx.Exec(ctx, applyStoreFencesSQL, minID)
	return expired, err
}

// querier is what the retention helpers need: a pool or a transaction.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// retain is one retention run in one transaction under the exclusive
// erasure lock: the cutoff on the database clock, then the daily
// partitions before it dropped, the rows before it swept from the default
// partition (a late line that found no dated partition), and the
// tombstones before it pruned — their lines are gone with the partitions,
// and no batch can accept one again (insertTx checks the same cutoff under
// the shared lock).
func (p *pgStore) retain(ctx context.Context, retentionDays int) (int, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '30s'`); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, erasureBarrierSQL); err != nil {
		return 0, err
	}
	var cutoff time.Time
	if err := tx.QueryRow(ctx, retentionCutoffSQL, retentionDays).Scan(&cutoff); err != nil {
		return 0, err
	}
	dropped, err := dropPartitionsBefore(ctx, tx, cutoff)
	if err != nil {
		return dropped, err
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf(`DELETE FROM %s.%s_default WHERE ts < $1`, Schema, Table), cutoff); err != nil {
		return dropped, err
	}
	if err := pruneErasures(ctx, tx, cutoff); err != nil {
		return dropped, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM decisionlog.store_fences WHERE purged_at < $1`, cutoff); err != nil {
		return dropped, err
	}
	return dropped, tx.Commit(ctx)
}

// purgeStore: the fence (upsert, purged_at = now) and the exclusive barrier
// in one small transaction — committed, so a batch that filtered without
// the fence has committed and a later one applies it — then the store's
// lines and tombstones in one transaction with no lock held.
func (p *pgStore) purgeStore(ctx context.Context, store string, storeID int32, by string, before time.Time) (int64, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// the lock before the fence rows: retention deletes expired fences under
	// the same lock, so the other order could deadlock on a row
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '10s'`); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, erasureBarrierSQL); err != nil {
		return 0, err
	}
	const upsert = `INSERT INTO decisionlog.store_fences (store, store_id, purged_at, purged_by) VALUES ($1, $2, $3, $4)
	                ON CONFLICT (store, store_id) DO UPDATE SET purged_at = GREATEST(store_fences.purged_at, EXCLUDED.purged_at), purged_by = EXCLUDED.purged_by`
	for _, id := range []int32{storeID, 0} { // the incarnation, and the fence for lines without an id
		if _, err := tx.Exec(ctx, upsert, store, id, before, by); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	tx2, err := p.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx2.Rollback(ctx) }()
	tag, err := tx2.Exec(ctx, `DELETE FROM decisionlog.decisions WHERE store = $1 AND (store_id = $2 OR (store_id IS NULL AND ts <= $3))`, store, storeID, before)
	if err != nil {
		return 0, err
	}
	if _, err := tx2.Exec(ctx, `DELETE FROM decisionlog.erasures WHERE store = $1 AND erased_at <= $2`, store, before); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), tx2.Commit(ctx)
}

// pruneErasures drops tombstones older than the retention cutoff.
func pruneErasures(ctx context.Context, q querier, cutoff time.Time) error {
	_, err := q.Exec(ctx, `DELETE FROM decisionlog.erasures WHERE erased_at < $1`, cutoff)
	return err
}

// dropPartitionsBefore drops the daily partitions whose day is before cutoff.
func dropPartitionsBefore(ctx context.Context, q querier, cutoff time.Time) (int, error) {
	rows, err := q.Query(ctx, `
		SELECT c.relname FROM pg_inherits i
		  JOIN pg_class c ON c.oid = i.inhrelid
		  JOIN pg_class parent ON parent.oid = i.inhparent
		  JOIN pg_namespace n ON n.oid = parent.relnamespace
		 WHERE n.nspname = $1 AND parent.relname = $2 AND c.relname ~ ('^' || $2 || '_[0-9]{8}$')`, Schema, Table)
	if err != nil {
		return 0, err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err == nil {
			names = append(names, n)
		}
	}
	rows.Close()
	dropped := 0
	for _, n := range names {
		day, err := time.Parse("20060102", strings.TrimPrefix(n, Table+"_"))
		if err != nil || !day.Before(cutoff) {
			continue
		}
		if _, err := q.Exec(ctx, fmt.Sprintf(`DROP TABLE IF EXISTS %s.%s`, Schema, n)); err != nil {
			return dropped, err
		}
		dropped++
	}
	return dropped, nil
}

func (p *pgStore) close() { p.pool.Close() }

// isDuplicate: two instances creating the same object at once — the loser
// sees duplicate_table (42P07) or a unique violation on pg_type (23505).
func isDuplicate(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "42P07" || pgErr.Code == "23505"
	}
	return false
}

// PingPostgres checks a sink DSN without creating anything (doctor).
func PingPostgres(ctx context.Context, dsn string) error {
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer c.Close(ctx)
	return c.Ping(ctx)
}
