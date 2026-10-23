package decisionlog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
CREATE INDEX IF NOT EXISTS decisions_store_trace ON decisionlog.decisions (store, trace_id) WHERE trace_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS decisions_store_ts ON decisionlog.decisions (store, ts DESC, id DESC);
CREATE INDEX IF NOT EXISTS decisions_store_subject_ts ON decisionlog.decisions (store, subject_type, subject_id, ts DESC);
CREATE INDEX IF NOT EXISTS decisions_store_resource_ts ON decisionlog.decisions (store, resource_type, resource_id, ts DESC);
`

var columns = []string{"ts", "request_id", "trace_id", "span_id", "listener", "endpoint", "via", "store", "subject_type", "subject_id", "action",
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
	insert(ctx context.Context, rows []row) error
	dropPartitionsBefore(ctx context.Context, cutoff time.Time) (int, error)
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
	// Queued reports the current queue length (metrics).
	Queued func() int
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
	s := &PostgresSink{cfg: cfg, db: db, q: make(chan []byte, cfg.QueueSize), stop: make(chan struct{}), done: make(chan struct{})}
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
	for _, line := range batch {
		r, err := parseRow(line)
		if err != nil {
			continue // not a decision line; skip, never block the stream
		}
		rows = append(rows, r)
		day := r.ts.UTC().Truncate(24 * time.Hour)
		if _, ok := s.ensured.Load(day.Format("20060102")); !ok {
			days[day.Format("20060102")] = day
		}
	}
	if len(rows) == 0 {
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
		err = s.db.insert(cctx, rows)
	}
	if err != nil {
		s.down.Store(true)
		s.lastErr.Store(&err)
		// keep the lines for the next attempt (what the queue can hold)
		for _, line := range batch {
			select {
			case s.q <- line:
			default:
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
	cutoff := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -s.cfg.RetentionDays)
	_, _ = s.db.dropPartitionsBefore(cctx, cutoff)
	// a dropped day must be re-ensured should a late line still name it
	s.ensured.Range(func(k, _ any) bool { s.ensured.Delete(k); return true })
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
		e.Time, nullable(e.RequestID), nullable(e.TraceID), nullable(e.SpanID), e.Listener, e.Endpoint, nullable(e.Via), e.Store,
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

func (p *pgStore) insert(ctx context.Context, rows []row) error {
	src := make([][]any, len(rows))
	for i, r := range rows {
		src[i] = r.vals
	}
	_, err := p.pool.CopyFrom(ctx, pgx.Identifier{Schema, Table}, columns, pgx.CopyFromRows(src))
	return err
}

// dropPartitionsBefore drops the daily partitions whose day is before cutoff.
func (p *pgStore) dropPartitionsBefore(ctx context.Context, cutoff time.Time) (int, error) {
	rows, err := p.pool.Query(ctx, `
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
		if _, err := p.pool.Exec(ctx, fmt.Sprintf(`DROP TABLE IF EXISTS %s.%s`, Schema, n)); err != nil {
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
