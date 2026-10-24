package decisionlog

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fakeStore records what the sink asks of the database and can fail inserts.
type fakeStore struct {
	mu       sync.Mutex
	inserts  [][]row
	ensured  []time.Time
	dropped  []time.Time
	failWith error
	closed   bool
}

func (f *fakeStore) ensurePartitions(_ context.Context, days []time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensured = append(f.ensured, days...)
	return nil
}

func (f *fakeStore) insert(_ context.Context, rows []row) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != nil {
		return f.failWith
	}
	cp := append([]row(nil), rows...)
	f.inserts = append(f.inserts, cp)
	return nil
}

func (f *fakeStore) dropPartitionsBefore(_ context.Context, cutoff time.Time) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dropped = append(f.dropped, cutoff)
	return 1, nil
}

func (f *fakeStore) close()                                         { f.mu.Lock(); f.closed = true; f.mu.Unlock() }
func (f *fakeStore) pruneErasures(context.Context, time.Time) error { return nil }

func (f *fakeStore) rows() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, b := range f.inserts {
		n += len(b)
	}
	return n
}

func (f *fakeStore) batches() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.inserts) }

func (f *fakeStore) fail(err error) { f.mu.Lock(); f.failWith = err; f.mu.Unlock() }

func line(store, id string) string {
	return `{"ts":"2026-10-23T10:00:00Z","listener":"public","endpoint":"check","store":"` + store + `","subject":{"type":"user","id":"` + id + `"},"action":"can_read","resource":{"type":"doc","id":"d1"},"decision":true,"latency_ms":0.5}` + "\n"
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Lines batch by size and by the tick; the batch's day gets its partition
// ensured before the insert; Close flushes what is left.
func TestPostgresSinkBatches(t *testing.T) {
	f := &fakeStore{}
	s := newPostgresSink(PostgresConfig{BatchSize: 2, FlushInterval: 50 * time.Millisecond, QueueSize: 100}, f)
	var flushed []string
	var fmu sync.Mutex
	s.OnFlush = func(result string, n int) { fmu.Lock(); flushed = append(flushed, result); fmu.Unlock() }
	for _, id := range []string{"a", "b", "c"} {
		if _, err := s.Write([]byte(line("demo", id))); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "two batches (size, then tick)", func() bool { return f.rows() == 3 && f.batches() == 2 })
	if len(f.inserts[0]) != 2 || len(f.inserts[1]) != 1 {
		t.Fatalf("batch sizes %d/%d, want 2/1", len(f.inserts[0]), len(f.inserts[1]))
	}
	if len(f.ensured) == 0 || f.ensured[0].Format("20060102") != "20261023" {
		t.Fatalf("partition of the line's day not ensured: %v", f.ensured)
	}
	// the day is ensured once, not per batch
	if len(f.ensured) != 1 {
		t.Fatalf("ensured %d times, want 1", len(f.ensured))
	}
	// a partial write completes on the next one
	l := line("demo", "d")
	if _, err := s.Write([]byte(l[:10])); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte(l[10:])); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if f.rows() != 4 || !f.closed {
		t.Fatalf("after close: %d rows, closed=%v", f.rows(), f.closed)
	}
	fmu.Lock()
	defer fmu.Unlock()
	for _, r := range flushed {
		if r != "ok" {
			t.Fatalf("flush results %v", flushed)
		}
	}
}

// A failed insert marks the sink down: Write reports the error (so
// DECISION_LOG_REQUIRED fails closed), keeps the lines, and the next Write —
// the Logger's probe — flushes synchronously and clears the state once the
// database is back.
func TestPostgresSinkDownAndRecovery(t *testing.T) {
	f := &fakeStore{}
	boom := errors.New("connection refused")
	f.fail(boom)
	s := newPostgresSink(PostgresConfig{BatchSize: 1, FlushInterval: time.Hour, QueueSize: 100}, f)
	if _, err := s.Write([]byte(line("demo", "a"))); err != nil {
		t.Fatalf("the first write is queued, not yet failed: %v", err)
	}
	waitFor(t, "sink down", s.Down)
	if _, err := s.Write([]byte(line("demo", "b"))); !errors.Is(err, boom) {
		t.Fatalf("write while down must report the insert error, got %v", err)
	}
	f.fail(nil)
	if _, err := s.Write([]byte(line("demo", "c"))); err != nil {
		t.Fatalf("the write after recovery must succeed: %v", err)
	}
	if s.Down() {
		t.Fatal("sink still down after a successful flush")
	}
	_ = s.Close()
	if f.rows() != 3 {
		t.Fatalf("%d rows after recovery, want 3 (nothing lost)", f.rows())
	}
}

// A full queue drops the line and says so; malformed lines never block.
func TestPostgresSinkQueueFullAndMalformed(t *testing.T) {
	f := &fakeStore{}
	f.fail(errors.New("down"))
	s := newPostgresSink(PostgresConfig{BatchSize: 1000, FlushInterval: time.Hour, QueueSize: 2}, f)
	_, _ = s.Write([]byte(line("demo", "a")))
	_, _ = s.Write([]byte(line("demo", "b")))
	if _, err := s.Write([]byte(line("demo", "c"))); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("third line must be dropped: %v", err)
	}
	f.fail(nil)
	_, _ = s.Write([]byte("not json\n"))
	_ = s.Close()
	if f.rows() != 2 {
		t.Fatalf("%d rows, want the 2 queued lines (malformed skipped)", f.rows())
	}
}

func TestPostgresSinkRetention(t *testing.T) {
	f := &fakeStore{}
	s := newPostgresSink(PostgresConfig{RetentionDays: 7, FlushInterval: time.Hour}, f)
	s.retention(context.Background())
	if len(f.dropped) != 1 {
		t.Fatalf("retention did not run: %v", f.dropped)
	}
	want := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -7)
	if !f.dropped[0].Equal(want) {
		t.Fatalf("cutoff %v, want %v", f.dropped[0], want)
	}
	s.retention(context.Background()) // once an hour
	if len(f.dropped) != 1 {
		t.Fatal("retention ran twice within the hour")
	}
	_ = s.Close()
	f2 := &fakeStore{}
	s2 := newPostgresSink(PostgresConfig{RetentionDays: 0, FlushInterval: time.Hour}, f2)
	s2.retention(context.Background())
	_ = s2.Close()
	if len(f2.dropped) != 0 {
		t.Fatal("retention 0 must keep everything")
	}
}

func TestParseRow(t *testing.T) {
	r, err := parseRow([]byte(strings.TrimSpace(line("demo", "alice"))))
	if err != nil {
		t.Fatal(err)
	}
	if r.vals[7] != "demo" || r.vals[9] != "alice" || r.vals[13] != true || r.vals[1] != nil || r.vals[2] != nil {
		t.Fatalf("columns: %v", r.vals)
	}
	r2, _ := parseRow([]byte(`{"ts":"2026-10-23T10:00:00Z","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","span_id":"00f067aa0ba902b7","listener":"public","endpoint":"check","store":"demo"}`))
	if r2.vals[2] != "4bf92f3577b34da6a3ce929d0e0e4736" || r2.vals[3] != "00f067aa0ba902b7" {
		t.Fatalf("trace columns: %v", r2.vals)
	}
	if _, err := parseRow([]byte(`{"ts":"2026-10-23T10:00:00Z"}`)); err == nil {
		t.Fatal("a line without store/endpoint must be refused")
	}
}

// The Logger over the postgres sink: one line per Log, flushed by Close.
func TestOpenPostgresNeedsDSN(t *testing.T) {
	if _, err := Open(Config{Sink: "postgres", Sample: 1}); err == nil || !strings.Contains(err.Error(), "DECISION_LOG_DSN") {
		t.Fatalf("postgres without a DSN must be refused: %v", err)
	}
}

// Integration: against a real database (PGAUTHZD_TEST_DECISION_LOG_DSN), the
// schema is created, lines land in the day's partition, the plain query the
// console runs finds them, and retention drops old partitions.
func TestPostgresSinkIntegration(t *testing.T) {
	dsn := os.Getenv("PGAUTHZD_TEST_DECISION_LOG_DSN")
	if dsn == "" {
		t.Skip("PGAUTHZD_TEST_DECISION_LOG_DSN not set")
	}
	ctx := context.Background()
	ps, err := OpenPostgres(ctx, PostgresConfig{DSN: dsn, FlushInterval: 50 * time.Millisecond}) // retention is exercised explicitly below
	if err != nil {
		t.Fatal(err)
	}
	db := ps.db.(*pgStore)
	defer func() {
		_, _ = db.pool.Exec(ctx, `DROP SCHEMA IF EXISTS decisionlog CASCADE`)
		db.pool.Close()
	}()
	l := New(ps, 1, nil)
	decided := true
	for _, id := range []string{"alice", "bob"} {
		l.Log(Entry{Listener: "public", Endpoint: "check", Store: "it_demo", Subject: Ref{Type: "user", ID: id},
			Action: "can_read", Resource: Ref{Type: "doc", ID: "d1"}, Decision: &decided, State: "allow", Reason: "direct_tuple",
			ContextKeys: []string{"ip"}, LatencyMS: 1.5, TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", SpanID: "00f067aa0ba902b7"})
	}
	// an old line goes to a partition retention will drop
	old := time.Now().UTC().AddDate(0, 0, -30)
	l.Log(Entry{Time: old, Listener: "public", Endpoint: "check", Store: "it_demo", Subject: Ref{Type: "user", ID: "zed"}, Action: "can_read", Resource: Ref{Type: "doc", ID: "d1"}})
	waitFor(t, "lines inserted", func() bool {
		var n int
		_ = db.pool.QueryRow(ctx, `SELECT count(*) FROM decisionlog.decisions WHERE store = 'it_demo'`).Scan(&n)
		return n == 3
	})
	var reason, traceID string
	var keys []string
	if err := db.pool.QueryRow(ctx, `SELECT reason, coalesce(trace_id,''), ARRAY(SELECT jsonb_array_elements_text(line->'context_keys')) FROM decisionlog.decisions WHERE store='it_demo' AND subject_id='alice'`).Scan(&reason, &traceID, &keys); err != nil || reason != "direct_tuple" || len(keys) != 1 || traceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("row: %q %q %v %v", reason, traceID, keys, err)
	}
	var parts int
	if err := db.pool.QueryRow(ctx, `SELECT count(*) FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid WHERE c.relname ~ '^decisions_[0-9]{8}$'`).Scan(&parts); err != nil || parts < 3 {
		t.Fatalf("partitions: %d %v, want today, tomorrow and the old day", parts, err)
	}
	n, err := db.dropPartitionsBefore(ctx, time.Now().UTC().AddDate(0, 0, -7))
	if err != nil || n != 1 {
		t.Fatalf("retention dropped %d (%v), want 1", n, err)
	}

	// Erasure tombstones (review #21): alice is erased now; a line about her
	// decided BEFORE the erasure that flushes afterwards is dropped on
	// insert — on the subject side and on the resource side — while a line
	// decided after the erasure stays, and so does everyone else's.
	erasedAt := time.Now().UTC()
	if _, err := db.pool.Exec(ctx, `INSERT INTO decisionlog.erasures (store, subject_type, subject_id, erased_at, erased_by) VALUES ('it_demo', 'user', 'alice', $1, 'test')`, erasedAt); err != nil {
		t.Fatal(err)
	}
	before, after := erasedAt.Add(-time.Minute), erasedAt.Add(time.Minute)
	l.Log(Entry{Time: before, Listener: "public", Endpoint: "check", Store: "it_demo", Subject: Ref{Type: "user", ID: "alice"}, Action: "can_read", Resource: Ref{Type: "doc", ID: "late"}})
	l.Log(Entry{Time: before, Listener: "public", Endpoint: "check", Store: "it_demo", Subject: Ref{Type: "user", ID: "bob"}, Action: "can_read_user", Resource: Ref{Type: "user", ID: "alice"}})
	l.Log(Entry{Time: before, Listener: "public", Endpoint: "check", Store: "it_demo", Subject: Ref{Type: "user", ID: "bob"}, Action: "can_read", Resource: Ref{Type: "doc", ID: "late"}})
	l.Log(Entry{Time: after, Listener: "public", Endpoint: "check", Store: "it_demo", Subject: Ref{Type: "user", ID: "alice"}, Action: "can_read", Resource: Ref{Type: "doc", ID: "new"}})
	waitFor(t, "late lines flushed", func() bool {
		var n int
		_ = db.pool.QueryRow(ctx, `SELECT count(*) FROM decisionlog.decisions WHERE store = 'it_demo' AND resource_id IN ('late', 'new')`).Scan(&n)
		return n == 2
	})
	var kept []string
	rows, _ := db.pool.Query(ctx, `SELECT subject_id || '>' || resource_id FROM decisionlog.decisions WHERE store = 'it_demo' AND resource_id IN ('late', 'new') ORDER BY 1`)
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		kept = append(kept, s)
	}
	rows.Close()
	if strings.Join(kept, ",") != "alice>new,bob>late" {
		t.Fatalf("after the tombstone: %v (want alice's post-erasure line and bob's unrelated line only)", kept)
	}
	if err := db.pruneErasures(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var left int
	_ = db.pool.QueryRow(ctx, `SELECT count(*) FROM decisionlog.erasures`).Scan(&left)
	if left != 0 {
		t.Fatalf("tombstones left after pruning: %d", left)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

// Review #22 P1: a batch and an erasure in overlapping transactions. The
// erasure's barrier (tombstone, then the exclusive advisory lock, then
// commit; the delete afterwards) must wait for a batch in flight and make
// a later batch see the tombstone — in both orders, deterministically.
func TestPostgresSinkErasureInterleavings(t *testing.T) {
	dsn := os.Getenv("PGAUTHZD_TEST_DECISION_LOG_DSN")
	if dsn == "" {
		t.Skip("PGAUTHZD_TEST_DECISION_LOG_DSN not set")
	}
	ctx := context.Background()
	ps, err := OpenPostgres(ctx, PostgresConfig{DSN: dsn, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	db := ps.db.(*pgStore)
	// the sink pool is capped at two connections (one per batch in flight);
	// the erasing side and the observer are other clients with their own
	aux, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = aux.Exec(ctx, `DROP SCHEMA IF EXISTS decisionlog CASCADE`)
		aux.Close()
		db.pool.Close()
	}()
	lineAbout := func(subject, resource string, at time.Time) row {
		b, _ := json.Marshal(Entry{Time: at, Listener: "public", Endpoint: "check", Store: "it_race", Subject: Ref{Type: "user", ID: subject}, Action: "can_read", Resource: Ref{Type: "doc", ID: resource}})
		r, err := parseRow(b)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	count := func(resource string) int {
		var n int
		_ = aux.QueryRow(ctx, `SELECT count(*) FROM decisionlog.decisions WHERE store = 'it_race' AND resource_id = $1`, resource).Scan(&n)
		return n
	}
	// the console's erasure, step by step (the SQL mirrors eraseDecisions)
	eraseBarrier := func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO decisionlog.erasures (store, subject_type, subject_id, erased_at, erased_by) VALUES ('it_race', 'user', 'alice', now(), 'test')`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, erasureBarrierSQL)
		return err
	}
	eraseDelete := func() error {
		_, err := aux.Exec(ctx, `DELETE FROM decisionlog.decisions WHERE store = 'it_race' AND ((subject_type = 'user' AND subject_id = 'alice') OR (resource_type = 'user' AND resource_id = 'alice'))`)
		return err
	}
	waitingOnLock := func() bool {
		var n int
		_ = aux.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`).Scan(&n)
		return n == 1
	}
	before := time.Now().UTC().Add(-time.Minute)
	if err := db.ensurePartitions(ctx, []time.Time{before}); err != nil {
		t.Fatal(err)
	}

	// (a) the batch is in flight — copied and filtered, no tombstone yet —
	// when the erasure arrives: the barrier waits, the delete then sees the row.
	txW, err := db.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := insertTx(ctx, txW, []row{lineAbout("alice", "race-a", before)}); err != nil {
		t.Fatal(err)
	}
	erased := make(chan error, 1)
	go func() {
		txE, err := aux.Begin(ctx)
		if err != nil {
			erased <- err
			return
		}
		defer func() { _ = txE.Rollback(ctx) }()
		if err := eraseBarrier(txE); err != nil {
			erased <- err
			return
		}
		if err := txE.Commit(ctx); err != nil {
			erased <- err
			return
		}
		erased <- eraseDelete()
	}()
	waitFor(t, "the erasure to wait for the batch in flight", waitingOnLock)
	select {
	case err := <-erased:
		t.Fatalf("the erasure did not wait for the batch in flight: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if err := txW.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-erased; err != nil {
		t.Fatal(err)
	}
	if n := count("race-a"); n != 0 {
		t.Fatalf("(a) alice's line committed after the erasure survived: %d rows", n)
	}

	// (b) the erasure holds the barrier when a batch arrives: the batch
	// waits, then filters against the committed tombstone itself.
	txE, err := aux.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := eraseBarrier(txE); err != nil {
		t.Fatal(err)
	}
	inserted := make(chan error, 1)
	go func() {
		txW, err := db.pool.Begin(ctx)
		if err != nil {
			inserted <- err
			return
		}
		defer func() { _ = txW.Rollback(ctx) }()
		if err := insertTx(ctx, txW, []row{lineAbout("alice", "race-b", before), lineAbout("bob", "race-b", before)}); err != nil {
			inserted <- err
			return
		}
		inserted <- txW.Commit(ctx)
	}()
	waitFor(t, "the batch to wait for the erasure's barrier", waitingOnLock)
	select {
	case err := <-inserted:
		t.Fatalf("the batch did not wait for the barrier: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if err := txE.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-inserted; err != nil {
		t.Fatal(err)
	}
	if err := eraseDelete(); err != nil {
		t.Fatal(err)
	}
	var kept []string
	rows, _ := aux.Query(ctx, `SELECT subject_id FROM decisionlog.decisions WHERE store = 'it_race' AND resource_id = 'race-b' ORDER BY 1`)
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		kept = append(kept, s)
	}
	rows.Close()
	if strings.Join(kept, ",") != "bob" {
		t.Fatalf("(b) after the barrier: %v (want bob's line only)", kept)
	}
	if err := ps.Close(); err != nil {
		t.Fatal(err)
	}
}

// Review #22 P2: a line older than the retention window is refused on
// flush — it would recreate a dropped partition and outlive the tombstone
// that covered it — and counted; without retention everything is accepted.
func TestPostgresSinkRefusesLinesOlderThanRetention(t *testing.T) {
	f := &fakeStore{}
	s := newPostgresSink(PostgresConfig{RetentionDays: 7, BatchSize: 10, FlushInterval: 20 * time.Millisecond, QueueSize: 100}, f)
	var expired atomic.Int64
	s.OnExpired = func(n int) { expired.Add(int64(n)) }
	fresh, _ := json.Marshal(Entry{Time: time.Now().UTC(), Listener: "public", Endpoint: "check", Store: "s", Subject: Ref{Type: "user", ID: "a"}})
	stale, _ := json.Marshal(Entry{Time: time.Now().UTC().AddDate(0, 0, -8), Listener: "public", Endpoint: "check", Store: "s", Subject: Ref{Type: "user", ID: "a"}})
	edge, _ := json.Marshal(Entry{Time: time.Now().UTC().AddDate(0, 0, -7).Add(time.Hour), Listener: "public", Endpoint: "check", Store: "s", Subject: Ref{Type: "user", ID: "a"}}) // inside the window's first day
	for _, l := range [][]byte{fresh, stale, edge} {
		if _, err := s.Write(append(l, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "the fresh and the edge line inserted", func() bool { return f.rows() == 2 })
	if expired.Load() != 1 || s.Expired.Load() != 1 {
		t.Fatalf("expired %d/%d, want the stale line refused once", expired.Load(), s.Expired.Load())
	}
	_ = s.Close()

	f2 := &fakeStore{}
	s2 := newPostgresSink(PostgresConfig{RetentionDays: 0, BatchSize: 10, FlushInterval: 20 * time.Millisecond, QueueSize: 100}, f2)
	if _, err := s2.Write(append(stale, '\n')); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the old line inserted without retention", func() bool { return f2.rows() == 1 })
	if s2.Expired.Load() != 0 {
		t.Fatalf("without retention the old line must be accepted: rows %d expired %d", f2.rows(), s2.Expired.Load())
	}
	_ = s2.Close()
}

// A failed batch that the full queue cannot take back loses lines: they are
// counted (Dropped, OnDrop) — never silently gone (review #19).
func TestPostgresSinkDroppedOnRequeueOverflow(t *testing.T) {
	f := &fakeStore{}
	f.fail(errors.New("down"))
	s := newPostgresSink(PostgresConfig{QueueSize: 1, BatchSize: 1000, FlushInterval: time.Hour}, f)
	close(s.stop) // the flusher out of the way: this test drives the sink by hand
	<-s.done
	var reported int
	s.OnDrop = func(n int) { reported += n }
	batch := [][]byte{[]byte(strings.TrimSpace(line("demo", "a"))), []byte(strings.TrimSpace(line("demo", "b"))), []byte(strings.TrimSpace(line("demo", "c")))}
	if err := s.flushMany(context.Background(), batch); err == nil {
		t.Fatal("the failed insert must be reported")
	}
	if reported != 2 || s.Dropped.Load() != 2 || len(s.q) != 1 {
		t.Fatalf("dropped %d (total %d), queued %d; want 2 dropped, 1 kept", reported, s.Dropped.Load(), len(s.q))
	}
	f.fail(nil)
	if err := s.flushNow(context.Background()); err != nil || f.rows() != 1 {
		t.Fatalf("after recovery: %v, %d rows; want the 1 kept line", err, f.rows())
	}
}
