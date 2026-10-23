package decisionlog

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
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

func (f *fakeStore) close() { f.mu.Lock(); f.closed = true; f.mu.Unlock() }

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
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}
