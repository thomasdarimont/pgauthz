//go:build freshfallback

// Integration test for transparent freshness fallback (ADR 0009): proves that a
// read routes to the PRIMARY pool when the request context is stamped
// WithPrimaryFallback, against REAL streaming replication. White-box (package
// pgbackend) so it can drive the unexported read path (withRole → readPool).
//
// Run via scratch/prototypes/lsn-token/verify-fallback.sh, which brings up an
// isolated primary/replica pair and sets PRIMARY_URL / REPLICA_URL.
package pgbackend

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
)

func mustPool(t *testing.T, url string) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool %q: %v", url, err)
	}
	if err := p.Ping(context.Background()); err != nil {
		t.Fatalf("ping %q: %v", url, err)
	}
	return p
}

func TestFallbackRouting(t *testing.T) {
	ctx := context.Background()
	primary := mustPool(t, os.Getenv("PRIMARY_URL"))
	replica := mustPool(t, os.Getenv("REPLICA_URL"))
	defer primary.Close()
	defer replica.Close()

	// The reader's "local" pool is the replica; the fallback pool is the primary.
	b := New(replica, primary, 0, "")

	// read runs a scalar SELECT through the backend's read path (withRole with no
	// per-app role → readPool(ctx)), so the pool selection is exactly production's.
	read := func(c context.Context, sql string, dst any) {
		t.Helper()
		if err := b.withRole(c, func(q querier) error { return q.QueryRow(c, sql).Scan(dst) }); err != nil {
			t.Fatalf("read %q: %v", sql, err)
		}
	}

	// 1) Routing — which server answered? Replica is in recovery, primary is not.
	var inRecovery bool
	read(ctx, "SELECT pg_is_in_recovery()", &inRecovery)
	if !inRecovery {
		t.Fatal("plain context must read the local replica (expected in-recovery=true)")
	}
	read(authz.WithPrimaryFallback(ctx), "SELECT pg_is_in_recovery()", &inRecovery)
	if inRecovery {
		t.Fatal("WithPrimaryFallback context must read the primary (expected in-recovery=false)")
	}
	t.Log("routing OK: plain→replica, fallback→primary")

	// 2) Read-your-writes via fallback — pause the replica, write on the primary,
	//    and prove the fallback read sees it while the replica does not.
	if _, err := primary.Exec(ctx, "CREATE TABLE IF NOT EXISTS _fb_probe(i int)"); err != nil {
		t.Fatal(err)
	}
	if _, err := primary.Exec(ctx, "TRUNCATE _fb_probe"); err != nil {
		t.Fatal(err)
	}
	// Wait for the (empty) table to replicate before pausing replay.
	for i := 0; ; i++ {
		var present bool
		_ = replica.QueryRow(ctx, "SELECT to_regclass('_fb_probe') IS NOT NULL").Scan(&present)
		if present {
			break
		}
		if i > 50 {
			t.Fatal("table did not replicate to the replica")
		}
		time.Sleep(100 * time.Millisecond)
	}

	if _, err := replica.Exec(ctx, "SELECT pg_wal_replay_pause()"); err != nil {
		t.Fatal(err)
	}
	defer replica.Exec(ctx, "SELECT pg_wal_replay_resume()") //nolint:errcheck

	if _, err := primary.Exec(ctx, "INSERT INTO _fb_probe VALUES (1)"); err != nil {
		t.Fatal(err)
	}

	var n int
	read(ctx, "SELECT count(*) FROM _fb_probe", &n)
	if n != 0 {
		t.Fatalf("replica (replay paused) should NOT see the write yet, got count=%d", n)
	}
	read(authz.WithPrimaryFallback(ctx), "SELECT count(*) FROM _fb_probe", &n)
	if n != 1 {
		t.Fatalf("fallback read should see the primary's write, got count=%d", n)
	}
	t.Log("read-your-writes OK: replica stale (0), fallback sees the primary write (1)")
}
