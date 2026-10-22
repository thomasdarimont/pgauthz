package server

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// The Operations overview reads as the console's database role, so a table
// or function the role may not use fails here instead of on the tab; the
// recorder allowlist round-trips; purge_events honours the gate guard.
func TestOpsOverviewAndActions(t *testing.T) {
	s, pool, ctx := testServer(t)
	cs := s.cfg.ConsoleStore
	const store = "console_gotest_ops"
	_, _ = pool.Exec(ctx, `SELECT authz.delete_store($1, p_purge_audit => true)`, store)
	for _, stmt := range []string{
		`SELECT authz.create_store($1, 'ops test')`,
		`SELECT authz.model_register_type($1, 'doc')`,
		`SELECT authz.model_register_relation($1, 'download', NULL, '{"kind": "permission"}'::jsonb)`,
		`SELECT authz.model_register_relation($1, 'viewer')`,
		`SELECT authz.model_add_rule($1, 'doc', 'viewer', 'direct')`,
		`SELECT authz.model_add_rule($1, 'doc', 'download', 'computed', 'viewer')`,
		`SELECT authz.add_gate($1, 'doc', 'download', 'quota', '{"all_of": [{"count_within": {"window": "1 day", "max": 3, "plus": 1}}]}'::jsonb)`,
	} {
		if _, err := pool.Exec(ctx, stmt, store); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `SELECT authz.delete_store($1, p_purge_audit => true)`, store)
	}()
	p := &principal{typ: "user", id: "ops_owner", ctxTuples: "[]"}
	if _, err := pool.Exec(ctx, `SELECT authz.write_tuple(`+q(cs)+`, 'user', 'ops_owner', 'owner', 'store', $1)`, store); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `SELECT authz.delete_tuple(`+q(cs)+`, 'user', 'ops_owner', 'owner', 'store', $1)`, store)
	}()

	// the allowlist, as the person
	err := s.asPerson(ctx, p, "can_manage_access", "store", store, map[string]any{"op": "test"}, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT authz.grant_recorder_actions($1, 'authz_recorder_svc', ARRAY['download'])`, store).Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			t.Errorf("granted %d actions, want 1", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// the overview, as authz_console
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE authz_console`); err != nil {
		t.Fatal(err)
	}
	o, err := s.opsOverview(ctx, tx, store)
	if err != nil {
		t.Fatalf("overview as authz_console: %v", err)
	}
	if o.Retired || len(o.Readiness) == 0 || len(o.GateWindows) != 1 || o.GateWindows[0].Gate != "quota" {
		t.Errorf("overview: retired=%v readiness=%d bytes gates=%+v", o.Retired, len(o.Readiness), o.GateWindows)
	}
	if len(o.Recorders) != 1 || o.Recorders[0].DBRole != "authz_recorder_svc" || len(o.Recorders[0].Actions) != 1 {
		t.Errorf("recorders = %+v, want authz_recorder_svc → [download]", o.Recorders)
	}
	if len(o.Partitions) == 0 || o.Changefeed.SafeUntil.IsZero() {
		t.Errorf("partitions %d, safe_until %v", len(o.Partitions), o.Changefeed.SafeUntil)
	}
	if o.Derived.Installed && o.Derived.Error != "" {
		t.Errorf("derived status installed but unreadable: %s", o.Derived.Error)
	}
	_ = tx.Rollback(ctx)

	// retention: a cutoff inside the live gate window is refused, forced it is not
	err = s.asPerson(ctx, p, "can_manage_access", "store", store, map[string]any{"op": "test"}, func(tx pgx.Tx) error {
		var n int64
		return tx.QueryRow(ctx, `SELECT authz.purge_events($1, now(), false)`, store).Scan(&n)
	})
	if err == nil {
		t.Error("purge_events inside the gate window was not refused")
	}
	err = s.asPerson(ctx, p, "can_manage_access", "store", store, map[string]any{"op": "test"}, func(tx pgx.Tx) error {
		var n int64
		return tx.QueryRow(ctx, `SELECT authz.purge_events($1, now() - interval '30 days', false)`, store).Scan(&n)
	})
	if err != nil {
		t.Errorf("purge_events outside the gate window: %v", err)
	}
}
