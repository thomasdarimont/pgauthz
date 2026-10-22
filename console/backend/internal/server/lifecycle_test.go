package server

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Retiring a store (authz.retire_store) keeps its dictionary, its audit
// history and the console roles on it — so the model change history still
// reads, the owner still sees the store (marked retired) and can purge it
// later — while the live model is gone. Needs the database (see testServer).
func TestRetireStoreKeepsHistoryAndRoles(t *testing.T) {
	s, pool, ctx := testServer(t)
	cs := s.cfg.ConsoleStore
	const store = "console_gotest_retire"
	_, _ = pool.Exec(ctx, `SELECT authz.delete_store($1, p_purge_audit => true)`, store) // a previous run that died
	if _, err := pool.Exec(ctx, `SELECT authz.create_store($1, 'retire test')`, store); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `SELECT authz.delete_store($1, p_purge_audit => true)`, store)
		_, _ = pool.Exec(context.Background(), `SELECT authz.delete_tuple(`+q(cs)+`, 'user', 'retire_owner', 'owner', 'store', $1)`, store)
	}()
	if _, err := pool.Exec(ctx, `SELECT authz.write_tuple(`+q(cs)+`, 'user', 'retire_owner', 'owner', 'store', $1)`, store); err != nil {
		t.Fatal(err)
	}
	// a model with every kind of versioned part, as the person (performed_by)
	p := &principal{typ: "user", id: "retire_owner", ctxTuples: "[]"}
	err := s.asPerson(ctx, p, "can_edit_model", "store", store, map[string]any{"op": "test"}, func(tx pgx.Tx) error {
		for _, stmt := range []string{
			`SELECT authz.model_register_type($1, 'doc')`,
			`SELECT authz.model_register_relation($1, 'viewer')`,
			`SELECT authz.model_register_relation($1, 'can_share')`,
			`SELECT authz.model_add_rule($1, 'doc', 'viewer', 'direct')`,
			`SELECT authz.model_add_rule($1, 'doc', 'can_share', 'computed', 'viewer')`,
			`SELECT authz.model_add_grant_rule($1, 'doc', 'viewer', 'can_share')`,
			`SELECT authz.create_condition($1, 'daytime', 'true', 'sql', NULL)`,
			`SELECT authz.add_gate($1, 'doc', 'viewer', 'quota', '{"all_of": [{"count_within": {"action": "viewer", "max": 3, "window": "1 day"}}]}'::jsonb)`,
			`SELECT authz.model_set_type_labels($1, 'doc', ARRAY['group:docs'])`,
			`SELECT authz.model_drop_grant_rule($1, 'doc', 'viewer')`,
		} {
			if _, err := tx.Exec(ctx, stmt, store); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Read the history as the console's own database role (authz_console,
	// roles.sql): the audit tables need explicit SELECT grants, which the
	// superuser test connection would not notice are missing.
	changes, err := s.modelChangesAsConsole(ctx, pool, store)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, c := range changes {
		kinds[c.Kind+":"+c.Action]++
		if c.PerformedBy != "user:retire_owner" {
			t.Errorf("%s %s performed_by = %q, want the person", c.Kind, c.Action, c.PerformedBy)
		}
		if c.Kind != "condition" && (c.ObjectType != "doc" || c.Relation == "") {
			t.Errorf("%s: names not resolved: %+v", c.Kind, c)
		}
	}
	for k, want := range map[string]int{"rule:INSERT": 2, "grant_rule:INSERT": 1, "grant_rule:DELETE": 1, "condition:INSERT": 1, "gate:INSERT": 1} {
		if kinds[k] != want {
			t.Errorf("model changes %s = %d, want %d (all: %v)", k, kinds[k], want, kinds)
		}
	}
	// Newest first. Everything above happened in one transaction (one
	// performed_at), so the order is only defined within a table: the grant
	// rule's removal comes before its addition.
	var sawDelete bool
	for _, c := range changes {
		if c.Kind != "grant_rule" {
			continue
		}
		if c.Action == "DELETE" {
			sawDelete = true
		} else if !sawDelete {
			t.Error("grant rule INSERT listed before its DELETE: not newest first")
		}
	}

	// retire, as the console would
	err = s.asPerson(ctx, p, "can_manage_access", "store", store, map[string]any{"op": "retire_store"}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT authz.retire_store($1)`, store)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.allStores(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found *storeRow
	for i := range rows {
		if rows[i].Name == store {
			found = &rows[i]
		}
	}
	if found == nil || found.RetiredAt == nil {
		t.Fatalf("retired store missing or not marked retired: %+v", found)
	}
	var owners int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuples t JOIN authz.types ot ON ot.id = t.object_type JOIN authz.relations rl ON rl.id = t.relation
		 WHERE t.store_id = (SELECT id FROM authz.stores WHERE name = `+q(cs)+`) AND ot.name = 'store' AND t.object_id = $1 AND rl.name = 'owner'`, store).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if owners != 1 {
		t.Errorf("console owner role gone after retire: %d owners", owners)
	}
	if after, err := s.modelChangesAsConsole(ctx, pool, store); err != nil || len(after) != len(changes) {
		t.Errorf("model history after retire: %d rows, err %v; want %d", len(after), err, len(changes))
	}
	if _, err := pool.Exec(ctx, `SELECT authz.check_access($1, 'user', 'x', 'viewer', 'doc', 'y')`, store); err == nil {
		t.Error("a live check on a retired store succeeded")
	}
	// purge: the retired store is deleted like any other
	if _, err := pool.Exec(ctx, `SELECT authz.delete_store($1, p_purge_audit => true)`, store); err != nil {
		t.Fatal(err)
	}
}

// modelChangesAsConsole reads the model history in a transaction running as
// authz_console (SET LOCAL ROLE), so a grant missing from roles.sql fails
// here instead of on the Activity tab.
func (s *Server) modelChangesAsConsole(ctx context.Context, pool *pgxpool.Pool, store string) ([]modelChangeRow, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE authz_console`); err != nil {
		return nil, err
	}
	return s.modelChanges(ctx, tx, store, 100)
}
