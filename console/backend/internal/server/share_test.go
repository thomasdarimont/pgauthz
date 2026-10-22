package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
)

// The share dialog's two calls against a model with a grant rule: the
// options say what the actor may do, apply_grants refuses an actor the rule
// does not allow and applies for one it does — as the person, recorded.
func TestShareOptionsAndApply(t *testing.T) {
	s, pool, ctx := testServer(t)
	cs := s.cfg.ConsoleStore
	const store = "console_gotest_share"
	_, _ = pool.Exec(ctx, `SELECT authz.delete_store($1, p_purge_audit => true)`, store)
	for _, stmt := range []string{
		`SELECT authz.create_store($1, 'share test')`,
		`SELECT authz.model_register_type($1, 'user')`,
		`SELECT authz.model_register_type($1, 'doc')`,
		`SELECT authz.model_register_relation($1, 'owner')`,
		`SELECT authz.model_register_relation($1, 'viewer')`,
		`SELECT authz.model_register_relation($1, 'can_share', NULL, '{"kind": "permission"}'::jsonb)`,
		`SELECT authz.model_add_rule($1, 'doc', 'owner', 'direct')`,
		`SELECT authz.model_add_rule($1, 'doc', 'viewer', 'direct')`,
		`SELECT authz.model_add_type_restriction($1, 'doc', 'viewer', 'user')`,
		`SELECT authz.model_add_rule($1, 'doc', 'can_share', 'computed', 'owner')`,
		`SELECT authz.model_add_grant_rule($1, 'doc', 'viewer', 'can_share')`,
		`SELECT authz.write_tuple($1, 'user', 'alice', 'owner', 'doc', 'plan')`,
	} {
		if _, err := pool.Exec(ctx, stmt, store); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `SELECT authz.delete_store($1, p_purge_audit => true)`, store)
	}()
	if _, err := pool.Exec(ctx, `SELECT authz.write_tuple($1, 'user', 'share_owner', 'owner', 'store', $2)`, cs, store); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `SELECT authz.delete_tuple($1, 'user', 'share_owner', 'owner', 'store', $2)`, cs, store)
	}()
	p := &principal{typ: "user", id: "share_owner", ctxTuples: "[]"}

	// options: alice (owner → can_share) may grant viewer; bob may not
	var canGrant bool
	var grantees []string
	if err := pool.QueryRow(ctx, `SELECT can_grant, grantee_types FROM authz.grant_options($1, 'user', 'alice', 'doc', 'plan') WHERE relation = 'viewer'`, store).Scan(&canGrant, &grantees); err != nil || !canGrant || len(grantees) == 0 {
		t.Fatalf("alice's options: %v can_grant=%v grantees=%v", err, canGrant, grantees)
	}
	if err := pool.QueryRow(ctx, `SELECT can_grant FROM authz.grant_options($1, 'user', 'bob', 'doc', 'plan') WHERE relation = 'viewer'`, store).Scan(&canGrant); err != nil || canGrant {
		t.Fatalf("bob's options: %v can_grant=%v, want false", err, canGrant)
	}

	apply := func(actor string, grants []tupleReq) (map[string]int, error) {
		raw, _ := json.Marshal(grants)
		var out json.RawMessage
		err := s.asPerson(ctx, p, "can_grant", "store", store, map[string]any{"op": "share"}, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT authz.apply_grants($1, 'user', $2, $3::jsonb, '[]'::jsonb)`, store, actor, raw).Scan(&out)
		})
		if err != nil {
			return nil, err
		}
		var m map[string]int
		return m, json.Unmarshal(out, &m)
	}
	g := []tupleReq{{UserType: "user", UserID: "carol", Relation: "viewer", ObjectType: "doc", ObjectID: "plan"}}
	if _, err := apply("bob", g); err == nil {
		t.Error("bob's grant was not refused")
	}
	m, err := apply("alice", g)
	if err != nil || m["granted"] != 1 {
		t.Fatalf("alice's grant: %v %v", err, m)
	}
	var ok bool
	if err := pool.QueryRow(ctx, `SELECT authz.check_access($1, 'user', 'carol', 'viewer', 'doc', 'plan')`, store).Scan(&ok); err != nil || !ok {
		t.Errorf("carol is not a viewer after the grant: %v %v", err, ok)
	}
}
