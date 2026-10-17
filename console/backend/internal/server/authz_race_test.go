package server

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"thomasdarimont.de/authz/console-bff/internal/config"
)

// The last-owner invariant under concurrency (review finding 1): two owners
// removing each other at the same time must leave one owner, never zero.
// Needs a pgauthz database with the console store installed:
//
//	PGAUTHZ_TEST_DATABASE_URL=postgres://authz:authz@localhost:55433/authz go test ./internal/server -run LastOwner
func TestConcurrentLastOwnerRemoval(t *testing.T) {
	dsn := os.Getenv("PGAUTHZ_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PGAUTHZ_TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s := &Server{cfg: config.Config{ConsoleStore: "console", SubjectType: "user"}, engine: pool}
	const store = "race_test_store"
	// two owners of a scratch store object in the console store
	for _, who := range []string{"race_a", "race_b"} {
		if _, err := pool.Exec(ctx, `SELECT authz.write_tuple('console', 'user', $1, 'owner', 'store', $2)`, who, store); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		for _, who := range []string{"race_a", "race_b"} {
			_, _ = pool.Exec(context.Background(), `SELECT authz.delete_tuple('console', 'user', $1, 'owner', 'store', $2)`, who, store)
		}
	}()

	remove := func(actor, victim string) error {
		p := &principal{typ: "user", id: actor, ctxTuples: "[]"}
		return s.asPerson(ctx, p, "can_manage_access", "store", store, map[string]any{"op": "remove"}, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT authz.delete_tuple('console', 'user', $1, 'owner', 'store', $2)`, victim, store); err != nil {
				return err
			}
			// widen the window: the other transaction is now trying the same
			time.Sleep(300 * time.Millisecond)
			return s.ensureOwner(ctx, tx, "store", store)
		})
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = remove("race_a", "race_b") }()
	go func() { defer wg.Done(); errs[1] = remove("race_b", "race_a") }()
	wg.Wait()

	var owners int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM authz.tuples t JOIN authz.types ot ON ot.id = t.object_type JOIN authz.relations rl ON rl.id = t.relation
		 WHERE t.store_id = (SELECT id FROM authz.stores WHERE name = 'console') AND ot.name = 'store' AND t.object_id = $1 AND rl.name = 'owner'`, store).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if owners != 1 {
		t.Fatalf("expected exactly one owner left, got %d (errors: %v, %v)", owners, errs[0], errs[1])
	}
	// Exactly one removal is refused. Which refusal depends on the order the
	// lock hands out: the second transaction either sees that its actor is no
	// longer an owner (the in-transaction re-check says no) or, when the
	// first one failed, counts down to zero (last owner).
	failed := 0
	for _, e := range errs {
		var se scopeError
		switch {
		case e == nil:
		case e == errLastOwner, errors.As(e, &se):
			failed++
		default:
			t.Fatalf("unexpected error: %v", e)
		}
	}
	if failed != 1 {
		t.Fatalf("expected exactly one removal refused, got %d (errors: %v, %v)", failed, errs[0], errs[1])
	}
}

func TestIsSelfBindsType(t *testing.T) {
	s := &Server{cfg: config.Config{SubjectType: "user", SelfSubjectTypes: []string{"internal_user"}}}
	p := &principal{typ: "user", id: "alice"}
	cases := []struct {
		typ, id string
		want    bool
	}{
		{"user", "alice", true},
		{"internal_user", "alice", true},
		{"agent", "alice", false},
		{"service_account", "alice", false},
		{"user", "bob", false},
	}
	for _, c := range cases {
		if got := s.isSelf(p, c.typ, c.id); got != c.want {
			t.Errorf("isSelf(%s:%s) = %v, want %v", c.typ, c.id, got, c.want)
		}
	}
}
