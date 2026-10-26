package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"thomasdarimont.de/authz/pgauthzd/internal/api"
	"thomasdarimont.de/authz/pgauthzd/pkg/issuers"
)

type fakeBindings struct {
	rev  int64
	rows []issuers.Binding
	err  error
	n    int
}

func (f *fakeBindings) IssuerBindingsRevision(context.Context) (int64, error) { return f.rev, f.err }
func (f *fakeBindings) IssuerBindings(context.Context) ([]issuers.Binding, error) {
	f.n++
	return f.rows, f.err
}

// The reloader applies a new revision (merge, swap), skips an unchanged one
// without re-reading the rows, keeps the set in force on a reader error,
// and ignores rows the merge rejects.
func TestIssuerReloader(t *testing.T) {
	env := []issuers.Issuer{{Issuer: "https://corp", Audience: "api", JWKSURL: "https://corp/jwks", Stores: []string{"docs", "tenant-.*"}}}
	set := api.NewIssuers(api.IssuerConfigsFrom(env))
	db := &fakeBindings{rev: 3, rows: []issuers.Binding{{Issuer: "https://corp", Stores: []string{"tenant-.*"}, Enabled: true}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := startIssuerReloader(ctx, db, env, issuers.MergeOptions{}, set, time.Hour)
	if set.Revision() != 3 || strings.Join(set.Configs()[0].Stores, ",") != "tenant-.*" || set.Configs()[0].BindingSource != "db" {
		t.Fatalf("startup merge not applied: rev %d %+v", set.Revision(), set.Configs()[0])
	}
	// unchanged: no row read
	reads := db.n
	r.reload(ctx, "poll")
	if db.n != reads || set.Revision() != 3 {
		t.Fatal("an unchanged revision must not re-read or swap")
	}
	// a reader error keeps the set
	db.err = errors.New("db down")
	db.rev = 4
	r.reload(ctx, "poll")
	if set.Revision() != 3 {
		t.Fatal("a reader error must leave the set in force")
	}
	db.err = nil
	// a widening row is rejected: the environment binding returns, revision advances
	db.rev, db.rows = 5, []issuers.Binding{{Issuer: "https://corp", Stores: []string{"hr"}, Enabled: true}}
	r.reload(ctx, "notify")
	if set.Revision() != 5 || set.Configs()[0].BindingSource != "env" || strings.Join(set.Configs()[0].Stores, ",") != "docs,tenant-.*" {
		t.Fatalf("rejected row must fall back to the environment: %+v", set.Configs()[0])
	}
	// a deleted row (no rows): back to the environment
	db.rev, db.rows = 6, nil
	r.reload(ctx, "poll")
	if set.Revision() != 6 || set.Configs()[0].BindingSource != "env" {
		t.Fatalf("after delete: %+v", set.Configs()[0])
	}
}
