package app

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"thomasdarimont.de/authz/pgauthzd/internal/api"
	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
	"thomasdarimont.de/authz/pgauthzd/pkg/issuers"
)

// bindingReader is what the reloader needs from the database (the direct
// pgx backend; a fake in tests).
type bindingReader interface {
	IssuerBindingsRevision(ctx context.Context) (int64, error)
	IssuerBindings(ctx context.Context) ([]issuers.Binding, error)
}

// notifier wakes the reloader when the database says the bindings changed
// (LISTEN authz_issuer_bindings on the primary); optional — polling always
// runs, since NOTIFY does not reach a hot standby.
type notifier interface {
	ListenIssuerBindings(ctx context.Context, onChange func())
}

// issuerReloader merges the database's issuer bindings over the
// environment's issuers (ISSUERS_SOURCE=env+db) and swaps the result into
// the shared set: at start, on every poll that sees a new revision, and on
// every notification. A set that fails to build (a row the merge rejects
// is skipped with a warning; a reader error) leaves the set in force
// untouched and is counted (pgauthzd_issuers_reloads_total{result}).
type issuerReloader struct {
	db   bindingReader
	env  []issuers.Issuer
	opts issuers.MergeOptions // the host restriction for group issuers (GROUP_ISSUER_HOSTS)
	set  *api.Issuers
	mu   sync.Mutex
	last int64
}

func startIssuerReloader(ctx context.Context, db bindingReader, env []issuers.Issuer, opts issuers.MergeOptions, set *api.Issuers, poll time.Duration) *issuerReloader {
	r := &issuerReloader{db: db, env: env, opts: opts, set: set}
	// The first merge before the listeners open, so the first request already
	// sees the database's bindings; a failure here is logged, not fatal — the
	// environment's set serves until the database answers.
	r.reload(ctx, "startup")
	go func() {
		t := time.NewTicker(poll)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r.reload(ctx, "poll")
			}
		}
	}()
	if n, ok := db.(notifier); ok {
		go n.ListenIssuerBindings(ctx, func() { r.reload(ctx, "notify") })
	}
	return r
}

// reload applies the database's current revision when it differs from the
// one in force. Serialized: a notification and a poll never race.
func (r *issuerReloader) reload(ctx context.Context, why string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rev, err := r.db.IssuerBindingsRevision(cctx)
	if err != nil {
		metrics.IssuersReloads.WithLabelValues("error").Inc()
		slog.Warn("issuer bindings: reading the revision failed; the set in force stays", "why", why, "err", err)
		return
	}
	if rev == r.last && r.set.Revision() == rev {
		metrics.IssuersReloads.WithLabelValues("unchanged").Inc()
		return
	}
	rows, err := r.db.IssuerBindings(cctx)
	if err != nil {
		metrics.IssuersReloads.WithLabelValues("error").Inc()
		slog.Warn("issuer bindings: reading the bindings failed; the set in force stays", "why", why, "err", err)
		return
	}
	merged, problems := issuers.MergeWith(r.env, rows, r.opts)
	for _, p := range problems {
		metrics.IssuersReloads.WithLabelValues("rejected").Inc()
		slog.Warn("issuer bindings: "+p, "revision", rev)
	}
	r.set.Replace(api.IssuerConfigsFrom(merged), rev)
	r.last = rev
	metrics.IssuersReloads.WithLabelValues("applied").Inc()
	dbBound := 0
	for _, m := range merged {
		if m.BindingSource == "db" {
			dbBound++
		}
	}
	slog.Info("issuer bindings applied", "why", why, "revision", rev, "issuers", len(merged), "from_db", dbBound, "rejected", len(problems))
}
