package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// awaitEngine keeps re-checking while the engine is absent, returns the first
// non-"not installed" outcome unchanged, and stops on context cancellation.
func TestAwaitEngine(t *testing.T) {
	old := engineRetryInterval
	engineRetryInterval = time.Millisecond
	t.Cleanup(func() { engineRetryInterval = old })

	t.Run("passes once the engine lands", func(t *testing.T) {
		calls := 0
		err := awaitEngine(context.Background(), "decision-only", func(context.Context) error {
			calls++
			if calls < 3 {
				return &pgconn.PgError{Code: "42704", Message: `role "authz_writer" does not exist`}
			}
			return nil
		})
		if err != nil || calls != 3 {
			t.Fatalf("err=%v calls=%d, want nil after 3 attempts", err, calls)
		}
	})

	t.Run("a real assertion failure is fatal immediately", func(t *testing.T) {
		want := errors.New("decision-only profile requires a read-only DB role")
		calls := 0
		err := awaitEngine(context.Background(), "decision-only", func(context.Context) error {
			calls++
			return want
		})
		if !errors.Is(err, want) || calls != 1 {
			t.Fatalf("err=%v calls=%d, want the assertion error after 1 attempt", err, calls)
		}
	})

	t.Run("stops when the context is cancelled", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		err := awaitEngine(ctx, "full", func(context.Context) error {
			return &pgconn.PgError{Code: "42P01"}
		})
		if err == nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err=%v, want a context deadline error", err)
		}
	})
}
