package pgbackend

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// The search functions turn the engine's 'Unknown type' / 'Unknown relation'
// RAISE into an empty result (AuthZEN 1.0 §8.3), but only that RAISE: any
// other engine error, and any non-PG error, must keep propagating.
func TestIsUnknownEntity(t *testing.T) {
	pg := func(code, msg string) error {
		return fmt.Errorf("list_subjects: %w", &pgconn.PgError{Code: code, Message: msg})
	}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"unknown type", pg("P0001", "Unknown type: spaceship"), true},
		{"unknown relation", pg("P0001", "Unknown relation: fly"), true},
		{"unknown store is not an entity", pg("P0001", "Unknown store: nope"), false},
		{"other raise", pg("P0001", "Permission denied: role x"), false},
		{"other sqlstate same text", pg("42501", "Unknown type: spaceship"), false},
		{"plain error", errors.New("Unknown type: spaceship"), false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isUnknownEntity(c.err); got != c.want {
				t.Fatalf("isUnknownEntity(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}
