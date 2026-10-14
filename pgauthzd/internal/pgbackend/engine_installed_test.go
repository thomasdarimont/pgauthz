package pgbackend

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIsEngineNotInstalled(t *testing.T) {
	cases := map[string]struct {
		err  error
		want bool
	}{
		"missing role (roles.sql not run)":    {&pgconn.PgError{Code: "42704", Message: `role "authz_writer" does not exist`}, true},
		"missing table (migrations not run)":  {&pgconn.PgError{Code: "42P01", Message: `relation "authz.tuples" does not exist`}, true},
		"missing schema":                      {&pgconn.PgError{Code: "3F000"}, true},
		"wrapped":                             {fmt.Errorf("checking read-only role: %w", &pgconn.PgError{Code: "42704"}), true},
		"permission denied is a real failure": {&pgconn.PgError{Code: "42501"}, false},
		"non-pg error":                        {errors.New("dial tcp: connection refused"), false},
		"nil":                                 {nil, false},
	}
	for name, c := range cases {
		if got := IsEngineNotInstalled(c.err); got != c.want {
			t.Errorf("%s: IsEngineNotInstalled() = %v, want %v", name, got, c.want)
		}
	}
}
