package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
)

// newFlags returns a FlagSet with the shared --dsn flag registered.
func newFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	dsn := fs.String("dsn", os.Getenv("PGAUTHZ_DSN"), "PostgreSQL DSN (or PGAUTHZ_DSN)")
	return fs, dsn
}

func connect(ctx context.Context, dsn string) (*pgx.Conn, error) {
	if dsn == "" {
		return nil, fmt.Errorf("no DSN: pass --dsn or set PGAUTHZ_DSN " +
			"(dev stack: postgres://authz:authz@localhost:55433/authz)")
	}
	return pgx.Connect(ctx, dsn)
}

// queryJSON runs a query whose single result column is json/jsonb and
// unmarshals it into out.
func queryJSON(ctx context.Context, conn *pgx.Conn, out any, sql string, args ...any) error {
	var raw []byte
	if err := conn.QueryRow(ctx, sql, args...).Scan(&raw); err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func prettyJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

// parseAll parses flags wherever they appear (Go's flag package stops at the
// first positional argument; CLI users reasonably write
// `model test file.yaml --junit out.xml`). Returns the positional arguments.
func parseAll(fs *flag.FlagSet, args []string) []string {
	var pos []string
	fs.Parse(args)
	for fs.NArg() > 0 {
		pos = append(pos, fs.Arg(0))
		rest := fs.Args()[1:]
		if len(rest) == 0 {
			break
		}
		fs.Parse(rest)
	}
	return pos
}
