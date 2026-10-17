package pgauthzadm

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DB is the slice of pgx that this package needs. *pgx.Conn, pgx.Tx and
// *pgxpool.Pool all satisfy it.
type DB interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// QueryJSON runs a query whose single result column is json/jsonb and
// unmarshals it into out.
func QueryJSON(ctx context.Context, db DB, out any, sql string, args ...any) error {
	var raw []byte
	if err := db.QueryRow(ctx, sql, args...).Scan(&raw); err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}
