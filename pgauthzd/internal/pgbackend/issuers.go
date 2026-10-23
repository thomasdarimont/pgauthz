package pgbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/pkg/issuers"
)

// IssuerBindingsRevision is the current revision of authz.issuer_bindings —
// what the reloader polls (reader tier, SECURITY DEFINER function).
func (b *Backend) IssuerBindingsRevision(ctx context.Context) (int64, error) {
	var rev int64
	err := b.readPool(ctx).QueryRow(ctx, `SELECT authz.issuer_bindings_revision()`).Scan(&rev)
	return rev, err
}

// IssuerBindings lists the database's issuer bindings.
func (b *Backend) IssuerBindings(ctx context.Context) ([]issuers.Binding, error) {
	rows, err := b.readPool(ctx).Query(ctx, `
		SELECT issuer, stores, db_roles, client_db_roles, pep_clients, enabled, coalesce(description, ''),
		       created_at, coalesce(created_by, ''), updated_at, coalesce(updated_by, '')
		  FROM authz.list_issuer_bindings()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []issuers.Binding
	for rows.Next() {
		var r issuers.Binding
		if err := rows.Scan(&r.Issuer, &r.Stores, &r.DBRoles, &r.ClientDBRoles, &r.PEPClients, &r.Enabled, &r.Description, &r.CreatedAt, &r.CreatedBy, &r.UpdatedAt, &r.UpdatedBy); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListenIssuerBindings wakes onChange on every NOTIFY authz_issuer_bindings
// (sent by the binding trigger) until ctx ends. A dedicated connection from
// the primary pool; a lost connection is retried every few seconds. Polling
// is the fallback the reloader always runs, since NOTIFY does not reach a
// hot standby.
func (b *Backend) ListenIssuerBindings(ctx context.Context, onChange func()) {
	for ctx.Err() == nil {
		conn, err := b.pool.Acquire(ctx)
		if err == nil {
			if _, err = conn.Exec(ctx, "LISTEN authz_issuer_bindings"); err == nil {
				for ctx.Err() == nil {
					if _, err = conn.Conn().WaitForNotification(ctx); err != nil {
						break
					}
					onChange()
				}
			}
			conn.Release()
		}
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// AssertAdmin verifies the connection role holds authz_admin — what the
// admin API's SQL functions require; a management instance without it
// refuses to start rather than fail every call.
func (b *Backend) AssertAdmin(ctx context.Context) error {
	var ok bool
	if err := b.pool.QueryRow(ctx, `SELECT pg_has_role(current_user, 'authz_admin', 'MEMBER')`).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("the connection role is not a member of authz_admin (connect a management instance as a role that holds it, e.g. pgauthzd_admin)")
	}
	return nil
}

// SetIssuerBinding creates or replaces a binding (authz.set_issuer_binding)
// as the connection role; the actor is recorded in the audit row.
func (b *Backend) SetIssuerBinding(ctx context.Context, bnd issuers.Binding, performedBy string) (int64, error) {
	cdr, _ := json.Marshal(orMap(bnd.ClientDBRoles))
	pep, _ := json.Marshal(orMapList(bnd.PEPClients))
	var rev int64
	err := b.pool.QueryRow(ctx, `SELECT authz.set_issuer_binding($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7, $8)`,
		bnd.Issuer, orSlice(bnd.Stores), orSlice(bnd.DBRoles), string(cdr), string(pep), bnd.Enabled, nullable(bnd.Description), nullable(performedBy)).Scan(&rev)
	return rev, bindingError(err)
}

// bindingError surfaces the engine's validation of a binding
// (authz._validate_issuer_binding raises invalid_parameter_value) as the
// caller's 400 with the engine's message; anything else stays a fault.
func bindingError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "22023" {
		return fmt.Errorf("%w: %s", authz.ErrInvalidRequest, pgErr.Message)
	}
	return err
}

// DeleteIssuerBinding drops a binding (authz.delete_issuer_binding).
func (b *Backend) DeleteIssuerBinding(ctx context.Context, issuer, performedBy string) (bool, error) {
	var existed bool
	err := b.pool.QueryRow(ctx, `SELECT authz.delete_issuer_binding($1, $2)`, issuer, nullable(performedBy)).Scan(&existed)
	return existed, bindingError(err)
}

func orSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
func orMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
func orMapList(m map[string][]string) map[string][]string {
	if m == nil {
		return map[string][]string{}
	}
	return m
}
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
