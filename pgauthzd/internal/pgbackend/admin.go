package pgbackend

// The admin API's store and model resources (ADR 0016): thin calls to the
// engine's store lifecycle and model registry functions on the full
// instance's writer pool, each write inside a transaction that names the
// actor (authz.performed_by → authz._actor() → audit, registry created_by).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"thomasdarimont.de/authz/pgauthzadm"
	"thomasdarimont.de/authz/pgauthzd/internal/authz"
)

// adminError surfaces the engine's refusals — its RAISEs (P0001), invalid
// parameters (22023), a duplicate (23505), a check (23514) — as the caller's
// 400 with the engine's message; anything else stays a fault.
func adminError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "P0001", "22023", "23505", "23514", "22P02":
			msg := pgErr.Message
			if pgErr.Hint != "" {
				msg += " — " + pgErr.Hint
			}
			return fmt.Errorf("%w: %s", authz.ErrInvalidRequest, msg)
		}
	}
	return err
}

// asActor runs fn in a transaction whose authz.performed_by is the actor.
func (b *Backend) asActor(ctx context.Context, actor string, fn func(tx pgx.Tx) error) error {
	tx, err := b.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('authz.performed_by', $1, true)`, actor); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return adminError(err)
	}
	return tx.Commit(ctx)
}

const storeRowSQL = `
	SELECT s.name, coalesce(s.description, ''), coalesce(s.docs_url, ''), coalesce(s.store_group, ''), s.created_at, s.retired_at,
	       CASE WHEN s.retired_at IS NULL THEN (SELECT to_jsonb(ms) FROM authz.model_status(s.name) ms) END
	  FROM authz.list_stores() s`

func scanStore(row pgx.Row) (authz.StoreRow, error) {
	var s authz.StoreRow
	var model *json.RawMessage
	if err := row.Scan(&s.Name, &s.Description, &s.DocsURL, &s.Group, &s.CreatedAt, &s.RetiredAt, &model); err != nil {
		return s, err
	}
	if model != nil {
		s.Model = *model
	}
	return s, nil
}

// ListStores: every store, live and retired, by name.
func (b *Backend) ListStores(ctx context.Context) ([]authz.StoreRow, error) {
	rows, err := b.pool.Query(ctx, storeRowSQL+` ORDER BY s.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []authz.StoreRow{}
	for rows.Next() {
		s, err := scanStore(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetStore: one store; found is false for an unknown name.
func (b *Backend) GetStore(ctx context.Context, name string) (authz.StoreRow, bool, error) {
	s, err := scanStore(b.pool.QueryRow(ctx, storeRowSQL+` WHERE s.name = $1`, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return s, false, nil
	}
	return s, err == nil, err
}

// UpsertStore creates the store when it does not exist (create_store), sets
// what is given (update_store: nil = unchanged, "" = cleared) and retires
// it when asked (retire_store; a retired store cannot be reopened — the
// engine has no un-retire). Returns the row and whether it was created.
func (b *Backend) UpsertStore(ctx context.Context, name string, description, docsURL *string, retired *bool, actor string) (authz.StoreRow, bool, error) {
	cur, found, err := b.GetStore(ctx, name)
	if err != nil {
		return cur, false, err
	}
	if found && cur.RetiredAt != nil && retired != nil && !*retired {
		return cur, false, fmt.Errorf("%w: store %s is retired; the engine cannot reopen a retired store (create it anew under another name)", authz.ErrInvalidRequest, name)
	}
	err = b.asActor(ctx, actor, func(tx pgx.Tx) error {
		if !found {
			var desc any
			if description != nil && *description != "" {
				desc = *description
			}
			if _, err := tx.Exec(ctx, `SELECT authz.create_store($1, $2)`, name, desc); err != nil {
				return err
			}
		}
		if (description != nil || docsURL != nil) && (cur.RetiredAt == nil) {
			var d, u any
			if description != nil && found {
				d = *description
			}
			if docsURL != nil {
				u = *docsURL
			}
			if d != nil || u != nil {
				if _, err := tx.Exec(ctx, `SELECT authz.update_store($1, $2, $3)`, name, d, u); err != nil {
					return err
				}
			}
		}
		if retired != nil && *retired && cur.RetiredAt == nil {
			if _, err := tx.Exec(ctx, `SELECT authz.retire_store($1)`, name); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return cur, false, err
	}
	row, _, err := b.GetStore(ctx, name)
	return row, !found, err
}

// DeleteStore removes a store physically (delete_store); existed is false
// for an unknown name.
func (b *Backend) DeleteStore(ctx context.Context, name string, purgeAudit bool, actor string) (int32, time.Time, bool, error) {
	_, found, err := b.GetStore(ctx, name)
	if err != nil || !found {
		return 0, time.Time{}, false, err
	}
	var id int32
	var at time.Time
	err = b.asActor(ctx, actor, func(tx pgx.Tx) error {
		// the receipt: incarnation and deletion time read inside the engine's lifecycle lock
		return tx.QueryRow(ctx, `SELECT store_id, deleted_at FROM authz.delete_store_receipt($1, $2)`, name, purgeAudit).Scan(&id, &at)
	})
	return id, at.UTC(), true, err
}

// StoreDeletions: the engine's deletion receipts for a name, newest first.
func (b *Backend) StoreDeletions(ctx context.Context, name string) ([]authz.StoreDeletion, error) {
	rows, err := b.pool.Query(ctx, `SELECT store_id, deleted_at, coalesce(deleted_by, '') FROM authz.store_deletions($1)`, name)
	if err != nil {
		return nil, adminError(err)
	}
	defer rows.Close()
	out := []authz.StoreDeletion{}
	for rows.Next() {
		var d authz.StoreDeletion
		if err := rows.Scan(&d.StoreID, &d.DeletedAt, &d.DeletedBy); err != nil {
			return nil, err
		}
		d.DeletedAt = d.DeletedAt.UTC()
		out = append(out, d)
	}
	return out, rows.Err()
}

// ExportModel: the store's live model in the canonical definition shape.
func (b *Backend) ExportModel(ctx context.Context, store string) (json.RawMessage, error) {
	var def json.RawMessage
	err := b.pool.QueryRow(ctx, `SELECT authz.export_model($1)`, store).Scan(&def)
	return def, adminError(err)
}

// ModelStatus: the store's managed-model state (authz.model_status row).
func (b *Backend) ModelStatus(ctx context.Context, store string) (json.RawMessage, error) {
	var st json.RawMessage
	err := b.pool.QueryRow(ctx, `SELECT to_jsonb(ms) FROM authz.model_status($1) ms`, store).Scan(&st)
	return st, adminError(err)
}

// PlanApply: the dry run of applying a registry version (NULL = latest).
func (b *Backend) PlanApply(ctx context.Context, store, name string, version *int) (json.RawMessage, error) {
	var plan json.RawMessage
	err := b.pool.QueryRow(ctx, `SELECT authz.plan_model_apply($1, $2, $3)`, store, name, version).Scan(&plan)
	return plan, adminError(err)
}

// ApplyModel makes the store match a registry version; returns the version applied.
func (b *Backend) ApplyModel(ctx context.Context, store, name string, version *int, actor string) (int, error) {
	var applied int
	err := b.asActor(ctx, actor, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT authz.apply_model($1, $2, $3)`, store, name, version).Scan(&applied)
	})
	return applied, err
}

// ListModelVersions: the registry, every model or one (authz.list_model_versions rows).
func (b *Backend) ListModelVersions(ctx context.Context, name string) ([]json.RawMessage, error) {
	var n any
	if name != "" {
		n = name
	}
	return b.jsonRows(ctx, `SELECT to_jsonb(v) FROM authz.list_model_versions($1) v`, n)
}

// RolloutStatus: every store under a model name (authz.model_rollout_status rows).
func (b *Backend) RolloutStatus(ctx context.Context, name string) ([]json.RawMessage, error) {
	return b.jsonRows(ctx, `SELECT to_jsonb(r) FROM authz.model_rollout_status($1) r`, name)
}

func (b *Backend) jsonRows(ctx context.Context, sql string, args ...any) ([]json.RawMessage, error) {
	rows, err := b.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, adminError(err)
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var j json.RawMessage
		if err := rows.Scan(&j); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// PublishModel publishes the next version of name from a store's live model
// (fromStore), from a definition (the export shape) or from an OpenFGA
// model (converted through an ephemeral store); idempotent on the checksum.
func (b *Backend) PublishModel(ctx context.Context, name, fromStore string, definition, openfga json.RawMessage, description, actor string) (int, error) {
	var version int
	var desc any
	if description != "" {
		desc = description
	}
	err := b.asActor(ctx, actor, func(tx pgx.Tx) error {
		switch {
		case fromStore != "":
			return tx.QueryRow(ctx, `SELECT authz.publish_model($1, $2, $3)`, name, fromStore, desc).Scan(&version)
		case len(openfga) > 0:
			return tx.QueryRow(ctx, `SELECT authz.publish_model_openfga($1, $2::jsonb, $3)`, name, string(openfga), desc).Scan(&version)
		default:
			return tx.QueryRow(ctx, `SELECT authz.publish_model_definition($1, $2::jsonb, $3)`, name, string(definition), desc).Scan(&version)
		}
	})
	return version, err
}

// DescribeModel: the store's live model as OpenFGA-style DSL text (display).
func (b *Backend) DescribeModel(ctx context.Context, store string) (string, error) {
	var text string
	err := b.pool.QueryRow(ctx, `SELECT authz.describe_model($1)`, store).Scan(&text)
	return text, adminError(err)
}

// ── recorder allowlists and namespaces ──────────────────────────────────

// RecorderActions: the store's recorder allowlists (authz.list_recorder_actions).
func (b *Backend) RecorderActions(ctx context.Context, store string) ([]authz.RecorderRow, error) {
	rows, err := b.pool.Query(ctx, `SELECT db_role, actions FROM authz.list_recorder_actions($1)`, store)
	if err != nil {
		return nil, adminError(err)
	}
	defer rows.Close()
	out := []authz.RecorderRow{}
	for rows.Next() {
		var r authz.RecorderRow
		if err := rows.Scan(&r.DBRole, &r.Actions); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetRecorderActions makes the role's allowlist exactly actions (lift it
// first, then grant), in one transaction.
func (b *Backend) SetRecorderActions(ctx context.Context, store, role string, actions []string, actor string) error {
	return b.asActor(ctx, actor, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT authz.revoke_recorder_actions($1, $2, NULL)`, store, role); err != nil {
			return err
		}
		if len(actions) == 0 {
			return nil
		}
		_, err := tx.Exec(ctx, `SELECT authz.grant_recorder_actions($1, $2, $3::text[])`, store, role, actions)
		return err
	})
}

// RevokeRecorderActions lifts the role's whole allowlist; existed says whether there was one.
func (b *Backend) RevokeRecorderActions(ctx context.Context, store, role, actor string) (bool, error) {
	var n int
	err := b.asActor(ctx, actor, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT authz.revoke_recorder_actions($1, $2, NULL)`, store, role).Scan(&n)
	})
	return n > 0, err
}

// Namespaces: the store's namespaces with their types and role grants.
func (b *Backend) Namespaces(ctx context.Context, store string) ([]authz.NamespaceRow, error) {
	rows, err := b.pool.Query(ctx, `SELECT namespace, types, access FROM authz.list_namespaces($1)`, store)
	if err != nil {
		return nil, adminError(err)
	}
	defer rows.Close()
	out := []authz.NamespaceRow{}
	for rows.Next() {
		var r authz.NamespaceRow
		if err := rows.Scan(&r.Name, &r.Types, &r.Access); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetNamespaceAccess makes the role's grant on the namespace exactly
// (canRead, canWrite): revoke both, grant what is asked (both false = no row).
func (b *Backend) SetNamespaceAccess(ctx context.Context, store, namespace, role string, canRead, canWrite bool, actor string) error {
	return b.asActor(ctx, actor, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT authz.revoke_namespace_access($1, $2, $3, true, true)`, store, namespace, role); err != nil {
			return err
		}
		if !canRead && !canWrite {
			return nil
		}
		_, err := tx.Exec(ctx, `SELECT authz.grant_namespace_access($1, $2, $3, $4, $5)`, store, namespace, role, canRead, canWrite)
		return err
	})
}

// RevokeNamespaceAccess removes the role's grant on the namespace; existed says whether there was one.
func (b *Backend) RevokeNamespaceAccess(ctx context.Context, store, namespace, role, actor string) (bool, error) {
	var existed bool
	err := b.asActor(ctx, actor, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT authz.revoke_namespace_access($1, $2, $3, true, true)`, store, namespace, role).Scan(&existed)
	})
	return existed, err
}

// ── data subject requests ───────────────────────────────────────────────

// SubjectObjects: the takeout as rows (authz.list_subject_objects).
func (b *Backend) SubjectObjects(ctx context.Context, store, subjectType, subjectID string, relations, objectTypes []string, limit int) ([]authz.SubjectObjectRow, error) {
	rows, err := b.pool.Query(ctx, `SELECT object_type, relation, object_id, is_wildcard, direct, truncated
	                                  FROM authz.list_subject_objects($1, $2, $3, $4::text[], $5::text[], $6)`,
		store, subjectType, subjectID, relations, objectTypes, limit)
	if err != nil {
		return nil, adminError(err)
	}
	defer rows.Close()
	out := []authz.SubjectObjectRow{}
	for rows.Next() {
		var r authz.SubjectObjectRow
		if err := rows.Scan(&r.ObjectType, &r.Relation, &r.ObjectID, &r.IsWildcard, &r.Direct, &r.Truncated); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, adminError(rows.Err())
}

// ExportSubject: the export document (authz.export_subject, every part).
func (b *Backend) ExportSubject(ctx context.Context, store, subjectType, subjectID string, relations []string, limit int) (json.RawMessage, error) {
	var doc json.RawMessage
	err := b.pool.QueryRow(ctx, `SELECT authz.export_subject($1, $2, $3, $4::text[], true, true, true, $5)`,
		store, subjectType, subjectID, relations, limit).Scan(&doc)
	return doc, adminError(err)
}

// TestModel runs a fixture (pgauthzadm.RunFixture — the runner pgauthzctl
// and the console's Scenarios share) in an ephemeral store inside one
// transaction as the actor: the store is created, seeded, asserted against
// and dropped with its audit rows before the commit, so a run leaves no
// trace — unless keep retains the store for debugging. modelJSON is the
// OpenFGA model a fixture's model_file resolved to (the client parses a
// .fga); a registry ref or a live store needs none.
func (b *Backend) TestModel(ctx context.Context, fix *pgauthzadm.Fixture, modelJSON []byte, keep bool, actor string) (*pgauthzadm.RunReport, error) {
	rnd := make([]byte, 4)
	_, _ = rand.Read(rnd)
	opts := pgauthzadm.RunOptions{ModelJSON: modelJSON, Store: "pgauthzd_test_" + hex.EncodeToString(rnd), KeepStore: keep, PurgeAudit: true}
	var report *pgauthzadm.RunReport
	err := b.asActor(ctx, actor, func(tx pgx.Tx) error {
		r, err := pgauthzadm.RunFixture(ctx, tx, fix, opts)
		report = r
		return err
	})
	return report, err
}

// ── store groups (ADR 0017) ──────────────────────────────────────────────

// ListStoreGroups: every group with its store count (authz.list_store_groups).
func (b *Backend) ListStoreGroups(ctx context.Context) ([]authz.StoreGroupRow, error) {
	rows, err := b.pool.Query(ctx, `SELECT name, coalesce(description, ''), store_count, created_at, created_by, updated_at, updated_by FROM authz.list_store_groups()`)
	if err != nil {
		return nil, adminError(err)
	}
	defer rows.Close()
	out := []authz.StoreGroupRow{}
	for rows.Next() {
		var g authz.StoreGroupRow
		if err := rows.Scan(&g.Name, &g.Description, &g.StoreCount, &g.CreatedAt, &g.CreatedBy, &g.UpdatedAt, &g.UpdatedBy); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// UpsertStoreGroup creates the group (created = true) or updates its
// description (nil leaves it), as the actor.
func (b *Backend) UpsertStoreGroup(ctx context.Context, name string, description *string, actor string) (bool, error) {
	created := false
	err := b.asActor(ctx, actor, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM authz.list_store_groups() WHERE name = $1)`, name).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			created = true
			_, err := tx.Exec(ctx, `SELECT authz.create_store_group($1, $2)`, name, description)
			return err
		}
		if description == nil {
			return nil
		}
		_, err := tx.Exec(ctx, `SELECT authz.update_store_group($1, $2)`, name, *description)
		return err
	})
	return created, err
}

// DeleteStoreGroup drops an empty group (false when there was none).
func (b *Backend) DeleteStoreGroup(ctx context.Context, name, actor string) (bool, error) {
	var deleted bool
	err := b.asActor(ctx, actor, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT authz.delete_store_group($1)`, name).Scan(&deleted)
	})
	return deleted, err
}

// SetStoreGroup attaches the store to the group, or detaches it ("").
func (b *Backend) SetStoreGroup(ctx context.Context, store, group, actor string) error {
	return b.asActor(ctx, actor, func(tx pgx.Tx) error {
		var g any
		if group != "" {
			g = group
		}
		_, err := tx.Exec(ctx, `SELECT authz.set_store_group($1, $2)`, store, g)
		return err
	})
}

// ModelConsumers: the groups that may apply the owner group's models.
func (b *Backend) ModelConsumers(ctx context.Context, owner string) ([]authz.ModelConsumerRow, error) {
	rows, err := b.pool.Query(ctx, `SELECT consumer_group, created_at, created_by FROM authz.list_model_consumers($1)`, owner)
	if err != nil {
		return nil, adminError(err)
	}
	defer rows.Close()
	out := []authz.ModelConsumerRow{}
	for rows.Next() {
		var r authz.ModelConsumerRow
		if err := rows.Scan(&r.Group, &r.CreatedAt, &r.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (b *Backend) GrantModelConsumer(ctx context.Context, owner, consumer, actor string) error {
	return b.asActor(ctx, actor, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT authz.grant_model_consumer($1, $2)`, owner, consumer)
		return err
	})
}

func (b *Backend) RevokeModelConsumer(ctx context.Context, owner, consumer, actor string) (bool, error) {
	var revoked bool
	err := b.asActor(ctx, actor, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT authz.revoke_model_consumer($1, $2)`, owner, consumer).Scan(&revoked)
	})
	return revoked, err
}
