package pgbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"thomasdarimont.de/authz/authzen/internal/api"
	"thomasdarimont.de/authz/authzen/internal/authz"
)

// Backend implements authz.Backend using direct PostgreSQL calls.
type Backend struct {
	pool *pgxpool.Pool
	// roleOK caches per-role validation results (member of authz_reader and
	// not admin-capable). Populated lazily; definitive answers only — a
	// dropped/regranted role needs a service restart to be re-evaluated.
	roleOK sync.Map // role string -> bool
}

func New(pool *pgxpool.Pool) *Backend {
	return &Backend{pool: pool}
}

// querier is the subset of pgx query methods shared by the pool and a
// transaction, so request handlers can run either directly on the pool or
// inside a role-scoped transaction.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// withRole runs fn against the database. When the request context carries a
// per-app DB role (derived from the verified token — see the middleware's
// DB_ROLE_CLAIM / CLIENT_DB_ROLES), the queries run inside a transaction with
// `SET LOCAL ROLE <role>` applied, so pgauthz's namespace enforcement keys on
// the caller's app role instead of the service's connection role. Fail closed:
// an unknown, non-reader, or admin-capable role is rejected.
func (b *Backend) withRole(ctx context.Context, fn func(q querier) error) error {
	role := api.DBRoleFromContext(ctx)
	if role == "" {
		return fn(b.pool)
	}
	if err := b.checkRole(ctx, role); err != nil {
		return err
	}
	tx, err := b.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin role-scoped tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	// SET LOCAL is transaction-scoped, so the role never leaks back into the
	// pooled connection. Identifier-quoted — role names are caller-derived.
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
		return fmt.Errorf("assuming db role %q: %w", role, err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// checkRole validates a per-app DB role before assuming it, mirroring the
// writer-side _pre_request() policy: the role must be a member of
// authz_reader and must NOT be admin-capable. Unknown roles error → fail closed.
func (b *Backend) checkRole(ctx context.Context, role string) error {
	if v, ok := b.roleOK.Load(role); ok {
		if v.(bool) {
			return nil
		}
		return fmt.Errorf("db role %q is not an allowed reader role", role)
	}
	var allowed bool
	err := b.pool.QueryRow(ctx,
		`SELECT pg_has_role($1, 'authz_reader', 'member')
		    AND NOT pg_has_role($1, 'authz_admin', 'member')`, role).Scan(&allowed)
	if err != nil {
		// unknown role / lookup failure: fail closed, do not cache
		return fmt.Errorf("validating db role %q: %w", role, err)
	}
	b.roleOK.Store(role, allowed)
	if !allowed {
		return fmt.Errorf("db role %q is not an allowed reader role", role)
	}
	return nil
}

func (b *Backend) CheckAccess(ctx context.Context, req authz.EvalRequest) (bool, error) {
	var decision bool
	err := b.withRole(ctx, func(q querier) error {
		if req.Context != nil {
			ctxJSON, jerr := json.Marshal(req.Context)
			if jerr != nil {
				return fmt.Errorf("marshaling context: %w", jerr)
			}
			return q.QueryRow(ctx,
				"SELECT authz.check_access_with_context($1, $2, $3, $4, $5, $6, $7)",
				req.Store, req.SubjectType, req.SubjectID, req.Action,
				req.ObjectType, req.ObjectID, ctxJSON,
			).Scan(&decision)
		}
		return q.QueryRow(ctx,
			"SELECT authz.check_access($1, $2, $3, $4, $5, $6)",
			req.Store, req.SubjectType, req.SubjectID, req.Action,
			req.ObjectType, req.ObjectID,
		).Scan(&decision)
	})
	if err != nil {
		return false, fmt.Errorf("check_access: %w", err)
	}
	return decision, nil
}

func (b *Backend) CheckAccessBatch(ctx context.Context, store string, reqs []authz.EvalRequest,
	globalContext map[string]any, semantic string) ([]authz.EvalResult, error) {

	// Build JSONB checks array matching the SQL function's expected format
	checks := make([]map[string]string, len(reqs))
	for i, req := range reqs {
		checks[i] = map[string]string{
			"user_type":   req.SubjectType,
			"user_id":     req.SubjectID,
			"relation":    req.Action,
			"object_type": req.ObjectType,
			"object_id":   req.ObjectID,
		}
	}

	checksJSON, err := json.Marshal(checks)
	if err != nil {
		return nil, fmt.Errorf("marshaling checks: %w", err)
	}

	var ctxJSON []byte
	if globalContext != nil {
		ctxJSON, err = json.Marshal(globalContext)
		if err != nil {
			return nil, fmt.Errorf("marshaling context: %w", err)
		}
	}

	var resultJSON []byte
	err = b.withRole(ctx, func(q querier) error {
		return q.QueryRow(ctx,
			"SELECT authz.check_access_batch($1, $2, $3, $4)",
			store, checksJSON, ctxJSON, semantic,
		).Scan(&resultJSON)
	})
	if err != nil {
		return nil, fmt.Errorf("check_access_batch: %w", err)
	}

	var rawResults []struct {
		Decision *bool `json:"decision"`
	}
	if err := json.Unmarshal(resultJSON, &rawResults); err != nil {
		return nil, fmt.Errorf("unmarshaling batch results: %w", err)
	}

	results := make([]authz.EvalResult, len(rawResults))
	for i, r := range rawResults {
		if r.Decision != nil {
			results[i].Decision = *r.Decision
		}
	}
	return results, nil
}

func (b *Backend) ListResources(ctx context.Context, store string,
	subjectType, subjectID, action, objectType string,
	reqContext map[string]any, page *authz.PageRequest) ([]string, *authz.PageResponse, error) {

	limit, offset, after := pageParams(page)

	var ctxJSON []byte
	if reqContext != nil {
		var err error
		ctxJSON, err = json.Marshal(reqContext)
		if err != nil {
			return nil, nil, fmt.Errorf("marshaling context: %w", err)
		}
	}

	// Request limit+1 to detect if more pages exist
	queryLimit := limit + 1

	var ids []string
	err := b.withRole(ctx, func(q querier) error {
		rows, err := q.Query(ctx,
			"SELECT object_id FROM authz.list_objects($1, $2, $3, $4, $5, $6, $7, $8, $9)",
			store, subjectType, subjectID, action, objectType, ctxJSON, queryLimit, offset, textOrNil(after),
		)
		if err != nil {
			return fmt.Errorf("list_objects: %w", err)
		}
		defer rows.Close()
		ids, err = collectStrings(rows, queryLimit)
		return err
	})
	if err != nil {
		return nil, nil, err
	}

	return buildPage(ids, limit)
}

func (b *Backend) ListSubjects(ctx context.Context, store string,
	subjectType, action, objectType, objectID string,
	reqContext map[string]any, page *authz.PageRequest) ([]string, *authz.PageResponse, error) {

	limit, offset, after := pageParams(page)

	var ctxJSON []byte
	if reqContext != nil {
		var err error
		ctxJSON, err = json.Marshal(reqContext)
		if err != nil {
			return nil, nil, fmt.Errorf("marshaling context: %w", err)
		}
	}

	queryLimit := limit + 1

	var ids []string
	err := b.withRole(ctx, func(q querier) error {
		rows, err := q.Query(ctx,
			"SELECT subject_id FROM authz.list_subjects($1, $2, $3, $4, $5, $6, $7, $8, $9)",
			store, subjectType, action, objectType, objectID, ctxJSON, queryLimit, offset, textOrNil(after),
		)
		if err != nil {
			return fmt.Errorf("list_subjects: %w", err)
		}
		defer rows.Close()
		ids, err = collectStrings(rows, queryLimit)
		return err
	})
	if err != nil {
		return nil, nil, err
	}

	return buildPage(ids, limit)
}

func (b *Backend) ListActions(ctx context.Context, store string,
	subjectType, subjectID, objectType, objectID string,
	reqContext map[string]any) ([]string, error) {

	var ctxJSON []byte
	if reqContext != nil {
		var err error
		ctxJSON, err = json.Marshal(reqContext)
		if err != nil {
			return nil, fmt.Errorf("marshaling context: %w", err)
		}
	}

	var actions []string
	err := b.withRole(ctx, func(q querier) error {
		rows, err := q.Query(ctx,
			"SELECT action FROM authz.list_actions($1, $2, $3, $4, $5, $6)",
			store, subjectType, subjectID, objectType, objectID, ctxJSON,
		)
		if err != nil {
			return fmt.Errorf("list_actions: %w", err)
		}
		defer rows.Close()
		actions, err = collectStrings(rows, 0)
		return err
	})
	if err != nil {
		return nil, err
	}
	return actions, nil
}

func (b *Backend) Healthz(ctx context.Context) error {
	return b.pool.Ping(ctx)
}

// --- helpers ---

func pageParams(page *authz.PageRequest) (limit, offset int, after string) {
	if page == nil {
		return 100, 0, ""
	}
	limit = page.Limit
	if limit <= 0 {
		limit = 100
	}
	return limit, page.Offset, page.After
}

// textOrNil maps an empty keyset cursor to a SQL NULL so list_objects /
// list_subjects fall back to offset paging; a non-empty cursor stays a value
// (and, being non-NULL, takes precedence over p_offset in the SQL function).
func textOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func collectStrings(rows pgx.Rows, _ int) ([]string, error) {
	var result []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

func buildPage(ids []string, limit int) ([]string, *authz.PageResponse, error) {
	hasMore := len(ids) > limit
	if hasMore {
		ids = ids[:limit]
	}

	var pageResp *authz.PageResponse
	if hasMore {
		// Keyset cursor: the next page starts after the last id we return.
		pageResp = &authz.PageResponse{
			HasMore:   true,
			NextToken: api.EncodePageAfter(ids[len(ids)-1]),
		}
	}

	if ids == nil {
		ids = []string{}
	}

	return ids, pageResp, nil
}
