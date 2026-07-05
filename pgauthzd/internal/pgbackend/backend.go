package pgbackend

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"thomasdarimont.de/authz/pgauthzd/internal/api"
	"thomasdarimont.de/authz/pgauthzd/internal/authz"
)

// Backend implements authz.Backend using direct PostgreSQL calls.
type Backend struct {
	pool *pgxpool.Pool
	// roleOK caches per-role validation results (member of authz_reader and
	// not admin-capable) with a bounded TTL: a dropped role or revoked
	// membership takes effect within roleCacheTTL, not at the next restart.
	// Security-sensitive caches must not live forever.
	roleOK       sync.Map // role string -> roleCacheEntry
	roleCacheTTL time.Duration
}

type roleCacheEntry struct {
	allowed bool
	checked time.Time
}

// New creates a Backend. roleCacheTTL bounds how long a role-validation
// result (allowed OR denied) may be reused; 0 disables caching entirely
// (every request re-validates against pg_has_role).
func New(pool *pgxpool.Pool, roleCacheTTL time.Duration) *Backend {
	return &Backend{pool: pool, roleCacheTTL: roleCacheTTL}
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
	if b.roleCacheTTL > 0 {
		if v, ok := b.roleOK.Load(role); ok {
			e := v.(roleCacheEntry)
			if time.Since(e.checked) < b.roleCacheTTL {
				if e.allowed {
					return nil
				}
				return fmt.Errorf("db role %q is not an allowed reader role", role)
			}
			// expired — fall through and re-validate
		}
	}
	var allowed bool
	err := b.pool.QueryRow(ctx,
		`SELECT pg_has_role($1, 'authz_reader', 'member')
		    AND NOT pg_has_role($1, 'authz_admin', 'member')`, role).Scan(&allowed)
	if err != nil {
		// unknown role / lookup failure: fail closed, do not cache
		return fmt.Errorf("validating db role %q: %w", role, err)
	}
	if b.roleCacheTTL > 0 {
		b.roleOK.Store(role, roleCacheEntry{allowed: allowed, checked: time.Now()})
	}
	if !allowed {
		return fmt.Errorf("db role %q is not an allowed reader role", role)
	}
	return nil
}

// writeWithRole runs a mutating fn inside a single transaction that assumes a
// writer-capable role and applies the request's consistency mode. It mirrors
// the PostgREST-writer trust boundary: the per-app role from the token (when
// present, validated writer + not admin) is assumed via SET LOCAL ROLE, else
// the connection's default writer identity is used; the tx is scoped so the
// role never leaks back into the pool. Consistency maps to a whitelisted
// synchronous_commit (strict-revocation lives here, per-tx, as it did on the
// writer connection URI).
func (b *Backend) writeWithRole(ctx context.Context, consistency string, fn func(q querier) error) error {
	role := api.DBRoleFromContext(ctx)
	tx, err := b.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin write tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if role != "" {
		if err := b.checkWriterRole(ctx, role); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
			return fmt.Errorf("assuming writer role %q: %w", role, err)
		}
	}
	if sc := syncCommit(consistency); sc != "" {
		// Whitelisted constant, never caller text — safe to interpolate.
		if _, err := tx.Exec(ctx, "SET LOCAL synchronous_commit = "+sc); err != nil {
			return fmt.Errorf("setting consistency %q: %w", consistency, err)
		}
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// checkWriterRole validates a per-app role before assuming it for a write,
// mirroring the writer-side _pre_request(): member of authz_writer, not admin.
// Fail closed on unknown roles. Reuses the same cache as checkRole but under a
// distinct key so a reader-only role can't be cached as write-capable.
func (b *Backend) checkWriterRole(ctx context.Context, role string) error {
	cacheKey := "w:" + role
	if b.roleCacheTTL > 0 {
		if v, ok := b.roleOK.Load(cacheKey); ok {
			e := v.(roleCacheEntry)
			if time.Since(e.checked) < b.roleCacheTTL {
				if e.allowed {
					return nil
				}
				return fmt.Errorf("db role %q is not an allowed writer role: %w", role, authz.ErrForbiddenRole)
			}
		}
	}
	var allowed bool
	err := b.pool.QueryRow(ctx,
		`SELECT pg_has_role($1, 'authz_writer', 'member')
		    AND NOT pg_has_role($1, 'authz_admin', 'member')`, role).Scan(&allowed)
	if err != nil {
		return fmt.Errorf("validating writer db role %q: %w", role, err)
	}
	if b.roleCacheTTL > 0 {
		b.roleOK.Store(cacheKey, roleCacheEntry{allowed: allowed, checked: time.Now()})
	}
	if !allowed {
		return fmt.Errorf("db role %q is not an allowed writer role: %w", role, authz.ErrForbiddenRole)
	}
	return nil
}

// syncCommit maps a request consistency mode to a whitelisted
// synchronous_commit setting; "" means leave the connection default untouched.
// "applied" is strict revocation (wait for the sync standby to apply) — the
// remote_apply the writer connection used; "eventual" trades durability for
// latency on writes that tolerate it.
func syncCommit(consistency string) string {
	switch consistency {
	case "applied", "strict", "remote_apply":
		return "remote_apply"
	case "durable", "on":
		return "on"
	case "eventual", "local":
		return "local"
	default:
		return ""
	}
}

// WriteTuples implements authz.NativeWriter.WriteTuples via
// authz.write_tuples_jsonb, recording performed_by = the authenticated subject.
func (b *Backend) WriteTuples(ctx context.Context, req authz.WriteRequest) (int, error) {
	var n int
	err := b.writeWithRole(ctx, req.Consistency, func(q querier) error {
		return q.QueryRow(ctx,
			"SELECT authz.write_tuples_jsonb($1, $2, $3)",
			req.Store, []byte(req.Tuples), textOrNil(req.PerformedBy),
		).Scan(&n)
	})
	if err != nil {
		return 0, fmt.Errorf("write_tuples_jsonb: %w", err)
	}
	return n, nil
}

// DeleteTuples implements authz.NativeWriter.DeleteTuples via
// authz.delete_tuples_jsonb, recording performed_by = the authenticated subject.
func (b *Backend) DeleteTuples(ctx context.Context, req authz.WriteRequest) (int, error) {
	var n int
	err := b.writeWithRole(ctx, req.Consistency, func(q querier) error {
		return q.QueryRow(ctx,
			"SELECT authz.delete_tuples_jsonb($1, $2, $3)",
			req.Store, []byte(req.Tuples), textOrNil(req.PerformedBy),
		).Scan(&n)
	})
	if err != nil {
		return 0, fmt.Errorf("delete_tuples_jsonb: %w", err)
	}
	return n, nil
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

// CheckAccessDetailed implements authz.DetailedChecker via the engine's
// check_access_detailed (explain-backed; per-decision opt-in). The boolean
// rides inside the report; everything else becomes the response context.
func (b *Backend) CheckAccessDetailed(ctx context.Context, req authz.EvalRequest) (bool, map[string]any, error) {
	var ctxJSON []byte
	if req.Context != nil {
		var err error
		ctxJSON, err = json.Marshal(req.Context)
		if err != nil {
			return false, nil, fmt.Errorf("marshaling context: %w", err)
		}
	}
	var raw []byte
	err := b.withRole(ctx, func(q querier) error {
		return q.QueryRow(ctx,
			"SELECT authz.check_access_detailed($1, $2, $3, $4, $5, $6, $7)",
			req.Store, req.SubjectType, req.SubjectID, req.Action,
			req.ObjectType, req.ObjectID, ctxJSON,
		).Scan(&raw)
	})
	if err != nil {
		return false, nil, fmt.Errorf("check_access_detailed: %w", err)
	}
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		return false, nil, fmt.Errorf("unmarshaling detailed result: %w", err)
	}
	decision, _ := report["decision"].(bool)
	delete(report, "decision") // the boolean is the response's own field
	delete(report, "store")    // the caller already knows the store
	return decision, report, nil
}

// CheckWithContextualTuples implements authz.ContextualChecker via
// authz.check_access_with_contextual_tuples_jsonb: the ephemeral tuples are
// evaluated with the stored graph but never persisted.
func (b *Backend) CheckWithContextualTuples(ctx context.Context, req authz.EvalRequest, contextualTuples json.RawMessage) (bool, error) {
	var ctxJSON []byte
	if req.Context != nil {
		var err error
		if ctxJSON, err = json.Marshal(req.Context); err != nil {
			return false, fmt.Errorf("marshaling context: %w", err)
		}
	}
	var decision bool
	err := b.withRole(ctx, func(q querier) error {
		return q.QueryRow(ctx,
			"SELECT authz.check_access_with_contextual_tuples_jsonb($1,$2,$3,$4,$5,$6,$7,$8)",
			req.Store, req.SubjectType, req.SubjectID, req.Action,
			req.ObjectType, req.ObjectID, ctxJSON, []byte(contextualTuples),
		).Scan(&decision)
	})
	if err != nil {
		return false, fmt.Errorf("check_access_with_contextual_tuples_jsonb: %w", err)
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

// AssertReadOnly verifies the pool's connection role cannot write — the
// database-enforced guarantee behind a decision-only instance. The role must
// NOT be a member of authz_writer (which gates the write functions) and must
// hold no direct write privilege on authz.tuples. A decision-only instance
// that was accidentally pointed at a writable DSN fails to start rather than
// silently becoming write-capable. (SECURITY: the guarantee lives in the DB
// role, not the profile flag.)
// Explain implements authz.NativeReader.Explain via authz.explain_access,
// through withRole so the per-app namespace isolation that governs reads also
// governs the explanation.
func (b *Backend) Explain(ctx context.Context, req authz.EvalRequest) (json.RawMessage, error) {
	var ctxJSON []byte
	if req.Context != nil {
		var err error
		if ctxJSON, err = json.Marshal(req.Context); err != nil {
			return nil, fmt.Errorf("marshaling context: %w", err)
		}
	}
	var raw []byte
	err := b.withRole(ctx, func(q querier) error {
		return q.QueryRow(ctx,
			"SELECT authz.explain_access($1,$2,$3,$4,$5,$6,$7)",
			req.Store, req.SubjectType, req.SubjectID, req.Action,
			req.ObjectType, req.ObjectID, ctxJSON,
		).Scan(&raw)
	})
	if err != nil {
		return nil, fmt.Errorf("explain_access: %w", err)
	}
	return raw, nil
}

// WatchChanges implements authz.NativeReader.WatchChanges via
// authz.watch_changes, aggregated into a JSON array + a next-cursor. Runs as
// the pooled (auditor) role — the changefeed is an audit-scope operation, not
// per-app-namespace scoped.
func (b *Backend) WatchChanges(ctx context.Context, req authz.WatchRequest) (json.RawMessage, error) {
	// Empty cursor = from the beginning: pass '-infinity', NOT NULL. The
	// changefeed cursor compares (performed_at, seq) > (p_after_at, ...), and
	// any comparison against NULL is NULL → zero rows.
	afterAt := "-infinity"
	if req.AfterAt != "" {
		afterAt = req.AfterAt
	}
	// Same NULL trap as afterAt: the lag gate is performed_at <= now() - p_lag,
	// so a NULL p_lag excludes everything. Default to 1s (the function default).
	lag := "1 second"
	if req.Lag != "" {
		lag = req.Lag
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 1000
	}
	// The changefeed cursor is the COMPOSITE (performed_at, seq) — the function
	// compares (performed_at, seq) > (p_after_at, p_after_seq). Return both as
	// the next cursor; seq alone is insufficient (a resumed page with
	// after_at='-infinity' would re-match everything). last_* are the max of
	// the page (rows already come ordered), NULL-safe to the incoming cursor.
	var events []byte
	var lastAt *time.Time
	var lastSeq int64
	err := b.pool.QueryRow(ctx, `
		SELECT coalesce(jsonb_agg(to_jsonb(w) ORDER BY w.performed_at, w.seq), '[]'::jsonb),
		       max(w.performed_at),
		       coalesce(max(w.seq), $3::bigint)
		  FROM authz.watch_changes($1, $2::timestamptz, $3, $4, $5::interval, $6, $7, $8) w`,
		req.Store, afterAt, req.AfterSeq, limit, lag,
		nilIfEmpty(req.ObjectTypes), nilIfEmpty(req.Namespaces), nilIfEmpty(req.Relations),
	).Scan(&events, &lastAt, &lastSeq)
	if err != nil {
		return nil, fmt.Errorf("watch_changes: %w", err)
	}
	cursor := map[string]any{"after_seq": lastSeq}
	if lastAt != nil {
		cursor["after_at"] = lastAt.UTC().Format(time.RFC3339Nano)
	} else {
		cursor["after_at"] = req.AfterAt // unchanged when the page is empty
	}
	out, _ := json.Marshal(map[string]any{
		"store":       req.Store,
		"events":      json.RawMessage(events),
		"next_cursor": cursor,
	})
	return out, nil
}

func nilIfEmpty(s []string) any {
	if len(s) == 0 {
		return nil
	}
	return s
}

func (b *Backend) AssertReadOnly(ctx context.Context) error {
	var writer, tuplesWrite bool
	err := b.pool.QueryRow(ctx, `
		SELECT pg_has_role(current_user, 'authz_writer', 'MEMBER'),
		       has_table_privilege(current_user, 'authz.tuples', 'INSERT')
		    OR has_table_privilege(current_user, 'authz.tuples', 'UPDATE')
		    OR has_table_privilege(current_user, 'authz.tuples', 'DELETE')`,
	).Scan(&writer, &tuplesWrite)
	if err != nil {
		return fmt.Errorf("checking read-only role: %w", err)
	}
	if writer || tuplesWrite {
		return fmt.Errorf("decision-only profile requires a read-only DB role, but the " +
			"connection role can write (member of authz_writer or has write on authz.tuples) — " +
			"connect as a reader-only role (e.g. authzen_direct / a role inheriting only authz_reader)")
	}
	return nil
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
