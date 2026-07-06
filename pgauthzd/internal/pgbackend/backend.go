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
	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
)

// observe times a DB operation and records duration + errors by op and pool
// (ADR 0010). op ∈ read|write|freshness; pool from poolLabel(ctx).
func (b *Backend) observe(ctx context.Context, op string, fn func() error) error {
	start := time.Now()
	err := fn()
	pool := b.poolLabel(ctx)
	metrics.DBQueryDuration.WithLabelValues(op, pool).Observe(time.Since(start).Seconds())
	if err != nil {
		metrics.DBErrors.WithLabelValues(op, pool).Inc()
	}
	return err
}

// Backend implements authz.Backend using direct PostgreSQL calls.
type Backend struct {
	pool *pgxpool.Pool
	// primaryPool, when non-nil, is a reader-role pool to the PRIMARY for
	// TRANSPARENT freshness fallback (ADR 0009): reads on a context marked
	// authz.WithPrimaryFallback route here (the primary is authoritative)
	// instead of the guard returning 409. nil = fallback off (409 behavior).
	primaryPool *pgxpool.Pool
	// roleOK caches per-role validation results (member of authz_reader and
	// not admin-capable) with a bounded TTL: a dropped role or revoked
	// membership takes effect within roleCacheTTL, not at the next restart.
	// Security-sensitive caches must not live forever.
	roleOK       sync.Map // role string -> roleCacheEntry
	roleCacheTTL time.Duration
	// defaultRole, when non-empty, is the trusted role the read path SET LOCAL
	// ROLEs to when a request carries no per-app role — so reads never run as
	// the raw connection role (whose SET-ROLE memberships would otherwise leak
	// into membership-keyed checks). See config.DefaultDBRole.
	defaultRole string
	// localPool is the metrics label for this backend's own pool ("replica" on a
	// decision-only reader, "primary" on a full writer); the fallback pool is
	// labelled "fallback". Matches the pool-stats names (ADR 0010).
	localPool string
}

type roleCacheEntry struct {
	allowed bool
	checked time.Time
}

// New creates a Backend. roleCacheTTL bounds how long a role-validation
// result (allowed OR denied) may be reused; 0 disables caching entirely
// (every request re-validates against pg_has_role). defaultRole is the trusted
// fallback read role (empty = run as the connection role). primaryPool, when
// non-nil, enables transparent freshness fallback (ADR 0009) — reads on a
// context marked authz.WithPrimaryFallback route to it; pass nil to disable.
func New(pool, primaryPool *pgxpool.Pool, roleCacheTTL time.Duration, defaultRole, localPool string) *Backend {
	if localPool == "" {
		localPool = "local"
	}
	return &Backend{pool: pool, primaryPool: primaryPool, roleCacheTTL: roleCacheTTL, defaultRole: defaultRole, localPool: localPool}
}

// poolLabel is the metrics pool name for a request: "fallback" when routed to
// the primary fallback pool, else this backend's local pool name (ADR 0010).
func (b *Backend) poolLabel(ctx context.Context) string {
	if b.primaryPool != nil && authz.PrimaryFallback(ctx) {
		return "fallback"
	}
	return b.localPool
}

// readPool returns the pool a read should run on: the PRIMARY fallback pool when
// the request context is marked (ADR 0009) and one is configured, else the local
// (replica) pool. Fail-safe: without a primary pool it always uses the local
// pool — the guard never marks the context for fallback in that case.
func (b *Backend) readPool(ctx context.Context) *pgxpool.Pool {
	if b.primaryPool != nil && authz.PrimaryFallback(ctx) {
		return b.primaryPool
	}
	return b.pool
}

// HasPrimaryFallback implements authz.FreshnessFallback: whether transparent
// primary fallback is configured on this backend.
func (b *Backend) HasPrimaryFallback() bool { return b.primaryPool != nil }

// AssertFreshPrimary runs the freshness verdict against the PRIMARY pool (ADR
// 0009): the fallback guard re-validates a token here before serving from the
// primary, so a promoted primary on a new timeline still rejects a cross-timeline
// token (wrong_epoch) rather than being assumed authoritative.
func (b *Backend) AssertFreshPrimary(ctx context.Context, epoch int32, lsn string) (string, error) {
	if b.primaryPool == nil {
		return "unknown", nil // no fallback pool → can't confirm; fail closed
	}
	var verdict string
	if err := b.primaryPool.QueryRow(ctx,
		"SELECT authz.assert_fresh($1, $2::pg_lsn)", epoch, lsn).Scan(&verdict); err != nil {
		return "", fmt.Errorf("asserting freshness on primary: %w", err)
	}
	return verdict, nil
}

// StoreStats implements authz.StoreStatser (ADR 0010, Slice 3): top-N stores by
// tuple count + the total store count, via the SECURITY DEFINER authz.store_stats.
func (b *Backend) StoreStats(ctx context.Context, limit int) ([]authz.StoreStat, int64, error) {
	rows, err := b.pool.Query(ctx, "SELECT store, tuples, stores_total FROM authz.store_stats($1)", limit)
	if err != nil {
		return nil, 0, fmt.Errorf("store_stats: %w", err)
	}
	defer rows.Close()
	var (
		stats []authz.StoreStat
		total int64
	)
	for rows.Next() {
		var s authz.StoreStat
		if err := rows.Scan(&s.Store, &s.Tuples, &total); err != nil {
			return nil, 0, err
		}
		stats = append(stats, s)
	}
	return stats, total, rows.Err()
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
	return b.observe(ctx, "read", func() error { return b.withRoleInner(ctx, fn) })
}

func (b *Backend) withRoleInner(ctx context.Context, fn func(q querier) error) error {
	role := api.DBRoleFromContext(ctx)
	if role == "" {
		// No per-app role: fall back to the configured trusted default (always
		// SET ROLE so the connection role's SET-ROLE memberships never leak),
		// or run as the connection role when no default is set.
		if b.defaultRole == "" {
			return fn(b.readPool(ctx))
		}
		return b.withFixedRole(ctx, b.defaultRole, fn)
	}
	if err := b.checkRole(ctx, role); err != nil {
		return err
	}
	return b.withFixedRole(ctx, role, fn)
}

// withFixedRole runs fn in a transaction that SET LOCAL ROLEs to role (already
// validated or operator-trusted).
func (b *Backend) withFixedRole(ctx context.Context, role string, fn func(q querier) error) error {
	tx, err := b.readPool(ctx).Begin(ctx)
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

// checkRole validates a per-app DB role before assuming it: the role must be a
// member of authz_reader and must NOT be admin-capable (the rule the former SQL
// _pre_request_reader hook enforced; pgauthzd owns it now). Unknown roles error
// → fail closed.
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
// writer-capable role and applies the request's consistency mode. The per-app
// role from the token (when present, validated writer + not admin) is assumed
// via SET LOCAL ROLE, else
// the connection's default writer identity is used; the tx is scoped so the
// role never leaks back into the pool. Consistency maps to a whitelisted
// synchronous_commit (strict-revocation lives here, per-tx, as it did on the
// writer connection URI).
func (b *Backend) writeWithRole(ctx context.Context, consistency string, fn func(q querier) error) error {
	return b.observe(ctx, "write", func() error { return b.writeWithRoleInner(ctx, consistency, fn) })
}

func (b *Backend) writeWithRoleInner(ctx context.Context, consistency string, fn func(q querier) error) error {
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
	sc, ok := syncCommit(consistency)
	if !ok {
		// Fail closed: never silently downgrade a misspelled consistency request.
		return fmt.Errorf("%w %q (expected applied | durable | eventual)",
			authz.ErrInvalidConsistency, consistency)
	}
	if sc != "" {
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

// checkWriterRole validates a per-app role before assuming it for a write:
// member of authz_writer, not admin (the rule the former SQL _pre_request hook
// enforced). Fail closed on unknown roles. Reuses the same cache as checkRole but under a
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

// syncCommit maps a request consistency mode to a whitelisted synchronous_commit
// setting. An empty mode ("") means "leave the connection default untouched" and
// returns ("", true). An UNRECOGNIZED mode returns ok=false so the caller FAILS
// CLOSED — a misspelled consistency request must never be silently reinterpreted
// as a weaker guarantee (this replaces the fail-closed check the former SQL
// _pre_request hook performed). "applied" is strict revocation (wait for the
// sync standby to apply) — the remote_apply the writer connection used;
// "eventual" trades durability for latency on writes that tolerate it.
func syncCommit(consistency string) (value string, ok bool) {
	switch consistency {
	case "":
		return "", true // absent → connection default
	case "applied", "strict", "remote_apply":
		return "remote_apply", true
	case "durable", "on":
		return "on", true
	case "eventual", "local":
		return "local", true
	default:
		return "", false // unknown → fail closed
	}
}

// FreshnessToken mints a freshness token on the primary (ADR 0009). It is taken
// on a pooled connection AFTER the write committed, not inside the write tx:
// pg_current_wal_insert_lsn() is monotonic, so a token read just after a commit
// is >= that write's LSN (sound — never behind, at worst a hair ahead). Errors
// if this instance is a standby (authz.freshness_token raises there).
func (b *Backend) FreshnessToken(ctx context.Context) (int32, string, error) {
	var epoch int32
	var lsn string
	if err := b.observe(ctx, "freshness", func() error {
		return b.pool.QueryRow(ctx, "SELECT epoch, lsn::text FROM authz.freshness_token()").Scan(&epoch, &lsn)
	}); err != nil {
		return 0, "", fmt.Errorf("minting freshness token: %w", err)
	}
	return epoch, lsn, nil
}

// AssertFresh reports whether THIS node satisfies a freshness token (ADR 0009):
// fresh | stale | wrong_epoch | unknown. On the primary it is always 'fresh';
// on a standby it compares the token's timeline+LSN to the replica's replay
// position (fail-closed to 'unknown' when the timeline is unreadable).
func (b *Backend) AssertFresh(ctx context.Context, epoch int32, lsn string) (string, error) {
	var verdict string
	if err := b.observe(ctx, "freshness", func() error {
		return b.pool.QueryRow(ctx, "SELECT authz.assert_fresh($1, $2::pg_lsn)", epoch, lsn).Scan(&verdict)
	}); err != nil {
		return "", fmt.Errorf("asserting freshness: %w", err)
	}
	return verdict, nil
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

// DeleteUserTuples implements authz.NativeWriter.DeleteUserTuples via
// authz.delete_user_tuples (offboarding).
func (b *Backend) DeleteUserTuples(ctx context.Context, req authz.DeleteUserRequest) (int, error) {
	var n int
	err := b.writeWithRole(ctx, req.Consistency, func(q querier) error {
		return q.QueryRow(ctx,
			"SELECT authz.delete_user_tuples($1, $2, $3, $4)",
			req.Store, req.UserType, req.UserID, textOrNil(req.PerformedBy),
		).Scan(&n)
	})
	if err != nil {
		return 0, fmt.Errorf("delete_user_tuples: %w", err)
	}
	return n, nil
}

// WriteTuplesChecked implements authz.NativeWriter.WriteTuplesChecked via
// authz.write_tuples_checked: preconditions gate deletes+writes atomically.
func (b *Backend) WriteTuplesChecked(ctx context.Context, req authz.CheckedWriteRequest) (json.RawMessage, error) {
	var raw []byte
	err := b.writeWithRole(ctx, req.Consistency, func(q querier) error {
		return q.QueryRow(ctx,
			"SELECT authz.write_tuples_checked($1, $2, $3, $4, $5)",
			req.Store, jsonbOrDefault(req.Preconditions), jsonbOrDefault(req.Deletes),
			jsonbOrDefault(req.Writes), textOrNil(req.PerformedBy),
		).Scan(&raw)
	})
	if err != nil {
		return nil, fmt.Errorf("write_tuples_checked: %w", err)
	}
	return raw, nil
}

// jsonbOrDefault passes an empty JSONB array when the field is absent, matching
// the engine function's defaults.
func jsonbOrDefault(b json.RawMessage) []byte {
	if len(b) == 0 {
		return []byte("[]")
	}
	return []byte(b)
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

// AssertWritable verifies the pool's connection role IS writer-capable — the
// startup check for the native write listener. It must be a member of
// authz_writer (which gates the write functions); a role that can't write fails
// closed rather than 500ing on the first write. The inverse of AssertReadOnly.
func (b *Backend) AssertWritable(ctx context.Context) error {
	var writer bool
	err := b.pool.QueryRow(ctx,
		`SELECT pg_has_role(current_user, 'authz_writer', 'MEMBER')`).Scan(&writer)
	if err != nil {
		return fmt.Errorf("checking writer role: %w", err)
	}
	if !writer {
		return fmt.Errorf("the write listener requires a writer-capable DB role, but the " +
			"connection role is not a member of authz_writer — connect as a writer role " +
			"(e.g. pgauthzd_rw / a role inheriting authz_writer)")
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
