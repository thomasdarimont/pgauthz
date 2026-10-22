package server

// The Operations tab (per store) and Platform → Operations (fleet): the
// engine's maintenance surface, read as the console and acted on as the
// person. Reads need can_view_audit on the store (can_view_health on the
// platform); actions need can_manage_access (owners, platform admins) and
// are recorded in the console's action log like every other change.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type gateWindowRow struct {
	ObjectType string `json:"object_type"`
	Relation   string `json:"relation"`
	Gate       string `json:"gate"`
	Clause     string `json:"clause"`
	Window     string `json:"window"`
}

type recorderRow struct {
	DBRole  string   `json:"db_role"`
	Actions []string `json:"actions"`
}

type partitionRow struct {
	Parent  string `json:"parent"` // tuples_audit | events
	Name    string `json:"name"`
	Bound   string `json:"bound"` // the partition bound expression; "DEFAULT" for the fail-safe partition
	Bytes   int64  `json:"bytes"`
	Default bool   `json:"default"`
}

type changefeedInfo struct {
	CursorAt  *time.Time `json:"cursor_at"`
	CursorSeq *int64     `json:"cursor_seq"`
	SafeUntil time.Time  `json:"safe_until"`
}

type derivedInfo struct {
	Installed bool            `json:"installed"`
	Status    json.RawMessage `json:"status,omitempty"` // materialized_relations_status() row for the store, when registered
	Error     string          `json:"error,omitempty"`
}

type opsOverview struct {
	Retired     bool            `json:"retired"`
	Readiness   json.RawMessage `json:"readiness"` // events_readiness row; null for a retired store
	GateWindows []gateWindowRow `json:"gate_windows"`
	Recorders   []recorderRow   `json:"recorders"`
	TupleStats  json.RawMessage `json:"tuple_stats"`
	Changefeed  changefeedInfo  `json:"changefeed"`
	Derived     derivedInfo     `json:"derived"`
	Partitions  []partitionRow  `json:"partitions"`  // fleet-wide, read-only here
	LoginRoles  []string        `json:"login_roles"` // suggestions for the recorder allowlist
}

// handleOps — GET /api/stores/{store}/ops: everything an operator checks
// about one store, in one round trip.
func (s *Server) handleOps(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view_audit")
	if p == nil {
		return
	}
	o, err := s.opsOverview(r.Context(), s.engine, store)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, o)
}

// opsOverview reads the overview on q (the pool, or a transaction — the test
// reads as the console's database role that way).
func (s *Server) opsOverview(ctx context.Context, q querier, store string) (*opsOverview, error) {
	o := &opsOverview{GateWindows: []gateWindowRow{}, Recorders: []recorderRow{}, Partitions: []partitionRow{}, LoginRoles: []string{}}
	if err := q.QueryRow(ctx, `SELECT deleted_at IS NOT NULL FROM authz.stores WHERE name = $1`, store).Scan(&o.Retired); err != nil {
		return nil, err
	}
	if !o.Retired { // the live-only parts
		if err := q.QueryRow(ctx, `SELECT row_to_json(r) FROM authz.events_readiness($1) r`, store).Scan(&o.Readiness); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		rows, err := q.Query(ctx, `SELECT object_type, relation, gate, clause, "window"::text FROM authz.gate_windows($1)`, store)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var g gateWindowRow
			if err := rows.Scan(&g.ObjectType, &g.Relation, &g.Gate, &g.Clause, &g.Window); err != nil {
				rows.Close()
				return nil, err
			}
			o.GateWindows = append(o.GateWindows, g)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if err := q.QueryRow(ctx, `SELECT authz.tuple_stats($1)`, store).Scan(&o.TupleStats); err != nil {
			return nil, err
		}
	}
	rows, err := q.Query(ctx, `
		SELECT ra.db_role, array_agg(rl.name ORDER BY rl.name)
		  FROM authz.recorder_actions ra
		  JOIN authz.stores s ON s.id = ra.store_id
		  JOIN authz.relations rl ON rl.id = ra.action
		 WHERE s.name = $1 GROUP BY ra.db_role ORDER BY ra.db_role`, store)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var x recorderRow
		if err := rows.Scan(&x.DBRole, &x.Actions); err != nil {
			rows.Close()
			return nil, err
		}
		o.Recorders = append(o.Recorders, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := q.QueryRow(ctx, `SELECT c.at, c.seq, authz.watch_safe_until() FROM authz.watch_cursor($1) c`, store).
		Scan(&o.Changefeed.CursorAt, &o.Changefeed.CursorSeq, &o.Changefeed.SafeUntil); err != nil {
		return nil, err
	}
	// Derived permissions (db/replication/materialized_relations.sql) are an
	// optional install: absent is a state, not an error.
	if err := q.QueryRow(ctx, `SELECT to_regprocedure('authz.materialized_relations_status()') IS NOT NULL`).Scan(&o.Derived.Installed); err != nil {
		return nil, err
	}
	if o.Derived.Installed {
		//goland:noinspection SqlResolve -- an optional install (db/replication/materialized_relations.sql), absent from a plain schema
		err := q.QueryRow(ctx, `SELECT row_to_json(r) FROM authz.materialized_relations_status() r WHERE r.store = $1`, store).Scan(&o.Derived.Status)
		var pgErr *pgconn.PgError
		switch {
		case err == nil, errors.Is(err, pgx.ErrNoRows): // not registered: Status stays empty
		case errors.As(err, &pgErr) && pgErr.Code == "42501":
			o.Derived.Error = "the console's database role may not read the derived-permissions status"
		default:
			return nil, err
		}
	}
	if o.Partitions, err = s.partitions(ctx, q); err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT rolname FROM pg_roles WHERE rolcanlogin AND rolname NOT LIKE 'pg\_%' ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return nil, err
		}
		o.LoginRoles = append(o.LoginRoles, name)
	}
	rows.Close()
	return o, rows.Err()
}

// partitions lists the monthly partitions of the audit trail and the action
// log with their bounds and sizes (fleet-wide: partitions are not per store).
func (s *Server) partitions(ctx context.Context, q querier) ([]partitionRow, error) {
	rows, err := q.Query(ctx, `
		SELECT p.relname, c.relname, pg_get_expr(c.relpartbound, c.oid), pg_total_relation_size(c.oid)
		  FROM pg_inherits i
		  JOIN pg_class c ON c.oid = i.inhrelid
		  JOIN pg_class p ON p.oid = i.inhparent
		  JOIN pg_namespace n ON n.oid = p.relnamespace
		 WHERE n.nspname = 'authz' AND p.relname IN ('tuples_audit', 'events')
		 ORDER BY p.relname, c.relname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []partitionRow{}
	for rows.Next() {
		var x partitionRow
		if err := rows.Scan(&x.Parent, &x.Name, &x.Bound, &x.Bytes); err != nil {
			return nil, err
		}
		x.Default = x.Bound == "DEFAULT"
		out = append(out, x)
	}
	return out, rows.Err()
}

// ── store actions (can_manage_access, as the person, recorded) ─────────────

type recorderReq struct {
	DBRole  string   `json:"db_role"`
	Actions []string `json:"actions"`
}

var validRole = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

// handleOpsRecorderGrant — POST .../ops/recorders: allow a recorder role
// these actions on the store (grant_recorder_actions).
func (s *Server) handleOpsRecorderGrant(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_manage_access")
	if p == nil {
		return
	}
	var req recorderReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if !validRole.MatchString(req.DBRole) || len(req.Actions) == 0 {
		writeError(w, http.StatusBadRequest, "db_role (a PostgreSQL role name) and at least one action are required")
		return
	}
	var n int
	err := s.asPerson(r.Context(), p, "can_manage_access", "store", store, map[string]any{"op": "grant_recorder_actions", "db_role": req.DBRole, "actions": req.Actions}, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT authz.grant_recorder_actions($1, $2, $3::text[])`, store, req.DBRole, req.Actions).Scan(&n)
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "granted": n})
}

// handleOpsRecorderRevoke — POST .../ops/recorders/revoke: remove actions
// from a recorder role's allowlist, or (no actions) the whole allowlist.
func (s *Server) handleOpsRecorderRevoke(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_manage_access")
	if p == nil {
		return
	}
	var req recorderReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if !validRole.MatchString(req.DBRole) {
		writeError(w, http.StatusBadRequest, "db_role (a PostgreSQL role name) is required")
		return
	}
	var actions any
	if len(req.Actions) > 0 {
		actions = req.Actions
	}
	var n int
	err := s.asPerson(r.Context(), p, "can_manage_access", "store", store, map[string]any{"op": "revoke_recorder_actions", "db_role": req.DBRole, "actions": req.Actions}, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT authz.revoke_recorder_actions($1, $2, $3::text[])`, store, req.DBRole, actions).Scan(&n)
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "revoked": n})
}

type purgeEventsReq struct {
	Before time.Time `json:"before"`
	Force  bool      `json:"force"`
}

// handleOpsPurgeEvents — POST .../ops/purge-events: per-store action-log
// retention (purge_events). The engine refuses a cutoff inside a live gate
// window unless forced; that refusal reaches the person as the error.
func (s *Server) handleOpsPurgeEvents(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_manage_access")
	if p == nil {
		return
	}
	var req purgeEventsReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Before.IsZero() {
		writeError(w, http.StatusBadRequest, "before (a timestamp) is required")
		return
	}
	var n int64
	err := s.asPerson(r.Context(), p, "can_manage_access", "store", store, map[string]any{"op": "purge_events", "before": req.Before, "force": req.Force}, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT authz.purge_events($1, $2, $3)`, store, req.Before, req.Force).Scan(&n)
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "purged": n})
}

type cleanupExpiredReq struct {
	Grace string `json:"grace"` // a PostgreSQL interval such as "1 day"; empty = none
}

var validGrace = regexp.MustCompile(`^(0|\d{1,4} ?(minute|hour|day|week|month)s?)$`)

// handleOpsCleanupExpired — POST .../ops/cleanup-expired: reclaim expired
// tuples older than the grace (cleanup_expired_tuples), attributed to the
// person in the audit trail.
func (s *Server) handleOpsCleanupExpired(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_manage_access")
	if p == nil {
		return
	}
	var req cleanupExpiredReq
	if !decodeJSON(w, r, &req) {
		return
	}
	grace := strings.TrimSpace(req.Grace)
	if grace == "" {
		grace = "0"
	}
	if !validGrace.MatchString(grace) {
		writeError(w, http.StatusBadRequest, "grace must be an interval such as 1 day or 12 hours")
		return
	}
	var n int
	err := s.asPerson(r.Context(), p, "can_manage_access", "store", store, map[string]any{"op": "cleanup_expired_tuples", "grace": grace}, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT authz.cleanup_expired_tuples($1, $2::interval, $3)`, store, grace, p.typ+":"+p.id).Scan(&n)
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": n})
}

type redundantReq struct {
	ObjectType string `json:"object_type"`
	Relation   string `json:"relation"`
	Apply      bool   `json:"apply"` // false: find (dry run); true: delete them
}

type redundantRow struct {
	UserType   string    `json:"user_type"`
	UserID     string    `json:"user_id"`
	Relation   string    `json:"relation"`
	ObjectType string    `json:"object_type"`
	ObjectID   string    `json:"object_id"`
	CreatedAt  time.Time `json:"created_at"`
}

const redundantPageLimit = 500

// handleOpsRedundant — POST .../ops/redundant: direct tuples already granted
// through another rule path. apply=false lists them (find_redundant_tuples,
// first 500 and whether there are more); apply=true removes them all
// (cleanup_redundant_tuples, dry_run off), as the person.
func (s *Server) handleOpsRedundant(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_manage_access")
	if p == nil {
		return
	}
	var req redundantReq
	if !decodeJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	scan := func(rows pgx.Rows, limit int) ([]redundantRow, bool, error) {
		defer rows.Close()
		out := []redundantRow{}
		more := false
		for rows.Next() {
			var x redundantRow
			if err := rows.Scan(&x.UserType, &x.UserID, &x.Relation, &x.ObjectType, &x.ObjectID, &x.CreatedAt); err != nil {
				return nil, false, err
			}
			if limit > 0 && len(out) == limit {
				more = true
				continue
			}
			out = append(out, x)
		}
		return out, more, rows.Err()
	}
	if !req.Apply {
		rows, err := s.engine.Query(ctx, `
			SELECT user_type, user_id, relation, object_type, object_id, created_at
			  FROM authz.find_redundant_tuples($1, $2, $3) LIMIT $4`, store, nullable(req.ObjectType), nullable(req.Relation), redundantPageLimit+1)
		if err != nil {
			writeEngineError(w, err)
			return
		}
		found, more, err := scan(rows, redundantPageLimit)
		if err != nil {
			writeEngineError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tuples": found, "more": more, "applied": false})
		return
	}
	var removed []redundantRow
	err := s.asPerson(ctx, p, "can_manage_access", "store", store, map[string]any{"op": "cleanup_redundant_tuples", "object_type": req.ObjectType, "relation": req.Relation}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT user_type, user_id, relation, object_type, object_id, created_at
			  FROM authz.cleanup_redundant_tuples($1, $2, $3, NULL, false) WHERE deleted`, store, nullable(req.ObjectType), nullable(req.Relation))
		if err != nil {
			return err
		}
		removed, _, err = scan(rows, 0)
		return err
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tuples": removed, "removed": len(removed), "applied": true})
}

// ── fleet (Platform → Operations) ─────────────────────────────────────────

// handlePlatformOps — GET /api/platform/ops: the partitions of the audit
// trail and the action log, every store's gate readiness, the longest gate
// window (what retention must keep), and store sizes.
func (s *Server) handlePlatformOps(w http.ResponseWriter, r *http.Request) {
	p := s.require(w, r, "can_view_health", "platform", s.cfg.PlatformID)
	if p == nil {
		return
	}
	ctx := r.Context()
	parts, err := s.partitions(ctx, s.engine)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	var readiness json.RawMessage
	if err := s.engine.QueryRow(ctx, `SELECT coalesce(json_agg(row_to_json(r)), '[]'::json) FROM authz.events_readiness(NULL) r`).Scan(&readiness); err != nil {
		writeEngineError(w, err)
		return
	}
	var maxWindow *string
	if err := s.engine.QueryRow(ctx, `SELECT authz.max_gate_window(NULL)::text`).Scan(&maxWindow); err != nil {
		writeEngineError(w, err)
		return
	}
	// Store sizes: live tuples (store_stats) and the storage of the store's
	// tuple partitions. authz.tuples is partitioned per object type
	// (FOR VALUES IN (<types.id>)), so a partition maps to its store through
	// the dictionary; the default partition belongs to no store.
	var sizes json.RawMessage
	if err := s.engine.QueryRow(ctx, `
		WITH part AS (
			SELECT pg_total_relation_size(c.oid) AS bytes,
			       (regexp_match(pg_get_expr(c.relpartbound, c.oid), 'IN \(\s*(\d+)'))[1]::int AS type_id
			  FROM pg_inherits i
			  JOIN pg_class c ON c.oid = i.inhrelid
			  JOIN pg_class p ON p.oid = i.inhparent
			  JOIN pg_namespace n ON n.oid = p.relnamespace
			 WHERE n.nspname = 'authz' AND p.relname = 'tuples'),
		per_store AS (
			SELECT ty.store_id, sum(part.bytes) AS bytes
			  FROM part JOIN authz.types ty ON ty.id = part.type_id
			 GROUP BY ty.store_id)
		SELECT coalesce(json_agg(json_build_object('store', ss.store, 'tuples', ss.tuples, 'bytes', coalesce(ps.bytes, 0))
		                         ORDER BY coalesce(ps.bytes, 0) DESC, ss.tuples DESC, ss.store), '[]'::json)
		  FROM authz.store_stats(200) ss
		  JOIN authz.stores st ON st.name = ss.store
		  LEFT JOIN per_store ps ON ps.store_id = st.id`).Scan(&sizes); err != nil {
		writeEngineError(w, err)
		return
	}
	var safeUntil time.Time
	if err := s.engine.QueryRow(ctx, `SELECT authz.watch_safe_until()`).Scan(&safeUntil); err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"partitions": parts, "readiness": readiness, "max_gate_window": maxWindow, "store_sizes": sizes, "safe_until": safeUntil, "now": time.Now(),
	})
}

type ensurePartitionsReq struct {
	MonthsAhead int `json:"months_ahead"`
}

// handlePlatformEnsurePartitions — POST /api/platform/partitions/ensure:
// create the monthly partitions of both logs this many months ahead.
func (s *Server) handlePlatformEnsurePartitions(w http.ResponseWriter, r *http.Request) {
	p := s.require(w, r, "can_manage_access", "platform", s.cfg.PlatformID)
	if p == nil {
		return
	}
	var req ensurePartitionsReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.MonthsAhead < 0 || req.MonthsAhead > 24 {
		writeError(w, http.StatusBadRequest, "months_ahead must be between 0 and 24")
		return
	}
	ctx := r.Context()
	var audit, events int
	err := s.asPersonAuthorized(ctx, p, s.platformGate(ctx, p, "can_manage_access"), "can_manage_access", "platform", s.cfg.PlatformID, map[string]any{"op": "ensure_partitions", "months_ahead": req.MonthsAhead}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT authz.ensure_audit_partitions($1)`, req.MonthsAhead).Scan(&audit); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT authz.ensure_event_partitions($1)`, req.MonthsAhead).Scan(&events)
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "audit_created": audit, "events_created": events})
}

type dropEventPartitionsReq struct {
	Before string `json:"before"` // YYYY-MM-DD: every month wholly before it goes
	Force  bool   `json:"force"`
}

var validDate = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// handlePlatformDropEventPartitions — POST /api/platform/partitions/drop-events:
// fleet-wide action-log retention (drop_event_partitions_before); refused by
// the engine inside a live gate window unless forced.
func (s *Server) handlePlatformDropEventPartitions(w http.ResponseWriter, r *http.Request) {
	p := s.require(w, r, "can_manage_access", "platform", s.cfg.PlatformID)
	if p == nil {
		return
	}
	var req dropEventPartitionsReq
	if !decodeJSON(w, r, &req) {
		return
	}
	if !validDate.MatchString(req.Before) {
		writeError(w, http.StatusBadRequest, "before must be a date (YYYY-MM-DD)")
		return
	}
	ctx := r.Context()
	var n int
	err := s.asPersonAuthorized(ctx, p, s.platformGate(ctx, p, "can_manage_access"), "can_manage_access", "platform", s.cfg.PlatformID, map[string]any{"op": "drop_event_partitions_before", "before": req.Before, "force": req.Force}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT authz.drop_event_partitions_before($1::date, $2)`, req.Before, req.Force).Scan(&n)
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "dropped": n})
}
