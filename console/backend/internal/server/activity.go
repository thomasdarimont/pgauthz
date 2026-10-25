package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

type auditRow struct {
	Action           string          `json:"action"`
	PerformedAt      time.Time       `json:"performed_at"`
	PerformedBy      string          `json:"performed_by"`
	UserType         string          `json:"user_type"`
	UserID           string          `json:"user_id"`
	UserRelation     string          `json:"user_relation"`
	Relation         string          `json:"relation"`
	ObjectType       string          `json:"object_type"`
	ObjectID         string          `json:"object_id"`
	ConditionContext json.RawMessage `json:"condition_context"`
}

type eventRow struct {
	Seq         int64           `json:"seq"`
	SubjectType string          `json:"subject_type"`
	SubjectID   string          `json:"subject_id"`
	Action      string          `json:"action"`
	ObjectType  string          `json:"object_type"`
	ObjectID    string          `json:"object_id"`
	Kind        string          `json:"kind"`
	Payload     json.RawMessage `json:"payload"`
	OccurredAt  time.Time       `json:"occurred_at"`
	RecordedBy  string          `json:"recorded_by"`
}

// modelChangeRow is one entry of the model change history: a rule,
// condition, temporal gate or grant rule that was added (INSERT) or removed
// (DELETE), from the engine's model audit tables. A change to an existing
// condition, gate or grant rule is a DELETE + INSERT pair.
type modelChangeRow struct {
	Seq         int64           `json:"seq"`
	Kind        string          `json:"kind"` // rule | condition | gate | grant_rule | relation_constraint
	Action      string          `json:"action"`
	PerformedAt time.Time       `json:"performed_at"`
	PerformedBy string          `json:"performed_by"`
	ObjectType  string          `json:"object_type"` // rules, gates, grant rules
	Relation    string          `json:"relation"`    //
	Name        string          `json:"name"`        // conditions, gates
	Detail      json.RawMessage `json:"detail"`      // the definition as it was
}

// handleActivity — four logs for one store: the tuple audit trail (who
// changed which relationship), the model change history (rules, conditions,
// gates, grant rules — the versioned parts of the model), the store's own
// action log (what principals did, recorded by its PEPs), and the console's
// action log for this store (who edited, published, shared through the
// console). A retired store keeps its audit trail and history; its action
// log is live-only and comes back empty.
func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view_audit")
	if p == nil {
		return
	}
	ctx := r.Context()
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var retired bool
	if err := s.engine.QueryRow(ctx, `SELECT deleted_at IS NOT NULL FROM authz.stores WHERE name = $1`, store).Scan(&retired); err != nil {
		writeEngineError(w, err)
		return
	}

	audit := []auditRow{}
	rows, err := s.engine.Query(ctx, `
		SELECT a.action, a.performed_at, a.performed_by, ut.name, a.user_id, coalesce(ur.name,''),
		       rl.name, ot.name, a.object_id, coalesce(a.condition_context, 'null'::jsonb)
		  FROM authz.tuples_audit a
		  JOIN authz.stores s ON s.id = a.store_id
		  JOIN authz.types ut ON ut.id = a.user_type
		  JOIN authz.types ot ON ot.id = a.object_type
		  JOIN authz.relations rl ON rl.id = a.relation
		  LEFT JOIN authz.relations ur ON ur.id = a.user_relation
		 WHERE s.name = $1 ORDER BY a.performed_at DESC LIMIT $2`, store, limit)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	for rows.Next() {
		var a auditRow
		if err := rows.Scan(&a.Action, &a.PerformedAt, &a.PerformedBy, &a.UserType, &a.UserID, &a.UserRelation,
			&a.Relation, &a.ObjectType, &a.ObjectID, &a.ConditionContext); err != nil {
			rows.Close()
			writeEngineError(w, err)
			return
		}
		audit = append(audit, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		writeEngineError(w, err)
		return
	}

	model, err := s.modelChanges(ctx, s.engine, store, limit)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	events := []eventRow{}
	if !retired {
		if events, err = s.events(r, store, nil, nil, limit); err != nil {
			writeEngineError(w, err)
			return
		}
	}
	console, err := s.events(r, s.cfg.ConsoleStore, nullable("store"), nullable(store), limit)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": audit, "model": model, "events": events, "console": console, "retired": retired})
}

// modelChanges reads the store's model change history, newest first: the
// union of models_audit (rules), conditions_audit, model_gates_audit and
// grant_rules_audit, with ids resolved to names. Names are resolved through
// the dictionary, which outlives the things it names (a removed type keeps
// its row until the store is deleted), so old entries still read well; an
// id that cannot be resolved is shown as #id. Runs on q (the pool, or a
// transaction — the test reads as the console's database role that way).
func (s *Server) modelChanges(ctx context.Context, q querier, store string, limit int) ([]modelChangeRow, error) {
	rows, err := q.Query(ctx, `
		WITH st AS (SELECT id FROM authz.stores WHERE name = $1)
		SELECT * FROM (
			SELECT a.seq, 'rule' AS kind, a.action, a.performed_at, a.performed_by,
			       coalesce(ot.name, '#' || a.object_type) AS object_type, coalesce(rl.name, '#' || a.relation) AS relation, '' AS name,
			       jsonb_build_object('id', a.model_id,
			           'rule_type', CASE a.rule_type WHEN 1 THEN 'direct' WHEN 2 THEN 'computed' WHEN 3 THEN 'ttu' END,
			           'computed_relation', cr.name, 'tupleset_relation', tr.name, 'tupleset_computed', tc.name,
			           'group_id', a.group_id,
			           'group_op', CASE a.group_op WHEN 0 THEN 'or' WHEN 1 THEN 'intersection' WHEN 2 THEN 'exclusion' END,
			           'negated', a.negated, 'allow_object_wildcard', a.allow_object_wildcard) AS detail
			  FROM authz.models_audit a
			  LEFT JOIN authz.types ot ON ot.id = a.object_type
			  LEFT JOIN authz.relations rl ON rl.id = a.relation
			  LEFT JOIN authz.relations cr ON cr.id = a.computed_relation
			  LEFT JOIN authz.relations tr ON tr.id = a.tupleset_relation
			  LEFT JOIN authz.relations tc ON tc.id = a.tupleset_computed
			 WHERE a.store_id = (SELECT id FROM st)
			UNION ALL
			SELECT a.seq, 'condition', a.action, a.performed_at, a.performed_by, '', '', a.name,
			       jsonb_build_object('id', a.condition_id, 'lang', a.lang, 'expression', a.expression, 'required_context', a.required_context)
			  FROM authz.conditions_audit a
			 WHERE a.store_id = (SELECT id FROM st)
			UNION ALL
			SELECT a.seq, 'gate', a.action, a.performed_at, a.performed_by,
			       coalesce(ot.name, '#' || a.object_type), coalesce(rl.name, '#' || a.relation), a.name,
			       jsonb_build_object('id', a.gate_id, 'spec', a.spec)
			  FROM authz.model_gates_audit a
			  LEFT JOIN authz.types ot ON ot.id = a.object_type
			  LEFT JOIN authz.relations rl ON rl.id = a.relation
			 WHERE a.store_id = (SELECT id FROM st)
			UNION ALL
			SELECT a.seq, 'grant_rule', a.action, a.performed_at, a.performed_by,
			       coalesce(ot.name, '#' || a.object_type), coalesce(rl.name, '#' || a.relation), '',
			       jsonb_build_object('id', a.grant_rule_id, 'requires', coalesce(rq.name, '#' || a.requires), 'requires_revoke', rv.name)
			  FROM authz.grant_rules_audit a
			  LEFT JOIN authz.types ot ON ot.id = a.object_type
			  LEFT JOIN authz.relations rl ON rl.id = a.relation
			  LEFT JOIN authz.relations rq ON rq.id = a.requires
			  LEFT JOIN authz.relations rv ON rv.id = a.requires_revoke
			 WHERE a.store_id = (SELECT id FROM st)
			UNION ALL
			SELECT a.seq, 'relation_constraint', a.action, a.performed_at, a.performed_by,
			       coalesce(ot.name, '#' || a.object_type), coalesce(rl.name, '#' || a.relation), '',
			       jsonb_build_object('id', a.constraint_id, 'max_direct', a.max_direct, 'max_effective', a.max_effective)
			  FROM authz.relation_constraints_audit a
			  LEFT JOIN authz.types ot ON ot.id = a.object_type
			  LEFT JOIN authz.relations rl ON rl.id = a.relation
			 WHERE a.store_id = (SELECT id FROM st)
		) x ORDER BY performed_at DESC, seq DESC LIMIT $2`, store, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []modelChangeRow{}
	for rows.Next() {
		var m modelChangeRow
		if err := rows.Scan(&m.Seq, &m.Kind, &m.Action, &m.PerformedAt, &m.PerformedBy, &m.ObjectType, &m.Relation, &m.Name, &m.Detail); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// events reads a store's action log, optionally for one object, newest first.
func (s *Server) events(r *http.Request, store string, objectType, objectID any, limit int) ([]eventRow, error) {
	rows, err := s.engine.Query(r.Context(), `
		SELECT seq, subject_type, subject_id, action, coalesce(object_type,''), coalesce(object_id,''), kind,
		       coalesce(payload, '{}'::jsonb), occurred_at, coalesce(recorded_by,'')
		  FROM authz.list_events($1, p_object_type => $2, p_object_id => $3, p_limit => $4)
		 ORDER BY occurred_at DESC, seq DESC`, store, objectType, objectID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []eventRow{}
	for rows.Next() {
		var e eventRow
		if err := rows.Scan(&e.Seq, &e.SubjectType, &e.SubjectID, &e.Action, &e.ObjectType, &e.ObjectID, &e.Kind,
			&e.Payload, &e.OccurredAt, &e.RecordedBy); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
