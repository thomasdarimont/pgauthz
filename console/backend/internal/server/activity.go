package server

import (
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

// handleActivity — three logs for one store: the tuple audit trail (who
// changed which relationship), the store's own action log (what principals
// did, recorded by its PEPs), and the console's action log for this store
// (who edited, published, shared through the console).
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

	audit := []auditRow{}
	rows, err := s.engine.Query(ctx, `
		SELECT a.action, a.performed_at, coalesce(a.performed_by,''), ut.name, a.user_id, coalesce(ur.name,''),
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

	events, err := s.events(r, store, nil, nil, limit)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	console, err := s.events(r, s.cfg.ConsoleStore, nullable("store"), nullable(store), limit)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": audit, "events": events, "console": console})
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
