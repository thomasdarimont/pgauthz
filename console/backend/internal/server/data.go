package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

type tupleRow struct {
	UserType         string          `json:"user_type"`
	UserID           string          `json:"user_id"`
	UserRelation     string          `json:"user_relation"`
	Relation         string          `json:"relation"`
	ObjectType       string          `json:"object_type"`
	ObjectID         string          `json:"object_id"`
	ConditionName    string          `json:"condition_name"`
	ConditionContext json.RawMessage `json:"condition_context"`
	ExpiresAt        *string         `json:"expires_at"`
}

// handleTuples — browse a store's relationship tuples (optionally filtered by
// a substring over all identifiers).
func (s *Server) handleTuples(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view")
	if p == nil {
		return
	}
	q := r.URL.Query().Get("q")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	// Server-side order, from a whitelist (the UI's sortable columns); the
	// default is the natural reading order object → relation → subject.
	orders := map[string]string{
		"object":    "ot.name, t.object_id",
		"relation":  "rl.name",
		"subject":   "ut.name, t.user_id, ur.name",
		"condition": "c.name NULLS LAST",
		"expires":   "t.expires_at NULLS LAST",
	}
	order, ok := orders[r.URL.Query().Get("sort")]
	if !ok {
		order = orders["object"]
	}
	dir := " ASC"
	if r.URL.Query().Get("dir") == "desc" {
		dir = " DESC"
		order = strings.ReplaceAll(order, "NULLS LAST", "DESC NULLS LAST")
		order = strings.ReplaceAll(order, ", ", " DESC, ")
	}
	const from = `
		  FROM authz.tuples t
		  JOIN authz.stores s ON s.id = t.store_id
		  JOIN authz.types ot ON ot.id = t.object_type
		  JOIN authz.relations rl ON rl.id = t.relation
		  JOIN authz.types ut ON ut.id = t.user_type
		  LEFT JOIN authz.relations ur ON ur.id = t.user_relation
		  LEFT JOIN authz.conditions c ON c.id = t.condition_id
		 WHERE s.name = $1
		   AND ($2 = '' OR concat_ws(' ', ut.name, t.user_id, ur.name, rl.name, ot.name, t.object_id, c.name) ILIKE '%' || $2 || '%')`
	var total int
	if err := s.engine.QueryRow(r.Context(), `SELECT count(*)`+from, store, q).Scan(&total); err != nil {
		writeEngineError(w, err)
		return
	}
	rows, err := s.engine.Query(r.Context(), `
		SELECT ut.name, t.user_id, coalesce(ur.name,''), rl.name, ot.name, t.object_id,
		       coalesce(c.name,''), coalesce(t.condition_context, 'null'::jsonb), t.expires_at::text`+from+`
		 ORDER BY `+order+dir+`, ot.name, t.object_id, rl.name, ut.name, t.user_id
		 LIMIT $3 OFFSET $4`, store, q, limit, offset)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	defer rows.Close()
	out := []tupleRow{}
	for rows.Next() {
		var t tupleRow
		if err := rows.Scan(&t.UserType, &t.UserID, &t.UserRelation, &t.Relation, &t.ObjectType, &t.ObjectID,
			&t.ConditionName, &t.ConditionContext, &t.ExpiresAt); err != nil {
			writeEngineError(w, err)
			return
		}
		out = append(out, t)
	}
	writeJSON(w, http.StatusOK, map[string]any{"tuples": out, "limit": limit, "offset": offset, "total": total})
}

// tupleReq is a tuple as the UI sends it and as the import hands it to
// write_tuples_jsonb: the optional parts are omitted when empty, since the
// engine reads an empty condition name or expiry as given, not as absent.
type tupleReq struct {
	UserType         string          `json:"user_type"`
	UserID           string          `json:"user_id"`
	UserRelation     string          `json:"user_relation,omitempty"`
	Relation         string          `json:"relation"`
	ObjectType       string          `json:"object_type"`
	ObjectID         string          `json:"object_id"`
	Condition        string          `json:"condition,omitempty"`
	ConditionContext json.RawMessage `json:"condition_context,omitempty"`
	ExpiresAt        string          `json:"expires_at,omitempty"`
}

func (t tupleReq) valid() bool {
	return t.UserType != "" && t.UserID != "" && t.Relation != "" && t.ObjectType != "" && t.ObjectID != ""
}

// handleWriteTuple — grant a relationship in the managed store. Console
// sharers write tuples directly (the engine still enforces the model's type
// restrictions and conditions); the end-user sharing path with per-object
// grant rules is authz.grant through the application's PEP, not the console.
func (s *Server) handleWriteTuple(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view") // the namespace scope check below decides
	if p == nil {
		return
	}
	var t tupleReq
	if !decodeJSON(w, r, &t) || !t.valid() {
		if t.UserType == "" || !t.valid() {
			writeError(w, http.StatusBadRequest, "user_type, user_id, relation, object_type, object_id are required")
		}
		return
	}
	ns, err := s.typeNamespace(r.Context(), store, t.ObjectType)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	if err := s.authorizeScoped(r.Context(), p, "can_grant", store, []string{ns}); err != nil {
		if !writeScopeError(w, err) {
			writeEngineError(w, err)
		}
		return
	}
	err = s.asPersonScoped(r.Context(), p, "can_grant", "store", store, []string{ns}, map[string]any{"op": "write", "tuple": t}, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(),
			`SELECT authz.write_tuple($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11::timestamptz)`,
			store, t.UserType, t.UserID, t.Relation, t.ObjectType, t.ObjectID, nullable(t.UserRelation),
			nullable(t.Condition), nullableJSON(t.ConditionContext), p.typ+":"+p.id, nullable(t.ExpiresAt))
		return err
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type deleteTuplesReq struct {
	Tuples []tupleReq `json:"tuples"`
}

// handleDeleteTuple — revoke one or several relationships in the managed
// store, in one transaction ({tuples: [...]}; a single tuple body still works).
func (s *Server) handleDeleteTuple(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view") // the namespace scope check below decides
	if p == nil {
		return
	}
	var raw map[string]json.RawMessage
	if !decodeJSON(w, r, &raw) {
		return
	}
	var tuples []tupleReq
	if list, ok := raw["tuples"]; ok {
		if err := json.Unmarshal(list, &tuples); err != nil {
			writeError(w, http.StatusBadRequest, "tuples must be a list")
			return
		}
	} else {
		body, _ := json.Marshal(raw)
		var t tupleReq
		if err := json.Unmarshal(body, &t); err != nil {
			writeError(w, http.StatusBadRequest, "bad tuple")
			return
		}
		tuples = []tupleReq{t}
	}
	if len(tuples) == 0 || len(tuples) > 500 {
		writeError(w, http.StatusBadRequest, "1 to 500 tuples per request")
		return
	}
	for _, t := range tuples {
		if !t.valid() {
			writeError(w, http.StatusBadRequest, "user_type, user_id, relation, object_type, object_id are required")
			return
		}
	}
	deleted := 0
	touched := make([]string, 0, len(tuples))
	for _, t := range tuples {
		ns, err := s.typeNamespace(r.Context(), store, t.ObjectType)
		if err != nil {
			writeEngineError(w, err)
			return
		}
		touched = append(touched, ns)
	}
	if err := s.authorizeScoped(r.Context(), p, "can_grant", store, touched); err != nil {
		if !writeScopeError(w, err) {
			writeEngineError(w, err)
		}
		return
	}
	err := s.asPersonScoped(r.Context(), p, "can_grant", "store", store, touched, map[string]any{"op": "delete", "tuples": tuples}, func(tx pgx.Tx) error {
		for _, t := range tuples {
			var ok bool
			if err := tx.QueryRow(r.Context(), `SELECT authz.delete_tuple($1, $2, $3, $4, $5, $6, $7, $8)`,
				store, t.UserType, t.UserID, t.Relation, t.ObjectType, t.ObjectID, nullable(t.UserRelation), p.typ+":"+p.id).Scan(&ok); err != nil {
				return err
			}
			if ok {
				deleted++
			}
		}
		return nil
	})
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": deleted})
}

// handleTupleStats — the Data tab's numbers (authz.tuple_stats): live
// totals, expiry, wildcards, conditions, and rows per object type. Never
// identifiers.
func (s *Server) handleTupleStats(w http.ResponseWriter, r *http.Request) {
	p, store := s.requireStore(w, r, "can_view")
	if p == nil {
		return
	}
	var raw []byte
	if err := s.engine.QueryRow(r.Context(), `SELECT authz.tuple_stats($1)`, store).Scan(&raw); err != nil {
		writeEngineError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}
