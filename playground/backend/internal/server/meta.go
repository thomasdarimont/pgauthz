package server

import (
	"context"
	"net/http"
)

// metaRoute builds a handler that returns a JSON array of names. needsStore=true
// requires a ?store= param; the query then takes it as $1.
func (s *Server) metaRoute(needsStore bool, query string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.sessionFromReq(r) == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "not authenticated"})
			return
		}
		if s.engineDB == nil {
			writeJSON(w, http.StatusOK, []string{})
			return
		}
		if needsStore {
			store := r.URL.Query().Get("store")
			if store == "" {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "store query param required"})
				return
			}
			writeJSON(w, http.StatusOK, s.queryStrings(r.Context(), query, store))
			return
		}
		writeJSON(w, http.StatusOK, s.queryStrings(r.Context(), query))
	}
}

func (s *Server) queryStrings(ctx context.Context, q string, args ...any) []string {
	res := []string{}
	rows, err := s.engineDB.Query(ctx, q, args...)
	if err != nil {
		return res
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		if rows.Scan(&v) == nil {
			res = append(res, v)
		}
	}
	return res
}

func (s *Server) handleModel(w http.ResponseWriter, r *http.Request) {
	if !s.exploreGate(w, r) {
		return
	}
	store := r.URL.Query().Get("store")
	if store == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "store query param required"})
		return
	}
	var dsl string
	if err := s.engineDB.QueryRow(r.Context(), `SELECT authz.describe_model($1)`, store).Scan(&dsl); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"dsl": dsl})
}

func (s *Server) handleTuples(w http.ResponseWriter, r *http.Request) {
	if !s.exploreGate(w, r) {
		return
	}
	store := r.URL.Query().Get("store")
	if store == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "store query param required"})
		return
	}
	rows, err := s.engineDB.Query(r.Context(), `
		SELECT ot.name, t.object_id, r.name, ut.name, t.user_id, coalesce(ur.name, ''),
		       coalesce(c.name, ''), coalesce(t.condition_context::text, '')
		FROM authz.tuples t
		JOIN authz.stores s ON s.id = t.store_id
		JOIN authz.types ot ON ot.id = t.object_type AND ot.store_id = s.id
		JOIN authz.relations r ON r.id = t.relation AND r.store_id = s.id
		JOIN authz.types ut ON ut.id = t.user_type AND ut.store_id = s.id
		LEFT JOIN authz.relations ur ON ur.id = t.user_relation AND ur.store_id = s.id
		LEFT JOIN authz.conditions c ON c.id = t.condition_id AND c.store_id = s.id
		WHERE s.name = $1 ORDER BY ot.name, t.object_id, r.name LIMIT 1000`, store)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]string{}
	for rows.Next() {
		var ot, oid, rel, ut, uid, ur, cond, condCtx string
		if rows.Scan(&ot, &oid, &rel, &ut, &uid, &ur, &cond, &condCtx) == nil {
			out = append(out, map[string]string{
				"object_type": ot, "object_id": oid, "relation": rel,
				"user_type": ut, "user_id": uid, "user_relation": ur,
				"condition_name": cond, "condition_context": condCtx,
			})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleTypes lists the store's object types with their logical-grouping labels.
func (s *Server) handleTypes(w http.ResponseWriter, r *http.Request) {
	if !s.exploreGate(w, r) {
		return
	}
	store := r.URL.Query().Get("store")
	if store == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "store query param required"})
		return
	}
	rows, err := s.engineDB.Query(r.Context(), `
		SELECT t.name, t.labels, coalesce(t.description, '')
		FROM authz.types t JOIN authz.stores s ON s.id = t.store_id
		WHERE s.name = $1 ORDER BY t.name`, store)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var name, description string
		var labels []string
		if rows.Scan(&name, &labels, &description) == nil {
			if labels == nil {
				labels = []string{}
			}
			out = append(out, map[string]any{"name": name, "labels": labels, "description": description})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleConditions lists the store's named conditions (ABAC expressions).
func (s *Server) handleConditions(w http.ResponseWriter, r *http.Request) {
	if !s.exploreGate(w, r) {
		return
	}
	store := r.URL.Query().Get("store")
	if store == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "store query param required"})
		return
	}
	rows, err := s.engineDB.Query(r.Context(), `
		SELECT c.name, c.lang, c.expression, coalesce(c.required_context::text, '')
		FROM authz.conditions c JOIN authz.stores s ON s.id = c.store_id
		WHERE s.name = $1 ORDER BY c.name`, store)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]string{}
	for rows.Next() {
		var name, lang, expr, req string
		if rows.Scan(&name, &lang, &expr, &req) == nil {
			out = append(out, map[string]string{
				"name": name, "lang": lang, "expression": expr, "required_context": req,
			})
		}
	}
	writeJSON(w, http.StatusOK, out)
}
