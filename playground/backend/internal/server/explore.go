package server

// Explore mode: engine-direct, read-only, ARBITRARY subjects.
// OpenFGA-playground style: inspect the model + tuples and run check/explain for
// any subject (not just the logged-in user). Read-only; gated by login. This is
// an admin/dev exploration tool — keep the playground itself access-restricted.

import (
	"encoding/json"
	"net/http"
	"strings"
)

type exploreReq struct {
	Store    string            `json:"store"`
	Subject  map[string]string `json:"subject"`
	Action   string            `json:"action"`
	Resource map[string]string `json:"resource"`
	Context  json.RawMessage   `json:"context"`
}

// ctxArg returns the request context as a jsonb argument, or nil (SQL NULL) when
// no usable context was supplied — both check_access_with_context and
// explain_access treat NULL as "no context" (conditions then fail closed).
func (q exploreReq) ctxArg() any {
	s := strings.TrimSpace(string(q.Context))
	if s == "" || s == "null" || s == "{}" {
		return nil
	}
	return s
}

func (s *Server) exploreInput(w http.ResponseWriter, r *http.Request) (exploreReq, bool) {
	var q exploreReq
	if !s.exploreGate(w, r) {
		return q, false
	}
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad json"})
		return q, false
	}
	if q.Store == "" || q.Subject["type"] == "" || q.Action == "" || q.Resource["type"] == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "store, subject.type, action, resource.type required"})
		return q, false
	}
	return q, true
}

func (s *Server) handleExploreCheck(w http.ResponseWriter, r *http.Request) {
	q, ok := s.exploreInput(w, r)
	if !ok {
		return
	}
	var allowed bool
	err := s.engineDB.QueryRow(r.Context(), `SELECT authz.check_access_with_context($1,$2,$3,$4,$5,$6,$7)`,
		q.Store, q.Subject["type"], q.Subject["id"], q.Action, q.Resource["type"], q.Resource["id"], q.ctxArg()).Scan(&allowed)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"allowed": allowed})
}

func (s *Server) handleExploreExplain(w http.ResponseWriter, r *http.Request) {
	q, ok := s.exploreInput(w, r)
	if !ok {
		return
	}
	var raw []byte
	err := s.engineDB.QueryRow(r.Context(), `SELECT authz.explain_access($1,$2,$3,$4,$5,$6,$7)`,
		q.Store, q.Subject["type"], q.Subject["id"], q.Action, q.Resource["type"], q.Resource["id"], q.ctxArg()).Scan(&raw)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}

// exploreGate requires a session and a configured engine connection.
func (s *Server) exploreGate(w http.ResponseWriter, r *http.Request) bool {
	if !s.cfg.ExploreEnabled {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "explore mode is disabled"})
		return false
	}
	se := s.sessionFromReq(r)
	if se == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "not authenticated"})
		return false
	}
	if s.cfg.ExploreRole != "" && !tokenHasRole(se.accessToken, s.cfg.ExploreRole) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "explore mode requires role: " + s.cfg.ExploreRole})
		return false
	}
	if s.engineDB == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "engine connection not configured"})
		return false
	}
	return true
}
