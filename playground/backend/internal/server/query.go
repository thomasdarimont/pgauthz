package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// allowedRules are the OPA rules the SPA may invoke (prevents arbitrary data.* access).
// Read-only by design — no mutation rules (e.g. `write`) are exposed.
var allowedRules = map[string]bool{
	"allow":               true,
	"explain":             true,
	"accessible_objects":  true,
	"accessible_subjects": true,
	"permitted_actions":   true,
}

type queryReq struct {
	Rule  string         `json:"rule"`
	Input map[string]any `json:"input"`
}

// handleQuery forwards a whitelisted OPA query, injecting the session's access
// token server-side so the SPA never sees it and every query runs as that user.
func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	se := s.sessionFromReq(r)
	if se == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "not authenticated"})
		return
	}
	var q queryReq
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad json"})
		return
	}
	if !allowedRules[q.Rule] {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "rule not allowed: " + q.Rule})
		return
	}
	if q.Input == nil {
		q.Input = map[string]any{}
	}
	q.Input["token"] = se.accessToken // inject server-side; SPA never sees the token

	body, _ := json.Marshal(map[string]any{"input": q.Input})
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost,
		s.cfg.OpaURL+"/v1/data/authz/"+q.Rule, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(out)
}
