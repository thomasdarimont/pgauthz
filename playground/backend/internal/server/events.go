package server

// Action-log demo (ADR 0012): let the playground user ACT, not only ask.
//
// record/reserve are proxied to pgauthzd-full's native /pgauthz/v1/events
// endpoints with the session's access token — the same path a PEP takes, so
// pgauthzd verifies the JWT, its RECORDER_ROLE claim gate applies, and
// recorded_by is the token subject (never asserted by the SPA). The BFF only
// checks the role up front for a friendlier message.
//
// reset purges a demo store's action log (authz.purge_events with p_force —
// the retention guard exists precisely to stop this in production) so a gate
// demo can be repeated. Deliberately narrow: a dedicated connection role that
// may EXECUTE purge_events and nothing else, a Keycloak role, and a store
// allowlist. Nothing here can touch tuples or the model.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
)

func (s *Server) eventsEnabled(token string) bool {
	if s.cfg.EventsURL == "" {
		return false
	}
	return (s.cfg.RecorderRole != "" && tokenHasRole(token, s.cfg.RecorderRole)) ||
		(s.cfg.WriterRole != "" && tokenHasRole(token, s.cfg.WriterRole))
}

func (s *Server) resetEnabled(token string) bool {
	return s.resetDB != nil && s.cfg.ResetRole != "" && len(s.cfg.ResetStores) > 0 &&
		tokenHasRole(token, s.cfg.ResetRole)
}

// eventsProxy forwards {store, ...body} to pgauthzd-full at
// /stores/<store><path> (the store rides in the path, the rest of the body is
// passed through verbatim), returning pgauthzd's status and JSON as-is.
func (s *Server) eventsProxy(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		se := s.sessionFromReq(r)
		if se == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "not authenticated"})
			return
		}
		if s.cfg.EventsURL == "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "events backend not configured (EVENTS_URL)"})
			return
		}
		if !s.eventsEnabled(se.accessToken) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "recording needs the '" + s.cfg.RecorderRole + "' role (a PEP credential — see the README)"})
			return
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad json"})
			return
		}
		var store string
		if raw, ok := body["store"]; ok {
			_ = json.Unmarshal(raw, &store)
			delete(body, "store")
		}
		if store == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "store required"})
			return
		}
		out, _ := json.Marshal(body)
		target := s.cfg.EventsURL + "/stores/" + url.PathEscape(store) + path
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target, bytes.NewReader(out))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+se.accessToken)
		resp, err := s.http.Do(req)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "events backend unreachable: " + err.Error()})
			return
		}
		defer resp.Body.Close()
		res, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(res)
	}
}

// handleEventsReset purges every event of an allowlisted demo store.
func (s *Server) handleEventsReset(w http.ResponseWriter, r *http.Request) {
	se := s.sessionFromReq(r)
	if se == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "not authenticated"})
		return
	}
	if s.resetDB == nil || s.cfg.ResetRole == "" || len(s.cfg.ResetStores) == 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "events reset not configured"})
		return
	}
	if !tokenHasRole(se.accessToken, s.cfg.ResetRole) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "resetting the action log needs the '" + s.cfg.ResetRole + "' role"})
		return
	}
	var q struct {
		Store string `json:"store"`
	}
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil || q.Store == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "store required"})
		return
	}
	if !slices.Contains(s.cfg.ResetStores, q.Store) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "store '" + q.Store + "' is not a resettable demo store (PLAYGROUND_RESET_STORES)"})
		return
	}
	// p_force: the retention guard refuses cutoffs inside a live gate window —
	// which is exactly what a demo reset wants to do.
	var purged int64
	err := s.resetDB.QueryRow(r.Context(), `SELECT authz.purge_events($1, now(), true)`, q.Store).Scan(&purged)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"store": q.Store, "purged": purged})
}
