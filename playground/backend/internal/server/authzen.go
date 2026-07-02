package server

import (
	"bytes"
	"io"
	"net/http"
)

// authzenProxy forwards an AuthZEN request to the authzen-opa service, injecting
// the session's access token as a Bearer credential (the SPA never sees the token,
// exactly like the OPA path). `path` is the AuthZEN sub-path on the service, e.g.
// "/access/v1/evaluation". The playground is single-store here: the store is the
// authzen-opa service's DEFAULT_STORE, so it's never in the request.
func (s *Server) authzenProxy(method, path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.sessionFromReq(r) == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "not authenticated"})
			return
		}
		if s.cfg.AuthzenURL == "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "AuthZEN backend not configured"})
			return
		}
		se := s.sessionFromReq(r) // re-read for the token
		var body io.Reader
		if method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			body = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(r.Context(), method, s.cfg.AuthzenURL+path, body)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+se.accessToken)
		resp, err := s.http.Do(req)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": "AuthZEN backend unreachable: " + err.Error()})
			return
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(out)
	}
}
