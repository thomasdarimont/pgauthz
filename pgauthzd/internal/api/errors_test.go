package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every error names its request: the JSON body carries the X-Request-ID
// the RequestID middleware set (unique, also on the response header and
// the log line); a browser without a token gets a readable page with the
// same reference, an API client keeps the JSON.
func TestErrorsCarryTheRequestID(t *testing.T) {
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeUnauthorized(w, r)
	}))
	// an API client: JSON with the id
	req := httptest.NewRequest("POST", "/pgauthz/v1/check", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var body struct {
		Status    int    `json:"status"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	id := w.Header().Get("X-Request-ID")
	if w.Code != 401 || body.RequestID == "" || body.RequestID != id || len(id) < 12 {
		t.Fatalf("json error: %d %s header %q", w.Code, w.Body.String(), id)
	}
	// a browser (address bar): the page, same id, still a 401 with the challenge
	req = httptest.NewRequest("GET", "/console/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") || !strings.Contains(w.Body.String(), w.Header().Get("X-Request-ID")) || !strings.Contains(w.Body.String(), "pgauthzd") || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("html error: %d %s %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	// a caller that accepts both keeps JSON; an incoming id is kept
	req = httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Accept", "text/html, application/json")
	req.Header.Set("X-Request-ID", "client-ref-42")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") || !strings.Contains(w.Body.String(), `"request_id":"client-ref-42"`) {
		t.Fatalf("json preferred: %s %s", w.Header().Get("Content-Type"), w.Body.String())
	}
}
