package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
)

type errorResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	// RequestID is the X-Request-ID of this request (RequestID middleware):
	// quoted from a screenshot or a pasted body, it finds the request's log
	// line (`request_id`) and, for a decision, the decision log entry.
	RequestID string `json:"request_id,omitempty"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(errorResponse{Status: status, Message: msg, RequestID: w.Header().Get("X-Request-ID")})
}

// prefersHTML: the request comes from a browser's address bar — it accepts
// text/html and does not ask for JSON — so the error is a page a person can
// read, with the same request id. API clients (and anything accepting JSON)
// keep the JSON body.
func prefersHTML(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/html") && !strings.Contains(accept, "application/json")
}

// writeErrorFor is writeError with the request at hand: a browser gets the
// readable page, everything else the JSON body.
func writeErrorFor(w http.ResponseWriter, r *http.Request, status int, msg string) {
	if r == nil || !prefersHTML(r) {
		writeError(w, status, msg)
		return
	}
	id := w.Header().Get("X-Request-ID")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Vary", "Accept")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>%d — pgauthzd</title>`+
		`<style>body{font:15px/1.5 system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;color:#1f2933}`+
		`h1{font-size:1.4rem}code{background:#f0f3f5;padding:.1em .35em;border-radius:3px}p.ref{color:#52606d}</style></head>`+
		`<body><h1>%d %s</h1><p>%s</p>`+
		`<p>This address is <strong>pgauthzd</strong>, the pgauthz API: it answers programs that send a bearer token, not browsers. `+
		`The management console is a separate address — ask your operator for it.</p>`+
		`<p class="ref">Reference for support: <code>%s</code> (quote it: it names this request in the server's log).</p></body></html>`,
		status, status, html.EscapeString(http.StatusText(status)), html.EscapeString(msg), html.EscapeString(id))
}

func writeBadRequest(w http.ResponseWriter, msg string) {
	writeError(w, http.StatusBadRequest, msg)
}

// writeUnauthorized is the 401 for a missing, malformed or unverifiable
// bearer token. It names the expected scheme in WWW-Authenticate (RFC 6750
// §3; AuthZEN 1.0 §11.3 SHOULD).
func writeUnauthorized(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="pgauthz"`)
	writeErrorFor(w, r, http.StatusUnauthorized, "invalid or missing authorization token")
}

// writeUnsupportedMediaType is the 415 for a request body whose Content-Type
// is not JSON (AuthZEN 1.0 §10.1: requests MUST carry application/json).
func writeUnsupportedMediaType(w http.ResponseWriter, got string) {
	writeError(w, http.StatusUnsupportedMediaType, "unsupported Content-Type "+strconv.Quote(got)+": the request body must be application/json")
}

func writeForbidden(w http.ResponseWriter, msg string) {
	writeError(w, http.StatusForbidden, msg)
}

// writeSearchError maps a search-path failure: an enumeration refusal
// (ADR 0011 — hooks loaded, unfiltered enumeration not enabled) is the
// caller's 403 with an actionable message, anything else is a 500.
func writeSearchError(w http.ResponseWriter, err error) {
	if errors.Is(err, authz.ErrEnumerationRefused) {
		writeError(w, http.StatusForbidden,
			"enumeration_refused_with_hooks: policy hooks are loaded and search results are graph-derived supersets that hooks do not filter; enable per-candidate filtering with HOOK_FILTERED_ENUMERATION=true, or accept superset semantics with ALLOW_UNFILTERED_ENUMERATION_WITH_HOOKS=true (both on OPA)")
		return
	}
	if errors.Is(err, authz.ErrEnumerationCapExceeded) {
		writeError(w, http.StatusForbidden,
			"enumeration_refused_too_many_candidates: the candidate set exceeds HOOK_FILTER_MAX_CANDIDATES for hook-filtered enumeration; narrow the query (pagination/type) or raise the cap on OPA")
		return
	}
	writeInternalError(w, err)
}

// writeDecisionError maps a decision-path failure (check, batch, explain):
// a request naming a type or action the store's model does not declare is
// the caller's 400, with the engine's message (authz.ErrInvalidRequest from
// the backend); anything else is a 500.
func writeDecisionError(w http.ResponseWriter, err error) {
	if errors.Is(err, authz.ErrInvalidRequest) {
		writeBadRequest(w, err.Error())
		return
	}
	writeInternalError(w, err)
}

func writeInternalError(w http.ResponseWriter, err error) {
	slog.Error("internal error", "error", err)
	writeError(w, http.StatusInternalServerError, "internal server error")
}
