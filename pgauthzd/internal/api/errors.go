package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
)

type errorResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(errorResponse{Status: status, Message: msg})
}

func writeBadRequest(w http.ResponseWriter, msg string) {
	writeError(w, http.StatusBadRequest, msg)
}

// writeUnauthorized is the 401 for a missing, malformed or unverifiable
// bearer token. It names the expected scheme in WWW-Authenticate (RFC 6750
// §3; AuthZEN 1.0 §11.3 SHOULD).
func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="pgauthz"`)
	writeError(w, http.StatusUnauthorized, "invalid or missing authorization token")
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
