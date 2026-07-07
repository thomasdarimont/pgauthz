package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

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

func writeUnauthorized(w http.ResponseWriter) {
	writeError(w, http.StatusUnauthorized, "invalid or missing authorization token")
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
			"enumeration_refused_with_hooks: policy hooks are loaded and search results are graph-derived supersets that hooks do not filter; set ALLOW_UNFILTERED_ENUMERATION_WITH_HOOKS=true on OPA to accept superset semantics")
		return
	}
	writeInternalError(w, err)
}

func writeInternalError(w http.ResponseWriter, err error) {
	slog.Error("internal error", "error", err)
	writeError(w, http.StatusInternalServerError, "internal server error")
}
