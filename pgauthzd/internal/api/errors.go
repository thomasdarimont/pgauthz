package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
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

func writeInternalError(w http.ResponseWriter, err error) {
	slog.Error("internal error", "error", err)
	writeError(w, http.StatusInternalServerError, "internal server error")
}
