package api

import (
	"net/http"
	"strings"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
)

// Freshness tokens over HTTP (ADR 0009). Writes return the minted token; reads
// opt into read-your-writes with a header pair, so the guard applies uniformly
// across every read endpoint without per-body plumbing:
//
//	X-PGAuthz-Consistency: at_least_as_fresh   (read mode; else minimize_latency)
//	X-PGAuthz-Revision:    <token>             (the token returned by the write)
//
// A write echoes X-PGAuthz-Revision (and a "revision" body field where the
// response is a JSON object). A read that a replica cannot satisfy gets 409 with
// X-PGAuthz-Stale: <verdict> so the caller can retry against the primary.
const (
	ConsistencyHeader = "X-PGAuthz-Consistency"
	RevisionHeader    = "X-PGAuthz-Revision"
	StaleHeader       = "X-PGAuthz-Stale"

	consistencyAtLeastAsFresh = "at_least_as_fresh"
)

// freshnessOK enforces an at_least_as_fresh read. It is a NO-OP unless the
// request carries that mode AND a token, so it is safe to wrap every read route.
// Returns false (having written a response) when the request must not proceed.
func (h *Handler) freshnessOK(w http.ResponseWriter, r *http.Request) bool {
	mode := r.Header.Get(ConsistencyHeader)
	token := r.Header.Get(RevisionHeader)
	if !strings.EqualFold(mode, consistencyAtLeastAsFresh) || token == "" {
		return true // minimize_latency / fully_consistent / absent → routing, not this guard
	}
	if !h.cfg.FreshnessEnabled() {
		writeBadRequest(w, "freshness tokens are not enabled on this instance (set FRESHNESS_TOKEN_KEY)")
		return false
	}
	epoch, lsn, err := authz.DecodeFreshnessToken([]byte(h.cfg.FreshnessKey), token)
	if err != nil {
		writeBadRequest(w, "invalid "+RevisionHeader+": "+err.Error())
		return false
	}
	fc, ok := h.raw.(authz.FreshnessChecker)
	if !ok {
		writeError(w, http.StatusNotImplemented, "freshness checks require the direct pgx backend")
		return false
	}
	verdict, err := fc.AssertFresh(r.Context(), epoch, lsn)
	if err != nil {
		writeInternalError(w, err)
		return false
	}
	if verdict == "fresh" {
		return true
	}
	// This replica cannot satisfy the token (stale/wrong_epoch/unknown) → tell the
	// caller to retry against the primary. Retryable, not a server fault.
	w.Header().Set(StaleHeader, verdict)
	writeError(w, http.StatusConflict,
		"replica cannot satisfy the freshness token ("+verdict+"); retry against the primary")
	return false
}

// readGuard wraps a read handler with the freshness guard (a no-op unless the
// caller opts in). Applied at route registration so every read is covered.
func (h *Handler) readGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.freshnessOK(w, r) {
			return
		}
		next(w, r)
	}
}

// mintRevision mints a freshness token for a just-completed write and sets the
// X-PGAuthz-Revision response header, returning the token (or "" when disabled /
// unsupported / on a soft mint failure). Minting is best-effort: the write has
// already committed, so a mint error must not fail the request — the client
// simply gets no token for it.
func (h *Handler) mintRevision(w http.ResponseWriter, r *http.Request) string {
	if !h.cfg.FreshnessEnabled() {
		return ""
	}
	fm, ok := h.rawWrite.(authz.FreshnessMinter)
	if !ok {
		return ""
	}
	epoch, lsn, err := fm.FreshnessToken(r.Context())
	if err != nil {
		return ""
	}
	tok := authz.EncodeFreshnessToken([]byte(h.cfg.FreshnessKey), epoch, lsn)
	w.Header().Set(RevisionHeader, tok)
	return tok
}
