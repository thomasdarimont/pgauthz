package api

import (
	"encoding/base64"
	"encoding/json"
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
	return h.checkFreshToken(w, r, token)
}

// checkFreshToken verifies a token's signature and asserts that THIS node
// satisfies it. Returns false (having written 400/409/500/501) when the read
// must not proceed. Shared by the header guard (freshnessOK) and the
// cursor-bound pagination floor (pageFreshness).
func (h *Handler) checkFreshToken(w http.ResponseWriter, r *http.Request, token string) bool {
	if !h.cfg.FreshnessEnabled() {
		writeBadRequest(w, "freshness tokens are not enabled on this instance (set FRESHNESS_TOKEN_KEY)")
		return false
	}
	epoch, lsn, err := authz.DecodeFreshnessToken([]byte(h.cfg.FreshnessKey), token)
	if err != nil {
		writeBadRequest(w, "invalid freshness token: "+err.Error())
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

// ── Freshness-bound pagination cursors (ADR 0009) ───────────────────────────
//
// A paginated search under `at_least_as_fresh` must not silently mix pre- and
// post-revoke states across pages: once page 1 is served fresh, page 2 must be
// at least as fresh. We enforce that by binding the freshness floor INTO the
// cursor, so it travels with pagination and a client cannot drop it mid-scan
// (nor can a load balancer route a later page to a laggier replica undetected).
//
// A bound cursor is `f1.<base64url(json{c: <keyset cursor>, r: <freshness token>})>`.
// The `f1.` prefix (containing a '.', which RawURLEncoding never emits) makes it
// unambiguous from a plain keyset cursor.

const boundCursorPrefix = "f1."

type boundCursor struct {
	C string `json:"c"` // inner keyset cursor (the engine's next_token)
	R string `json:"r"` // freshness token (the floor)
}

// bindCursor wraps a keyset cursor with a freshness floor. freshTok=="" (or an
// empty cursor) returns the cursor unchanged, so non-freshness pagination and
// last pages are untouched.
func bindCursor(cursor, freshTok string) string {
	if freshTok == "" || cursor == "" {
		return cursor
	}
	b, _ := json.Marshal(boundCursor{C: cursor, R: freshTok})
	return boundCursorPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// unbindCursor splits a possibly-bound cursor into its inner keyset cursor and
// freshness floor (""=plain, unbound cursor). A malformed bound cursor degrades
// to raw so the keyset decoder can reject it.
func unbindCursor(s string) (cursor, freshTok string) {
	rest, ok := strings.CutPrefix(s, boundCursorPrefix)
	if !ok {
		return s, ""
	}
	data, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return s, ""
	}
	var bc boundCursor
	if json.Unmarshal(data, &bc) != nil {
		return s, ""
	}
	return bc.C, bc.R
}

// pageFreshness resolves and enforces the freshness floor for a paginated read,
// and returns the floor to bind onto the NEXT page's cursor. It rewrites
// p.Token in place to the inner keyset cursor so the normal page decoder is
// unchanged. Returns ok=false (response already written) when a cursor-bound
// floor is not satisfied. A no-op (returns "", true) when freshness is unused.
func (h *Handler) pageFreshness(w http.ResponseWriter, r *http.Request, p *PageToken) (freshTok string, ok bool) {
	var cursorTok string
	if p != nil && p.Token != "" {
		p.Token, cursorTok = unbindCursor(p.Token)
	}
	if cursorTok != "" {
		// Continuation of a fresh scan: enforce the floor the cursor carries and
		// keep binding it onto subsequent pages, regardless of request headers.
		if !h.checkFreshToken(w, r, cursorTok) {
			return "", false
		}
		return cursorTok, true
	}
	// First page: the header guard (readGuard → freshnessOK) already enforced the
	// header token; carry it forward so page 2+ stay pinned to it.
	if strings.EqualFold(r.Header.Get(ConsistencyHeader), consistencyAtLeastAsFresh) {
		return r.Header.Get(RevisionHeader), true
	}
	return "", true
}
