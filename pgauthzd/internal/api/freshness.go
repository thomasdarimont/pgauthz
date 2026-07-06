package api

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
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
	// ServedByHeader reports "primary" when a read was transparently served from
	// the primary fallback pool because the local replica wasn't fresh enough.
	ServedByHeader = "X-PGAuthz-Served-By"
	// RevisionStatusHeader reports the mint outcome on a write:
	// issued | unavailable (enabled but minting failed — the write itself
	// committed) | disabled (feature not configured). Lets a caller that expects
	// read-your-writes tell a broken mint from a switched-off feature.
	RevisionStatusHeader = "X-PGAuthz-Revision-Status"

	consistencyAtLeastAsFresh = "at_least_as_fresh"
)

// freshnessOK enforces an at_least_as_fresh read. It is a NO-OP unless the
// request carries that mode AND a token, so it is safe to wrap every read route.
// Returns false (having written a response) when the request must not proceed.
func (h *Handler) freshnessOK(w http.ResponseWriter, r *http.Request) bool {
	mode := r.Header.Get(ConsistencyHeader)
	if !strings.EqualFold(mode, consistencyAtLeastAsFresh) {
		return true // minimize_latency / fully_consistent / absent → routing, not this guard
	}
	token := r.Header.Get(RevisionHeader)
	if token == "" {
		// at_least_as_fresh REQUIRES a token. A missing one is a client error, NOT
		// a silent downgrade to a low-latency read — that would fail OPEN (a config
		// mistake would look successful while serving possibly-stale data).
		writeBadRequest(w, consistencyAtLeastAsFresh+" requires an "+RevisionHeader+" token")
		return false
	}
	return h.checkFreshToken(w, r, token)
}

// checkFreshToken verifies a token's signature and asserts that THIS node
// satisfies it. Returns false (having written 400/409/500/501) when the read
// must not proceed. Shared by the header guard (freshnessOK) and the
// cursor-bound pagination floor (pageFreshness).
func (h *Handler) checkFreshToken(w http.ResponseWriter, r *http.Request, token string) bool {
	if !h.cfg.FreshnessEnabled() {
		writeBadRequest(w, "freshness tokens are not enabled on this instance (set FRESHNESS_TOKEN_KEYS)")
		return false
	}
	epoch, lsn, kid, err := authz.DecodeFreshnessToken(h.freshKeys, token)
	if err != nil {
		// The CALLER gets one fixed opaque message for every bad-token cause — a
		// probe must not distinguish "key retired by rotation" from "forged" (no
		// oracle). The operational detail (unknown kid / signature / malformed,
		// wrapped in err) goes to the server log only.
		slog.Info("rejected freshness token", "reason", err)
		writeBadRequest(w, "invalid freshness token")
		return false
	}
	// Rotation drain signal: which keyring entry verified this token. The old
	// key is safe to drop once its kid flatlines. kid values come from the
	// configured keyring only (never attacker-controlled), so the label is
	// bounded.
	metrics.FreshnessKeyVerified.WithLabelValues(kid).Inc()
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
	metrics.FreshnessVerdicts.WithLabelValues(verdict).Inc()
	if verdict == "fresh" {
		return true
	}
	// Not fresh (stale/wrong_epoch/unknown). With transparent fallback configured,
	// re-validate against the PRIMARY before serving from it — the primary is NOT
	// unconditionally authoritative for this token: a promoted primary on a new
	// timeline must reject a cross-timeline token too (ADR 0009). Only serve from
	// the primary if it can actually satisfy the token; otherwise fail closed.
	primaryConsulted := false
	if fb, ok := h.raw.(authz.FreshnessFallback); ok && fb.HasPrimaryFallback() {
		pv, perr := fb.AssertFreshPrimary(r.Context(), epoch, lsn)
		if perr != nil {
			writeInternalError(w, perr)
			return false
		}
		metrics.FreshnessVerdicts.WithLabelValues(pv).Inc()
		if pv == "fresh" {
			*r = *r.WithContext(authz.WithPrimaryFallback(r.Context()))
			w.Header().Set(ServedByHeader, "primary")
			metrics.FreshnessFallback.Inc()
			return true
		}
		verdict, primaryConsulted = pv, true // primary can't satisfy it either → fail closed below
	}
	writeFreshnessConflict(w, verdict, primaryConsulted)
	return false
}

// freshnessConflict is the structured 409 body for an unsatisfiable
// at_least_as_fresh read: the verdict plus whether the primary was already
// consulted let a client pick the RIGHT recovery, instead of the old generic
// "retry against the primary" — which is wrong advice for wrong_epoch (no retry
// can ever succeed: the token's timeline is gone) and after a failed
// transparent fallback (the primary WAS the retry).
type freshnessConflict struct {
	Status           int    `json:"status"`
	Error            string `json:"error"`
	Verdict          string `json:"verdict"`
	PrimaryConsulted bool   `json:"primary_consulted"`
	Message          string `json:"message"`
}

func writeFreshnessConflict(w http.ResponseWriter, verdict string, primaryConsulted bool) {
	w.Header().Set(StaleHeader, verdict)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	json.NewEncoder(w).Encode(freshnessConflict{
		Status:           http.StatusConflict,
		Error:            "freshness_constraint_unsatisfied",
		Verdict:          verdict,
		PrimaryConsulted: primaryConsulted,
		Message:          freshnessAction(verdict, primaryConsulted),
	})
}

// freshnessAction is the per-verdict client guidance (reviews #5/#6):
//
//	stale       → retry the primary / another replica, or wait
//	unknown     → this node can't judge; retry the primary
//	wrong_epoch → NOT retryable, and NOT fixed by an unrelated re-mint: the
//	              original write may have been LOST in the failover, so the
//	              client must re-read and reconcile its intended state on the
//	              new primary (reapply idempotently), then use that write's
//	              token. This matters most for revokes/offboarding.
func freshnessAction(verdict string, primaryConsulted bool) string {
	switch verdict {
	case "wrong_epoch":
		return "the token was minted on a different WAL timeline (a failover happened since the write), and " +
			"the write it covers may have been lost — re-read and reconcile the intended authorization state " +
			"on the current primary, reapplying the change idempotently if it is missing, then use the token " +
			"from that write"
	case "unknown":
		if primaryConsulted {
			return "neither this node nor the primary could determine freshness; retry later"
		}
		return "this node cannot determine its WAL timeline; retry against the primary"
	default: // stale
		if primaryConsulted {
			return "the primary was consulted and cannot satisfy the token either; retry later"
		}
		return "this node has not replayed up to the token's position; retry against the primary or wait"
	}
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

// mintRevision mints a freshness token for a just-completed write, sets the
// X-PGAuthz-Revision response header, and reports the outcome in
// X-PGAuthz-Revision-Status (issued | unavailable | disabled). Minting is
// best-effort: the write has already committed, so a mint error must not fail
// the request — but it must not be SILENT either (review #5): the failure is
// counted, logged, and marked `unavailable` so the caller knows it lost
// read-your-writes for this write (vs `disabled` = feature off).
func (h *Handler) mintRevision(w http.ResponseWriter, r *http.Request) string {
	if !h.cfg.FreshnessEnabled() {
		w.Header().Set(RevisionStatusHeader, "disabled")
		return ""
	}
	fm, ok := h.rawWrite.(authz.FreshnessMinter)
	if !ok {
		// Freshness is ENABLED but this write backend cannot mint — a topology
		// anomaly (a full instance's direct pgx backend always can), not the
		// feature being off. Report `unavailable` (review #6) and count it so
		// the misconfiguration is visible, same as a runtime mint failure.
		metrics.FreshnessMintFailures.Inc()
		slog.Error("freshness tokens enabled but the write backend cannot mint them (no FreshnessMinter)")
		w.Header().Set(RevisionStatusHeader, "unavailable")
		return ""
	}
	epoch, lsn, err := fm.FreshnessToken(r.Context())
	if err != nil {
		metrics.FreshnessMintFailures.Inc()
		slog.Error("freshness token mint failed; write committed without a revision", "error", err)
		w.Header().Set(RevisionStatusHeader, "unavailable")
		return ""
	}
	metrics.FreshnessMinted.Inc()
	tok := authz.EncodeFreshnessToken(h.freshKeys[0], epoch, lsn)
	w.Header().Set(RevisionHeader, tok)
	w.Header().Set(RevisionStatusHeader, "issued")
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
