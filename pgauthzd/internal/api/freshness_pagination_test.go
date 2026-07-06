package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/config"
)

func TestBindUnbindCursor(t *testing.T) {
	// empty floor (or empty cursor) → unchanged, no binding
	if got := bindCursor("keyset-abc", ""); got != "keyset-abc" {
		t.Fatalf("empty floor should not wrap: %q", got)
	}
	if c, r := unbindCursor("keyset-abc"); c != "keyset-abc" || r != "" {
		t.Fatalf("plain cursor: got (%q,%q)", c, r)
	}

	// bound cursor round-trips
	tok := "MToxLzIz.YWJjZA"
	bound := bindCursor("keyset-abc", tok)
	if !strings.HasPrefix(bound, boundCursorPrefix) {
		t.Fatalf("expected wrapped cursor, got %q", bound)
	}
	if c, r := unbindCursor(bound); c != "keyset-abc" || r != tok {
		t.Fatalf("round trip: got (%q,%q) want (keyset-abc,%q)", c, r, tok)
	}

	// malformed bound cursor → degrades to raw (keyset decoder rejects later)
	if _, r := unbindCursor(boundCursorPrefix + "!!!not-base64"); r != "" {
		t.Fatalf("malformed bound cursor should degrade to raw, got floor %q", r)
	}
}

func TestPageFreshnessBoundCursorStale(t *testing.T) {
	tok := authz.EncodeFreshnessToken(testKeyring[0], 1, "0/50")
	b := &freshStub{verdict: "stale"}
	h := NewHandler(b, b, b, &config.Config{Profile: config.ProfileDecisionOnly, FreshnessKeys: testFreshKeys})

	w := httptest.NewRecorder()
	p := &PageToken{Token: bindCursor("keyset-xyz", tok)}
	_, ok := h.pageFreshness(w, httptest.NewRequest(http.MethodPost, "/pgauthz/v1/list-objects", nil), p)
	if ok || w.Code != http.StatusConflict {
		t.Fatalf("stale bound cursor: ok=%v code=%d body=%s", ok, w.Code, w.Body.String())
	}
	if w.Header().Get(StaleHeader) != "stale" {
		t.Fatalf("expected X-PGAuthz-Stale=stale, got %q", w.Header().Get(StaleHeader))
	}
	if p.Token != "keyset-xyz" {
		t.Fatalf("cursor should be unwrapped in place, got %q", p.Token)
	}
}

func TestPageFreshnessBoundCursorFresh(t *testing.T) {
	tok := authz.EncodeFreshnessToken(testKeyring[0], 1, "0/50")
	b := &freshStub{verdict: "fresh"}
	h := NewHandler(b, b, b, &config.Config{Profile: config.ProfileDecisionOnly, FreshnessKeys: testFreshKeys})

	// bound cursor, fresh → ok, floor propagated for the next page, cursor unwrapped
	p := &PageToken{Token: bindCursor("keyset-2", tok)}
	ft, ok := h.pageFreshness(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/x", nil), p)
	if !ok || ft != tok || p.Token != "keyset-2" {
		t.Fatalf("fresh bound cursor: ok=%v ft=%q token=%q", ok, ft, p.Token)
	}

	// first page (no cursor): the at_least_as_fresh header floor is carried forward
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.Header.Set(ConsistencyHeader, "at_least_as_fresh")
	r.Header.Set(RevisionHeader, tok)
	ft, ok = h.pageFreshness(httptest.NewRecorder(), r, nil)
	if !ok || ft != tok {
		t.Fatalf("first-page header floor: ok=%v ft=%q", ok, ft)
	}

	// no freshness at all → no floor, proceed
	ft, ok = h.pageFreshness(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/x", nil), &PageToken{Token: "plain-keyset"})
	if !ok || ft != "" {
		t.Fatalf("plain pagination: ok=%v ft=%q", ok, ft)
	}
}
