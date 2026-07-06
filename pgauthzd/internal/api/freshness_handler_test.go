package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/config"
)

// freshStub implements authz.Backend + NativeWriter + FreshnessMinter +
// FreshnessChecker so we can drive mint (write path) and the read guard.
type freshStub struct {
	authz.Backend
	epoch          int32
	lsn            string
	verdict        string // replica verdict
	primaryVerdict string // verdict when re-checked on the primary (fallback)
	assertErr      error
	fallback       bool
}

func (b *freshStub) HasPrimaryFallback() bool { return b.fallback }
func (b *freshStub) AssertFreshPrimary(context.Context, int32, string) (string, error) {
	return b.primaryVerdict, nil
}

func (b *freshStub) WriteTuples(context.Context, authz.WriteRequest) (int, error)  { return 1, nil }
func (b *freshStub) DeleteTuples(context.Context, authz.WriteRequest) (int, error) { return 1, nil }
func (b *freshStub) DeleteUserTuples(context.Context, authz.DeleteUserRequest) (int, error) {
	return 1, nil
}
func (b *freshStub) WriteTuplesChecked(context.Context, authz.CheckedWriteRequest) (json.RawMessage, error) {
	return nil, nil
}
func (b *freshStub) FreshnessToken(context.Context) (int32, string, error) {
	return b.epoch, b.lsn, nil
}
func (b *freshStub) AssertFresh(context.Context, int32, string) (string, error) {
	return b.verdict, b.assertErr
}

// Replica stale + the PRIMARY confirms fresh ⇒ transparent fallback proceeds,
// marked in the context and the X-PGAuthz-Served-By header.
func TestFreshnessTransparentFallback(t *testing.T) {
	tok := authz.EncodeFreshnessToken(testKeyring[0], 1, "0/50")
	b := &freshStub{verdict: "stale", fallback: true, primaryVerdict: "fresh"}
	h := NewHandler(b, b, b, &config.Config{Profile: config.ProfileDecisionOnly, FreshnessKeys: testFreshKeys})
	w := httptest.NewRecorder()
	r := freshGuardReq("at_least_as_fresh", tok)
	if ok := h.freshnessOK(w, r); !ok {
		t.Fatalf("with fallback, a stale read confirmed fresh on the primary should proceed; code=%d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get(ServedByHeader); got != "primary" {
		t.Fatalf("expected X-PGAuthz-Served-By: primary, got %q", got)
	}
	if !authz.PrimaryFallback(r.Context()) {
		t.Fatal("request context should be marked for primary fallback")
	}
}

// Fallback must re-validate on the primary: if the primary ALSO can't satisfy
// the token (e.g. a promoted primary on a new timeline → wrong_epoch), the guard
// fails closed (409) instead of blindly serving from it (ADR 0009 #2).
func TestFreshnessFallbackPrimaryAlsoStale(t *testing.T) {
	tok := authz.EncodeFreshnessToken(testKeyring[0], 1, "0/50")
	b := &freshStub{verdict: "stale", fallback: true, primaryVerdict: "wrong_epoch"}
	h := NewHandler(b, b, b, &config.Config{Profile: config.ProfileDecisionOnly, FreshnessKeys: testFreshKeys})
	w := httptest.NewRecorder()
	r := freshGuardReq("at_least_as_fresh", tok)
	if ok := h.freshnessOK(w, r); ok {
		t.Fatal("fallback must NOT proceed when the primary can't satisfy the token")
	}
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", w.Code)
	}
	if got := w.Header().Get(StaleHeader); got != "wrong_epoch" {
		t.Fatalf("expected X-PGAuthz-Stale: wrong_epoch (primary verdict), got %q", got)
	}
	if authz.PrimaryFallback(r.Context()) {
		t.Fatal("context must NOT be marked for primary fallback when the primary is not fresh")
	}
}

// at_least_as_fresh with NO token is a client error (400), not a silent
// downgrade to a low-latency read (ADR 0009 #3).
func TestFreshnessMissingTokenIs400(t *testing.T) {
	b := &freshStub{}
	h := NewHandler(b, b, b, &config.Config{Profile: config.ProfileDecisionOnly, FreshnessKeys: testFreshKeys})
	w := httptest.NewRecorder()
	if ok := h.freshnessOK(w, freshGuardReq("at_least_as_fresh", "")); ok {
		t.Fatal("at_least_as_fresh without a token must not proceed")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

const testFreshKey = "unit-test-key"

var (
	testFreshKeys = []string{testFreshKey}
	testKeyring   = authz.NewKeyring(testFreshKeys)
)

// A successful write with freshness enabled mints a token in both the
// X-PGAuthz-Revision header and the response body, decodable to the minted value.
func TestWriteMintsRevision(t *testing.T) {
	b := &freshStub{epoch: 1, lsn: "0/ABC"}
	h := NewHandler(b, b, b, &config.Config{Profile: config.ProfileFull, DefaultStore: "demo", FreshnessKeys: testFreshKeys})
	w := httptest.NewRecorder()
	h.WriteTuples(w, writeReq())
	if w.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", w.Code, w.Body.String())
	}
	tok := w.Header().Get(RevisionHeader)
	if tok == "" {
		t.Fatal("expected X-PGAuthz-Revision header")
	}
	if !strings.Contains(w.Body.String(), `"revision"`) {
		t.Fatalf("expected revision in body: %s", w.Body.String())
	}
	e, l, kid, err := authz.DecodeFreshnessToken(testKeyring, tok)
	if err != nil || e != 1 || l != "0/ABC" || kid != testKeyring[0].KID {
		t.Fatalf("decode header token: {%d,%s,%s} err=%v", e, l, kid, err)
	}
}

// Key rotation at the guard: a token minted under the retiring key still passes
// while that key is anywhere in the keyring (any order), and 400s once removed.
func TestFreshnessGuardKeyRotation(t *testing.T) {
	oldRing := authz.NewKeyring([]string{"old-secret"})
	tok := authz.EncodeFreshnessToken(oldRing[0], 1, "0/50") // minted pre-rotation

	cases := []struct {
		name   string
		keys   []string
		wantOK bool
	}{
		{"accept-before-mint (old,new)", []string{"old-secret", "new-secret"}, true},
		{"flipped (new,old)", []string{"new-secret", "old-secret"}, true},
		{"old key removed", []string{"new-secret"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &freshStub{verdict: "fresh"}
			h := NewHandler(b, b, b, &config.Config{Profile: config.ProfileDecisionOnly, FreshnessKeys: tc.keys})
			w := httptest.NewRecorder()
			ok := h.freshnessOK(w, freshGuardReq("at_least_as_fresh", tok))
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v (code=%d body=%s)", ok, tc.wantOK, w.Code, w.Body.String())
			}
			if !tc.wantOK && w.Code != http.StatusBadRequest {
				t.Fatalf("retired-key token should be 400, got %d", w.Code)
			}
		})
	}
}

// Mint always uses the FIRST keyring entry (post-flip, new tokens carry the new
// kid even while the old key still verifies).
func TestWriteMintsWithFirstKey(t *testing.T) {
	keys := []string{"new-secret", "old-secret"}
	ringOf := authz.NewKeyring(keys)
	b := &freshStub{epoch: 2, lsn: "1/DEF"}
	h := NewHandler(b, b, b, &config.Config{Profile: config.ProfileFull, DefaultStore: "demo", FreshnessKeys: keys})
	w := httptest.NewRecorder()
	h.WriteTuples(w, writeReq())
	_, _, kid, err := authz.DecodeFreshnessToken(ringOf, w.Header().Get(RevisionHeader))
	if err != nil || kid != ringOf[0].KID {
		t.Fatalf("mint must use the first key: kid=%s want %s err=%v", kid, ringOf[0].KID, err)
	}
}

// With freshness disabled (no key), a write mints nothing.
func TestWriteNoMintWhenDisabled(t *testing.T) {
	b := &freshStub{epoch: 1, lsn: "0/ABC"}
	h := NewHandler(b, b, b, &config.Config{Profile: config.ProfileFull, DefaultStore: "demo"})
	w := httptest.NewRecorder()
	h.WriteTuples(w, writeReq())
	if w.Header().Get(RevisionHeader) != "" || strings.Contains(w.Body.String(), "revision") {
		t.Fatalf("freshness disabled: expected no token; body=%s", w.Body.String())
	}
}

func freshGuardReq(mode, token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/pgauthz/v1/check", nil)
	if mode != "" {
		r.Header.Set(ConsistencyHeader, mode)
	}
	if token != "" {
		r.Header.Set(RevisionHeader, token)
	}
	return r
}

func TestFreshnessGuard(t *testing.T) {
	validTok := authz.EncodeFreshnessToken(testKeyring[0], 1, "0/50")
	tests := []struct {
		name     string
		cfgKeys  []string
		mode     string
		token    string
		verdict  string
		wantOK   bool
		wantCode int
	}{
		{"no header proceeds", testFreshKeys, "", "", "fresh", true, 0},
		{"minimize_latency proceeds", testFreshKeys, "minimize_latency", validTok, "stale", true, 0},
		{"fresh proceeds", testFreshKeys, "at_least_as_fresh", validTok, "fresh", true, 0},
		{"stale is 409", testFreshKeys, "at_least_as_fresh", validTok, "stale", false, http.StatusConflict},
		{"wrong_epoch is 409", testFreshKeys, "at_least_as_fresh", validTok, "wrong_epoch", false, http.StatusConflict},
		{"unknown is 409", testFreshKeys, "at_least_as_fresh", validTok, "unknown", false, http.StatusConflict},
		{"bad token is 400", testFreshKeys, "at_least_as_fresh", "garbage", "fresh", false, http.StatusBadRequest},
		{"disabled+token is 400", nil, "at_least_as_fresh", validTok, "fresh", false, http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := &freshStub{verdict: tc.verdict}
			h := NewHandler(b, b, b, &config.Config{Profile: config.ProfileDecisionOnly, FreshnessKeys: tc.cfgKeys})
			w := httptest.NewRecorder()
			ok := h.freshnessOK(w, freshGuardReq(tc.mode, tc.token))
			if ok != tc.wantOK {
				t.Fatalf("ok=%v want %v (code=%d body=%s)", ok, tc.wantOK, w.Code, w.Body.String())
			}
			if !tc.wantOK {
				if w.Code != tc.wantCode {
					t.Fatalf("code=%d want %d body=%s", w.Code, tc.wantCode, w.Body.String())
				}
				if tc.wantCode == http.StatusConflict && w.Header().Get(StaleHeader) != tc.verdict {
					t.Fatalf("X-PGAuthz-Stale=%q want %q", w.Header().Get(StaleHeader), tc.verdict)
				}
			}
		})
	}
}
