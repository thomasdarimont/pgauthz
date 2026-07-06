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
	epoch     int32
	lsn       string
	verdict   string
	assertErr error
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

const testFreshKey = "unit-test-key"

// A successful write with freshness enabled mints a token in both the
// X-Authz-Revision header and the response body, decodable to the minted value.
func TestWriteMintsRevision(t *testing.T) {
	b := &freshStub{epoch: 1, lsn: "0/ABC"}
	h := NewHandler(b, b, b, &config.Config{Profile: config.ProfileFull, DefaultStore: "demo", FreshnessKey: testFreshKey})
	w := httptest.NewRecorder()
	h.WriteTuples(w, writeReq())
	if w.Code != http.StatusOK {
		t.Fatalf("got %d body=%s", w.Code, w.Body.String())
	}
	tok := w.Header().Get(RevisionHeader)
	if tok == "" {
		t.Fatal("expected X-Authz-Revision header")
	}
	if !strings.Contains(w.Body.String(), `"revision"`) {
		t.Fatalf("expected revision in body: %s", w.Body.String())
	}
	e, l, err := authz.DecodeFreshnessToken([]byte(testFreshKey), tok)
	if err != nil || e != 1 || l != "0/ABC" {
		t.Fatalf("decode header token: {%d,%s} err=%v", e, l, err)
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
	validTok := authz.EncodeFreshnessToken([]byte(testFreshKey), 1, "0/50")
	tests := []struct {
		name     string
		cfgKey   string
		mode     string
		token    string
		verdict  string
		wantOK   bool
		wantCode int
	}{
		{"no header proceeds", testFreshKey, "", "", "fresh", true, 0},
		{"minimize_latency proceeds", testFreshKey, "minimize_latency", validTok, "stale", true, 0},
		{"fresh proceeds", testFreshKey, "at_least_as_fresh", validTok, "fresh", true, 0},
		{"stale is 409", testFreshKey, "at_least_as_fresh", validTok, "stale", false, http.StatusConflict},
		{"wrong_epoch is 409", testFreshKey, "at_least_as_fresh", validTok, "wrong_epoch", false, http.StatusConflict},
		{"unknown is 409", testFreshKey, "at_least_as_fresh", validTok, "unknown", false, http.StatusConflict},
		{"bad token is 400", testFreshKey, "at_least_as_fresh", "garbage", "fresh", false, http.StatusBadRequest},
		{"disabled+token is 400", "", "at_least_as_fresh", validTok, "fresh", false, http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := &freshStub{verdict: tc.verdict}
			h := NewHandler(b, b, b, &config.Config{Profile: config.ProfileDecisionOnly, FreshnessKey: tc.cfgKey})
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
					t.Fatalf("X-Authz-Stale=%q want %q", w.Header().Get(StaleHeader), tc.verdict)
				}
			}
		})
	}
}
