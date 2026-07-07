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

// writeStubBackend implements authz.Backend + authz.NativeWriter; WriteTuples
// returns whatever writeErr is set to, so we can drive the handler's status
// mapping. Only the methods the write path touches are meaningful.
type writeStubBackend struct {
	authz.Backend // embedded nil: unused methods panic if ever called
	writeErr      error
	written       int
}

func (b *writeStubBackend) WriteTuples(context.Context, authz.WriteRequest) (int, error) {
	return b.written, b.writeErr
}
func (b *writeStubBackend) DeleteUserTuples(context.Context, authz.DeleteUserRequest) (int, error) {
	return b.written, b.writeErr
}
func (b *writeStubBackend) WriteTuplesChecked(context.Context, authz.CheckedWriteRequest) (json.RawMessage, error) {
	return nil, b.writeErr
}
func (b *writeStubBackend) DeleteTuples(context.Context, authz.WriteRequest) (int, error) {
	return b.written, b.writeErr
}

func writeReq() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/pgauthz/v1/write",
		strings.NewReader(`{"tuples":[{"user_type":"user","user_id":"a","relation":"viewer","object_type":"doc","object_id":"d"}]}`))
	return r
}

// A forbidden per-app role (reader-only token reaching the write path) must
// surface as 403, not a 500 server fault.
func TestWriteForbiddenRoleIs403(t *testing.T) {
	h := NewHandler(&writeStubBackend{writeErr: authz.ErrForbiddenRole}, &writeStubBackend{writeErr: authz.ErrForbiddenRole}, &writeStubBackend{writeErr: authz.ErrForbiddenRole}, &config.Config{Profile: config.ProfileFull, DefaultStore: "demo"})
	w := httptest.NewRecorder()
	h.WriteTuples(w, writeReq())
	if w.Code != http.StatusForbidden {
		t.Fatalf("forbidden role: got %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

// A genuine backend fault stays a 500.
func TestWriteInternalErrorIs500(t *testing.T) {
	h := NewHandler(&writeStubBackend{writeErr: context.DeadlineExceeded}, &writeStubBackend{writeErr: context.DeadlineExceeded}, &writeStubBackend{writeErr: context.DeadlineExceeded}, &config.Config{Profile: config.ProfileFull, DefaultStore: "demo"})
	w := httptest.NewRecorder()
	h.WriteTuples(w, writeReq())
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("internal error: got %d, want 500", w.Code)
	}
}

// A successful write is 200 with the affected count.
func TestWriteOK(t *testing.T) {
	h := NewHandler(&writeStubBackend{written: 1}, &writeStubBackend{written: 1}, &writeStubBackend{written: 1}, &config.Config{Profile: config.ProfileFull, DefaultStore: "demo"})
	w := httptest.NewRecorder()
	h.WriteTuples(w, writeReq())
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"written":1`) {
		t.Fatalf("ok write: got %d body=%s", w.Code, w.Body.String())
	}
}

// The read-only (decision-only) profile refuses writes with 403 even though the
// backend is write-capable — the profile gate fires before the backend call.
func TestWriteDecisionOnlyIs403(t *testing.T) {
	h := NewHandler(&writeStubBackend{written: 1}, &writeStubBackend{written: 1}, &writeStubBackend{written: 1}, &config.Config{Profile: config.ProfileDecisionOnly, DefaultStore: "demo"})
	w := httptest.NewRecorder()
	h.WriteTuples(w, writeReq())
	if w.Code != http.StatusForbidden {
		t.Fatalf("decision-only write: got %d, want 403", w.Code)
	}
}

// A backend whose rawWrite does NOT implement NativeWriter returns 501.
func TestWriteNonWriterBackendIs501(t *testing.T) {
	h := NewHandler(&opaishBackend{}, &opaishBackend{}, &opaishBackend{}, &config.Config{Profile: config.ProfileFull, DefaultStore: "demo"})
	w := httptest.NewRecorder()
	h.WriteTuples(w, writeReq())
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("non-writer backend write: got %d, want 501", w.Code)
	}
}

// opaishBackend implements authz.Backend but NOT authz.NativeWriter.
type opaishBackend struct{ authz.Backend }

// ── performed_by attribution guard (review #7) ───────────────────────────────

// writeReqAs builds a write request carrying an authenticated JWT subject and
// an optional body performed_by.
func writeReqAs(jwtSubject, performedBy string) *http.Request {
	body := `{"tuples":[{"user_type":"user","user_id":"a","relation":"viewer","object_type":"doc","object_id":"d"}]`
	if performedBy != "" {
		body += `,"performed_by":"` + performedBy + `"`
	}
	body += `}`
	r := httptest.NewRequest(http.MethodPost, "/pgauthz/v1/write", strings.NewReader(body))
	ctx := context.WithValue(r.Context(), ctxSubjectType, "user")
	ctx = context.WithValue(ctx, ctxSubjectID, jwtSubject)
	return r.WithContext(ctx)
}

// On the PUBLIC listener the audit author is token-derived: a body
// performed_by that differs from the authenticated subject is 403 (audit
// actor spoofing), unless ALLOW_SUBJECT_OVERRIDE (trusted-PEP mode). The
// service-token CALLBACK listener keeps trusting the body value — it is the
// upstream OPA's assertion of the subject it authenticated.
func TestWritePerformedByAttribution(t *testing.T) {
	cases := []struct {
		name           string
		publicListener bool
		override       bool
		performedBy    string
		wantCode       int
	}{
		{"public: no body value → JWT subject", true, false, "", http.StatusOK},
		{"public: matching value ok", true, false, "alice", http.StatusOK},
		{"public: DIFFERING value is 403", true, false, "mallory-as-bob", http.StatusForbidden},
		{"public + ALLOW_SUBJECT_OVERRIDE: differing value ok (trusted PEP)", true, true, "bob", http.StatusOK},
		{"callback: differing value ok (trusted OPA assertion)", false, false, "bob", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &writeStubBackend{written: 1}
			h := NewHandler(b, b, b, &config.Config{
				Profile: config.ProfileFull, DefaultStore: "demo",
				AllowSubjectOverride: tc.override,
			})
			h.requireWriterRole = tc.publicListener // the listener discriminator
			w := httptest.NewRecorder()
			h.WriteTuples(w, writeReqAs("alice", tc.performedBy))
			if w.Code != tc.wantCode {
				t.Fatalf("got %d, want %d; body=%s", w.Code, tc.wantCode, w.Body.String())
			}
		})
	}
}
