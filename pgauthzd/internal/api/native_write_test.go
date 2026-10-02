package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
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
	lastReserve   authz.ReserveEventRequest
	lastGrant     authz.GrantRequest
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
func (b *writeStubBackend) Grant(_ context.Context, req authz.GrantRequest) (bool, error) {
	b.lastGrant = req
	return b.written > 0, b.writeErr
}
func (b *writeStubBackend) Revoke(_ context.Context, req authz.GrantRequest) (bool, error) {
	b.lastGrant = req
	return b.written > 0, b.writeErr
}
func (b *writeStubBackend) ApplyGrants(context.Context, authz.ApplyGrantsRequest) (json.RawMessage, error) {
	if b.writeErr != nil {
		return nil, b.writeErr
	}
	return json.RawMessage(`{"granted": 2, "revoked": 1}`), nil
}
func (b *writeStubBackend) DeleteTuples(context.Context, authz.WriteRequest) (int, error) {
	return b.written, b.writeErr
}
func (b *writeStubBackend) RecordEvents(context.Context, authz.RecordEventsRequest) (json.RawMessage, error) {
	if b.writeErr != nil {
		return nil, b.writeErr
	}
	return json.RawMessage(`{"recorded": ` + strconvItoa(b.written) + `, "duplicates": 1, "seqs": [7, null]}`), nil
}

func strconvItoa(n int) string { return strconv.Itoa(n) }
func (b *writeStubBackend) ReserveEvent(_ context.Context, req authz.ReserveEventRequest) (json.RawMessage, error) {
	if b.writeErr != nil {
		return nil, b.writeErr
	}
	b.lastReserve = req
	return json.RawMessage(`{"allowed": false, "seq": 9, "kind": "denied", "reason": "gate_denied", "gates": [{"gate": "cap", "clause": "0:count_within", "result": false, "reason": "gate_denied", "observed": 3, "threshold": 3}]}`), nil
}

func writeReq() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/pgauthz/v1/write",
		strings.NewReader(`{"tuples":[{"user_type":"user","user_id":"a","relation":"viewer","object_type":"doc","object_id":"d"}]}`))
	// An authenticated subject is always present in reality (the JWT middleware
	// sets it on the public listener; OPA asserts performed_by on the callback)
	// — and some attributable actor is REQUIRED since review #8 (no empty
	// audit attribution).
	ctx := context.WithValue(r.Context(), ctxSubjectType, "user")
	ctx = context.WithValue(ctx, ctxSubjectID, "tester")
	return r.WithContext(ctx)
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

// Whitespace-only and oversized actors are rejected: "   " would satisfy a
// naive non-empty check while being useless as audit attribution, and the
// immutable trail must not be stuffable with junk (review #9).
func TestWritePerformedByNormalization(t *testing.T) {
	cases := []struct {
		name        string
		performedBy string
		wantCode    int
	}{
		{"whitespace-only is 400 (empty after trim)", "   ", http.StatusBadRequest},
		{"oversized is 400", strings.Repeat("x", 300), http.StatusBadRequest},
		{"trimmed value matching subject ok", "  alice  ", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &writeStubBackend{written: 1}
			h := NewHandler(b, b, b, &config.Config{Profile: config.ProfileFull, DefaultStore: "demo"})
			h.requireWriterRole = false // callback semantics: body value is trusted
			w := httptest.NewRecorder()
			// no subject ctx: on the callback listener the body value is all there is
			body := `{"tuples":[{"user_type":"user","user_id":"a","relation":"viewer","object_type":"doc","object_id":"d"}],"performed_by":` + strconvQuote(tc.performedBy) + `}`
			r := httptest.NewRequest(http.MethodPost, "/pgauthz/v1/write", strings.NewReader(body))
			h.WriteTuples(w, r)
			if w.Code != tc.wantCode {
				t.Fatalf("got %d, want %d; body=%s", w.Code, tc.wantCode, w.Body.String())
			}
		})
	}
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// The callback listener has no JWT subject to fall back to: an omitted
// performed_by must be a 400, never an EMPTY audit attribution (review #8).
func TestWriteCallbackEmptyActorIs400(t *testing.T) {
	b := &writeStubBackend{written: 1}
	h := NewHandler(b, b, b, &config.Config{Profile: config.ProfileFull, DefaultStore: "demo"})
	// callback semantics (requireWriterRole=false) + NO subject ctx + NO body value
	r := httptest.NewRequest(http.MethodPost, "/pgauthz/v1/write",
		strings.NewReader(`{"tuples":[{"user_type":"user","user_id":"a","relation":"viewer","object_type":"doc","object_id":"d"}]}`))
	w := httptest.NewRecorder()
	h.WriteTuples(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty audit actor: got %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// The body-cap middleware (HTTP_MAX_BODY_BYTES) must stop an oversized payload
// at the decode boundary instead of buffering it without bound (review #9).
func TestMaxBodyCapsOversizedWrite(t *testing.T) {
	b := &writeStubBackend{written: 1}
	h := NewHandler(b, b, b, &config.Config{Profile: config.ProfileFull, DefaultStore: "demo"})
	mux := newPublicMux(h, false)
	handler := MaxBody(1024)(mux)

	big := `{"tuples":[{"user_type":"user","user_id":"` + strings.Repeat("a", 4096) + `","relation":"viewer","object_type":"doc","object_id":"d"}],"performed_by":"tester"}`
	r := httptest.NewRequest(http.MethodPost, "/pgauthz/v1/write", strings.NewReader(big))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized body: got %d, want 400; body=%s", w.Code, w.Body.String())
	}

	small := `{"tuples":[{"user_type":"user","user_id":"a","relation":"viewer","object_type":"doc","object_id":"d"}],"performed_by":"tester"}`
	r = httptest.NewRequest(http.MethodPost, "/pgauthz/v1/write", strings.NewReader(small))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("in-limit body must pass: got %d body=%s", w.Code, w.Body.String())
	}
}

// --- Action log (POST /pgauthz/v1/events, ADR 0012) ---------------------------

func eventsReqWithRoles(roles []string, recordedBy string) *http.Request {
	body := `{"events":[{"subject_type":"user","subject_id":"alice","action":"download","object_type":"doc","object_id":"d","kind":"request","payload":{"input":{"bytes":1}},"event_id":"r1/request"}]`
	if recordedBy != "" {
		body += `,"recorded_by":` + strconvQuote(recordedBy)
	}
	body += `}`
	r := httptest.NewRequest(http.MethodPost, "/pgauthz/v1/events", strings.NewReader(body))
	ctx := context.WithValue(r.Context(), ctxSubjectType, "user")
	ctx = context.WithValue(ctx, ctxSubjectID, "alice")
	if roles != nil {
		ctx = context.WithValue(ctx, ctxRoles, roles)
	}
	return r.WithContext(ctx)
}

// The RECORDER_ROLE gate on the public listener: the recorder role passes, the
// writer role passes (a writer can record), anything else is 403; the callback
// listener skips the gate like it skips the writer gate.
func TestRecordEventsRoleGate(t *testing.T) {
	cases := []struct {
		name           string
		publicListener bool
		roles          []string
		wantCode       int
	}{
		{"public: recorder role ok", true, []string{"authz_recorder"}, http.StatusOK},
		{"public: writer role ok (a writer can record)", true, []string{"authz_writer"}, http.StatusOK},
		{"public: reader-only is 403", true, []string{"viewer"}, http.StatusForbidden},
		{"public: no roles is 403", true, nil, http.StatusForbidden},
		{"callback: gate skipped", false, nil, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &writeStubBackend{written: 1}
			h := NewHandler(b, b, b, &config.Config{
				Profile: config.ProfileFull, DefaultStore: "demo",
				WriterRole: "authz_writer", RecorderRole: "authz_recorder",
			})
			h.requireWriterRole = tc.publicListener
			w := httptest.NewRecorder()
			h.RecordEvents(w, eventsReqWithRoles(tc.roles, "alice"))
			if w.Code != tc.wantCode {
				t.Fatalf("got %d, want %d; body=%s", w.Code, tc.wantCode, w.Body.String())
			}
			if tc.wantCode == http.StatusOK && !strings.Contains(w.Body.String(), `"recorded":1`) {
				t.Fatalf("ok record: body=%s", w.Body.String())
			}
		})
	}
}

// The engine's content rejections (undeclared action, out-of-bounds
// occurred_at, malformed element) are the caller's 400; a DB-role refusal is
// 403; a genuine fault stays 500. The decision-only profile refuses with 403.
func TestRecordEventsErrorMapping(t *testing.T) {
	cases := []struct {
		name     string
		profile  config.Profile
		err      error
		wantCode int
	}{
		{"invalid request is 400", config.ProfileFull, authz.ErrInvalidRequest, http.StatusBadRequest},
		{"forbidden role is 403", config.ProfileFull, authz.ErrForbiddenRole, http.StatusForbidden},
		{"backend fault is 500", config.ProfileFull, context.DeadlineExceeded, http.StatusInternalServerError},
		{"decision-only is 403", config.ProfileDecisionOnly, nil, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &writeStubBackend{written: 1, writeErr: tc.err}
			h := NewHandler(b, b, b, &config.Config{Profile: tc.profile, DefaultStore: "demo"})
			h.requireWriterRole = false
			w := httptest.NewRecorder()
			h.RecordEvents(w, eventsReqWithRoles(nil, "alice"))
			if w.Code != tc.wantCode {
				t.Fatalf("got %d, want %d; body=%s", w.Code, tc.wantCode, w.Body.String())
			}
		})
	}
}

// recorded_by shares performed_by's trust split: token-derived on the public
// listener (a differing value is 403), required on the callback listener.
func TestRecordEventsRecordedByAttribution(t *testing.T) {
	b := &writeStubBackend{written: 1}
	h := NewHandler(b, b, b, &config.Config{Profile: config.ProfileFull, DefaultStore: "demo"})
	h.requireWriterRole = true
	w := httptest.NewRecorder()
	h.RecordEvents(w, eventsReqWithRoles([]string{"authz_recorder"}, "mallory-as-bob"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("differing recorded_by on public listener: got %d, want 403; body=%s", w.Code, w.Body.String())
	}

	h.requireWriterRole = false
	r := httptest.NewRequest(http.MethodPost, "/pgauthz/v1/events",
		strings.NewReader(`{"events":[{"subject_type":"user","subject_id":"a","action":"download"}]}`))
	w = httptest.NewRecorder()
	h.RecordEvents(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "recorded_by is required") {
		t.Fatalf("empty recorded_by on callback listener: got %d, want 400; body=%s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	h.RecordEvents(w, httptest.NewRequest(http.MethodPost, "/pgauthz/v1/events",
		strings.NewReader(`{"recorded_by":"svc:files"}`)))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "events is required") {
		t.Fatalf("missing events: got %d; body=%s", w.Code, w.Body.String())
	}
}

// --- Strict tier (POST /pgauthz/v1/events/reserve, ADR 0012 phase 3) ----------

func reserveReq(roles []string, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/pgauthz/v1/events/reserve", strings.NewReader(body))
	ctx := context.WithValue(r.Context(), ctxSubjectType, "user")
	ctx = context.WithValue(ctx, ctxSubjectID, "alice")
	if roles != nil {
		ctx = context.WithValue(ctx, ctxRoles, roles)
	}
	return r.WithContext(ctx)
}

// The reserve shares the events endpoint's gates and passes the engine result
// through with the store added; consistency defaults to `applied`; the JWT
// subject is the acting subject (token-only mode).
func TestReserveEventPassthroughAndDefaults(t *testing.T) {
	b := &writeStubBackend{written: 1}
	h := NewHandler(b, b, b, &config.Config{Profile: config.ProfileFull, DefaultStore: "demo", RecorderRole: "authz_recorder"})
	h.requireWriterRole = true
	w := httptest.NewRecorder()
	h.ReserveEvent(w, reserveReq([]string{"authz_recorder"},
		`{"subject":{"type":"user","id":"alice"},"action":{"name":"transfer"},"resource":{"type":"account","id":"acc-1"},"context":{"amount":5},"payload":{"input":{"amount":5}}}`))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d; body=%s", w.Code, w.Body.String())
	}
	for _, want := range []string{`"allowed":false`, `"reason":"gate_denied"`, `"store":"demo"`, `"gates":[`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("body lacks %s: %s", want, w.Body.String())
		}
	}
	if b.lastReserve.Consistency != "applied" || b.lastReserve.SubjectID != "alice" || b.lastReserve.Action != "transfer" ||
		b.lastReserve.ObjectType != "account" || b.lastReserve.RecordedBy != "alice" {
		t.Fatalf("request not passed through: %+v", b.lastReserve)
	}
}

func TestReserveEventGatesAndValidation(t *testing.T) {
	cases := []struct {
		name     string
		profile  config.Profile
		roles    []string
		body     string
		wantCode int
	}{
		{"reader-only role is 403", config.ProfileFull, []string{"viewer"},
			`{"subject":{"type":"user","id":"alice"},"action":{"name":"t"},"resource":{"type":"a","id":"1"}}`, http.StatusForbidden},
		{"decision-only is 403", config.ProfileDecisionOnly, []string{"authz_recorder"},
			`{"subject":{"type":"user","id":"alice"},"action":{"name":"t"},"resource":{"type":"a","id":"1"}}`, http.StatusForbidden},
		{"missing resource id is 400", config.ProfileFull, []string{"authz_recorder"},
			`{"subject":{"type":"user","id":"alice"},"action":{"name":"t"},"resource":{"type":"a"}}`, http.StatusBadRequest},
		{"differing body subject is 403 in token-only mode", config.ProfileFull, []string{"authz_recorder"},
			`{"subject":{"type":"user","id":"bob"},"action":{"name":"t"},"resource":{"type":"a","id":"1"}}`, http.StatusForbidden},
		{"writer role passes", config.ProfileFull, []string{"authz_writer"},
			`{"subject":{"type":"user","id":"alice"},"action":{"name":"t"},"resource":{"type":"a","id":"1"}}`, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &writeStubBackend{written: 1}
			h := NewHandler(b, b, b, &config.Config{Profile: tc.profile, DefaultStore: "demo",
				WriterRole: "authz_writer", RecorderRole: "authz_recorder"})
			h.requireWriterRole = true
			w := httptest.NewRecorder()
			h.ReserveEvent(w, reserveReq(tc.roles, tc.body))
			if w.Code != tc.wantCode {
				t.Fatalf("got %d, want %d; body=%s", w.Code, tc.wantCode, w.Body.String())
			}
		})
	}
}

// Grant/revoke: the actor is the token subject; a differing body actor is
// refused on the public listener; the engine's refusal (ErrForbiddenRole)
// surfaces as 403 with its message; the writer role is NOT required.
func TestGrantActorRules(t *testing.T) {
	stub := &writeStubBackend{written: 1}
	h := &Handler{
		cfg:               &config.Config{Profile: config.ProfileFull, WriterRole: "authz_writer", SubjectTypeDefault: "user"},
		rawWrite:          stub,
		requireWriterRole: true,
	}
	body := `{"user":{"type":"user","id":"dave"},"relation":"editor","object":{"type":"document","id":"plan"}}`

	t.Run("actor is the token subject, no writer role needed", func(t *testing.T) {
		r := jsonReq("POST", "/pgauthz/v1/grant", body)
		r = r.WithContext(context.WithValue(context.WithValue(r.Context(), ctxSubjectType, "user"), ctxSubjectID, "bob"))
		w := httptest.NewRecorder()
		h.Grant(w, r)
		if w.Code != 200 {
			t.Fatalf("status %d: %s", w.Code, w.Body)
		}
		if stub.lastGrant.ActorType != "user" || stub.lastGrant.ActorID != "bob" || stub.lastGrant.Relation != "editor" {
			t.Fatalf("actor/relation not forwarded: %+v", stub.lastGrant)
		}
		if !strings.Contains(w.Body.String(), `"granted":true`) {
			t.Fatalf("body: %s", w.Body)
		}
	})
	t.Run("a differing body actor is refused on the public listener", func(t *testing.T) {
		r := jsonReq("POST", "/pgauthz/v1/grant", `{"actor":"alice","user":{"type":"user","id":"dave"},"relation":"editor","object":{"type":"document","id":"plan"}}`)
		r = r.WithContext(context.WithValue(context.WithValue(r.Context(), ctxSubjectType, "user"), ctxSubjectID, "bob"))
		w := httptest.NewRecorder()
		h.Grant(w, r)
		if w.Code != 403 {
			t.Fatalf("expected 403, got %d: %s", w.Code, w.Body)
		}
	})
	t.Run("engine refusal is 403 with the engine's message", func(t *testing.T) {
		refused := &writeStubBackend{writeErr: fmt.Errorf("%w: grant refused: user:bob is not allowed can_share_edit on document:plan", authz.ErrForbiddenRole)}
		h2 := &Handler{cfg: h.cfg, rawWrite: refused, requireWriterRole: true}
		r := jsonReq("POST", "/pgauthz/v1/revoke", body)
		r = r.WithContext(context.WithValue(context.WithValue(r.Context(), ctxSubjectType, "user"), ctxSubjectID, "bob"))
		w := httptest.NewRecorder()
		h2.Revoke(w, r)
		if w.Code != 403 || !strings.Contains(w.Body.String(), "grant refused: user:bob is not allowed can_share_edit") {
			t.Fatalf("expected 403 with engine message, got %d: %s", w.Code, w.Body)
		}
	})
	t.Run("missing fields are 400", func(t *testing.T) {
		r := jsonReq("POST", "/pgauthz/v1/grant", `{"user":{"type":"user","id":"dave"}}`)
		r = r.WithContext(context.WithValue(context.WithValue(r.Context(), ctxSubjectType, "user"), ctxSubjectID, "bob"))
		w := httptest.NewRecorder()
		h.Grant(w, r)
		if w.Code != 400 {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})
}
