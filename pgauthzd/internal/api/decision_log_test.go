package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/config"
	"thomasdarimont.de/authz/pgauthzd/internal/decisionlog"
)

// detailStub adds the detailed check to the contract stub: allow with a
// reason, so DECISION_LOG_DETAIL has something to log.
type detailStub struct{ contractStub }

func (detailStub) CheckAccessDetailed(context.Context, authz.EvalRequest) (bool, map[string]any, error) {
	return true, map[string]any{"state": "allow", "reason": "direct_tuple", "conditions": []any{}}, nil
}

// Provenance capabilities (ADR 0013): model version of the store and OPA
// policy provenance.
func (detailStub) ModelVersion(context.Context, string) (authz.ModelVersion, error) {
	v := 7
	return authz.ModelVersion{Name: "acme-collab", Version: &v, Checksum: "sha256:abc"}, nil
}
func (detailStub) PolicyProvenance() authz.PolicyProvenance {
	return authz.PolicyProvenance{OPAVersion: "1.18.2", Bundles: map[string]string{"policy": "rev-42"}}
}

// NativeReader: the native handlers require the direct backend's surface.
func (detailStub) Explain(context.Context, authz.EvalRequest) (json.RawMessage, error) {
	return json.RawMessage(`{"decision": {"allowed": false, "reason": "gate_denied"}, "tree": {}}`), nil
}
func (detailStub) GrantOptions(context.Context, authz.GrantOptionsRequest) (json.RawMessage, error) {
	return json.RawMessage(`[]`), nil
}
func (detailStub) WatchChanges(context.Context, authz.WatchRequest) (json.RawMessage, error) {
	return json.RawMessage(`{"changes": []}`), nil
}

func newLoggedHandler(t *testing.T, b authz.Backend, detail bool) (*Handler, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	cfg := &config.Config{AllowSubjectOverride: true, DefaultStore: "demo", DecisionLogDetail: detail}
	h := NewHandler(b, b, b, cfg, WithDecisionLog(decisionlog.New(&buf, 1, nil)), WithVersion("v-test"))
	return h, &buf
}

func lines(buf *bytes.Buffer) []map[string]any {
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			panic("bad line: " + l)
		}
		out = append(out, m)
	}
	return out
}

func TestDecisionLogEvaluation(t *testing.T) {
	h, buf := newLoggedHandler(t, contractStub{}, false)
	w := httptest.NewRecorder()
	h.Evaluation(w, jsonReq("POST", "/access/v1/evaluation",
		`{"subject":{"type":"agent","id":"acme_assist"},"action":{"name":"documents_read"},
		  "resource":{"type":"customer_doc","id":"d1"},"context":{"device":{"managed":true},"clearance":"high"}}`))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	got := lines(buf)
	if len(got) != 1 {
		t.Fatalf("want 1 line, got %d: %s", len(got), buf.String())
	}
	l := got[0]
	if l["endpoint"] != "evaluation" || l["listener"] != "public" || l["via"] != "engine" || l["store"] != "demo" {
		t.Fatalf("line labels: %v", l)
	}
	if l["decision"] != true || l["state"] != "allow" || l["action"] != "documents_read" {
		t.Fatalf("line outcome: %v", l)
	}
	if s := l["subject"].(map[string]any); s["type"] != "agent" || s["id"] != "acme_assist" {
		t.Fatalf("line subject: %v", s)
	}
	if ck, _ := l["context_keys"].([]any); len(ck) != 2 || ck[0] != "clearance" || ck[1] != "device" {
		t.Fatalf("context_keys: %v", l["context_keys"])
	}
	if strings.Contains(buf.String(), "high") {
		t.Fatalf("context value leaked: %s", buf.String())
	}
	if _, ok := l["reason"]; ok {
		t.Fatalf("plain check must not carry a reason: %v", l)
	}
}

func TestDecisionLogDetailForLogOnly(t *testing.T) {
	h, buf := newLoggedHandler(t, detailStub{}, true)
	w := httptest.NewRecorder()
	h.Evaluation(w, jsonReq("POST", "/access/v1/evaluation",
		`{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"d1"}}`))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	// the response stays plain (no context) — detail was for the log only
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["context"]; ok {
		t.Fatalf("DECISION_LOG_DETAIL must not change the response: %s", w.Body.String())
	}
	l := lines(buf)[0]
	if l["reason"] != "direct_tuple" || l["state"] != "allow" {
		t.Fatalf("log line lacks the detail: %v", l)
	}

	// native check: same rule
	w = httptest.NewRecorder()
	h.NativeCheck(w, jsonReq("POST", "/pgauthz/v1/check",
		`{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"d1"}}`))
	if w.Code != 200 || strings.Contains(w.Body.String(), "detail") {
		t.Fatalf("native response changed: %d %s", w.Code, w.Body.String())
	}
	if l := lines(buf)[1]; l["endpoint"] != "check" || l["reason"] != "direct_tuple" {
		t.Fatalf("native line: %v", l)
	}

	// explain logs the decision it explains
	w = httptest.NewRecorder()
	h.Explain(w, jsonReq("POST", "/pgauthz/v1/explain",
		`{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"d1"}}`))
	if w.Code != 200 {
		t.Fatalf("explain: %d %s", w.Code, w.Body.String())
	}
	if l := lines(buf)[2]; l["endpoint"] != "explain" || l["decision"] != false || l["reason"] != "gate_denied" || l["state"] != "deny" {
		t.Fatalf("explain line: %v", l)
	}
}

func TestDecisionLogBatchAndOff(t *testing.T) {
	h, buf := newLoggedHandler(t, detailStub{}, false)
	w := httptest.NewRecorder()
	h.NativeCheckBatch(w, jsonReq("POST", "/pgauthz/v1/check-batch",
		`{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"context":{"clearance":"high"},
		  "checks":[{"resource":{"type":"document","id":"d1"}},{"resource":{"type":"document","id":"d2"},"context":{"hour":9}}]}`))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	got := lines(buf)
	if len(got) != 2 || got[0]["endpoint"] != "check-batch" || got[1]["resource"].(map[string]any)["id"] != "d2" {
		t.Fatalf("batch lines: %s", buf.String())
	}
	if ck, _ := got[1]["context_keys"].([]any); len(ck) != 2 || ck[0] != "clearance" || ck[1] != "hour" {
		t.Fatalf("batch context keys not merged: %v", got[1]["context_keys"])
	}

	// off: a handler without the option logs nothing and still answers
	hOff := NewHandler(contractStub{}, contractStub{}, contractStub{}, &config.Config{AllowSubjectOverride: true, DefaultStore: "demo"})
	w = httptest.NewRecorder()
	hOff.Evaluation(w, jsonReq("POST", "/access/v1/evaluation",
		`{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"d1"}}`))
	if w.Code != 200 {
		t.Fatalf("off handler: status %d", w.Code)
	}
}

func TestDecisionLogProvenance(t *testing.T) {
	// engine-answered: model provenance + daemon version, no policy block
	h, buf := newLoggedHandler(t, detailStub{}, false)
	w := httptest.NewRecorder()
	h.Evaluation(w, jsonReq("POST", "/access/v1/evaluation",
		`{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"d1"}}`))
	l := lines(buf)[0]
	if l["pgauthzd_version"] != "v-test" {
		t.Fatalf("version missing: %v", l)
	}
	m, _ := l["model"].(map[string]any)
	if m["name"] != "acme-collab" || m["version"] != float64(7) || m["checksum"] != "sha256:abc" {
		t.Fatalf("model provenance: %v", l["model"])
	}
	if _, ok := l["policy"]; ok {
		t.Fatalf("engine-answered line must not carry policy provenance: %v", l)
	}
	// the model read is cached: a second decision does not re-read (same stub → same value; just no error)
	w = httptest.NewRecorder()
	h.Evaluation(w, jsonReq("POST", "/access/v1/evaluation",
		`{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"d2"}}`))
	if len(lines(buf)) != 2 {
		t.Fatal("second line missing")
	}

	// OPA-fronted: policy provenance from the backend's latest report
	var obuf bytes.Buffer
	ocfg := &config.Config{AllowSubjectOverride: true, DefaultStore: "demo", OPAURL: "http://opa:8181"}
	oh := NewHandler(detailStub{}, detailStub{}, nil, ocfg, WithDecisionLog(decisionlog.New(&obuf, 1, nil)))
	w = httptest.NewRecorder()
	oh.Evaluation(w, jsonReq("POST", "/access/v1/evaluation",
		`{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"d1"}}`))
	ol := lines(&obuf)[0]
	if ol["via"] != "opa" {
		t.Fatalf("via: %v", ol)
	}
	p, _ := ol["policy"].(map[string]any)
	if p["opa_version"] != "1.18.2" || p["bundles"].(map[string]any)["policy"] != "rev-42" {
		t.Fatalf("policy provenance: %v", ol["policy"])
	}
}

type flakyWriter struct{ fail bool }

func (f *flakyWriter) Write(b []byte) (int, error) {
	if f.fail {
		return 0, errors.New("disk full")
	}
	return len(b), nil
}

func TestDecisionLogRequiredFailsClosed(t *testing.T) {
	old := decisionlog.ProbeInterval
	decisionlog.ProbeInterval = 0 // recovery is the guard's probe, not a lucky side channel
	defer func() { decisionlog.ProbeInterval = old }()
	fw := &flakyWriter{}
	cfg := &config.Config{AllowSubjectOverride: true, DefaultStore: "demo", DecisionLog: "stdout", DecisionLogRequired: true}
	h := NewHandler(detailStub{}, detailStub{}, detailStub{}, cfg, WithDecisionLog(decisionlog.New(fw, 1, nil)))
	body := `{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"d1"}}`

	// healthy sink: decisions flow, readiness ok
	w := httptest.NewRecorder()
	h.Evaluation(w, jsonReq("POST", "/access/v1/evaluation", body))
	if w.Code != 200 {
		t.Fatalf("healthy: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.Readyz(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != 200 {
		t.Fatalf("readyz healthy: %d", w.Code)
	}

	// the sink fails: this decision is answered (already decided), the write fails ...
	fw.fail = true
	w = httptest.NewRecorder()
	h.Evaluation(w, jsonReq("POST", "/access/v1/evaluation", body))
	if w.Code != 200 {
		t.Fatalf("decision during the failing write should still answer: %d", w.Code)
	}
	// ... and from now on decisions and readiness refuse
	for _, call := range []func(w *httptest.ResponseRecorder){
		func(w *httptest.ResponseRecorder) { h.Evaluation(w, jsonReq("POST", "/access/v1/evaluation", body)) },
		func(w *httptest.ResponseRecorder) { h.NativeCheck(w, jsonReq("POST", "/pgauthz/v1/check", body)) },
		func(w *httptest.ResponseRecorder) { h.Explain(w, jsonReq("POST", "/pgauthz/v1/explain", body)) },
		func(w *httptest.ResponseRecorder) { h.Readyz(w, httptest.NewRequest("GET", "/readyz", nil)) },
	} {
		w = httptest.NewRecorder()
		call(w)
		if w.Code != 503 {
			t.Fatalf("required + unhealthy must be 503, got %d %s", w.Code, w.Body.String())
		}
	}
	// the sink recovers: the next guarded call probes it and resumes — here a
	// search under required+searches, which is guarded exactly like a decision.
	fw.fail = false
	h.cfg.DecisionLogSearches = true
	w = httptest.NewRecorder()
	h.NativeListActions(w, jsonReq("POST", "/pgauthz/v1/list-actions", body))
	if w.Code != 200 {
		t.Fatalf("search after the sink recovered: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.Evaluation(w, jsonReq("POST", "/access/v1/evaluation", body))
	if w.Code != 200 {
		t.Fatalf("after recovery: %d %s", w.Code, w.Body.String())
	}

	// not required: a broken sink never blocks
	cfg2 := &config.Config{AllowSubjectOverride: true, DefaultStore: "demo", DecisionLog: "stdout"}
	h2 := NewHandler(detailStub{}, detailStub{}, detailStub{}, cfg2, WithDecisionLog(decisionlog.New(&flakyWriter{fail: true}, 1, nil)))
	w = httptest.NewRecorder()
	h2.Evaluation(w, jsonReq("POST", "/access/v1/evaluation", body))
	w = httptest.NewRecorder()
	h2.Evaluation(w, jsonReq("POST", "/access/v1/evaluation", body))
	if w.Code != 200 {
		t.Fatalf("best-effort mode must not fail closed: %d", w.Code)
	}
}

func TestDecisionLogSearchLines(t *testing.T) {
	var buf bytes.Buffer
	cfg := &config.Config{AllowSubjectOverride: true, DefaultStore: "demo", DecisionLog: "stdout", DecisionLogSearches: true}
	h := NewHandler(detailStub{}, detailStub{}, detailStub{}, cfg, WithDecisionLog(decisionlog.New(&buf, 1, nil)))
	w := httptest.NewRecorder()
	h.SearchResource(w, jsonReq("POST", "/access/v1/search/resource",
		`{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document"},"context":{"clearance":"high"}}`))
	if w.Code != 200 {
		t.Fatalf("search: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.NativeListActions(w, jsonReq("POST", "/pgauthz/v1/list-actions",
		`{"subject":{"type":"user","id":"alice"},"resource":{"type":"document","id":"d1"}}`))
	if w.Code != 200 {
		t.Fatalf("list-actions: %d %s", w.Code, w.Body.String())
	}
	got := lines(&buf)
	if len(got) != 2 {
		t.Fatalf("want 2 search lines, got %d: %s", len(got), buf.String())
	}
	l := got[0]
	if l["endpoint"] != "search/resource" || l["result_count"] != float64(2) || l["action"] != "can_read" {
		t.Fatalf("search line: %v", l)
	}
	if _, ok := l["decision"]; ok {
		t.Fatalf("a search line carries no decision: %v", l)
	}
	if strings.Contains(buf.String(), "doc_1") || strings.Contains(buf.String(), "high") {
		t.Fatalf("ids or context values leaked: %s", buf.String())
	}
	if ck, _ := l["context_keys"].([]any); len(ck) != 1 || ck[0] != "clearance" {
		t.Fatalf("context keys: %v", l["context_keys"])
	}
	if got[1]["endpoint"] != "list-actions" || got[1]["result_count"] != float64(1) {
		t.Fatalf("native line: %v", got[1])
	}

	// off: searches are counted, not logged
	buf.Reset()
	cfg.DecisionLogSearches = false
	w = httptest.NewRecorder()
	h.SearchResource(w, jsonReq("POST", "/access/v1/search/resource",
		`{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document"}}`))
	if buf.Len() != 0 {
		t.Fatalf("search logged while off: %s", buf.String())
	}
}

// Review #12: required mode must recover WITHOUT any other write reaching
// the logger — the guard probes the sink itself.
func TestDecisionLogRequiredRecoversByProbe(t *testing.T) {
	old := decisionlog.ProbeInterval
	decisionlog.ProbeInterval = 0
	defer func() { decisionlog.ProbeInterval = old }()
	fw := &flakyWriter{}
	var buf bytes.Buffer
	cfg := &config.Config{AllowSubjectOverride: true, DefaultStore: "demo", DecisionLog: "stdout", DecisionLogRequired: true}
	h := NewHandler(detailStub{}, detailStub{}, detailStub{}, cfg, WithDecisionLog(decisionlog.New(io.MultiWriter(&buf, fw), 1, nil)))
	body := `{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"d1"}}`

	fw.fail = true
	w := httptest.NewRecorder()
	h.Evaluation(w, jsonReq("POST", "/access/v1/evaluation", body)) // answered; its write fails
	w = httptest.NewRecorder()
	h.Evaluation(w, jsonReq("POST", "/access/v1/evaluation", body))
	if w.Code != 503 {
		t.Fatalf("unhealthy sink must refuse: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.Readyz(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != 503 {
		t.Fatalf("readyz must be 503 while the sink is down: %d", w.Code)
	}

	// the sink comes back: the next decision's guard probes, recovers, decides
	fw.fail = false
	buf.Reset()
	w = httptest.NewRecorder()
	h.Evaluation(w, jsonReq("POST", "/access/v1/evaluation", body))
	if w.Code != 200 {
		t.Fatalf("decisions must resume once the sink accepts a line: %d %s", w.Code, w.Body.String())
	}
	got := lines(&buf)
	if len(got) != 2 || got[0]["endpoint"] != "decision_log_probe" || got[0]["state"] != "sink_recovered" || got[1]["endpoint"] != "evaluation" {
		t.Fatalf("expected a probe marker followed by the decision line: %s", buf.String())
	}
	w = httptest.NewRecorder()
	h.Readyz(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != 200 {
		t.Fatalf("readyz after recovery: %d", w.Code)
	}
}

// Review #13: with search lines asked for under required mode, a search is
// refused while the sink is down, exactly like a decision; with search lines
// off, searches keep answering (counted only).
func TestDecisionLogRequiredCoversSearchesWhenAskedFor(t *testing.T) {
	old := decisionlog.ProbeInterval
	decisionlog.ProbeInterval = 0
	defer func() { decisionlog.ProbeInterval = old }()
	body := `{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"d1"}}`
	down := func(searches bool) (*Handler, *flakyWriter) {
		fw := &flakyWriter{}
		cfg := &config.Config{AllowSubjectOverride: true, DefaultStore: "demo", DecisionLog: "stdout",
			DecisionLogRequired: true, DecisionLogSearches: searches}
		h := NewHandler(detailStub{}, detailStub{}, detailStub{}, cfg, WithDecisionLog(decisionlog.New(fw, 1, nil)))
		fw.fail = true
		w := httptest.NewRecorder()
		h.Evaluation(w, jsonReq("POST", "/access/v1/evaluation", body)) // trips the circuit
		return h, fw
	}

	// search evidence asked for → searches fail closed too
	h, fw := down(true)
	for _, call := range []func(w *httptest.ResponseRecorder){
		func(w *httptest.ResponseRecorder) {
			h.SearchAction(w, jsonReq("POST", "/access/v1/search/action", body))
		},
		func(w *httptest.ResponseRecorder) {
			h.NativeListActions(w, jsonReq("POST", "/pgauthz/v1/list-actions", body))
		},
		func(w *httptest.ResponseRecorder) {
			h.NativeListObjects(w, jsonReq("POST", "/pgauthz/v1/list-objects", body))
		},
	} {
		w := httptest.NewRecorder()
		call(w)
		if w.Code != 503 {
			t.Fatalf("search under required+searches with a down sink must be 503, got %d %s", w.Code, w.Body.String())
		}
	}
	fw.fail = false
	w := httptest.NewRecorder()
	h.SearchAction(w, jsonReq("POST", "/access/v1/search/action", body))
	if w.Code != 200 {
		t.Fatalf("search must resume after the sink recovers: %d %s", w.Code, w.Body.String())
	}

	// search evidence not asked for → searches keep answering while decisions refuse
	h, _ = down(false)
	w = httptest.NewRecorder()
	h.SearchAction(w, jsonReq("POST", "/access/v1/search/action", body))
	if w.Code != 200 {
		t.Fatalf("searches without search lines must not be refused: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.Evaluation(w, jsonReq("POST", "/access/v1/evaluation", body))
	if w.Code != 503 {
		t.Fatalf("decisions must still refuse: %d", w.Code)
	}
}

// Review #14: required mode with no logger attached must fail closed, not
// silently degrade (a nil logger reports healthy).
func TestDecisionLogRequiredWithoutLoggerRefuses(t *testing.T) {
	cfg := &config.Config{AllowSubjectOverride: true, DefaultStore: "demo", DecisionLog: "stdout", DecisionLogRequired: true}
	h := NewHandler(detailStub{}, detailStub{}, detailStub{}, cfg) // no WithDecisionLog
	body := `{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"document","id":"d1"}}`
	w := httptest.NewRecorder()
	h.Evaluation(w, jsonReq("POST", "/access/v1/evaluation", body))
	if w.Code != 503 {
		t.Fatalf("required mode without a logger must refuse: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.Readyz(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != 503 {
		t.Fatalf("readyz without a logger under required mode must be 503: %d", w.Code)
	}
}
