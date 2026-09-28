package api

import (
	"bytes"
	"context"
	"encoding/json"
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
