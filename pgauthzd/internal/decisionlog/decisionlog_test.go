package decisionlog

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNilLoggerIsOff(t *testing.T) {
	var l *Logger
	if l.Enabled() {
		t.Fatal("nil logger must report disabled")
	}
	l.Log(Entry{}) // must not panic
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got, err := Open(Config{Sink: "off", Sample: 1}); got != nil || err != nil {
		t.Fatalf("Open(off) = %v, %v; want nil, nil", got, err)
	}
	if got, err := Open(Config{Sink: "", Sample: 1}); got != nil || err != nil {
		t.Fatalf("Open('') = %v, %v; want nil, nil", got, err)
	}
}

func TestOpenRejectsBadConfig(t *testing.T) {
	if _, err := Open(Config{Sink: "syslog", Sample: 1}); err == nil {
		t.Fatal("unknown sink accepted")
	}
	if _, err := Open(Config{Sink: "stdout", Sample: 1.5}); err == nil {
		t.Fatal("sample > 1 accepted")
	}
	if _, err := Open(Config{Sink: "file:", Sample: 1}); err == nil {
		t.Fatal("empty file path accepted")
	}
}

func TestLineShapeAndRedaction(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, 1, nil)
	e := Entry{
		Time: time.Date(2026, 9, 28, 14, 5, 0, 0, time.UTC), RequestID: "r-1",
		Listener: "public", Endpoint: "evaluation", Via: "engine", Store: "demo",
		Subject: Ref{"agent", "acme_assist"}, Action: "documents_read", Resource: Ref{"customer_doc", "d1"},
		Decision: Bool(false), Actor: "internal_user:alice", Issuer: "https://idp", LatencyMS: 0.42,
		ContextKeys: Keys(map[string]any{"device": map[string]any{"managed": true}, "clearance": "high"}),
	}
	v := 3
	e.PgauthzdVersion = "1.2.3"
	e.Model = &ModelRef{Name: "m", Version: &v, Checksum: "sha256:x"}
	e.Policy = &PolicyRef{OPAVersion: "1.18.2", Bundles: map[string]string{"policy": "r1"}}
	e.FromDetail(map[string]any{
		"state": "conditional", "reason": "intersection_unsatisfied",
		"missing_context": []any{"request.device"}, "conditions": []any{"managed_device"},
	})
	l.Log(e)
	line := buf.String()
	if !strings.HasSuffix(line, "\n") || strings.Count(line, "\n") != 1 {
		t.Fatalf("want exactly one line, got %q", line)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	for _, k := range []string{"ts", "request_id", "listener", "endpoint", "via", "store", "subject", "action", "resource", "decision", "state", "reason", "missing_context", "conditions", "context_keys", "actor", "issuer", "pgauthzd_version", "model", "policy", "latency_ms"} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing key %q in %s", k, line)
		}
	}
	if strings.Contains(line, "high") || strings.Contains(line, "managed\":true") {
		t.Fatalf("context VALUES leaked into the line: %s", line)
	}
	if ck, _ := got["context_keys"].([]any); len(ck) != 2 || ck[0] != "clearance" || ck[1] != "device" {
		t.Fatalf("context_keys = %v, want sorted [clearance device]", got["context_keys"])
	}
	if got["state"] != "conditional" || got["reason"] != "intersection_unsatisfied" {
		t.Fatalf("detail not applied: %s", line)
	}
	if _, ok := got["error"]; ok {
		t.Fatalf("empty error must be omitted: %s", line)
	}
}

func TestSamplingOnlyDropsPlainAllows(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, 0.0, nil) // sample 0: every plain allow is dropped
	results := map[string]int{}
	l.OnResult = func(r string) { results[r]++ }
	l.rnd = func() float64 { return 0.5 }
	l.Log(Entry{Endpoint: "check", Decision: Bool(true)})                       // dropped
	l.Log(Entry{Endpoint: "check", Decision: Bool(false)})                      // kept: deny
	l.Log(Entry{Endpoint: "check", Decision: Bool(true), State: "conditional"}) // kept: conditional
	l.Log(Entry{Endpoint: "check", Error: "db down"})                           // kept: error
	l.Log(Entry{Endpoint: "check"})                                             // kept: no decision (error path)
	if results[ResultSampledOut] != 1 || results[ResultLogged] != 4 {
		t.Fatalf("results = %v, want 1 sampled_out / 4 logged", results)
	}
	if strings.Count(buf.String(), "\n") != 4 {
		t.Fatalf("want 4 lines, got %q", buf.String())
	}
	// sample 1 keeps everything
	buf.Reset()
	l = New(&buf, 1, nil)
	l.Log(Entry{Decision: Bool(true)})
	if strings.Count(buf.String(), "\n") != 1 {
		t.Fatal("sample 1 dropped an allow")
	}
}

func TestFileSinkAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.log")
	if err := os.WriteFile(path, []byte("{\"old\":1}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	l, err := Open(Config{Sink: "file:" + path, Sample: 1})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	l.Log(Entry{Endpoint: "check", Store: "s", Decision: Bool(true)})
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	b, _ := os.ReadFile(path)
	if strings.Count(string(b), "\n") != 2 || !strings.HasPrefix(string(b), "{\"old\":1}") {
		t.Fatalf("file not appended: %q", string(b))
	}
}

func TestGatesOf(t *testing.T) {
	g := GatesOf([]any{
		map[string]any{"gate": "quota", "clause": "0:count_within", "passed": false, "reason": "gate_denied"},
		map[string]any{"gate": "x", "result": true},
		"junk",
	})
	if len(g) != 2 || g[0].Gate != "quota" || g[0].Passed || g[0].Reason != "gate_denied" || !g[1].Passed {
		t.Fatalf("GatesOf = %+v", g)
	}
	if GatesOf(nil) != nil || GatesOf("x") != nil {
		t.Fatal("non-array input must yield nil")
	}
}

type failWriter struct{ fail bool }

func (f *failWriter) Write(b []byte) (int, error) {
	if f.fail {
		return 0, os.ErrClosed
	}
	return len(b), nil
}

func TestHealthyTracksLastWrite(t *testing.T) {
	var nilLogger *Logger
	if !nilLogger.Healthy() {
		t.Fatal("nil logger must be healthy")
	}
	fw := &failWriter{}
	l := New(fw, 1, nil)
	if !l.Healthy() {
		t.Fatal("healthy before the first write")
	}
	fw.fail = true
	l.Log(Entry{Endpoint: "check", Decision: Bool(false)})
	if l.Healthy() {
		t.Fatal("a failed write must mark the logger unhealthy")
	}
	fw.fail = false
	l.Log(Entry{Endpoint: "check", Decision: Bool(false)})
	if !l.Healthy() {
		t.Fatal("a successful write must clear the unhealthy state")
	}
}

func TestProbeRecoversASink(t *testing.T) {
	old := ProbeInterval
	ProbeInterval = 0
	defer func() { ProbeInterval = old }()
	var nilLogger *Logger
	if !nilLogger.Probe() {
		t.Fatal("nil logger probe must be true")
	}
	fw := &failWriter{fail: true}
	var buf bytes.Buffer
	l := New(io.MultiWriter(&buf, fw), 1, nil)
	l.Log(Entry{Endpoint: "check", Decision: Bool(false)})
	if l.Healthy() {
		t.Fatal("expected unhealthy after a failed write")
	}
	if l.Probe() {
		t.Fatal("probe against a still-failing sink must report unhealthy")
	}
	fw.fail = false
	buf.Reset()
	if !l.Probe() {
		t.Fatal("probe must recover once the sink accepts writes")
	}
	if !strings.Contains(buf.String(), `"endpoint":"decision_log_probe"`) || !strings.Contains(buf.String(), `"state":"sink_recovered"`) {
		t.Fatalf("probe must leave a marker line: %q", buf.String())
	}
	if !l.Healthy() || !l.Probe() {
		t.Fatal("healthy after recovery; a probe on a healthy logger is a no-op true")
	}
}

func TestProbeIsRateLimited(t *testing.T) {
	old := ProbeInterval
	ProbeInterval = time.Hour
	defer func() { ProbeInterval = old }()
	fw := &failWriter{fail: true}
	l := New(fw, 1, nil)
	l.Log(Entry{Endpoint: "check", Decision: Bool(false)})
	attempts := 0
	l.OnResult = func(string) { attempts++ }
	fw.fail = false
	l.Probe() // first probe within the interval: writes
	l.Probe() // second: suppressed
	if attempts != 1 {
		t.Fatalf("probe writes = %d, want 1 (rate-limited)", attempts)
	}
}
