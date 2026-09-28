// Package decisionlog writes pgauthzd's decision log (ADR 0013): one JSON
// line per access decision, opt-in, emitted by the daemon at the edge — never
// by the engine (the check path stays read-only).
//
// A Logger is nil-safe: a nil *Logger is the "off" configuration and every
// method is a no-op, so call sites never branch on whether logging is on.
package decisionlog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Entry is one decision. Field order is the line's key order; every field is
// optional except ts/listener/endpoint/store. Context VALUES are never part
// of an entry — only ContextKeys (the key names).
type Entry struct {
	Time      time.Time `json:"ts"`
	RequestID string    `json:"request_id,omitempty"`
	Listener  string    `json:"listener"`      // public | callback
	Endpoint  string    `json:"endpoint"`      // evaluation | evaluations | check | check-batch | explain | reserve
	Via       string    `json:"via,omitempty"` // engine | opa
	Store     string    `json:"store"`
	Subject   Ref       `json:"subject"`
	Action    string    `json:"action"`
	Resource  Ref       `json:"resource"`
	Decision  *bool     `json:"decision,omitempty"` // absent on error
	State     string    `json:"state,omitempty"`    // allow | deny | conditional
	Reason    string    `json:"reason,omitempty"`
	// MissingContext / Conditions: the detailed decision's explanation of a
	// `conditional` state (request keys a condition or gate needed).
	MissingContext []string `json:"missing_context,omitempty"`
	Conditions     []string `json:"conditions,omitempty"`
	// Gates: per-clause outcomes when the endpoint reports them (reserve).
	Gates []Gate `json:"gates,omitempty"`
	// ContextKeys: names of the request-context keys supplied, sorted. Never values.
	ContextKeys []string `json:"context_keys,omitempty"`
	Actor       string   `json:"actor,omitempty"`  // authenticated caller, "type:id"
	Issuer      string   `json:"issuer,omitempty"` // verified token issuer
	// Provenance: what decided. PgauthzdVersion is the daemon build; Model is
	// the store's model (registry name/version when registry-managed, and the
	// live checksum always); Policy is OPA's version + bundle revisions for an
	// OPA-fronted decision.
	PgauthzdVersion string     `json:"pgauthzd_version,omitempty"`
	Model           *ModelRef  `json:"model,omitempty"`
	Policy          *PolicyRef `json:"policy,omitempty"`
	// ResultCount is set on search lines (DECISION_LOG_SEARCHES): how many
	// ids a search returned — never the ids themselves.
	ResultCount *int    `json:"result_count,omitempty"`
	LatencyMS   float64 `json:"latency_ms"`
	Error       string  `json:"error,omitempty"`
}

// ModelRef is the model provenance of a store.
type ModelRef struct {
	Name     string `json:"name,omitempty"`
	Version  *int   `json:"version,omitempty"`
	Checksum string `json:"checksum,omitempty"`
}

// PolicyRef is the policy provenance of an OPA-fronted decision.
type PolicyRef struct {
	OPAVersion string            `json:"opa_version,omitempty"`
	Bundles    map[string]string `json:"bundles,omitempty"`
}

// Ref is a typed identifier.
type Ref struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
}

// Gate is one gate clause's outcome.
type Gate struct {
	Gate   string `json:"gate"`
	Clause string `json:"clause,omitempty"`
	Passed bool   `json:"passed"`
	Reason string `json:"reason,omitempty"`
}

// Config is the operator-facing configuration (DECISION_LOG*).
type Config struct {
	// Sink: "off" (or ""), "stdout", "stderr", or "file:<path>".
	Sink string
	// Sample in [0,1]: the fraction of ALLOW decisions written. Denies,
	// conditionals and errors are always written.
	Sample float64
}

// Result labels for the lines counter.
const (
	ResultLogged     = "logged"
	ResultSampledOut = "sampled_out"
	ResultError      = "error"
)

// Logger writes entries as JSON lines to a sink. Safe for concurrent use.
type Logger struct {
	mu     sync.Mutex
	w      *bufio.Writer
	dst    io.Writer // the sink under the buffer, to reset after a failed write
	closer io.Closer
	sample float64
	rnd    func() float64
	// OnResult, when set, is called with a result label per Log call
	// (wired to the metrics counter by the daemon).
	OnResult func(result string)
	// unhealthy is set when a write fails and cleared by the next successful
	// write; DECISION_LOG_REQUIRED reads it to fail closed.
	unhealthy atomic.Bool
}

// Healthy reports whether the last write succeeded (true for a nil Logger
// and before the first write).
func (l *Logger) Healthy() bool { return l == nil || !l.unhealthy.Load() }

// Open returns a Logger for cfg, or nil when the sink is off. A file sink is
// opened append-only (O_APPEND) so copy-truncate rotation works.
func Open(cfg Config) (*Logger, error) {
	sink := strings.TrimSpace(cfg.Sink)
	if sink == "" || sink == "off" {
		return nil, nil
	}
	if cfg.Sample < 0 || cfg.Sample > 1 {
		return nil, fmt.Errorf("decision log sample %v is outside [0,1]", cfg.Sample)
	}
	var (
		w      io.Writer
		closer io.Closer
	)
	switch {
	case sink == "stdout":
		w = os.Stdout
	case sink == "stderr":
		w = os.Stderr
	case strings.HasPrefix(sink, "file:"):
		path := strings.TrimPrefix(sink, "file:")
		if path == "" {
			return nil, fmt.Errorf("decision log sink %q: empty file path", sink)
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
		if err != nil {
			return nil, fmt.Errorf("decision log sink %q: %w", sink, err)
		}
		w, closer = f, f
	default:
		return nil, fmt.Errorf("decision log sink %q: expected off | stdout | stderr | file:<path>", sink)
	}
	return New(w, cfg.Sample, closer), nil
}

// New builds a Logger over an arbitrary writer (tests, custom sinks).
func New(w io.Writer, sample float64, closer io.Closer) *Logger {
	return &Logger{w: bufio.NewWriterSize(w, 64*1024), dst: w, closer: closer, sample: sample, rnd: rand.Float64}
}

// Enabled reports whether entries are written (false for a nil Logger).
func (l *Logger) Enabled() bool { return l != nil }

// Log writes one entry, applying the allow-sampling rule. Nil-safe.
func (l *Logger) Log(e Entry) {
	if l == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if l.sampledOut(e) {
		l.result(ResultSampledOut)
		return
	}
	b, err := json.Marshal(e)
	if err != nil {
		l.result(ResultError)
		return
	}
	l.mu.Lock()
	_, werr := l.w.Write(append(b, '\n'))
	if werr == nil {
		werr = l.w.Flush()
	}
	if werr != nil {
		// bufio keeps a failed write's error sticky; reset so the sink gets a
		// fresh attempt on the next line (the failed line is lost and counted).
		l.w.Reset(l.dst)
	}
	l.mu.Unlock()
	if werr != nil {
		l.unhealthy.Store(true)
		l.result(ResultError)
		return
	}
	l.unhealthy.Store(false)
	l.result(ResultLogged)
}

// sampledOut: only unqualified allows are subject to sampling.
func (l *Logger) sampledOut(e Entry) bool {
	if l.sample >= 1 {
		return false
	}
	if e.Error != "" || e.Decision == nil || !*e.Decision || e.State == "conditional" {
		return false
	}
	return l.rnd() >= l.sample
}

func (l *Logger) result(r string) {
	if l.OnResult != nil {
		l.OnResult(r)
	}
}

// Close flushes and closes a file sink. Nil-safe.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	err := l.w.Flush()
	if l.closer != nil {
		if cerr := l.closer.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

// Keys returns the sorted key names of a request context (never its values).
func Keys(ctx map[string]any) []string {
	if len(ctx) == 0 {
		return nil
	}
	out := make([]string, 0, len(ctx))
	for k := range ctx {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// FromDetail fills State, Reason, MissingContext and Conditions from a
// detailed decision (check_access_detailed shape). Unknown shapes are ignored.
func (e *Entry) FromDetail(detail map[string]any) {
	if detail == nil {
		return
	}
	if s, ok := detail["state"].(string); ok {
		e.State = s
	}
	if r, ok := detail["reason"].(string); ok {
		e.Reason = r
	}
	e.MissingContext = stringsOf(detail["missing_context"])
	e.Conditions = stringsOf(detail["conditions"])
}

// GatesOf normalizes a reserve/explain `gates` array ([{gate, clause,
// passed|result, reason}]) into Gate values; anything else yields nil.
func GatesOf(v any) []Gate {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]Gate, 0, len(arr))
	for _, it := range arr {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		g := Gate{}
		g.Gate, _ = m["gate"].(string)
		g.Clause, _ = m["clause"].(string)
		g.Reason, _ = m["reason"].(string)
		if p, ok := m["passed"].(bool); ok {
			g.Passed = p
		} else if p, ok := m["result"].(bool); ok {
			g.Passed = p
		}
		out = append(out, g)
	}
	return out
}

func stringsOf(v any) []string {
	arr, ok := v.([]any)
	if !ok || len(arr) == 0 {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, it := range arr {
		if s, ok := it.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Bool is a small helper for optional booleans.
func Bool(b bool) *bool { return &b }
