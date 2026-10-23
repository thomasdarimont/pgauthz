// Package decisionlog writes pgauthzd's decision log (ADR 0013): one JSON
// line per access decision, opt-in, emitted by the daemon at the edge — never
// by the engine (the check path stays read-only).
//
// A Logger is nil-safe: a nil *Logger is the "off" configuration and every
// method is a no-op, so call sites never branch on whether logging is on.
package decisionlog

import (
	"bufio"
	"context"
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
	// TraceID / SpanID: the OpenTelemetry trace the request belongs to and
	// the decision's own span (a propagated parent's, without an exporter) —
	// the join between a line and the application's trace.
	TraceID  string `json:"trace_id,omitempty"`
	SpanID   string `json:"span_id,omitempty"`
	Listener string `json:"listener"`      // public | callback
	Endpoint string `json:"endpoint"`      // evaluation | evaluations | check | check-batch | explain | reserve
	Via      string `json:"via,omitempty"` // engine | opa
	Store    string `json:"store"`
	Subject  Ref    `json:"subject"`
	Action   string `json:"action"`
	Resource Ref    `json:"resource"`
	Decision *bool  `json:"decision,omitempty"` // absent on error
	State    string `json:"state,omitempty"`    // allow | deny | conditional
	Reason   string `json:"reason,omitempty"`
	// MissingContext / Conditions: the detailed decision's explanation of a
	// `conditional` state (request keys a condition or gate needed).
	MissingContext []string `json:"missing_context,omitempty"`
	Conditions     []string `json:"conditions,omitempty"`
	// Gates: per-clause outcomes when the endpoint reports them (reserve).
	Gates []Gate `json:"gates,omitempty"`
	// Hooks: the policy-hook packages OPA consulted for an OPA-fronted
	// decision (ADR 0011; the detail's hooks_loaded), and HookDenials the
	// hooks that vetoed — so a line says not only THAT OPA took part (Via,
	// Policy) but which custom policies did, and which one denied.
	Hooks       []string     `json:"hooks,omitempty"`
	HookDenials []HookDenial `json:"hook_denials,omitempty"`
	// ContextKeys: names of the request-context keys supplied, sorted. Never values.
	ContextKeys []string `json:"context_keys,omitempty"`
	// ContextualTuples: how many what-if tuples the caller injected into this
	// decision (native check) — a line with it answers a hypothetical, not
	// the stored graph. Never the tuples themselves.
	ContextualTuples int    `json:"contextual_tuples,omitempty"`
	Actor            string `json:"actor,omitempty"` // authenticated caller, "type:id"
	// Client: the calling application — the token's azp (else client_id). Set
	// even when the credential names no user subject (a PEP's service token),
	// so every line says which app asked about whom (ADR 0014).
	Client string `json:"client,omitempty"`
	// OnBehalfOf: the token subject a delegated actor acts for ("type:id"),
	// when the caller's token named an actor (ACTOR_CLAIM). The decision was
	// made for Actor/Subject; this records whose task it served.
	OnBehalfOf string `json:"on_behalf_of,omitempty"`
	Issuer     string `json:"issuer,omitempty"` // verified token issuer
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
	// Sink: "off" (or ""), "stdout", "stderr", "file:<path>", or "postgres"
	// (the sink database named by DSN; ADR 0015).
	Sink string
	// Sample in [0,1]: the fraction of ALLOW decisions written. Denies,
	// conditionals and errors are always written.
	Sample float64
	// DSN, RetentionDays, QueueSize: the postgres sink's database, how many
	// days of partitions to keep (0 = all), and how many lines may wait
	// between flushes.
	DSN           string
	RetentionDays int
	QueueSize     int
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
	// lastProbe (unix nanos) rate-limits Probe so a dead sink is retried at
	// most once per ProbeInterval, not once per refused request.
	lastProbe atomic.Int64
	// Postgres is set for the postgres sink (metrics wiring); nil otherwise.
	Postgres *PostgresSink
}

// ProbeInterval bounds how often Probe retries a failed sink.
var ProbeInterval = time.Second

// Healthy reports whether the last write succeeded (true for a nil Logger
// and before the first write).
func (l *Logger) Healthy() bool { return l == nil || !l.unhealthy.Load() }

// Probe gives a failed sink a chance to recover: while the logger is
// unhealthy it writes a marker line at most once per ProbeInterval and
// reports whether the sink is healthy afterwards. Required mode refuses
// decisions before they reach Log, so without this nothing would ever retry
// the sink and a transient failure would need a restart. The marker line
// (`endpoint: decision_log_probe`, `state: sink_recovered`) is legitimate
// evidence: its presence in the stream is the proof that writes resumed.
func (l *Logger) Probe() bool {
	if l == nil || !l.unhealthy.Load() {
		return true
	}
	now := time.Now()
	last := l.lastProbe.Load()
	if last != 0 && now.Sub(time.Unix(0, last)) < ProbeInterval {
		return false
	}
	if !l.lastProbe.CompareAndSwap(last, now.UnixNano()) {
		return false // another request is probing right now
	}
	l.Log(Entry{Time: now.UTC(), Listener: "-", Endpoint: "decision_log_probe", State: "sink_recovered"})
	return l.Healthy()
}

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
	case sink == "postgres":
		ps, err := OpenPostgres(context.Background(), PostgresConfig{DSN: cfg.DSN, RetentionDays: cfg.RetentionDays, QueueSize: cfg.QueueSize})
		if err != nil {
			return nil, err
		}
		l := New(ps, cfg.Sample, ps)
		l.Postgres = ps
		return l, nil
	default:
		return nil, fmt.Errorf("decision log sink %q: expected off | stdout | stderr | file:<path> | postgres", sink)
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
	e.Hooks = stringsOf(detail["hooks_loaded"])
	e.HookDenials = hookDenialsOf(detail["hook_denials"])
}

// HookDenial is one policy-hook veto as OPA reports it: the hook's tier
// (global | store | platform), its package name, a code and a bounded message.
type HookDenial struct {
	Tier    string `json:"tier,omitempty"`
	Store   string `json:"store,omitempty"`
	Hook    string `json:"hook,omitempty"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// hookDenialsOf normalizes the detail's hook_denials list; anything that is
// not a list of objects yields nil.
func hookDenialsOf(v any) []HookDenial {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]HookDenial, 0, len(arr))
	for _, it := range arr {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		d := HookDenial{}
		d.Tier, _ = m["tier"].(string)
		d.Store, _ = m["store"].(string)
		d.Hook, _ = m["hook"].(string)
		d.Code, _ = m["code"].(string)
		d.Message, _ = m["message"].(string)
		out = append(out, d)
	}
	return out
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
