package api

// Decision log glue (ADR 0013): every decision-producing handler builds a
// decisionlog.Entry from what it already knows — the resolved request, the
// caller from the request context, the outcome — and hands it to the
// handler's logger. A nil logger is "off"; nothing here branches on it.

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"thomasdarimont.de/authz/pgauthzd/internal/decisionlog"
	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
)

// Option configures a Handler / router at construction.
type Option func(*Handler)

// WithVersion stamps decision-log lines with the daemon build version.
func WithVersion(v string) Option {
	return func(h *Handler) { h.version = v }
}

// modelVersionTTL bounds how often a store's model provenance is re-read
// (model_status exports the model to checksum it). A model publish is
// therefore attributed with up to this much delay in the log.
const modelVersionTTL = 30 * time.Second

type modelCacheEntry struct {
	mv  authz.ModelVersion
	exp time.Time
}

// modelProvenance returns the store's model provenance from a per-store TTL
// cache, reading it through the direct backend on a miss. nil when no direct
// backend is available (DB-less OPA gateway) or the read fails.
func (h *Handler) modelProvenance(ctx context.Context, store string) *decisionlog.ModelRef {
	mvr, ok := h.raw.(authz.ModelVersioner)
	if !ok || h.raw == nil {
		return nil
	}
	now := time.Now()
	h.modelMu.Lock()
	if e, ok := h.modelCache[store]; ok && now.Before(e.exp) {
		h.modelMu.Unlock()
		return refOf(e.mv)
	}
	h.modelMu.Unlock()
	mv, err := mvr.ModelVersion(ctx, store)
	if err != nil {
		// Provenance is best-effort: the line goes out without a model block.
		slog.Debug("decision log: model provenance unavailable", "store", store, "error", err)
		return nil
	}
	h.modelMu.Lock()
	if h.modelCache == nil {
		h.modelCache = map[string]modelCacheEntry{}
	}
	h.modelCache[store] = modelCacheEntry{mv: mv, exp: now.Add(modelVersionTTL)}
	h.modelMu.Unlock()
	return refOf(mv)
}

func refOf(mv authz.ModelVersion) *decisionlog.ModelRef {
	if mv.Name == "" && mv.Version == nil && mv.Checksum == "" {
		return nil
	}
	return &decisionlog.ModelRef{Name: mv.Name, Version: mv.Version, Checksum: mv.Checksum}
}

// policyProvenance returns OPA's version + bundle revisions for an OPA-fronted
// decision (the backend's latest provenance report), nil otherwise.
func (h *Handler) policyProvenance(via string) *decisionlog.PolicyRef {
	if via != "opa" {
		return nil
	}
	pp, ok := h.backend.(authz.PolicyProvenancer)
	if !ok {
		return nil
	}
	p := pp.PolicyProvenance()
	if p.OPAVersion == "" && len(p.Bundles) == 0 {
		return nil
	}
	return &decisionlog.PolicyRef{OPAVersion: p.OPAVersion, Bundles: p.Bundles}
}

// WithDecisionLog attaches the decision log (nil = off) — ADR 0013.
func WithDecisionLog(l *decisionlog.Logger) Option {
	return func(h *Handler) {
		if l != nil && l.OnResult == nil {
			l.OnResult = func(result string) { metrics.DecisionLogLines.WithLabelValues(result).Inc() }
		}
		h.decisions = l
	}
}

// RequestIDFromContext returns the request id set by the RequestID middleware.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxRequestID).(string); ok {
		return v
	}
	return ""
}

// decisionEntry starts an entry for one decision on this listener: caller
// identity, request id, endpoint, and the PARC request as resolved.
func (h *Handler) decisionEntry(r *http.Request, endpoint string, req authz.EvalRequest, via string) decisionlog.Entry {
	e := decisionlog.Entry{
		Listener: h.listener, Endpoint: endpoint, Via: via,
		Store:       req.Store,
		Subject:     decisionlog.Ref{Type: req.SubjectType, ID: req.SubjectID},
		Action:      req.Action,
		Resource:    decisionlog.Ref{Type: req.ObjectType, ID: req.ObjectID},
		RequestID:   RequestIDFromContext(r.Context()),
		Issuer:      IssuerFromContext(r.Context()),
		ContextKeys: decisionlog.Keys(req.Context),
	}
	if st, sid := SubjectFromContext(r.Context()); st != "" && sid != "" {
		e.Actor = st + ":" + sid
	}
	return e
}

// logDecision finalizes and writes an entry: outcome (decision + optional
// detail, or the error) and latency since start.
func (h *Handler) logDecision(e decisionlog.Entry, start time.Time, decision bool, detail map[string]any, err error) {
	if h.decisions == nil {
		return
	}
	e.LatencyMS = float64(time.Since(start).Microseconds()) / 1000
	e.PgauthzdVersion = h.version
	e.Model = h.modelProvenance(context.Background(), e.Store)
	e.Policy = h.policyProvenance(e.Via)
	if err != nil {
		e.Error = err.Error()
	} else {
		e.Decision = decisionlog.Bool(decision)
		e.FromDetail(detail)
		if e.State == "" {
			if decision {
				e.State = "allow"
			} else {
				e.State = "deny"
			}
		}
	}
	h.decisions.Log(e)
}

// viaLabel names the backend that answered an AuthZEN decision.
func (h *Handler) viaLabel() string {
	if h.cfg != nil && h.cfg.UsesOPA() {
		return "opa"
	}
	return "engine"
}

// wantDetailForLog reports whether a plain check should be upgraded to the
// detailed evaluation for the log's sake (DECISION_LOG_DETAIL) — the caller's
// response stays plain.
func (h *Handler) wantDetailForLog() bool {
	return h.decisions != nil && h.cfg != nil && h.cfg.DecisionLogDetail
}

// logBatch writes one line per evaluation of a batch. Batch backends answer
// booleans only, so lines carry decision/state without a reason; the shared
// batch context keys are merged into each line's context_keys. Under a
// short-circuit semantic the backend may return fewer results than requests;
// unevaluated items are not logged.
func (h *Handler) logBatch(r *http.Request, endpoint, via string, evals []authz.EvalRequest, shared map[string]any, results []authz.EvalResult, start time.Time, err error) {
	if h.decisions == nil {
		return
	}
	sharedKeys := decisionlog.Keys(shared)
	for i, ev := range evals {
		if err == nil && i >= len(results) {
			break
		}
		e := h.decisionEntry(r, endpoint, ev, via)
		if len(sharedKeys) > 0 {
			e.ContextKeys = mergeKeys(e.ContextKeys, sharedKeys)
		}
		if err != nil {
			h.logDecision(e, start, false, nil, err)
			continue
		}
		h.logDecision(e, start, results[i].Decision, nil, nil)
	}
}

func mergeKeys(a, b []string) []string {
	seen := map[string]bool{}
	for _, k := range a {
		seen[k] = true
	}
	out := append([]string{}, a...)
	for _, k := range b {
		if !seen[k] {
			out = append(out, k)
			seen[k] = true
		}
	}
	sort.Strings(out)
	return out
}
