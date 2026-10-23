package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"thomasdarimont.de/authz/pgauthzd/internal/telemetry"
)

// OpenTelemetry on a decision: the request's traceparent reaches the log
// line as trace_id (and the request id, absent an X-Request-ID), and with
// a recording provider the decision is a span under the server span,
// carrying the outcome; the line's span_id is that span's.
func TestDecisionTraceIDs(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	telemetry.SetEnabled(true)
	t.Cleanup(func() { telemetry.SetEnabled(false) })
	h, buf := newLoggedHandler(t, detailStub{}, false)
	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	serve := func(withExporter bool) (*tracetest.InMemoryExporter, map[string]any, http.Header) {
		t.Helper()
		var exp *tracetest.InMemoryExporter
		if withExporter {
			exp = tracetest.NewInMemoryExporter()
			otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp)))
		} else {
			otel.SetTracerProvider(trace.NewNoopTracerProvider())
		}
		t.Cleanup(func() { otel.SetTracerProvider(trace.NewNoopTracerProvider()) })
		buf.Reset()
		srv := otelhttp.NewHandler(RequestID(http.HandlerFunc(h.NativeCheck)), "test")
		r := jsonReq("POST", "/pgauthz/v1/check", `{"subject":{"type":"user","id":"alice"},"action":{"name":"can_read"},"resource":{"type":"doc","id":"d1"}}`)
		r.Header.Set("traceparent", "00-"+traceID+"-00f067aa0ba902b7-01")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		return exp, lines(buf)[0], w.Header()
	}

	// propagation only: the ids are the caller's
	_, l, hdr := serve(false)
	if l["trace_id"] != traceID || l["span_id"] != "00f067aa0ba902b7" {
		t.Fatalf("without exporter: %v", l)
	}
	if hdr.Get("X-Request-ID") != traceID {
		t.Fatalf("request id must default to the trace id, got %q", hdr.Get("X-Request-ID"))
	}

	// recording: the decision span is a child of the server span, in the caller's trace
	exp, l, _ := serve(true)
	spans := exp.GetSpans()
	var decision, server *tracetest.SpanStub
	for i := range spans {
		switch {
		case spans[i].Name == "pgauthz.check":
			decision = &spans[i]
		case spans[i].SpanKind == trace.SpanKindServer:
			server = &spans[i]
		}
	}
	if decision == nil || server == nil {
		t.Fatalf("spans: %v", names(spans))
	}
	if decision.SpanContext.TraceID().String() != traceID || decision.Parent.SpanID() != server.SpanContext.SpanID() {
		t.Fatalf("decision span not under the server span in the caller's trace: %+v", decision.SpanContext)
	}
	if l["trace_id"] != traceID || l["span_id"] != decision.SpanContext.SpanID().String() {
		t.Fatalf("line ids must be the decision span's: %v vs %s", l, decision.SpanContext.SpanID())
	}
	attrs := map[string]any{}
	for _, a := range decision.Attributes {
		attrs[string(a.Key)] = a.Value.AsInterface()
	}
	if attrs["pgauthz.store"] != "demo" || attrs["pgauthz.action"] != "can_read" || attrs["pgauthz.decision"] != true || attrs["pgauthz.subject.type"] != "user" || attrs["pgauthz.resource.type"] != "doc" {
		t.Fatalf("decision span attributes: %v", attrs)
	}
	if _, ok := attrs["pgauthz.subject"]; ok {
		t.Fatalf("identifiers are off by default: %v", attrs)
	}
	// TRACING_IDENTIFIERS=true: the ids too
	telemetry.SetIdentifiers(true)
	t.Cleanup(func() { telemetry.SetIdentifiers(false) })
	exp, _, _ = serve(true)
	for _, s := range exp.GetSpans() {
		if s.Name != "pgauthz.check" {
			continue
		}
		got := map[string]any{}
		for _, a := range s.Attributes {
			got[string(a.Key)] = a.Value.AsInterface()
		}
		if got["pgauthz.subject"] != "user:alice" || got["pgauthz.resource"] != "doc:d1" {
			t.Fatalf("with identifiers: %v", got)
		}
	}
	telemetry.SetIdentifiers(false)
	if !decision.EndTime.After(decision.StartTime) {
		t.Fatal("the span must span the decision")
	}
	// the request's span is tagged with the store (no path parsing needed)
	sattrs := map[string]any{}
	for _, a := range server.Attributes {
		sattrs[string(a.Key)] = a.Value.AsInterface()
	}
	if sattrs["pgauthz.store"] != "demo" {
		t.Fatalf("server span must carry pgauthz.store: %v", sattrs)
	}

	// TRACING=off: the same request leaves no ids on the line
	telemetry.SetEnabled(false)
	_, l, hdr = serve(false)
	if _, ok := l["trace_id"]; ok || hdr.Get("X-Request-ID") == traceID {
		t.Fatalf("off: line %v, request id %q", l, hdr.Get("X-Request-ID"))
	}
}

func names(spans tracetest.SpanStubs) []string {
	out := make([]string, len(spans))
	for i, s := range spans {
		out[i] = s.Name
	}
	return out
}
