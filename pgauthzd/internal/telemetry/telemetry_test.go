package telemetry

import (
	"context"
	"net/http"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

func TestExportingFromEnv(t *testing.T) {
	for _, k := range []string{"OTEL_TRACES_EXPORTER", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_PROTOCOL"} {
		t.Setenv(k, "")
	}
	if Exporting() {
		t.Fatal("nothing set: must not export")
	}
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")
	if !Exporting() || Protocol() != "http/protobuf" {
		t.Fatalf("endpoint set: exporting=%v protocol=%q", Exporting(), Protocol())
	}
	t.Setenv("OTEL_TRACES_EXPORTER", "none")
	if Exporting() {
		t.Fatal("OTEL_TRACES_EXPORTER=none must win over the endpoint")
	}
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	if !Exporting() || Protocol() != "grpc" {
		t.Fatalf("otlp/grpc: exporting=%v protocol=%q", Exporting(), Protocol())
	}
}

// Without an exporter Setup still installs the propagators: an incoming
// traceparent (or B3) yields a valid span context, IDs reports it, and an
// outgoing request carries it on.
func TestPropagationWithoutExporter(t *testing.T) {
	for _, k := range []string{"OTEL_TRACES_EXPORTER", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"} {
		t.Setenv(k, "")
	}
	shutdown, st, err := Setup(context.Background(), Config{Enabled: true, Version: "test"})
	if err != nil || st.Exporting || !st.Enabled {
		t.Fatalf("setup: %v %+v", err, st)
	}
	defer func() { _ = shutdown(context.Background()) }()
	in := http.Header{}
	in.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	ctx := otel.GetTextMapPropagator().Extract(context.Background(), propagation.HeaderCarrier(in))
	tid, sid := IDs(ctx)
	if tid != "4bf92f3577b34da6a3ce929d0e0e4736" || sid != "00f067aa0ba902b7" {
		t.Fatalf("ids %q %q", tid, sid)
	}
	// a child span without a recording provider keeps the trace, changes nothing
	_, span := Tracer().Start(ctx, "x")
	span.End()
	if !span.SpanContext().IsValid() || span.SpanContext().TraceID().String() != tid {
		t.Fatalf("non-recording child span must carry the trace: %v", span.SpanContext())
	}
	out := http.Header{}
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(out))
	if out.Get("traceparent") == "" || out.Get("X-B3-TraceId") == "" {
		t.Fatalf("outgoing headers lack propagation: %v", out)
	}
	b3 := http.Header{}
	b3.Set("X-B3-TraceId", "80f198ee56343ba864fe8b2a57d3eff7")
	b3.Set("X-B3-SpanId", "e457b5a2e4d86bd1")
	b3.Set("X-B3-Sampled", "1")
	if tid, _ := IDs(otel.GetTextMapPropagator().Extract(context.Background(), propagation.HeaderCarrier(b3))); tid != "80f198ee56343ba864fe8b2a57d3eff7" {
		t.Fatalf("B3 not extracted: %q", tid)
	}
	if tid, sid := IDs(context.Background()); tid != "" || sid != "" {
		t.Fatal("no span: ids must be empty")
	}
	_ = trace.SpanContext{}
}

// With OTEL_TRACES_EXPORTER=otlp Setup installs an exporting provider (the
// collector need not exist until spans flush).
func TestSetupExporter(t *testing.T) {
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
	shutdown, st, err := Setup(context.Background(), Config{Enabled: true, Version: "test"})
	if err != nil || !st.Exporting || st.Protocol != "http/protobuf" {
		t.Fatalf("setup: %v %+v", err, st)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200e6)
	defer cancel()
	_ = shutdown(ctx) // nothing to flush; an unreachable collector is not a setup error
	otel.SetTracerProvider(noop.NewTracerProvider())
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "carrier-pigeon")
	if _, _, err := Setup(context.Background(), Config{Enabled: true}); err == nil {
		t.Fatal("an unknown protocol must be refused")
	}
}

// TRACING=off: Setup installs nothing — an incoming traceparent is not
// read, IDs are empty, Enabled is false.
func TestDisabled(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")
	shutdown, st, err := Setup(context.Background(), Config{Enabled: false})
	if err != nil || st.Enabled || st.Exporting || Enabled() {
		t.Fatalf("disabled: %v %+v enabled=%v", err, st, Enabled())
	}
	defer func() { _ = shutdown(context.Background()) }()
	in := http.Header{}
	in.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	ctx := otel.GetTextMapPropagator().Extract(context.Background(), propagation.HeaderCarrier(in))
	if tid, _ := IDs(ctx); tid != "" {
		t.Fatalf("off must read no headers, got %q", tid)
	}
}
