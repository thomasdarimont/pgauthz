// Package telemetry sets pgauthzd up as an OpenTelemetry-instrumented
// service: W3C Trace Context and B3 propagation on every listener and on
// the calls to OPA, a span per request and a span per decision (see
// api.logDecision), and OTLP export when the standard OTEL_* variables ask
// for it. The decision log carries the active trace and span ids, so a line
// joins the application's trace of the request that asked.
//
// Propagation is always on — an incoming traceparent is honoured and
// forwarded whether or not spans are exported — so the decision log's
// trace_id correlates with the caller's trace even on an instance that
// exports nothing.
package telemetry

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"go.opentelemetry.io/contrib/propagators/b3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Config is what the daemon knows that the OTEL_* environment does not.
type Config struct {
	Enabled     bool   // TRACING: off = no propagation, no spans, nothing
	Identifiers bool   // TRACING_IDENTIFIERS: subject/resource IDS on spans (default: types only)
	ServiceName string // default service.name (OTEL_SERVICE_NAME wins)
	Version     string // service.version
}

// Status says what Setup configured.
type Status struct {
	Enabled   bool   // tracing is on (propagation + spans)
	Exporting bool   // spans leave the process (OTLP)
	Protocol  string // http/protobuf | grpc, when exporting
	Endpoint  string // the configured endpoint, when exporting (for logs)
}

// Exporting reports whether the OTEL_* environment asks for an exporter:
// OTEL_TRACES_EXPORTER=otlp, or an OTLP endpoint set with the exporter not
// disabled ("none").
func Exporting() bool {
	exp := strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_TRACES_EXPORTER")))
	if exp == "none" {
		return false
	}
	if exp == "otlp" {
		return true
	}
	return os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") != "" || os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != ""
}

// Protocol is the OTLP transport: OTEL_EXPORTER_OTLP_TRACES_PROTOCOL, else
// OTEL_EXPORTER_OTLP_PROTOCOL, else http/protobuf.
func Protocol() string {
	for _, k := range []string{"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "OTEL_EXPORTER_OTLP_PROTOCOL"} {
		if v := strings.ToLower(strings.TrimSpace(os.Getenv(k))); v != "" {
			return v
		}
	}
	return "http/protobuf"
}

func endpoint() string {
	if v := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"); v != "" {
		return v
	}
	return os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
}

// Setup installs the propagators and, when the environment asks for it,
// an OTLP exporter behind a batching tracer provider (sampler and resource
// attributes from the standard OTEL_TRACES_SAMPLER / OTEL_RESOURCE_ATTRIBUTES
// / OTEL_SERVICE_NAME). The returned shutdown flushes the exporter; call it
// on exit. Without an exporter the global provider stays the no-op one:
// spans are not recorded, but a propagated context still flows through.
func Setup(ctx context.Context, cfg Config) (shutdown func(context.Context) error, st Status, err error) {
	shutdown = func(context.Context) error { return nil }
	enabled.Store(cfg.Enabled)
	identifiers.Store(cfg.Identifiers)
	if !cfg.Enabled {
		// off: the no-op propagator and provider stay — no header is read,
		// no span is created, the decision log carries no ids.
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator())
		return shutdown, st, nil
	}
	st.Enabled = true
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
		b3.New(b3.WithInjectEncoding(b3.B3MultipleHeader|b3.B3SingleHeader)),
	))
	if !Exporting() {
		return shutdown, st, nil
	}
	st.Protocol, st.Endpoint = Protocol(), endpoint()
	var exp *otlptrace.Exporter
	switch st.Protocol {
	case "grpc":
		exp, err = otlptracegrpc.New(ctx)
	case "http/protobuf", "http/json", "http":
		exp, err = otlptracehttp.New(ctx)
	default:
		return shutdown, st, fmt.Errorf("OTEL_EXPORTER_OTLP_PROTOCOL %q: expected grpc or http/protobuf", st.Protocol)
	}
	if err != nil {
		return shutdown, st, fmt.Errorf("opentelemetry exporter: %w", err)
	}
	name := cfg.ServiceName
	if name == "" {
		name = "pgauthzd"
	}
	res, err := resource.New(ctx,
		resource.WithAttributes(attribute.String("service.name", name), attribute.String("service.version", cfg.Version)),
		resource.WithFromEnv(), // OTEL_SERVICE_NAME / OTEL_RESOURCE_ATTRIBUTES override the defaults above
		resource.WithTelemetrySDK(),
	)
	if err != nil {
		return shutdown, st, fmt.Errorf("opentelemetry resource: %w", err)
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
	otel.SetTracerProvider(tp)
	st.Exporting = true
	return tp.Shutdown, st, nil
}

// enabled is the master switch (TRACING): false = no spans anywhere.
var enabled atomic.Bool

// Enabled reports whether tracing is on.
func Enabled() bool { return enabled.Load() }

// SetEnabled flips the switch (tests).
func SetEnabled(on bool) { enabled.Store(on) }

// identifiers: whether spans may carry subject and resource IDS. Off by
// default — a tracing backend is usually shared more widely than the
// decision log, which keeps the ids (ADR 0013) and is joined by trace_id.
var identifiers atomic.Bool

// Identifiers reports whether spans carry subject/resource ids.
func Identifiers() bool { return identifiers.Load() }

// SetIdentifiers flips the identifier switch (tests).
func SetIdentifiers(on bool) { identifiers.Store(on) }

// Tracer is the daemon's tracer (the global provider's, so a test may swap
// the provider).
func Tracer() trace.Tracer { return otel.Tracer("pgauthzd") }

// IDs returns the active span's trace and span id as hex strings, or empty
// strings when the context carries no valid span — a propagated parent
// counts, so the ids are there without an exporter too.
func IDs(ctx context.Context) (traceID, spanID string) {
	if !Enabled() {
		return "", ""
	}
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return "", ""
	}
	return sc.TraceID().String(), sc.SpanID().String()
}
