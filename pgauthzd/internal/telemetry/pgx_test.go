package telemetry

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// A query becomes a client span named after the authz function, under the
// active span, carrying the statement text and the parameter count but no
// argument values; an error sets the status; without an active span
// nothing is created.
func TestPgxTracer(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp)))
	t.Cleanup(func() { otel.SetTracerProvider(noop.NewTracerProvider()) })
	SetEnabled(true)
	t.Cleanup(func() { SetEnabled(false) })
	tr := NewPgxTracer()

	ctx, parent := Tracer().Start(context.Background(), "request")
	const sql = "SELECT authz.check_access_with_context($1,$2,$3,$4,$5,$6,$7::jsonb)"
	qctx := tr.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: sql, Args: []any{"demo", "user", "alice-secret", "can_read"}})
	tr.TraceQueryEnd(qctx, nil, pgx.TraceQueryEndData{CommandTag: pgconn.NewCommandTag("SELECT 1")})
	qctx = tr.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: "SELECT 1"})
	tr.TraceQueryEnd(qctx, nil, pgx.TraceQueryEndData{Err: errors.New("boom")})
	parent.End()

	spans := exp.GetSpans()
	if len(spans) != 3 {
		t.Fatalf("spans: %d", len(spans))
	}
	q := spans[0]
	if q.Name != "authz.check_access_with_context" || q.SpanKind != trace.SpanKindClient || q.Parent.SpanID() != parent.SpanContext().SpanID() {
		t.Fatalf("query span: %s kind=%v parent=%v", q.Name, q.SpanKind, q.Parent)
	}
	attrs := map[string]any{}
	for _, a := range q.Attributes {
		attrs[string(a.Key)] = a.Value.AsInterface()
	}
	if attrs["db.query.text"] != sql || attrs["db.query.parameter_count"] != int64(4) || attrs["db.response.returned_rows"] != int64(1) {
		t.Fatalf("attributes: %v", attrs)
	}
	for _, a := range q.Attributes {
		if a.Value.Emit() == "alice-secret" {
			t.Fatal("argument values must never be recorded")
		}
	}
	if e := spans[1]; e.Name != "db.select" || e.Status.Code != codes.Error {
		t.Fatalf("error span: %s %v", e.Name, e.Status)
	}
	// no active span: no span at all
	if c := tr.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{SQL: sql}); c.Value(spanKey{}) != nil {
		t.Fatal("a query outside a trace must not start a span")
	}
	// off: no span even inside a trace
	SetEnabled(false)
	if c := tr.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: sql}); c.Value(spanKey{}) != nil {
		t.Fatal("TRACING=off must not start query spans")
	}
}
