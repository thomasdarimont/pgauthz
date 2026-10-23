package telemetry

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// PgxTracer is the pgx query tracer: one span per engine query, named after
// the authz.* function it calls (`authz.check_access`, `authz.list_objects`,
// …) or "db.query", with the statement TEXT as an attribute — the SQL
// pgauthzd sends is a fixed template with placeholders — and never the
// arguments (subject ids, context values). A span is a child of whatever is
// active on the query's context: the request's server span. The decision
// span of the same request is recorded after the fact (api.logDecision), so
// in a trace the two sit side by side under the request, with the query's
// own timing.
type PgxTracer struct {
	names sync.Map // sql → span name
}

// NewPgxTracer returns the tracer to set on a pool's ConnConfig.Tracer.
func NewPgxTracer() *PgxTracer { return &PgxTracer{} }

var fnRe = regexp.MustCompile(`authz\.([a-z_][a-z0-9_]*)\s*\(`)

// spanName derives the span name from the statement: the first authz.*
// function called, else the first word of the statement.
func (p *PgxTracer) spanName(sql string) string {
	if v, ok := p.names.Load(sql); ok {
		return v.(string)
	}
	name := "db.query"
	if m := fnRe.FindStringSubmatch(sql); m != nil {
		name = "authz." + m[1]
	} else if f := strings.Fields(sql); len(f) > 0 {
		name = "db." + strings.ToLower(f[0])
	}
	p.names.Store(sql, name)
	return name
}

type spanKey struct{}

// TraceQueryStart implements pgx.QueryTracer.
func (p *PgxTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if !Enabled() || !trace.SpanContextFromContext(ctx).IsValid() {
		return ctx // off, or nothing to attach to: no span, no cost
	}
	ctx, span := Tracer().Start(ctx, p.spanName(data.SQL),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("db.system.name", "postgresql"),
			attribute.String("db.query.text", strings.Join(strings.Fields(data.SQL), " ")),
			attribute.Int("db.query.parameter_count", len(data.Args)),
		))
	return context.WithValue(ctx, spanKey{}, span)
}

// TraceQueryEnd implements pgx.QueryTracer.
func (p *PgxTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	span, ok := ctx.Value(spanKey{}).(trace.Span)
	if !ok {
		return
	}
	if data.Err != nil {
		span.RecordError(data.Err)
		span.SetStatus(codes.Error, data.Err.Error())
	} else {
		span.SetAttributes(attribute.Int64("db.response.returned_rows", data.CommandTag.RowsAffected()))
	}
	span.End()
}
