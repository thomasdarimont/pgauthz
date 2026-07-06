// Package metrics is pgauthzd's Prometheus instrumentation (ADR 0010, Slice 1):
// HTTP RED, freshness verdict/fallback counters, build info, and pgx pool stats.
// Metrics are always collected (cheap); they are only EXPOSED when a metrics
// listener is configured (METRICS_LISTEN_ADDR) — never on the public client
// listener. Label cardinality is fixed here (no model-defined type/action labels).
package metrics

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// HTTPRequests / HTTPDuration are the RED baseline. `route` is the TEMPLATED
	// pattern (e.g. /stores/{store}/pgauthz/v1/check), so cardinality is bounded.
	HTTPRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pgauthzd_http_requests_total",
		Help: "HTTP requests handled, by templated route, method, and status.",
	}, []string{"route", "method", "status"})

	HTTPDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pgauthzd_http_request_duration_seconds",
		Help:    "HTTP request duration in seconds, by templated route and method.",
		Buckets: prometheus.DefBuckets,
	}, []string{"route", "method"})

	// FreshnessVerdicts is the replica-health signal (ADR 0009): a rising `stale`
	// ratio = a lagging replica; a `wrong_epoch` spike across readers = a failover.
	FreshnessVerdicts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pgauthzd_freshness_verdicts_total",
		Help: "Freshness-token verdicts from assert_fresh (ADR 0009): fresh|stale|wrong_epoch|unknown.",
	}, []string{"verdict"})

	// FreshnessFallback counts reads transparently re-run on the primary because
	// the local replica wasn't fresh enough — read-scaling erosion if it climbs.
	FreshnessFallback = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pgauthzd_freshness_fallback_total",
		Help: "Reads transparently re-run on the primary due to insufficient replica freshness (ADR 0009).",
	})

	buildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pgauthzd_build_info",
		Help: "Build/runtime info; value is always 1, the labels carry the data.",
	}, []string{"version", "commit", "go_version", "profile", "opa_enabled", "freshness_enabled", "fallback_enabled"})

	// ── Slice 2 ─────────────────────────────────────────────────────────────
	// Decisions. `api` ∈ native|authzen (client surface); OPA-fronting is an
	// instance property (build_info.opa_enabled), not a per-request label.
	// NOTE: `store` is per-tenant — bounded in practice, but bucket the long tail
	// into "other" if you run very many tenants (ADR 0010 cardinality policy).
	CheckDecisions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pgauthzd_check_decisions_total",
		Help: "Access-check decisions by store, decision (allow|deny|conditional|error), and api.",
	}, []string{"store", "decision", "api"})

	// Search / graph enumeration.
	SearchRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pgauthzd_search_requests_total",
		Help: "Search requests by store, kind (objects|subjects|actions), and result (ok|error).",
	}, []string{"store", "kind", "result"})

	SearchResultSize = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pgauthzd_search_result_size",
		Help:    "Search result-set size by kind.",
		Buckets: []float64{0, 1, 5, 10, 50, 100, 500, 1000, 5000},
	}, []string{"kind"})

	// Auth / security signals.
	JWTFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pgauthzd_jwt_validation_failures_total",
		Help: "JWT validation failures by reason (bad_signature|expired|unknown_issuer|audience|scope|missing|malformed).",
	}, []string{"reason"})

	AuthzDenied = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pgauthzd_authz_denied_total",
		Help: "Request-layer authorization denials by reason (writer_role|search_role|subject_override|store_binding|db_role_binding|forbidden_role).",
	}, []string{"reason"})

	// Backend latency.
	DBQueryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pgauthzd_db_query_duration_seconds",
		Help:    "PostgreSQL query duration by op (check|list|explain|write|freshness) and pool (primary|replica|fallback).",
		Buckets: prometheus.DefBuckets,
	}, []string{"op", "pool"})

	DBErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pgauthzd_db_errors_total",
		Help: "PostgreSQL query errors by op and pool.",
	}, []string{"op", "pool"})

	OPARequestDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "pgauthzd_opa_request_duration_seconds",
		Help:    "OPA policy request duration (only when fronting OPA).",
		Buckets: prometheus.DefBuckets,
	})

	OPARequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pgauthzd_opa_requests_total",
		Help: "OPA policy requests by result (ok|error).",
	}, []string{"result"})
)

// Decision label helpers keep the label vocabulary in one place.
const (
	APINative  = "native"
	APIAuthZEN = "authzen"
)

// SetBuildInfo records the process's build + config labels (value 1).
func SetBuildInfo(version, commit, goVersion, profile string, opa, freshness, fallback bool) {
	buildInfo.WithLabelValues(version, commit, goVersion, profile, yn(opa), yn(freshness), yn(fallback)).Set(1)
}

func yn(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// PoolStat is the subset of *pgxpool.Stat this package reads, so metrics doesn't
// import pgx (structural typing — *pgxpool.Stat satisfies it).
type PoolStat interface {
	AcquiredConns() int32
	IdleConns() int32
	TotalConns() int32
	MaxConns() int32
}

var (
	poolMu       sync.Mutex
	poolStatFns  = map[string]func() PoolStat{}
	poolConnDesc = prometheus.NewDesc(
		"pgauthzd_db_pool_connections",
		"pgx connection-pool connections by pool (primary|replica|fallback) and state.",
		[]string{"pool", "state"}, nil,
	)
)

// RegisterPool registers a named pool whose live stats are read on each scrape.
func RegisterPool(name string, statFn func() PoolStat) {
	poolMu.Lock()
	defer poolMu.Unlock()
	poolStatFns[name] = statFn
}

type poolCollector struct{}

func (poolCollector) Describe(ch chan<- *prometheus.Desc) { ch <- poolConnDesc }

func (poolCollector) Collect(ch chan<- prometheus.Metric) {
	poolMu.Lock()
	defer poolMu.Unlock()
	for name, fn := range poolStatFns {
		s := fn()
		emit := func(v float64, state string) {
			ch <- prometheus.MustNewConstMetric(poolConnDesc, prometheus.GaugeValue, v, name, state)
		}
		emit(float64(s.AcquiredConns()), "acquired")
		emit(float64(s.IdleConns()), "idle")
		emit(float64(s.TotalConns()), "total")
		emit(float64(s.MaxConns()), "max")
	}
}

func init() {
	prometheus.MustRegister(poolCollector{})
	// Pre-initialize fixed-enum labelled series to 0 so they export before the
	// first occurrence — otherwise a CounterVec exports no series until a label
	// value is first observed, and rate()/alerts over a missing series are empty
	// rather than a clean 0. (Only fixed enums; route/status are unbounded.)
	for _, v := range []string{"fresh", "stale", "wrong_epoch", "unknown"} {
		FreshnessVerdicts.WithLabelValues(v)
	}
	// Slice-2 fixed-enum, store-independent series (store/pool-labelled ones are
	// left to first observation — they'd otherwise need unbounded pre-init).
	for _, r := range []string{"missing", "malformed", "invalid_token"} {
		JWTFailures.WithLabelValues(r)
	}
	for _, r := range []string{"writer_role", "search_role", "store_binding", "db_role_binding", "subject_override"} {
		AuthzDenied.WithLabelValues(r)
	}
	for _, r := range []string{"ok", "error"} {
		OPARequests.WithLabelValues(r)
	}
}

// Handler returns the Prometheus exposition handler (also serves the default
// Go/process collectors, e.g. process_start_time_seconds).
func Handler() http.Handler { return promhttp.Handler() }
