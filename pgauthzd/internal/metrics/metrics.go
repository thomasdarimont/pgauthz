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
}

// Handler returns the Prometheus exposition handler (also serves the default
// Go/process collectors, e.g. process_start_time_seconds).
func Handler() http.Handler { return promhttp.Handler() }
