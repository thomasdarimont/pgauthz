package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeStat struct{}

func (fakeStat) AcquiredConns() int32 { return 3 }
func (fakeStat) IdleConns() int32     { return 7 }
func (fakeStat) TotalConns() int32    { return 10 }
func (fakeStat) MaxConns() int32      { return 25 }

// The /metrics endpoint exposes our series plus the default process collectors.
func TestExposition(t *testing.T) {
	SetBuildInfo("v-test", "abc123", "go1.x", "decision-only", false, true, true)
	RegisterPool("replica", func() PoolStat { return fakeStat{} })
	FreshnessVerdicts.WithLabelValues("stale").Inc()
	FreshnessFallback.Inc()

	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()

	for _, want := range []string{
		`pgauthzd_build_info{`,
		`profile="decision-only"`,
		`fallback_enabled="true"`,
		`pgauthzd_freshness_verdicts_total{verdict="stale"}`,
		`pgauthzd_freshness_verdicts_total{verdict="wrong_epoch"} 0`, // pre-initialized, never incremented
		`pgauthzd_freshness_fallback_total`,
		`pgauthzd_db_pool_connections{pool="replica",state="acquired"} 3`,
		`pgauthzd_db_pool_connections{pool="replica",state="max"} 25`,
		`process_start_time_seconds`, // default process collector
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics output missing %q", want)
		}
	}
}
