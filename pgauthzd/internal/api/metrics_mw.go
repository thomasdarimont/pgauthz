package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
)

// Metrics wraps the handler chain and records RED metrics (request count +
// duration) labelled by the TEMPLATED route, method, and status. The route is
// resolved via mux.Handler(r) so path wildcards ({store}) stay templated —
// bounded cardinality, no per-tenant path explosion. `mux` is used only for that
// resolution; `next` is the real (auth-wrapped) chain that serves the request.
func Metrics(mux *http.ServeMux, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := routeLabel(mux, r)
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(sw, r)
		metrics.HTTPRequests.WithLabelValues(route, r.Method, strconv.Itoa(sw.status)).Inc()
		metrics.HTTPDuration.WithLabelValues(route, r.Method).Observe(time.Since(start).Seconds())
	})
}

// routeLabel returns the templated route for a request (e.g.
// /stores/{store}/pgauthz/v1/check), or "unmatched" for a 404. The matched
// pattern is "METHOD /path"; the method is dropped since it's its own label.
func routeLabel(mux *http.ServeMux, r *http.Request) string {
	_, pattern := mux.Handler(r)
	if pattern == "" {
		return "unmatched"
	}
	if i := strings.IndexByte(pattern, ' '); i >= 0 {
		return pattern[i+1:]
	}
	return pattern
}
