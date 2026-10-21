package api

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Successful health probes log at DEBUG (orchestrators poll them constantly);
// a failing probe and every other request log at INFO.
func TestLoggingHealthProbesAtDebug(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	status := http.StatusOK
	h := Logging(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
	call := func(path string) string {
		buf.Reset()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return buf.String()
	}

	for _, p := range []string{"/readyz", "/livez", "/healthz"} {
		if out := call(p); out != "" {
			t.Errorf("%s 200 logged at INFO: %q", p, out)
		}
	}
	if out := call("/access/v1/evaluation"); !strings.Contains(out, "path=/access/v1/evaluation") {
		t.Errorf("a regular request must log at INFO, got %q", out)
	}
	status = http.StatusServiceUnavailable
	if out := call("/readyz"); !strings.Contains(out, "status=503") {
		t.Errorf("a FAILING probe must log at INFO, got %q", out)
	}
}
