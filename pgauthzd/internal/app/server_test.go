package app

import (
	"net/http"
	"testing"
	"time"

	"thomasdarimont.de/authz/pgauthzd/internal/config"
)

// Every listener carries the hardening limits (review #9): header/idle
// timeouts set, and deliberately NO WriteTimeout (long search/explain/watch
// responses must not be killed mid-write).
func TestNewServerHardening(t *testing.T) {
	cfg := &config.Config{
		HTTPReadHeaderTimeout: 5 * time.Second,
		HTTPIdleTimeout:       60 * time.Second,
	}
	s := newServer(cfg, ":0", http.NotFoundHandler())
	if s.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("ReadHeaderTimeout = %v, want 5s", s.ReadHeaderTimeout)
	}
	if s.IdleTimeout != 60*time.Second {
		t.Fatalf("IdleTimeout = %v, want 60s", s.IdleTimeout)
	}
	if s.WriteTimeout != 0 {
		t.Fatalf("WriteTimeout must stay 0 (long-running responses), got %v", s.WriteTimeout)
	}
}
