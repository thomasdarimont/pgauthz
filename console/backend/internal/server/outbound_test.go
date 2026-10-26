package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"thomasdarimont.de/authz/console-bff/internal/config"
)

// The outbound allow-list: patterns, the platform issuer's host, and the
// hosts of the fleet's environment-anchored issuers — never a row-anchored
// one (its hosts were chosen by an issuer admin).
func TestHostAllowed(t *testing.T) {
	for host, want := range map[string]bool{"id.acme.test": true, "a.b.acme.test": true, "acme.test": false, "ID.ACME.TEST:8443": true, "idp.example": true, "metadata.internal": false, "": false} {
		if got := hostAllowed([]string{"*.acme.test", "idp.example"}, host); got != want {
			t.Errorf("hostAllowed(%q) = %v", host, got)
		}
	}
	if !hostAllowed([]string{"*"}, "anything") || hostAllowed(nil, "anything") {
		t.Fatal("wildcard / empty")
	}
}

func TestOutboundAllowed(t *testing.T) {
	// pgauthzd's effective set: one environment issuer, one group issuer anchored by a row
	pgauthzd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"source": "env+db", "revision": 1, "issuers": []map[string]any{
			{"issuer": "https://id.corp.example/realms/x", "jwks_url": "https://keys.corp.example/jwks", "anchor_source": "env"},
			{"issuer": "https://id.tenant.example", "jwks_url": "https://id.tenant.example/jwks", "anchor_source": "db"},
		}})
	}))
	defer pgauthzd.Close()
	s := &Server{cfg: config.Config{Issuer: "https://id.platform.example/realms/p", OutboundHosts: []string{"*.acme.test"}, PgauthzdInternalURL: pgauthzd.URL}, http: http.DefaultClient}
	ctx := context.Background()
	for raw, want := range map[string]bool{
		"https://id.platform.example/realms/p/.well-known/openid-configuration": true, // the platform's
		"https://login.acme.test/x":             true,  // CONSOLE_OUTBOUND_HOSTS
		"https://id.corp.example/.well-known":   true,  // an environment issuer of the fleet
		"https://keys.corp.example/jwks":        true,  // … and its keys host
		"https://id.tenant.example/.well-known": false, // a row-anchored issuer: not inherited
		"https://169.254.169.254/latest":        false,
		"http://localhost:5432/":                false,
		"not a url":                             false,
	} {
		err := s.outboundAllowed(ctx, raw)
		if (err == nil) != want {
			t.Errorf("%s: allowed=%v (%v)", raw, err == nil, err)
		}
		if err != nil && want == false && raw != "not a url" && !strings.Contains(err.Error(), "CONSOLE_OUTBOUND_HOSTS") {
			t.Errorf("%s: the refusal must name the setting: %v", raw, err)
		}
	}
	// the Discover endpoint refuses before any request leaves; and a
	// redirect from an allowed host is not followed
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254/", http.StatusFound)
	}))
	defer target.Close()
	s.outbound = noRedirects(s.http)
	resp, err := s.outbound.Get(target.URL)
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("redirects must not be followed: %v %v", err, resp)
	}
	resp.Body.Close()
}

// CONSOLE_OUTBOUND_HOSTS: hosts only; "*" is refused in production. The
// policy: proxy needs an egress proxy configured and turns the check off;
// off is refused in production.
func TestValidateOutboundHosts(t *testing.T) {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		t.Setenv(k, "")
	}
	base := config.Config{SubjectIDClaims: []string{"sub"}}
	p := base
	p.OutboundHostPolicy = "proxy"
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "HTTPS_PROXY") {
		t.Fatalf("proxy without a proxy: %v", err)
	}
	t.Setenv("HTTPS_PROXY", "http://egress.internal:3128")
	if err := p.Validate(); err != nil || p.ChecksOutboundHosts() {
		t.Fatalf("proxy: %v", err)
	}
	s := &Server{cfg: p}
	if err := s.outboundAllowed(context.Background(), "https://169.254.169.254/latest"); err != nil {
		t.Fatalf("under proxy the console does not check hosts itself: %v", err)
	}
	o := base
	o.OutboundHostPolicy = "off"
	o.DeploymentEnvironment = "production"
	if err := o.Validate(); err == nil {
		t.Fatal("off in production must be refused")
	}
	c := base
	c.OutboundHosts = []string{"*.acme.test", "idp.example"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.OutboundHosts = []string{"https://idp.example"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "CONSOLE_OUTBOUND_HOSTS") {
		t.Fatalf("a URL is not a host: %v", err)
	}
	c.OutboundHosts = []string{"*"}
	c.DeploymentEnvironment = "production"
	if err := c.Validate(); err == nil {
		t.Fatal("* must be refused in production")
	}
}
