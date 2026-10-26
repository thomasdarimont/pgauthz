package server

// The console reaches out to identity providers people name in the Issuers
// form (Discover) and in a sign-in registration (discovery, the token
// endpoint). An issuer admin choosing those URLs must not be able to make
// the console fetch arbitrary addresses (SSRF): the host must be the
// platform issuer's, one of the fleet's environment-anchored issuers'
// (already trusted by every pgauthzd), or match CONSOLE_OUTBOUND_HOSTS.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// hostAllowed: an exact host, "*.suffix" (any depth below, not the apex)
// or "*"; case-insensitive, port ignored.
func hostAllowed(patterns []string, host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		return false
	}
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		switch {
		case p == "":
		case p == "*":
			return true
		case strings.HasPrefix(p, "*."):
			if strings.HasSuffix(host, p[1:]) && len(host) > len(p)-1 {
				return true
			}
		case p == host:
			return true
		}
	}
	return false
}

func urlHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// outboundHosts: the allow-list in force — the configured patterns, the
// platform issuer's host, and the hosts of the issuers the fleet trusts
// from its environment (the effective set, when pgauthzd is reachable).
func (s *Server) outboundHosts(ctx context.Context) []string {
	out := append([]string{}, s.cfg.OutboundHosts...)
	if h := urlHost(s.cfg.Issuer); h != "" {
		out = append(out, h)
	}
	if eff := s.effectiveIssuers(ctx); eff.Available && len(eff.Issuers) > 0 {
		var list []struct {
			Issuer       string `json:"issuer"`
			JWKSURL      string `json:"jwks_url"`
			AnchorSource string `json:"anchor_source"`
		}
		if json.Unmarshal(eff.Issuers, &list) == nil {
			for _, i := range list {
				if i.AnchorSource == "db" {
					continue // a row-anchored issuer: its hosts were chosen by an admin, not the environment
				}
				for _, h := range []string{urlHost(i.Issuer), urlHost(i.JWKSURL)} {
					if h != "" {
						out = append(out, h)
					}
				}
			}
		}
	}
	return out
}

// outboundAllowed refuses a URL whose host is not on the allow-list; the
// error names the setting so the person knows who can widen it.
func (s *Server) outboundAllowed(ctx context.Context, raw string) error {
	h := urlHost(raw)
	if h == "" {
		return fmt.Errorf("%q is not a URL", raw)
	}
	if !hostAllowed(s.outboundHosts(ctx), h) {
		return fmt.Errorf("the console does not reach %s: not the platform's identity provider and not in CONSOLE_OUTBOUND_HOSTS (a platform operator adds the host)", h)
	}
	return nil
}
