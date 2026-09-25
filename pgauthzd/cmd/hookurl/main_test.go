package main

import (
	"strings"
	"testing"
)

func TestCanonicalAccepts(t *testing.T) {
	cases := []struct {
		raw        string
		plain      bool
		host, port string
	}{
		{"https://policy.internal.example/v1/restrictions", false, "policy.internal.example", "443"},
		{"https://policy.internal.example:8443/v1?x=1#frag", false, "policy.internal.example", "8443"},
		{"https://[2001:db8::1]:8443/v1", false, "2001:db8::1", "8443"},
		{"https://10.0.0.5/v1", false, "10.0.0.5", "443"},
		{"http://localhost:8181/v1/data", false, "localhost", "8181"},
		{"http://127.0.0.1/v1", false, "127.0.0.1", "80"},
		{"http://[::1]:9000/v1", false, "::1", "9000"},
		{"http://restrictions.svc.cluster.local/v1", true, "restrictions.svc.cluster.local", "80"},
		{"https://xn--bcher-kva.example/v1", false, "xn--bcher-kva.example", "443"},
		{"HTTPS://policy.internal.example/v1", false, "policy.internal.example", "443"}, // scheme case is normalised by url.Parse for OPA too
	}
	for _, tc := range cases {
		d, err := Canonical(tc.raw, tc.plain)
		if err != nil {
			t.Errorf("%s: unexpected reject: %v", tc.raw, err)
			continue
		}
		if d.Host != tc.host || d.Port != tc.port {
			t.Errorf("%s: got %s:%s, want %s:%s", tc.raw, d.Host, d.Port, tc.host, tc.port)
		}
	}
}

func TestCanonicalRejects(t *testing.T) {
	cases := []struct {
		raw   string
		plain bool
		want  string // substring of the reason
	}{
		{"http://restrictions.svc.cluster.local/v1", false, "must be https"},
		{"https://user:pw@policy.internal.example/v1", false, "userinfo"},
		{"https://policy.internal.example@evil.example/v1", false, "userinfo"},
		{"https://Policy.Internal.Example/v1", false, "lowercase"},
		{"https://policy.internal.example./v1", false, "end with a dot"},
		{"https://bücher.example/v1", false, "punycode"},
		{"https://policy.internal.exa%6dple/v1", false, "escape"}, // Go refuses the escape at parse time
		{"https://[fe80::1%25eth0]/v1", false, "percent"},         // IPv6 zone: percent in the authority
		{"ftp://policy.internal.example/v1", false, "not allowed"},
		{"mailto:policy@internal.example", false, "opaque"},
		{"https:///v1", false, "no host"},
		{"https://[2001:db8::1/v1", false, "does not parse"},
		{" https://policy.internal.example/v1", false, "whitespace"},
		{"", false, "empty"},
	}
	for _, tc := range cases {
		_, err := Canonical(tc.raw, tc.plain)
		if err == nil {
			t.Errorf("%q: expected reject (%s), got accept", tc.raw, tc.want)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: reason %q does not mention %q", tc.raw, err, tc.want)
		}
	}
}

// The host the helper reports is the one OPA compares: an IPv6 literal without
// brackets, a name without port — never the raw authority.
func TestHostMatchesOPAHostname(t *testing.T) {
	d, err := Canonical("https://[2001:db8::1]:8443/v1", false)
	if err != nil || d.Host != "2001:db8::1" {
		t.Fatalf("got %+v, %v", d, err)
	}
}
