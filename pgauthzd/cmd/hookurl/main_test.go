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

// Adversarial destinations (review #11 asks for these to stay as regression
// tests). Two groups: URLs the canonicaliser must REJECT outright, and URLs it
// must accept while reporting the host OPA would really connect to — for
// those the allow_net comparison in validate-hooks.sh is the gate, so the
// reported host must never be the attacker's decoy (userinfo, fragment,
// query, path, suffix tricks).
func TestCanonicalAdversarialRejects(t *testing.T) {
	cases := []struct{ raw, want string }{
		// userinfo dressed up as host:port
		{"https://policy.internal.example:443@evil.example/v1", "userinfo"},
		{"https://policy.internal.example:pw@evil.example/v1", "userinfo"},
		{"https://policy.internal.example:8443@[::1]/v1", "userinfo"},
		{"http://[::1]@evil.example/v1", "userinfo"},
		// percent-encoded dots/letters in the authority: Go refuses the escape at
		// parse time (only the IPv6-zone %25 survives, caught as "percent")
		{"https://policy.internal.example%2eevil.example/v1", "does not parse"},
		{"https://%70olicy.internal.example/v1", "does not parse"},
		// control characters and whitespace
		{"https://policy.internal.example/\tv1", "does not parse"},
		{"https://policy.internal.example/v1\n", "whitespace"},
		{"\thttps://policy.internal.example/v1", "whitespace"},
		// broken ports / brackets
		{"https://policy.internal.example:443:8443/v1", "does not parse"},
		{"https://policy.internal.example:abc/v1", "does not parse"},
		{"https://[2001:db8::1]junk/v1", "does not parse"},
		// no network authority at all
		{`https:\\evil.example/v1`, "opaque"},
		{"javascript:alert(1)", "opaque"},
		{"//policy.internal.example/v1", "not allowed"},
		{"policy.internal.example/v1", "no host"}, // scheme-less: parsed as a path
		// case and unicode
		{"HTTPS://POLICY.INTERNAL.EXAMPLE/v1", "lowercase"},
		{"https://policy.internal​.example/v1", "punycode"},
		{"https://pоlicy.internal.example/v1", "punycode"}, // Cyrillic о
	}
	for _, tc := range cases {
		_, err := Canonical(tc.raw, false)
		if err == nil {
			t.Errorf("%q: expected reject (%s), got accept", tc.raw, tc.want)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: reason %q does not mention %q", tc.raw, err, tc.want)
		}
	}
}

func TestCanonicalAdversarialHost(t *testing.T) {
	// Accepted by the parser; the reported host is what allow_net is compared
	// against, so a decoy elsewhere in the URL must not change it.
	cases := []struct{ raw, host string }{
		{"https://policy.internal.example#@evil.example", "policy.internal.example"},
		{"https://policy.internal.example?redirect=https://evil.example", "policy.internal.example"},
		{"https://policy.internal.example/../../evil.example/v1", "policy.internal.example"},
		{"https://policy.internal.example:443/v1", "policy.internal.example"},
		{"https://policy.internal.example", "policy.internal.example"},
		// decoys that ARE the host: the allowlist must reject these, so the
		// helper must report them faithfully, never the allowlisted-looking part
		{"https://evil.example/https://policy.internal.example/v1", "evil.example"},
		{"https://policy.internal.example.evil.example/v1", "policy.internal.example.evil.example"},
		{"https://policy.internal.example-evil.example/v1", "policy.internal.example-evil.example"},
		{"https://0x0a000005/v1", "0x0a000005"},
		{"https://2130706433/v1", "2130706433"},
		{"https://[::ffff:10.0.0.5]/v1", "::ffff:10.0.0.5"},
		// IPv6 literals are reported as written (OPA compares the string; write
		// allow_net entries the same way)
		{"https://[2001:DB8::1]/v1", "2001:DB8::1"},
	}
	for _, tc := range cases {
		d, err := Canonical(tc.raw, false)
		if err != nil {
			t.Errorf("%q: unexpected reject: %v", tc.raw, err)
			continue
		}
		if d.Host != tc.host {
			t.Errorf("%q: host %q, want %q", tc.raw, d.Host, tc.host)
		}
	}
}
