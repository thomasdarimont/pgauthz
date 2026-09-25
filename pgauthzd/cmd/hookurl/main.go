// hookurl canonicalises the static destination URL of a policy-hook http.send
// call for scripts/validate-hooks.sh (ADR 0011).
//
// The validator compares each hook's destination host against the http
// capability profile's allow_net. OPA performs that comparison at evaluation
// time with Go's net/url: url.Parse(url).Hostname() must equal an allow_net
// entry exactly. Extracting the host with shell text tools risks a parser
// mismatch (IPv6 literals, userinfo, unusual-but-legal forms, default ports,
// case, percent-encoding, scheme confusion) — a URL the validator reads one
// way and OPA another. This helper uses the same parser OPA does, and is
// STRICTER than OPA wherever a divergence could otherwise be exploited or
// silently fail at runtime:
//
//   - https only; http is accepted for loopback destinations (local
//     development) or with --allow-plain-http (private networks) — an explicit
//     operator decision, never the default;
//   - no userinfo (credentials in policy source, host confusion);
//   - no opaque URLs (scheme:payload), no percent-encoding in the host;
//   - the host must already be in canonical form — lowercase ASCII or an IP
//     literal, no trailing dot — because OPA compares allow_net entries
//     byte-for-byte, so a "canonically equal" spelling that OPA does not
//     recognise would pass validation and fail closed at runtime.
//
// Usage: hookurl [--allow-plain-http] <url>
// Prints one JSON object {"scheme","host","port"} and exits 0; exits 2 with
// the reason on stderr when the URL is rejected.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// Dest is the canonical destination of a static http.send URL.
type Dest struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"` // exactly what OPA's url.Hostname() yields and compares to allow_net
	Port   string `json:"port"` // explicit or the scheme default
}

// Canonical parses raw the way OPA will and applies the validator's stricter
// rules. allowPlainHTTP admits http:// to non-loopback hosts.
func Canonical(raw string, allowPlainHTTP bool) (Dest, error) {
	if strings.TrimSpace(raw) != raw || raw == "" {
		return Dest{}, errors.New("url is empty or has surrounding whitespace")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Dest{}, fmt.Errorf("url does not parse: %v", err)
	}
	if u.Opaque != "" {
		return Dest{}, errors.New("opaque URL (scheme:payload) is not a network destination")
	}
	if u.User != nil {
		return Dest{}, errors.New("userinfo (user[:password]@) is not allowed in a hook destination")
	}
	scheme := u.Scheme // url.Parse lowercases the scheme, exactly as OPA sees it
	host := u.Hostname()
	if host == "" {
		return Dest{}, errors.New("url has no host")
	}
	if strings.Contains(u.Host, "%") {
		return Dest{}, errors.New("percent-encoding in the host is not allowed")
	}
	if ip := net.ParseIP(host); ip == nil {
		// A name: canonical form only, so the byte-exact allow_net comparison
		// OPA performs cannot diverge from what the validator accepted.
		for _, r := range host {
			if r > 0x7f {
				return Dest{}, fmt.Errorf("host %q is not ASCII — write it in punycode (xn--…), which is what OPA compares", host)
			}
		}
		if host != strings.ToLower(host) {
			return Dest{}, fmt.Errorf("host %q must be lowercase (OPA compares allow_net entries exactly)", host)
		}
		if strings.HasSuffix(host, ".") {
			return Dest{}, fmt.Errorf("host %q must not end with a dot", host)
		}
	}
	port := u.Port()
	switch scheme {
	case "https":
		if port == "" {
			port = "443"
		}
	case "http":
		if !allowPlainHTTP && !isLoopback(host) {
			return Dest{}, fmt.Errorf("http:// to %q is not allowed: hook destinations must be https (loopback excepted); pass --allow-plain-http for a private network you trust", host)
		}
		if port == "" {
			port = "80"
		}
	default:
		return Dest{}, fmt.Errorf("scheme %q is not allowed (https, or http to loopback)", scheme)
	}
	return Dest{Scheme: scheme, Host: host, Port: port}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func main() {
	allowPlain := false
	args := os.Args[1:]
	for len(args) > 0 && strings.HasPrefix(args[0], "--") {
		switch args[0] {
		case "--allow-plain-http":
			allowPlain = true
		default:
			fmt.Fprintf(os.Stderr, "unknown flag %s\n", args[0])
			os.Exit(2)
		}
		args = args[1:]
	}
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: hookurl [--allow-plain-http] <url>")
		os.Exit(2)
	}
	d, err := Canonical(args[0], allowPlain)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	_ = json.NewEncoder(os.Stdout).Encode(d)
}
