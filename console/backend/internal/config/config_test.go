package config

import (
	"strings"
	"testing"
)

// The subject-id claim list cannot name a token-technical claim: `iat` or
// `iss` are always present and would make every sign-in the same person.
func TestValidateSubjectIDClaims(t *testing.T) {
	ok := Config{SubjectIDClaims: []string{"preferred_username", "sub"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{{"iat"}, {"preferred_username", "iss"}, {"azp"}, {}} {
		if err := (Config{SubjectIDClaims: bad}).Validate(); err == nil || !strings.Contains(err.Error(), "CONSOLE_SUBJECT_ID_CLAIMS") {
			t.Errorf("%v must be refused, got %v", bad, err)
		}
	}
	// a CEL expression is the operator's own; the list is not consulted
	if err := (Config{SubjectIDCEL: "claims.sub", SubjectIDClaims: []string{"iat"}}).Validate(); err != nil {
		t.Fatal(err)
	}
}

// The platform provider's button: PROVIDER_LABEL, else the issuer's host —
// an EntraID tenant must not say "Keycloak".
func TestProviderName(t *testing.T) {
	if got := (Config{Issuer: "https://login.microsoftonline.com/abc/v2.0"}).ProviderName(); got != "login.microsoftonline.com" {
		t.Fatalf("host fallback: %q", got)
	}
	if got := (Config{Issuer: "https://id.example/realms/x", ProviderLabel: "ACME SSO"}).ProviderName(); got != "ACME SSO" {
		t.Fatalf("label: %q", got)
	}
}

// CONSOLE_AUTO_LOGIN is a switch or an https issuer, nothing else.
func TestValidateAutoLogin(t *testing.T) {
	base := Config{SubjectIDClaims: []string{"sub"}}
	for _, ok := range []string{"", "true", "false", "TRUE", "https://id.acme.test/realms/demo", "keycloak", "tenant-a"} {
		c := base
		c.AutoLogin = ok
		if err := c.Validate(); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"bad alias", "http://id.acme.test", "Keycloak!"} {
		c := base
		c.AutoLogin = bad
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "CONSOLE_AUTO_LOGIN") {
			t.Errorf("%q must be refused, got %v", bad, err)
		}
	}
}
