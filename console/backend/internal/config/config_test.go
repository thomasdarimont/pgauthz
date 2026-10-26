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
