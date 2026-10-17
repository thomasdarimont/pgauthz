package api

import (
	"errors"
	"testing"

	"thomasdarimont.de/authz/pgauthzd/internal/config"
)

// resolveSubjectPair is the central subject-assertion policy. With assert=false
// (self-subject, the default) the authenticated JWT subject is authoritative
// and a differing body subject is rejected; with assert=true (the coarse flag,
// or a pep_client for the store — ADR 0014) the body subject wins (JWT as
// fallback) — the trusted-PEP/PDP mode.
func TestResolveSubjectPair(t *testing.T) {
	cases := []struct {
		name             string
		allowOverride    bool
		bodyType, bodyID string
		jwtType, jwtID   string
		wantType, wantID string
		wantErr          error
	}{
		// Secure default (token-only).
		{"secure_jwt_only_empty_body", false, "", "", "internal_user", "alice", "internal_user", "alice", nil},
		{"secure_body_matches_jwt", false, "internal_user", "alice", "internal_user", "alice", "internal_user", "alice", nil},
		{"secure_body_mismatch_rejected", false, "internal_user", "bob", "internal_user", "alice", "", "", errSubjectForbidden},
		{"secure_type_mismatch_rejected", false, "client_user", "alice", "internal_user", "alice", "", "", errSubjectForbidden},
		{"secure_no_token_falls_back_to_body", false, "internal_user", "bob", "", "", "internal_user", "bob", nil},
		{"secure_no_token_no_body", false, "", "", "", "", "", "", errSubjectRequired},
		// Override (trusted PEP/PDP) mode.
		{"override_body_wins_over_jwt", true, "internal_user", "bob", "internal_user", "alice", "internal_user", "bob", nil},
		{"override_jwt_fallback", true, "", "", "internal_user", "alice", "internal_user", "alice", nil},
		{"override_nothing_supplied", true, "", "", "", "", "", "", errSubjectRequired},
		// A partial body subject is malformed, never completed from the token
		// (the token's type does not describe the body's id).
		{"override_partial_id_only", true, "", "bob", "internal_user", "alice", "", "", errSubjectRequired},
		{"override_partial_type_only", true, "user", "", "internal_user", "alice", "", "", errSubjectRequired},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{cfg: &config.Config{}}
			// the no-token cases run unauthenticated; every other case carries a verified token
			gotType, gotID, err := h.resolveSubjectPair(tc.bodyType, tc.bodyID, tc.jwtType, tc.jwtID, tc.allowOverride, tc.jwtType != "" || tc.jwtID != "")

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("want error %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotType != tc.wantType || gotID != tc.wantID {
				t.Fatalf("want (%q,%q), got (%q,%q)", tc.wantType, tc.wantID, gotType, gotID)
			}
		})
	}
}

// A verified token WITHOUT a subject claim (a service credential) is not the
// unauthenticated case: it may not name a subject unless it may assert.
func TestSubjectlessTokenCannotAssert(t *testing.T) {
	h := &Handler{cfg: &config.Config{}}
	if _, _, err := h.resolveSubjectPair("user", "alice", "", "", false, true); !errors.Is(err, errSubjectForbidden) {
		t.Fatalf("authenticated, no token subject, body names alice: want forbidden, got %v", err)
	}
	if _, _, err := h.resolveSubjectPair("", "", "", "", false, true); !errors.Is(err, errSubjectRequired) {
		t.Fatalf("authenticated, no subject anywhere: want required, got %v", err)
	}
	if st, sid, err := h.resolveSubjectPair("user", "alice", "", "", true, true); err != nil || st != "user" || sid != "alice" {
		t.Fatalf("asserting client: want alice, got %q %q %v", st, sid, err)
	}
}
