package api

import (
	"errors"
	"testing"

	"thomasdarimont.de/authz/pgauthzd/internal/config"
)

// resolveSubjectPair is the central subject-override policy. By default
// (AllowSubjectOverride=false) the authenticated JWT subject is authoritative
// and a differing body subject is rejected; with the flag on, the body subject
// wins (JWT as fallback) — the trusted-PEP/PDP mode.
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
		{"secure_no_jwt_falls_back_to_body", false, "internal_user", "bob", "", "", "internal_user", "bob", nil},
		{"secure_no_jwt_no_body", false, "", "", "", "", "", "", errSubjectRequired},
		// Override (trusted PEP/PDP) mode.
		{"override_body_wins_over_jwt", true, "internal_user", "bob", "internal_user", "alice", "internal_user", "bob", nil},
		{"override_jwt_fallback", true, "", "", "internal_user", "alice", "internal_user", "alice", nil},
		{"override_nothing_supplied", true, "", "", "", "", "", "", errSubjectRequired},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{cfg: &config.Config{AllowSubjectOverride: tc.allowOverride}}
			gotType, gotID, err := h.resolveSubjectPair(tc.bodyType, tc.bodyID, tc.jwtType, tc.jwtID)

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
