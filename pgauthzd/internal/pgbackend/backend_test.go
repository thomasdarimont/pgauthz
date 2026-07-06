package pgbackend

import "testing"

// TestSyncCommit covers the per-write consistency mode mapping and the
// fail-closed behavior on an unknown mode (which replaced the SQL _pre_request
// hook's invalid_parameter_value check — see backend.go syncCommit).
func TestSyncCommit(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"", "", true}, // absent → leave the connection default untouched
		{"applied", "remote_apply", true},
		{"strict", "remote_apply", true},
		{"remote_apply", "remote_apply", true},
		{"durable", "on", true},
		{"on", "on", true},
		{"eventual", "local", true},
		{"local", "local", true},
		{"fast", "", false},    // unknown → fail closed (never silently downgrade)
		{"APPLIED", "", false}, // case-sensitive: not a known mode
	}
	for _, c := range cases {
		got, ok := syncCommit(c.in)
		if got != c.want || ok != c.wantOK {
			t.Errorf("syncCommit(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.wantOK)
		}
	}
}
