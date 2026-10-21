package server

import "testing"

func TestLocalCredentialsMatch(t *testing.T) {
	cases := []struct {
		user, pass string
		want       bool
	}{
		{"admin", "secret", true},
		{"admin", "Secret", false},
		{"Admin", "secret", false},
		{"", "", false},
		{"admin", "", false},
		{"", "secret", false},
	}
	for _, c := range cases {
		if got := localCredentialsMatch("admin", "secret", c.user, c.pass); got != c.want {
			t.Errorf("(%q,%q) = %v, want %v", c.user, c.pass, got, c.want)
		}
	}
}
