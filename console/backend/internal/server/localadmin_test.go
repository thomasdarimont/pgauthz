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

func TestLocalAdminTuplesFor(t *testing.T) {
	base := `[{"user_type":"user","user_id":"admin","relation":"member","object_type":"team","object_id":"role_console_admin"}]`
	p := &principal{typ: "user", id: "admin", ctxTuples: base}
	if got := p.tuplesFor("store", []string{"todo"}); got != base {
		t.Fatalf("without a store role the tuples must be the memberships only, got %s", got)
	}
	p.storeRole = "owner"
	p.pathStore = "todo"
	got := p.tuplesFor("namespace", []string{"todo/dms"})
	for _, want := range []string{`"relation":"member"`, `"relation":"owner"`, `"object_id":"todo"`} {
		if !contains(got, want) {
			t.Errorf("namespace check on the request's store: missing %s in %s", want, got)
		}
	}
	got = p.tuplesFor("store", []string{"todo", "demo", "todo"})
	if n := count(got, `"relation":"owner"`); n != 2 {
		t.Errorf("one owner tuple per distinct store (todo once, demo once), got %d in %s", n, got)
	}
}

func contains(s, sub string) bool { return len(sub) > 0 && len(s) >= len(sub) && index(s, sub) >= 0 }
func index(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
func count(s, sub string) int {
	n := 0
	for i := index(s, sub); i >= 0; i = index(s, sub) {
		n++
		s = s[i+len(sub):]
	}
	return n
}
