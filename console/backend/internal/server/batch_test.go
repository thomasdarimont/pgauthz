package server

import (
	"strings"
	"testing"
)

// The importer understands the three shapes the exporter writes and reports
// what it cannot read with the line or element.
func TestParseTuples(t *testing.T) {
	native := `[{"user_type":"user","user_id":"alice","relation":"viewer","object_type":"doc","object_id":"a","condition":"daytime","condition_context":{"tz":"UTC"},"expires_at":"2030-01-01T00:00:00Z"}]`
	got, shape, err := parseTuples(native)
	if err != nil || shape != "json" || len(got) != 1 || got[0].Condition != "daytime" || string(got[0].ConditionContext) != `{"tz":"UTC"}` {
		t.Fatalf("native: %v %s %+v", err, shape, got)
	}
	openfga := `{"tuples":[{"key":{"user":"user:alice","relation":"viewer","object":"doc:a"}},{"key":{"user":"team:eng#member","relation":"editor","object":"doc:b"}},{"key":{"user":"user:*","relation":"viewer","object":"doc:c"}}]}`
	got, shape, err = parseTuples(openfga)
	if err != nil || shape != "openfga" || len(got) != 3 {
		t.Fatalf("openfga: %v %s %+v", err, shape, got)
	}
	if got[1].UserType != "team" || got[1].UserID != "eng" || got[1].UserRelation != "member" || got[2].UserID != "*" {
		t.Errorf("openfga subjects: %+v", got)
	}
	csvText := strings.Join([]string{
		"user_type,user_id,user_relation,relation,object_type,object_id,condition,condition_context,expires_at",
		"user,alice,,viewer,doc,a,,,",
		`team,eng,member,editor,doc,b,daytime,"{""tz"":""UTC""}",`,
		"",
	}, "\n")
	got, shape, err = parseTuples("\uFEFF" + csvText)
	if err != nil || shape != "csv" || len(got) != 2 {
		t.Fatalf("csv: %v %s %+v", err, shape, got)
	}
	if got[1].UserRelation != "member" || got[1].Condition != "daytime" || string(got[1].ConditionContext) != `{"tz":"UTC"}` {
		t.Errorf("csv row: %+v", got[1])
	}
	for _, bad := range []string{"", "user_id,relation\nalice,viewer", `{"tuples":[{"key":{"user":"alice","relation":"viewer","object":"doc:a"}}]}`, "[{"} {
		if _, _, err := parseTuples(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
