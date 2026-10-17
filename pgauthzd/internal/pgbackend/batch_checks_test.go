package pgbackend

import (
	"encoding/json"
	"testing"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
)

// The JSONB checks array carries a check's own context only when it has one,
// so property-less batches hit the engine exactly as before.
func TestBatchChecksCarryPerItemContext(t *testing.T) {
	checks := batchChecks([]authz.EvalRequest{
		{SubjectType: "user", SubjectID: "alice", Action: "delete", ObjectType: "record", ObjectID: "record-1",
			Context: map[string]any{"action": map[string]any{"properties": map[string]any{"soft": true}}}},
		{SubjectType: "user", SubjectID: "alice", Action: "read", ObjectType: "record", ObjectID: "record-1"},
	})
	data, err := json.Marshal(checks)
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"context":{"action":{"properties":{"soft":true}}},"object_id":"record-1","object_type":"record","relation":"delete","user_id":"alice","user_type":"user"},` +
		`{"object_id":"record-1","object_type":"record","relation":"read","user_id":"alice","user_type":"user"}]`
	if string(data) != want {
		t.Fatalf("got  %s\nwant %s", data, want)
	}
}
