package opabackend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"thomasdarimont.de/authz/pgauthzd/internal/authz"
)

// With provenance enabled the backend asks OPA for it and keeps the latest
// report (ADR 0013 decision-log provenance); off by default.
func TestProvenanceCapture(t *testing.T) {
	var sawProvenance bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawProvenance = strings.Contains(r.URL.RawQuery, "provenance=true")
		w.Header().Set("Content-Type", "application/json")
		if sawProvenance {
			w.Write([]byte(`{"result": true, "provenance": {"version": "1.18.2",
			  "bundles": {"policy": {"revision": "rev-42"}, "hooks": {"revision": "h-7"}}}}`))
			return
		}
		w.Write([]byte(`{"result": true}`))
	}))
	defer srv.Close()

	b := New(srv.URL, "authz", false, time.Second, false, "", false, 0)
	req := authz.EvalRequest{Store: "demo", SubjectType: "user", SubjectID: "alice", Action: "can_read", ObjectType: "doc", ObjectID: "d1"}
	if _, err := b.CheckAccess(context.Background(), req); err != nil {
		t.Fatalf("check: %v", err)
	}
	if sawProvenance {
		t.Fatal("provenance requested while disabled")
	}
	if p := b.PolicyProvenance(); p.OPAVersion != "" || len(p.Bundles) != 0 {
		t.Fatalf("provenance reported while disabled: %+v", p)
	}

	b.EnableProvenance()
	if _, err := b.CheckAccess(context.Background(), req); err != nil {
		t.Fatalf("check: %v", err)
	}
	if !sawProvenance {
		t.Fatal("provenance not requested after EnableProvenance")
	}
	p := b.PolicyProvenance()
	if p.OPAVersion != "1.18.2" || p.Bundles["policy"] != "rev-42" || p.Bundles["hooks"] != "h-7" {
		t.Fatalf("provenance = %+v", p)
	}
}
