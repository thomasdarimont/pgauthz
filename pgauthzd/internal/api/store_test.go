package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"thomasdarimont.de/authz/pgauthzd/internal/config"
)

func testHandler(issuers []config.Issuer) *Handler {
	return NewHandler(nil, &config.Config{
		DefaultStore: "demo",
		StoreHeader:  "X-AuthZ-Store",
		Issuers:      issuers,
	})
}

func TestStoreResolution(t *testing.T) {
	h := testHandler(nil)

	// default
	r := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", nil)
	if got := h.store(r); got != "demo" {
		t.Errorf("default: got %q, want demo", got)
	}

	// header beats default
	r.Header.Set("X-AuthZ-Store", "hdr")
	if got := h.store(r); got != "hdr" {
		t.Errorf("header: got %q, want hdr", got)
	}

	// path beats header
	r.SetPathValue("store", "pathstore")
	if got := h.store(r); got != "pathstore" {
		t.Errorf("path: got %q, want pathstore", got)
	}
}

func TestIssuerStoreBinding(t *testing.T) {
	h := testHandler([]config.Issuer{
		{Issuer: "https://tenant-a.idp", JWKSFile: "x", Stores: []string{"tenant-a", "tenant-a-.*"}},
		{Issuer: "https://open.idp", JWKSFile: "x"}, // no restriction
	})

	req := func(issuer, store string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/access/v1/evaluation", nil)
		r.SetPathValue("store", store)
		if issuer != "" {
			r = r.WithContext(context.WithValue(r.Context(), ctxIssuer, issuer))
		}
		return r
	}

	cases := []struct {
		name    string
		issuer  string
		store   string
		allowed bool
	}{
		{"exact match", "https://tenant-a.idp", "tenant-a", true},
		{"pattern match", "https://tenant-a.idp", "tenant-a-staging", true},
		{"pattern is anchored", "https://tenant-a.idp", "xtenant-a-staging", false},
		{"other store denied", "https://tenant-a.idp", "demo", false},
		{"unrestricted issuer", "https://open.idp", "anything", true},
		{"unknown issuer unrestricted", "https://other.idp", "anything", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			store, ok := h.storeChecked(w, req(tc.issuer, tc.store))
			if ok != tc.allowed {
				t.Fatalf("allowed = %v, want %v", ok, tc.allowed)
			}
			if tc.allowed && store != tc.store {
				t.Errorf("store = %q, want %q", store, tc.store)
			}
			if !tc.allowed && w.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", w.Code)
			}
		})
	}
}
