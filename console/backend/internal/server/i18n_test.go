package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"thomasdarimont.de/authz/console-bff/internal/config"
)

// Translation overrides: a <lang>.json in CONSOLE_I18N_DIR is served as-is,
// a missing one is an empty object, a bad code is refused, and the listing
// names a language after its "@language" entry.
func TestI18nOverrides(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fr.json"), []byte(`{"@language": "Français", "Stores": "Magasins"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "de.json"), []byte(`{"Stores": "Mandanten"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: config.Config{I18nDir: dir}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/i18n", s.handleI18nList)
	mux.HandleFunc("GET /api/i18n/{lang}", s.handleI18n)

	get := func(path string) (int, string) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code, rec.Body.String()
	}

	code, body := get("/api/i18n")
	var list []map[string]string
	if err := json.Unmarshal([]byte(body), &list); err != nil || code != 200 {
		t.Fatalf("list: %d %s", code, body)
	}
	if len(list) != 2 || list[0]["code"] != "de" || list[0]["name"] != "de" || list[1]["code"] != "fr" || list[1]["name"] != "Français" {
		t.Fatalf("unexpected listing: %v", list)
	}
	if code, body = get("/api/i18n/fr"); code != 200 || body == "" || !json.Valid([]byte(body)) {
		t.Fatalf("fr: %d %s", code, body)
	}
	if code, body = get("/api/i18n/es"); code != 200 || body != "{}\n" && body != "{}" {
		t.Fatalf("missing language should be an empty object: %d %q", code, body)
	}
	if code, _ = get("/api/i18n/..%2Fetc"); code != 400 && code != 404 {
		t.Fatalf("path escape accepted: %d", code)
	}
	if code, _ = get("/api/i18n/DE_x"); code != 400 {
		t.Fatalf("bad code accepted: %d", code)
	}
}
