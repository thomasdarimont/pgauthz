package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"

	_ "embed"

	"gopkg.in/yaml.v3"
)

// openapiYAML is the API contract (native /pgauthz/v1 + AuthZEN /access/v1),
// embedded so the binary always serves the description it was built with.
// openapi_test.go enforces spec↔code coverage and validates handler responses
// against it, so this document cannot silently drift from the routes.
//
//go:embed openapi.yaml
var openapiYAML []byte

// openapiVersionPlaceholder is the literal info.version in the embedded file,
// replaced with the build version at startup (SetOpenAPIVersion).
const openapiVersionPlaceholder = "0.0.0-dev"

var (
	openapiVersion = openapiVersionPlaceholder
	openapiOnce    sync.Once
	openapiJSON    []byte
	openapiSrc     []byte
	openapiErr     error
)

// SetOpenAPIVersion stamps the served document's info.version with the build
// version (the same value build_info reports). Call once at startup, before
// the first request; later calls are ignored (the document is rendered once).
func SetOpenAPIVersion(v string) {
	if v != "" {
		openapiVersion = v
	}
}

// renderOpenAPI prepares both served forms once: the YAML source with the
// version placeholder stamped, and its JSON conversion (yaml.v3 decodes
// string-keyed mappings to map[string]any, which json.Marshal accepts).
func renderOpenAPI() error {
	openapiOnce.Do(func() {
		openapiSrc = bytes.Replace(openapiYAML,
			[]byte("version: "+openapiVersionPlaceholder),
			[]byte("version: "+openapiVersion), 1)
		var doc map[string]any
		if openapiErr = yaml.Unmarshal(openapiSrc, &doc); openapiErr != nil {
			return
		}
		openapiJSON, openapiErr = json.Marshal(doc)
	})
	return openapiErr
}

// OpenAPIJSON — GET /pgauthz/v1/openapi.json: this server's API description.
// Unauthenticated (the document is public — it ships in the repository); it
// describes the FULL surface, with per-mode availability noted in the text.
func (h *Handler) OpenAPIJSON(w http.ResponseWriter, r *http.Request) {
	if err := renderOpenAPI(); err != nil {
		writeInternalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(openapiJSON)
}

// OpenAPIYAML — GET /pgauthz/v1/openapi.yaml: the YAML source of the same
// document (most OpenAPI tooling accepts either).
func (h *Handler) OpenAPIYAML(w http.ResponseWriter, r *http.Request) {
	if err := renderOpenAPI(); err != nil {
		writeInternalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	w.Write(openapiSrc)
}
