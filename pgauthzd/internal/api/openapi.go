package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
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

var openapiVersion = openapiVersionPlaceholder

// SetOpenAPIVersion stamps the served document's info.version with the build
// version (the same value build_info reports). Call once at startup, before
// the first request; later calls are ignored (documents are rendered once).
func SetOpenAPIVersion(v string) {
	if v != "" {
		openapiVersion = v
	}
}

// openapiDoc is one rendered variant of the document (JSON + YAML forms),
// prepared lazily once.
type openapiDoc struct {
	once sync.Once
	json []byte
	yaml []byte
	err  error
}

var (
	// openapiFull is the complete contract (instances serving the native
	// surface on their public listener).
	openapiFull openapiDoc
	// openapiOPAFronted is the INSTANCE-ACCURATE variant for an OPA-fronted
	// instance (review #6): its public listener does not register the native
	// /pgauthz/v1 routes, so its served document omits them too — a generated
	// client cannot be misled into calling operations this instance rejects.
	// The openapi meta endpoints themselves stay (they ARE registered).
	openapiOPAFronted openapiDoc
)

func (d *openapiDoc) render(dropNativePaths bool) error {
	d.once.Do(func() {
		src := bytes.Replace(openapiYAML,
			[]byte("version: "+openapiVersionPlaceholder),
			[]byte("version: "+openapiVersion), 1)
		var doc map[string]any
		if d.err = yaml.Unmarshal(src, &doc); d.err != nil {
			return
		}
		if dropNativePaths {
			if paths, ok := doc["paths"].(map[string]any); ok {
				for p := range paths {
					if strings.HasPrefix(p, "/pgauthz/v1/openapi.") {
						continue
					}
					if strings.HasPrefix(p, "/pgauthz/v1/") || strings.HasPrefix(p, "/stores/{store}/pgauthz/v1/") {
						delete(paths, p)
					}
				}
			}
			// Re-marshal the filtered document as the YAML form too (source
			// comments are lost in this variant — the full source remains in
			// the repository).
			if d.yaml, d.err = yaml.Marshal(doc); d.err != nil {
				return
			}
		} else {
			d.yaml = src
		}
		d.json, d.err = json.Marshal(doc)
	})
	return d.err
}

// openapiVariant picks the rendered document matching THIS instance's public
// surface.
func (h *Handler) openapiVariant() *openapiDoc {
	if h.cfg.UsesOPA() {
		return &openapiOPAFronted
	}
	return &openapiFull
}

// OpenAPIJSON — GET /pgauthz/v1/openapi.json: this server's API description.
// Unauthenticated (the document is public — it ships in the repository); it
// describes the FULL surface, with per-mode availability noted in the text.
func (h *Handler) OpenAPIJSON(w http.ResponseWriter, r *http.Request) {
	d := h.openapiVariant()
	if err := d.render(h.cfg.UsesOPA()); err != nil {
		writeInternalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(d.json)
}

// OpenAPIYAML — GET /pgauthz/v1/openapi.yaml: the YAML form of the same
// document (most OpenAPI tooling accepts either).
func (h *Handler) OpenAPIYAML(w http.ResponseWriter, r *http.Request) {
	d := h.openapiVariant()
	if err := d.render(h.cfg.UsesOPA()); err != nil {
		writeInternalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	w.Write(d.yaml)
}
