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

// The INSTANCE-ACCURATE variants (review #6): an OPA-fronted instance's
// public listener registers no native /pgauthz/v1 routes, and an instance
// without the admin API on its public listener registers no
// /pgauthz/v1/admin/ routes — each served document omits what the instance
// rejects, so a generated client cannot be misled. The openapi meta
// endpoints themselves stay (they ARE registered).
var openapiVariants sync.Map // [2]bool{dropNative, dropAdmin} -> *openapiDoc

func openapiVariantFor(dropNative, dropAdmin bool) *openapiDoc {
	v, _ := openapiVariants.LoadOrStore([2]bool{dropNative, dropAdmin}, &openapiDoc{})
	return v.(*openapiDoc)
}

func (d *openapiDoc) render(dropNativePaths, dropAdminPaths bool) error {
	d.once.Do(func() {
		src := bytes.Replace(openapiYAML,
			[]byte("version: "+openapiVersionPlaceholder),
			[]byte("version: "+openapiVersion), 1)
		var doc map[string]any
		if d.err = yaml.Unmarshal(src, &doc); d.err != nil {
			return
		}
		if dropNativePaths || dropAdminPaths {
			if paths, ok := doc["paths"].(map[string]any); ok {
				for p := range paths {
					if strings.HasPrefix(p, "/pgauthz/v1/openapi.") {
						continue
					}
					admin := strings.HasPrefix(p, "/pgauthz/v1/admin/")
					if (dropAdminPaths && admin) || (dropNativePaths && !admin && (strings.HasPrefix(p, "/pgauthz/v1/") || strings.HasPrefix(p, "/stores/{store}/pgauthz/v1/"))) {
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
	return openapiVariantFor(h.cfg.UsesOPA(), !h.adminOnPublic())
}

// adminOnPublic: the admin routes are mounted on this instance's public
// listener (ADMIN_API_ENABLED without ADMIN_LISTEN_ADDR, a full instance).
func (h *Handler) adminOnPublic() bool {
	return h.cfg != nil && h.cfg.AdminAPIEnabled && h.cfg.AdminListenAddr == "" && h.rawWrite != nil
}

// OpenAPIJSON — GET /pgauthz/v1/openapi.json: this server's API description.
// Unauthenticated (the document is public — it ships in the repository); it
// describes the FULL surface, with per-mode availability noted in the text.
func (h *Handler) OpenAPIJSON(w http.ResponseWriter, r *http.Request) {
	d := h.openapiVariant()
	if err := d.render(h.cfg.UsesOPA(), !h.adminOnPublic()); err != nil {
		writeInternalError(w, err)
		return
	}
	doc := stampServersJSON(d.json, h.publicBaseURL(r))
	if h.cfg.SwaggerUIOIDC() {
		doc = withOIDCSchemeJSON(doc, h.oidcScheme())
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(doc)
}

// oidcScheme is the `oidc` security scheme the served document offers when the
// Swagger UI login is configured. With the authorization and token endpoints
// configured it is an oauth2 scheme with the ONE flow the UI uses —
// authorizationCode (+ PKCE, set by the initializer) — so the Authorize dialog
// shows a single login; otherwise an openIdConnect scheme naming the issuer's
// discovery document, which works but makes Swagger UI render a section per
// grant type the provider advertises.
func (h *Handler) oidcScheme() map[string]any {
	description := "Log in at the OpenID Provider pgauthzd trusts (authorization code + PKCE, public client " +
		h.cfg.SwaggerUIOIDCClientID + "); the access token is then sent as the bearer token of the PUBLIC listener."
	if h.cfg.SwaggerUIOIDCAuthorizationURL != "" && h.cfg.SwaggerUIOIDCTokenURL != "" {
		scopes := map[string]any{}
		for _, sc := range strings.Fields(h.cfg.SwaggerUIOIDCScopes) {
			scopes[sc] = "requested by the UI"
		}
		return map[string]any{
			"type":        "oauth2",
			"description": description,
			"flows": map[string]any{
				"authorizationCode": map[string]any{
					"authorizationUrl": h.cfg.SwaggerUIOIDCAuthorizationURL,
					"tokenUrl":         h.cfg.SwaggerUIOIDCTokenURL,
					"scopes":           scopes,
				},
			},
		}
	}
	return map[string]any{
		"type":             "openIdConnect",
		"openIdConnectUrl": h.cfg.SwaggerUIOIDCIssuer + "/.well-known/openid-configuration",
		"description":      description,
	}
}

// withOIDCSchemeJSON adds the `oidc` security scheme and offers it as an
// alternative on every operation that accepts the public bearer token, so
// Swagger UI's Authorize can run the login and the token it obtains is sent
// exactly like a pasted one. Only when SWAGGER_UI_OIDC_* is configured; the
// source file does not know the deployment's issuer. On any shape surprise the
// document is returned unchanged.
func withOIDCSchemeJSON(doc []byte, scheme map[string]any) []byte {
	var root map[string]any
	if err := json.Unmarshal(doc, &root); err != nil {
		return doc
	}
	if !addOIDCScheme(root, scheme) {
		return doc
	}
	out, err := json.Marshal(root)
	if err != nil {
		return doc
	}
	return out
}

func addOIDCScheme(root map[string]any, scheme map[string]any) bool {
	components, _ := root["components"].(map[string]any)
	schemes, _ := components["securitySchemes"].(map[string]any)
	paths, _ := root["paths"].(map[string]any)
	if schemes == nil || paths == nil {
		return false
	}
	schemes["oidc"] = scheme
	// The document's default requirement (root `security: [bearerAuth]`) is what
	// most operations inherit; public ones override it with `security: []`,
	// a few name their own list.
	if sec, ok := root["security"].([]any); ok && hasBearer(sec) {
		root["security"] = append(sec, map[string]any{"oidc": []any{}})
	}
	for _, item := range paths {
		ops, _ := item.(map[string]any)
		for _, op := range ops {
			o, ok := op.(map[string]any)
			if !ok {
				continue
			}
			sec, has := o["security"].([]any)
			if !has || len(sec) == 0 {
				continue // public (security: []) or inheriting the root default — unchanged
			}
			if hasBearer(sec) {
				o["security"] = append(sec, map[string]any{"oidc": []any{}})
			}
		}
	}
	return true
}

func hasBearer(requirements []any) bool {
	for _, req := range requirements {
		if m, ok := req.(map[string]any); ok {
			if _, ok := m["bearerAuth"]; ok {
				return true
			}
		}
	}
	return false
}

// stampServersJSON sets the document's `servers` to the instance's public base
// URL (the one discovery advertises), so a Swagger UI or Postman that loaded
// the document from this instance sends its requests here — not to its own
// origin, which the source file's relative "/" would mean. A plain byte
// replace of the source's single `"url":"/"` server entry, so the cached
// rendering stays shared; falls back to the document unchanged if the entry
// is not where the source puts it.
func stampServersJSON(doc []byte, base string) []byte {
	marker := []byte(`"url":"/"`)
	if bytes.Count(doc, marker) != 1 {
		return doc
	}
	quoted, err := json.Marshal(base)
	if err != nil {
		return doc
	}
	return bytes.Replace(doc, marker, append([]byte(`"url":`), quoted...), 1)
}

// stampServersYAML is stampServersJSON for the YAML form (the source's
// `- url: /` line).
func stampServersYAML(doc []byte, base string) []byte {
	marker := []byte("url: /\n")
	if bytes.Count(doc, marker) != 1 {
		return doc
	}
	return bytes.Replace(doc, marker, []byte("url: "+base+"\n"), 1)
}

// OpenAPIYAML — GET /pgauthz/v1/openapi.yaml: the YAML form of the same
// document (most OpenAPI tooling accepts either).
func (h *Handler) OpenAPIYAML(w http.ResponseWriter, r *http.Request) {
	d := h.openapiVariant()
	if err := d.render(h.cfg.UsesOPA(), !h.adminOnPublic()); err != nil {
		writeInternalError(w, err)
		return
	}
	doc := stampServersYAML(d.yaml, h.publicBaseURL(r))
	if h.cfg.SwaggerUIOIDC() {
		// the YAML form loses the source comments for this variant, like the
		// OPA-fronted rendering does
		var root map[string]any
		if err := yaml.Unmarshal(doc, &root); err == nil && addOIDCScheme(root, h.oidcScheme()) {
			if out, err := yaml.Marshal(root); err == nil {
				doc = out
			}
		}
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	w.Write(doc)
}
