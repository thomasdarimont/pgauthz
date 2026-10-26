package api

import (
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"sync/atomic"

	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
	"thomasdarimont.de/authz/pgauthzd/pkg/issuers"
)

// The trusted-issuer set as one immutable value (scratch/notes/issuer-
// management.md): the JWT middleware's validators and role maps and the
// handler's store bindings and PEP clients, built together from the same
// issuer list, swapped atomically when ISSUERS_SOURCE=env+db applies a new
// revision of the database bindings. A request reads the set once; a swap
// never tears what it sees.

// issuerSet is one revision of the effective issuers.
type issuerSet struct {
	revision   int64
	configs    []IssuerConfig
	validators []*issuerValidator
	byIssuer   map[string]*issuerValidator  // exact "iss" match -> validator
	dbRoles    map[string][]*regexp.Regexp  // issuer -> allowed db-role patterns (absent = unrestricted)
	clientRole map[string]map[string]string // issuer -> (azp -> db role)
	stores     map[string][]*regexp.Regexp  // issuer -> store patterns (absent = unrestricted)
	pepClients map[string]map[string][]*regexp.Regexp
	disabled   map[string]bool
	admin      map[string][]*compiledAdmin // issuer -> management rules, in order (environment only)
}

// Issuers is the holder every reader goes through.
type Issuers struct {
	p atomic.Pointer[issuerSet]
}

// NewIssuers builds the holder from the configured issuers (revision 0: the
// environment's set).
func NewIssuers(cfgs []IssuerConfig) *Issuers {
	s := &Issuers{}
	s.p.Store(newIssuerSet(cfgs, 0, nil))
	return s
}

// emptySet: what a nil holder reads (handlers built as bare literals in tests).
var emptySet = newIssuerSet(nil, 0, nil)

// current returns the set in force. Nil-safe: no holder means no issuers.
func (s *Issuers) current() *issuerSet {
	if s == nil {
		return emptySet
	}
	if set := s.p.Load(); set != nil {
		return set
	}
	return emptySet
}

// Replace swaps in a new revision of the issuers. Validators of unchanged
// anchors are reused, so their cached signing keys survive the swap.
func (s *Issuers) Replace(cfgs []IssuerConfig, revision int64) {
	s.p.Store(newIssuerSet(cfgs, revision, s.p.Load()))
	metrics.IssuersRevision.Set(float64(revision))
}

// Revision is the applied database revision (0 = environment only).
func (s *Issuers) Revision() int64 { return s.current().revision }

// Configs returns the issuers of the set in force.
func (s *Issuers) Configs() []IssuerConfig { return s.current().configs }

func anchorsEqual(a, b IssuerConfig) bool {
	return a.Issuer == b.Issuer && a.Audience == b.Audience && a.JWKSURL == b.JWKSURL && a.JWKSFile == b.JWKSFile
}

func newIssuerSet(cfgs []IssuerConfig, revision int64, prev *issuerSet) *issuerSet {
	set := &issuerSet{
		revision:   revision,
		configs:    cfgs,
		byIssuer:   map[string]*issuerValidator{},
		dbRoles:    map[string][]*regexp.Regexp{},
		clientRole: map[string]map[string]string{},
		stores:     map[string][]*regexp.Regexp{},
		pepClients: map[string]map[string][]*regexp.Regexp{},
		disabled:   map[string]bool{},
		admin:      map[string][]*compiledAdmin{},
	}
	for _, ic := range cfgs {
		var v *issuerValidator
		if prev != nil {
			for _, pv := range prev.validators {
				if anchorsEqual(pv.cfg, ic) {
					v = pv
					break
				}
			}
		}
		if v == nil {
			v = &issuerValidator{cfg: ic}
		}
		set.validators = append(set.validators, v)
		if ic.Issuer == "" {
			continue
		}
		set.byIssuer[ic.Issuer] = v
		if ic.Disabled {
			set.disabled[ic.Issuer] = true
		}
		if len(ic.Admin) > 0 {
			set.admin[ic.Issuer] = compileAdminRules(ic.Admin)
		}
		if len(ic.DBRoles) > 0 {
			set.dbRoles[ic.Issuer] = compileAnchored(ic.DBRoles)
		}
		if len(ic.ClientDBRoles) > 0 {
			set.clientRole[ic.Issuer] = ic.ClientDBRoles
		}
		if len(ic.Stores) > 0 {
			set.stores[ic.Issuer] = compileAnchored(ic.Stores)
		}
		if len(ic.PEPClients) > 0 {
			clients := make(map[string][]*regexp.Regexp, len(ic.PEPClients))
			for client, patterns := range ic.PEPClients {
				clients[client] = compileAnchored(patterns)
			}
			set.pepClients[ic.Issuer] = clients
		}
	}
	return set
}

// compileAnchored compiles patterns validated upstream (config.Load /
// issuers.ValidateBindings) — anchored, so plain names match exactly.
func compileAnchored(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		out[i] = regexp.MustCompile("^(?:" + p + ")$")
	}
	return out
}

// IssuerConfigsFrom converts the shared model to the middleware's.
func IssuerConfigsFrom(list []issuers.Issuer) []IssuerConfig {
	out := make([]IssuerConfig, 0, len(list))
	for _, i := range list {
		out = append(out, IssuerConfig{
			Issuer: i.Issuer, Audience: i.Audience, Audiences: i.Audiences, JWKSURL: i.JWKSURL, JWKSFile: i.JWKSFile,
			DBRoles: i.DBRoles, ClientDBRoles: i.ClientDBRoles, Stores: i.Stores, PEPClients: i.PEPClients,
			Disabled: i.Disabled, BindingSource: i.BindingSource, EnvStores: i.EnvStores, Admin: i.Admin,
		})
	}
	return out
}

// WithIssuers shares one issuer holder between the handler and the JWT
// middleware (and across listeners), so a reload reaches every reader.
func WithIssuers(s *Issuers) Option {
	return func(h *Handler) { h.issuers = s }
}

// Issuers — GET /pgauthz/v1/issuers: the effective issuer set — anchors
// (keys redacted to their source), bindings, whether each issuer's bindings
// come from the environment or the database, the applied revision. On the
// public listener only for callers holding ISSUERS_REQUIRED_ROLE, and then
// the caller's own issuer only; the callback listener (OPA, the console's
// trusted path) always serves the whole set.
func (h *Handler) Issuers(w http.ResponseWriter, r *http.Request) {
	if h.gateDiagnostics {
		role := ""
		if h.cfg != nil {
			role = h.cfg.IssuersRequiredRole
		}
		if role == "" {
			metrics.AuthzDenied.WithLabelValues("issuers_role").Inc()
			writeForbidden(w, "the issuer set is not served on this listener (set ISSUERS_REQUIRED_ROLE to the role that may read it)")
			return
		}
		held := false
		for _, have := range RolesFromContext(r.Context()) {
			if have == role {
				held = true
				break
			}
		}
		if !held {
			metrics.AuthzDenied.WithLabelValues("issuers_role").Inc()
			writeForbidden(w, "reading the issuer set requires the '"+role+"' role")
			return
		}
	}
	// Multi-tenancy: on the public listener a caller sees its OWN issuer
	// only (the one that signed its token) — a tenant never learns another
	// tenant's identity provider; every issuer only as a platform admin
	// (the admin gate with platform scope). The callback listener is the
	// trusted internal path (OPA, the console) and serves the whole set.
	scope := adminScope{platform: !h.gateDiagnostics, issuer: IssuerFromContext(r.Context())}
	if !scope.platform {
		if s, err := h.adminGate(r); err == nil {
			scope = s
		}
	}
	h.writeIssuers(w, h.visibleIssuers(scope))
}

// writeIssuers renders issuers as the endpoint's JSON (keys redacted).
func (h *Handler) writeIssuers(w http.ResponseWriter, configs []IssuerConfig) {
	set := h.issuers.current()
	out := make([]map[string]any, 0, len(configs))
	for _, ic := range configs {
		e := map[string]any{
			"issuer":         ic.Issuer,
			"audience":       ic.Audience,
			"audiences":      ic.AcceptedAudiences(),
			"enabled":        !ic.Disabled,
			"binding_source": firstNonEmpty(ic.BindingSource, "env"),
			"stores":         orEmpty(ic.Stores),
			"db_roles":       orEmpty(ic.DBRoles),
		}
		switch {
		case ic.JWKSURL != "":
			e["jwks"] = "url"
			e["jwks_url"] = ic.JWKSURL
		case ic.JWKSFile != "":
			e["jwks"] = "file"
			e["jwks_file"] = filepath.Base(ic.JWKSFile)
		}
		if len(ic.ClientDBRoles) > 0 {
			e["client_db_roles"] = ic.ClientDBRoles
		}
		if len(ic.PEPClients) > 0 {
			e["pep_clients"] = ic.PEPClients
		}
		if len(ic.Admin) > 0 {
			e["admin"] = ic.Admin
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["issuer"].(string) < out[j]["issuer"].(string) })
	source := "env"
	if h.cfg != nil && h.cfg.IssuersSource != "" {
		source = h.cfg.IssuersSource
	}
	writeJSON(w, http.StatusOK, map[string]any{"source": source, "revision": set.revision, "issuers": out})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
