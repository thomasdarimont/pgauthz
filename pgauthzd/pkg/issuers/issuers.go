// Package issuers is the shared model of pgauthzd's trusted issuers: the
// anchors an operator configures in the environment (issuer, audience,
// signing keys), the bindings that say what an issuer's tokens may do here
// (stores, DB roles, PEP clients — ADR 0014), the validation both pgauthzd
// and the console apply, and the merge of database-managed bindings over
// the environment's entries (scratch/notes/issuer-management.md, option C:
// the database can narrow what the environment grants, never add trust).
//
// It is a public package of the pgauthzd module so the console and
// pgauthzctl validate exactly as the daemon does.
package issuers

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Issuer is one trusted identity provider with its bindings — the JSON shape
// of a JWT_ISSUERS entry.
type Issuer struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	JWKSURL  string `json:"jwks_url"`
	JWKSFile string `json:"jwks_file"`
	// Stores restricts which pgauthz stores this issuer's tokens may access
	// (store binding for multi-tenant setups: tenant A's IdP → tenant A's
	// stores). Each entry is an ANCHORED regular expression (^(?:entry)$), so
	// plain store names match exactly and patterns like "tenant_a_.*" cover
	// store families. Empty = no restriction (all stores).
	Stores []string `json:"stores"`
	// DBRoles restricts which per-app DB roles tokens from this issuer may
	// yield (via DB_ROLE_CLAIM or CLIENT_DB_ROLES) — without it, any trusted
	// issuer could claim another tenant's role. Anchored regexes like Stores.
	// Empty = no restriction. A violation is rejected (403), never silently
	// downgraded to the fixed connection role.
	DBRoles []string `json:"db_roles"`
	// ClientDBRoles maps client ids (`azp`) to per-app DB roles, scoped to
	// THIS issuer — azp values are only meaningful within an issuer, so the
	// per-issuer map avoids cross-tenant azp collisions that the global
	// CLIENT_DB_ROLES map (kept for single-issuer setups) cannot.
	ClientDBRoles map[string]string `json:"client_db_roles"`
	// PEPClients (ADR 0014) names the clients of this issuer — token `azp`,
	// else `client_id` — that may ASSERT a request-body subject (and a
	// differing performed_by / recorded_by), and in which stores: client id →
	// anchored store patterns, the Stores syntax. A pattern may not reach
	// beyond the issuer's Stores binding. Everything not listed is
	// self-subject: the token's subject is authoritative.
	PEPClients map[string][]string `json:"pep_clients"`
	// Disabled refuses every token of the issuer while its trust stays
	// configured — a database binding's `enabled = false` (incident
	// response: pause an identity provider without a deploy).
	Disabled bool `json:"disabled,omitempty"`
	// BindingSource says where the bindings came from: "env" or "db".
	BindingSource string `json:"binding_source,omitempty"`
	// EnvStores keeps the environment's stores binding when a database row
	// replaced it, so a later row can still be checked against it.
	EnvStores []string `json:"-"`
	// Admin names the tokens of this issuer that may call the management
	// API (ADMIN_API_ENABLED): every listed scope must be present, every
	// listed claim value present, and the client listed when clients are.
	// Environment only — the database never grants management.
	Admin *AdminBinding `json:"admin,omitempty"`
}

// The scopes of an admin binding: a tenant admin manages the issuer's own
// binding (default); a platform admin the whole fleet.
const (
	AdminScopeIssuer   = "issuer"
	AdminScopePlatform = "platform"
)

// AdminBinding is an issuer's management grant.
type AdminBinding struct {
	Scopes  []string            `json:"scopes,omitempty"`
	Claims  map[string][]string `json:"claims,omitempty"`
	Clients []string            `json:"clients,omitempty"`
	// Scope: "issuer" (default — this issuer's own binding) or "platform"
	// (every issuer: the operator's admin identity provider).
	Scope string `json:"scope,omitempty"`
}

// Empty reports an admin binding that would admit every token of the issuer.
func (a *AdminBinding) Empty() bool {
	return a == nil || (len(a.Scopes) == 0 && len(a.Claims) == 0 && len(a.Clients) == 0)
}

// Binding is a database row of authz.issuer_bindings: what an issuer's
// tokens may do, managed from the console.
// AuditRow is one entry of authz.issuer_bindings_audit: a write to a
// binding, as list_issuer_bindings_audit returns it (newest first).
type AuditRow struct {
	Seq         int64     `json:"seq"`
	Action      string    `json:"action"`
	PerformedAt time.Time `json:"performed_at"`
	PerformedBy string    `json:"performed_by"`
	Issuer      string    `json:"issuer"`
	Stores      []string  `json:"stores"`
	Enabled     *bool     `json:"enabled"`
	Description string    `json:"description,omitempty"`
}

type Binding struct {
	Issuer        string              `json:"issuer"`
	Stores        []string            `json:"stores"`
	DBRoles       []string            `json:"db_roles"`
	ClientDBRoles map[string]string   `json:"client_db_roles"`
	PEPClients    map[string][]string `json:"pep_clients"`
	Enabled       bool                `json:"enabled"`
	Description   string              `json:"description,omitempty"`
	// CreatedAt/By: the row's first write; UpdatedAt/By: its last (a replace
	// keeps the former). Read-only: a PUT carries them without effect.
	CreatedAt time.Time `json:"created_at,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	UpdatedBy string    `json:"updated_by,omitempty"`
}

// regexMeta are the characters that make a store pattern a pattern rather
// than a plain name.
const regexMeta = `\^$.|?*+()[]{}`

// Anchored compiles a store/role pattern the way the daemon applies it:
// anchored, so a plain name matches exactly.
func Anchored(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile("^(?:" + pattern + ")$")
}

// Covered reports whether pattern is within the binding patterns: equal to
// one, or a plain name one of them matches. A pattern can never be proven
// narrower than another pattern, so patterns must be listed verbatim.
func Covered(pattern string, within []string) bool {
	for _, w := range within {
		if w == pattern {
			return true
		}
		if !strings.ContainsAny(pattern, regexMeta) {
			if re, err := Anchored(w); err == nil && re.MatchString(pattern) {
				return true
			}
		}
	}
	return false
}

// ValidateBindings checks an issuer's bindings: anchored patterns compile,
// client maps are well formed, and every PEP client's store patterns are
// covered by the stores binding when one exists (assertion cannot widen
// where tokens may ask — ADR 0014). The anchors (audience, keys) are the
// environment's business and checked by the daemon's configuration.
func ValidateBindings(iss Issuer) error {
	for _, p := range iss.Stores {
		if _, err := Anchored(p); err != nil {
			return fmt.Errorf("invalid store pattern %q: %w", p, err)
		}
	}
	for _, p := range iss.DBRoles {
		if _, err := Anchored(p); err != nil {
			return fmt.Errorf("invalid db_roles pattern %q: %w", p, err)
		}
	}
	for client, role := range iss.ClientDBRoles {
		if strings.TrimSpace(client) == "" || strings.TrimSpace(role) == "" {
			return fmt.Errorf("client_db_roles: a non-empty client id and role are required (got %q: %q)", client, role)
		}
	}
	if iss.Admin != nil {
		if iss.Admin.Empty() {
			return fmt.Errorf("admin binding names no scopes, claims or clients — it would admit every token of the issuer to the management API")
		}
		for _, s := range iss.Admin.Scopes {
			if strings.TrimSpace(s) == "" {
				return fmt.Errorf("admin.scopes has an empty scope")
			}
		}
		for claim, values := range iss.Admin.Claims {
			if strings.TrimSpace(claim) == "" || len(values) == 0 {
				return fmt.Errorf("admin.claims[%q] needs a claim name and at least one value", claim)
			}
		}
		for _, c := range iss.Admin.Clients {
			if strings.TrimSpace(c) == "" {
				return fmt.Errorf("admin.clients has an empty client id")
			}
		}
		switch iss.Admin.Scope {
		case "", AdminScopeIssuer, AdminScopePlatform:
		default:
			return fmt.Errorf("admin.scope %q: expected issuer (default) or platform", iss.Admin.Scope)
		}
	}
	for client, patterns := range iss.PEPClients {
		if strings.TrimSpace(client) == "" {
			return fmt.Errorf("pep_clients has an empty client id")
		}
		if len(patterns) == 0 {
			return fmt.Errorf("pep_clients[%q] lists no stores (use [\".*\"] for every store of the binding)", client)
		}
		for _, p := range patterns {
			if _, err := Anchored(p); err != nil {
				return fmt.Errorf("pep_clients[%q]: invalid store pattern %q: %w", client, p, err)
			}
			if len(iss.Stores) > 0 && !Covered(p, iss.Stores) {
				return fmt.Errorf("pep_clients[%q]: store pattern %q is not covered by the issuer's stores binding %v — assertion cannot widen where tokens may ask", client, p, iss.Stores)
			}
		}
	}
	return nil
}

// Merge applies database bindings over the environment's issuers. For each
// environment issuer with a row of the same `iss`, the row's bindings
// REPLACE the environment's (the row is the whole binding, as the console
// edits it) — except that a row may only narrow the environment's stores:
// when the environment binds stores, the row must bind stores too and each
// of its patterns must be covered by the environment's. A row that breaks
// that rule, fails validation, or names an issuer the environment does not
// trust is reported and ignored (that issuer keeps its environment
// bindings): the database can never add trust or widen reach. Anchors
// always come from the environment.
func Merge(env []Issuer, rows []Binding) (merged []Issuer, problems []string) {
	byIssuer := make(map[string]Binding, len(rows))
	for _, r := range rows {
		byIssuer[r.Issuer] = r
	}
	seen := map[string]bool{}
	for _, e := range env {
		out := e
		out.BindingSource = "env"
		row, ok := byIssuer[e.Issuer]
		if ok && e.Issuer != "" {
			seen[e.Issuer] = true
			cand := e
			cand.EnvStores = e.Stores
			cand.Stores, cand.DBRoles = row.Stores, row.DBRoles
			cand.ClientDBRoles, cand.PEPClients = row.ClientDBRoles, row.PEPClients
			cand.Disabled = !row.Enabled
			cand.BindingSource = "db"
			if err := narrowing(e.Stores, row.Stores); err != nil {
				problems = append(problems, fmt.Sprintf("issuer %q: binding ignored: %v", e.Issuer, err))
			} else if err := ValidateBindings(cand); err != nil {
				problems = append(problems, fmt.Sprintf("issuer %q: binding ignored: %v", e.Issuer, err))
			} else {
				out = cand
			}
		}
		merged = append(merged, out)
	}
	var unknown []string
	for iss := range byIssuer {
		if !seen[iss] {
			unknown = append(unknown, iss)
		}
	}
	sort.Strings(unknown)
	for _, iss := range unknown {
		problems = append(problems, fmt.Sprintf("issuer %q: binding ignored: the environment does not trust this issuer (JWT_ISSUERS)", iss))
	}
	return merged, problems
}

// narrowing is the stores rule of Merge.
func narrowing(envStores, rowStores []string) error {
	if len(envStores) == 0 {
		return nil // the environment leaves the issuer unbound: the row may bind it
	}
	if len(rowStores) == 0 {
		return fmt.Errorf("stores must stay bound: the environment binds %v and a row may only narrow, not unbind", envStores)
	}
	for _, p := range rowStores {
		if !Covered(p, envStores) {
			return fmt.Errorf("store pattern %q is not covered by the environment's stores binding %v — a row may only narrow", p, envStores)
		}
	}
	return nil
}
