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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Issuer is one trusted identity provider with its bindings — the JSON shape
// of a JWT_ISSUERS entry.
type Issuer struct {
	Issuer string `json:"issuer"`
	// Alias: a short handle ([a-z0-9][a-z0-9_-]{0,63}, unique across the
	// set) that stands for the issuer URL wherever an issuer is referenced
	// — admin API queries, pgauthzctl, console deep links. From the
	// environment entry or the binding row (the row's wins).
	Alias    string `json:"alias,omitempty"`
	Audience string `json:"audience"`
	// Audiences: further accepted `aud` values — a token must carry the
	// audience OR one of these. Identity providers differ in what they put
	// there (Keycloak a client id, others the API's URI); listing both
	// lets a deployment move between them without a cut-over.
	Audiences []string `json:"audiences,omitempty"`
	// StoreGroup (ADR 0017): a group issuer — its tokens reach the group's
	// stores as they are now (Stores is that list, resolved by the engine).
	StoreGroup string `json:"store_group,omitempty"`
	// AnchorSource says where the trust anchor (keys, audiences) came from:
	// "env" (JWT_ISSUERS) or "db" (a group issuer's row, ADR 0017).
	AnchorSource string `json:"anchor_source,omitempty"`
	JWKSURL      string `json:"jwks_url"`
	JWKSFile     string `json:"jwks_file"`
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
	// API (ADMIN_API_ENABLED) — one rule, or a list tried in order: every
	// listed scope must be present, every listed claim value present, and
	// the client listed when clients are; the first satisfied rule decides
	// the credential's reach (scope, capabilities, stores). Environment
	// only — the database never grants management.
	Admin AdminRules `json:"admin,omitempty"`
}

// The scopes of an admin binding: a tenant admin manages the issuer's own
// binding (default); a platform admin the whole fleet.
const (
	AdminScopeIssuer   = "issuer"
	AdminScopePlatform = "platform"
)

// The capabilities of an admin rule: manage (every verb — the default, and
// what a rule without capabilities grants), test (run fixtures:
// POST /pgauthz/v1/admin/models/test), read (the GET verbs). manage
// implies the other two.
const (
	AdminCapManage = "manage"
	AdminCapTest   = "test"
	AdminCapRead   = "read"
)

// AdminBinding is one management rule of an issuer: who matches (scopes,
// claims, clients) and how far they reach (scope, capabilities, stores).
type AdminBinding struct {
	Scopes  []string            `json:"scopes,omitempty"`
	Claims  map[string][]string `json:"claims,omitempty"`
	Clients []string            `json:"clients,omitempty"`
	// Scope: "issuer" (default — this issuer's own binding) or "platform"
	// (every issuer: the operator's admin identity provider).
	Scope string `json:"scope,omitempty"`
	// Capabilities narrows the verbs: manage (default), test, read. A CI
	// credential that only runs fixtures holds ["test"] and no more.
	Capabilities []string `json:"capabilities,omitempty"`
	// Stores narrows an issuer-scoped rule to some of the issuer's stores
	// (anchored patterns, within the issuer's stores binding); empty = all
	// of them. Not for a platform rule.
	Stores []string `json:"stores,omitempty"`
	// Decide delegates the decision to an authorization store — the
	// management console's — instead of capabilities and stores listed
	// here: the credential becomes a subject of that store, and what it
	// may manage is whatever the store grants it (a person's or a
	// pipeline's platform and store roles, managed in the console). A rule
	// with Decide needs no scopes, claims or clients: the store is the
	// gate, a subject without tuples has nothing.
	Decide *AdminDecision `json:"decide,omitempty"`
}

// AdminDecision names the store that decides a delegated rule and how the
// token becomes one of its subjects: SubjectType (default user) and the
// claim the id is read from (default: the daemon's SUBJECT_ID_CLAIM —
// preferred_username; azp for a client credentials token). The token's
// roles and scopes travel into the check as contextual team memberships
// (team:role_<role>#member, team:scope_<scope>#member), the console's own
// convention, so a store shared with such a team covers everyone who
// carries the role or scope.
type AdminDecision struct {
	Store        string `json:"store"`
	SubjectType  string `json:"subject_type,omitempty"`
	SubjectClaim string `json:"subject_claim,omitempty"`
}

// Empty reports an admin rule that would admit every token of the issuer —
// unless a store decides for it, in which case admitting every token to
// ask the store is the point.
func (a *AdminBinding) Empty() bool {
	return a == nil || (len(a.Scopes) == 0 && len(a.Claims) == 0 && len(a.Clients) == 0 && a.Decide == nil)
}

// Can reports whether the rule grants the capability: an unset list is
// manage, and manage implies every capability.
func (a *AdminBinding) Can(capability string) bool {
	if len(a.Capabilities) == 0 {
		return true
	}
	for _, c := range a.Capabilities {
		if c == AdminCapManage || c == capability {
			return true
		}
	}
	return false
}

// AdminRules is an issuer's management rules. In JSON it is one object
// (the single-rule form every deployment used first) or a list; it always
// marshals as a list.
type AdminRules []AdminBinding

func (r *AdminRules) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "null" {
		*r = nil
		return nil
	}
	if strings.HasPrefix(trimmed, "{") {
		var one AdminBinding
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*r = AdminRules{one}
		return nil
	}
	var list []AdminBinding
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	*r = list
	return nil
}

func (r AdminRules) MarshalJSON() ([]byte, error) {
	return json.Marshal([]AdminBinding(r))
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
	StoreGroup  string    `json:"store_group,omitempty"` // the group the row belonged to when written
}

// ErrOwnership: a binding write or delete named the store group it had
// authorized against (ExpectGroup), and the row is owned otherwise by now
// — a concurrent transfer; the caller reads the row again (HTTP 409).
var ErrOwnership = errors.New("the issuer binding's owner changed")

// ExpectAny is the ExpectGroup value that skips the ownership check.
const ExpectAny = "*"

type Binding struct {
	Issuer        string              `json:"issuer"`
	Alias         string              `json:"alias,omitempty"`
	Stores        []string            `json:"stores"`
	DBRoles       []string            `json:"db_roles"`
	ClientDBRoles map[string]string   `json:"client_db_roles"`
	PEPClients    map[string][]string `json:"pep_clients"`
	Enabled       bool                `json:"enabled"`
	Description   string              `json:"description,omitempty"`
	// Group issuers (ADR 0017): StoreGroup names the group whose stores the
	// issuer reaches (then Stores is the engine's resolution of its members,
	// not patterns); JWKSURL and the audiences are the row's own trust
	// anchor — a provider the environment does not list, admitted for the
	// group only; Admin may carry delegated rules (decide), nothing else.
	StoreGroup string     `json:"store_group,omitempty"`
	JWKSURL    string     `json:"jwks_url,omitempty"`
	Audience   string     `json:"audience,omitempty"`
	Audiences  []string   `json:"audiences,omitempty"`
	Admin      AdminRules `json:"admin,omitempty"`
	// CreatedAt/By: the row's first write; UpdatedAt/By: its last (a replace
	// keeps the former). Read-only: a PUT carries them without effect.
	CreatedAt time.Time `json:"created_at,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	UpdatedBy string    `json:"updated_by,omitempty"`
}

// technicalClaims are token-mechanics claims that never identify a subject;
// a delegated rule naming one (`iat` for `sub`) is refused. azp / client_id
// are not here: they ARE the identity of a client credentials token.
var technicalClaims = map[string]bool{
	"iss": true, "aud": true, "exp": true, "iat": true, "nbf": true, "jti": true, "typ": true, "sid": true,
	"at_hash": true, "c_hash": true, "nonce": true, "acr": true, "amr": true, "auth_time": true,
	"session_state": true, "scope": true, "email_verified": true, "cnf": true,
}

// storeNameRe is a plain store (or type) name, as the engine accepts it.
var storeNameRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`)

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
	for n, rule := range iss.Admin {
		at := "admin"
		if len(iss.Admin) > 1 {
			at = fmt.Sprintf("admin[%d]", n)
		}
		if rule.Empty() {
			return fmt.Errorf("%s names no scopes, claims or clients — it would admit every token of the issuer to the management API", at)
		}
		for _, s := range rule.Scopes {
			if strings.TrimSpace(s) == "" {
				return fmt.Errorf("%s.scopes has an empty scope", at)
			}
		}
		for claim, values := range rule.Claims {
			if strings.TrimSpace(claim) == "" || len(values) == 0 {
				return fmt.Errorf("%s.claims[%q] needs a claim name and at least one value", at, claim)
			}
		}
		for _, c := range rule.Clients {
			if strings.TrimSpace(c) == "" {
				return fmt.Errorf("%s.clients has an empty client id", at)
			}
		}
		switch rule.Scope {
		case "", AdminScopeIssuer, AdminScopePlatform:
		default:
			return fmt.Errorf("%s.scope %q: expected issuer (default) or platform", at, rule.Scope)
		}
		for _, c := range rule.Capabilities {
			switch c {
			case AdminCapManage, AdminCapTest, AdminCapRead:
			default:
				return fmt.Errorf("%s.capabilities %q: expected manage, test or read", at, c)
			}
		}
		if len(rule.Stores) > 0 && rule.Scope == AdminScopePlatform {
			return fmt.Errorf("%s.stores narrows an issuer-scoped rule; a platform rule reaches every store", at)
		}
		if d := rule.Decide; d != nil {
			if !storeNameRe.MatchString(d.Store) {
				return fmt.Errorf("%s.decide.store %q: a store name ([a-zA-Z_][a-zA-Z0-9_]*, at most 63 characters)", at, d.Store)
			}
			if d.SubjectType != "" && !storeNameRe.MatchString(d.SubjectType) {
				return fmt.Errorf("%s.decide.subject_type %q: a type name", at, d.SubjectType)
			}
			for _, c := range strings.Split(d.SubjectClaim, ",") {
				if technicalClaims[strings.TrimSpace(c)] {
					return fmt.Errorf("%s.decide.subject_claim: %q is a token-technical claim, never a subject's identity", at, strings.TrimSpace(c))
				}
			}
			if len(rule.Capabilities) > 0 || len(rule.Stores) > 0 || rule.Scope == AdminScopePlatform {
				return fmt.Errorf("%s: decide (the store decides) takes no capabilities, stores or platform scope", at)
			}
		}
		for _, p := range rule.Stores {
			if _, err := Anchored(p); err != nil {
				return fmt.Errorf("invalid %s.stores pattern %q: %w", at, p, err)
			}
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

// aliasRe is the shape of an issuer alias: lowercase, a letter or digit
// first, then letters, digits, _ and -, at most 64 characters.
var aliasRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ValidAlias normalises an alias (trimmed, lowercased; "" = none) and
// refuses one of the wrong shape or one that looks like a URL.
func ValidAlias(alias string) (string, error) {
	a := strings.ToLower(strings.TrimSpace(alias))
	if a == "" {
		return "", nil
	}
	if !aliasRe.MatchString(a) {
		return "", fmt.Errorf("alias %q: letters, digits, _ and - only (max 64), starting with a letter or digit", alias)
	}
	return a, nil
}

// Resolve turns an issuer reference — the URL, or an alias — into the
// issuer URL within a set; "" when an alias names nothing. A URL is
// returned as given (trusted or not: the caller decides what that means).
func Resolve(set []Issuer, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	if strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "http://") {
		return ref
	}
	a := strings.ToLower(ref)
	for _, i := range set {
		if i.Alias == a {
			return i.Issuer
		}
	}
	return ""
}

// HostAllowed says whether a host matches one of the patterns: an exact
// host, "*.example.com" (any subdomain, at any depth — not the apex) or
// "*" (every host). Case-insensitive; a port is ignored.
func HostAllowed(patterns []string, host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		return false
	}
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		switch {
		case p == "":
		case p == "*":
			return true
		case strings.HasPrefix(p, "*."):
			if strings.HasSuffix(host, p[1:]) && len(host) > len(p)-1 {
				return true
			}
		case p == host:
			return true
		}
	}
	return false
}

// URLHost is the host of a URL ("" when it does not parse).
func URLHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// MergeOptions: what Merge may admit beyond the environment's issuers.
// RestrictGroupIssuerHosts applies GroupIssuerHosts to the issuer and the
// jwks_url of every row-anchored (group) issuer — the operator's list of
// identity-provider hosts tenants may bring (GROUP_ISSUER_HOSTS); with the
// restriction on and no host listed, no group issuer is admitted. A row's
// jwks_url is fetched by the daemon: without the list, whoever may write
// a binding row could point the daemon at any reachable address.
type MergeOptions struct {
	RestrictGroupIssuerHosts bool
	GroupIssuerHosts         []string
}

// DelegatedOnly refuses admin rules a database row may not carry: a row
// grants trust, the console store decides what its credentials manage, so
// every rule must delegate (decide) and none may list capabilities,
// stores or platform scope of its own.
func DelegatedOnly(rules AdminRules) error {
	for i, r := range rules {
		if r.Decide == nil || r.Decide.Store == "" {
			return fmt.Errorf("admin[%d]: a database row's admin rules delegate only (decide.store)", i)
		}
		if len(r.Capabilities) > 0 || len(r.Stores) > 0 || r.Scope == AdminScopePlatform {
			return fmt.Errorf("admin[%d]: a database row's admin rule takes no capabilities, stores or platform scope", i)
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
// that rule or fails validation is reported and ignored (that issuer keeps
// its environment bindings): the database never widens reach, and a
// platform issuer's anchor always comes from the environment.
//
// A row naming an issuer the environment does not trust is admitted only
// as a GROUP issuer (ADR 0017): it names a store group and carries its own
// anchor (jwks_url + audiences), reaches the group's stores as the engine
// resolved them, and may hold delegated admin rules only. Anything else
// about an unknown issuer is reported and ignored.
func Merge(env []Issuer, rows []Binding) (merged []Issuer, problems []string) {
	return MergeWith(env, rows, MergeOptions{})
}

// GroupIssuerHostProblem says why a group issuer's hosts are not admitted
// under the options ("" when they are): the issuer's host and the jwks_url's
// host must both match GroupIssuerHosts.
func GroupIssuerHostProblem(opts MergeOptions, issuer, jwksURL string) string {
	if !opts.RestrictGroupIssuerHosts {
		return ""
	}
	if len(opts.GroupIssuerHosts) == 0 {
		return "GROUP_ISSUER_HOSTS names no host: set it to the identity-provider hosts tenants may bring (e.g. *.idp.example, login.microsoftonline.com)"
	}
	for _, h := range []string{URLHost(issuer), URLHost(jwksURL)} {
		if !HostAllowed(opts.GroupIssuerHosts, h) {
			return fmt.Sprintf("host %q is not in GROUP_ISSUER_HOSTS", h)
		}
	}
	return ""
}

// MergeWith is Merge under options (the daemon's host restriction for
// group issuers); Merge is MergeWith with none.
func MergeWith(env []Issuer, rows []Binding, opts MergeOptions) (merged []Issuer, problems []string) {
	byIssuer := make(map[string]Binding, len(rows))
	for _, r := range rows {
		byIssuer[r.Issuer] = r
	}
	// aliases: the environment's are taken as given (config.Load checked
	// them); a row's alias is applied unless it collides with another issuer
	aliasOf := map[string]string{} // alias → issuer
	for _, e := range env {
		if e.Alias != "" {
			aliasOf[e.Alias] = e.Issuer
		}
	}
	rowAlias := func(iss string, raw string) string {
		a, err := ValidAlias(raw)
		if err != nil {
			problems = append(problems, fmt.Sprintf("issuer %q: %v (alias ignored)", iss, err))
			return ""
		}
		if a == "" {
			return ""
		}
		if other, taken := aliasOf[a]; taken && other != iss {
			problems = append(problems, fmt.Sprintf("issuer %q: alias %q already names %q (alias ignored)", iss, a, other))
			return ""
		}
		aliasOf[a] = iss
		return a
	}
	seen := map[string]bool{}
	for _, e := range env {
		out := e
		out.BindingSource = "env"
		row, ok := byIssuer[e.Issuer]
		out.AnchorSource = "env"
		if ok && e.Issuer != "" {
			seen[e.Issuer] = true
			if a := rowAlias(e.Issuer, row.Alias); a != "" {
				out.Alias = a // the row's alias holds even when its bindings are rejected
			}
			cand := e
			cand.Alias = out.Alias
			cand.EnvStores = e.Stores
			cand.Stores, cand.DBRoles = row.Stores, row.DBRoles
			cand.ClientDBRoles, cand.PEPClients = row.ClientDBRoles, row.PEPClients
			cand.Disabled = !row.Enabled
			cand.BindingSource = "db"
			cand.StoreGroup = row.StoreGroup
			cand.AnchorSource = "env"
			if len(row.Admin) > 0 {
				problems = append(problems, fmt.Sprintf("issuer %q: the row's admin rules are ignored: a platform issuer's admin rules are the environment's", e.Issuer))
			}
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
		row := byIssuer[iss]
		if row.StoreGroup == "" || row.JWKSURL == "" {
			problems = append(problems, fmt.Sprintf("issuer %q: binding ignored: the environment does not trust this issuer (JWT_ISSUERS); a group issuer needs store_group and jwks_url", iss))
			continue
		}
		cand := Issuer{Issuer: iss, Alias: rowAlias(iss, row.Alias), Audience: row.Audience, Audiences: row.Audiences, JWKSURL: row.JWKSURL,
			Stores: row.Stores, DBRoles: row.DBRoles, ClientDBRoles: row.ClientDBRoles, PEPClients: row.PEPClients,
			Disabled: !row.Enabled, BindingSource: "db", AnchorSource: "db", StoreGroup: row.StoreGroup, Admin: row.Admin}
		switch {
		case row.Audience == "" && len(row.Audiences) == 0:
			problems = append(problems, fmt.Sprintf("issuer %q: group issuer ignored: no audience", iss))
		case !strings.HasPrefix(row.JWKSURL, "https://"):
			problems = append(problems, fmt.Sprintf("issuer %q: group issuer ignored: jwks_url must be https", iss))
		case GroupIssuerHostProblem(opts, iss, row.JWKSURL) != "":
			problems = append(problems, fmt.Sprintf("issuer %q: group issuer ignored: %s", iss, GroupIssuerHostProblem(opts, iss, row.JWKSURL)))
		default:
			if err := DelegatedOnly(row.Admin); err != nil {
				problems = append(problems, fmt.Sprintf("issuer %q: group issuer ignored: %v", iss, err))
			} else if err := ValidateBindings(cand); err != nil {
				problems = append(problems, fmt.Sprintf("issuer %q: group issuer ignored: %v", iss, err))
			} else {
				merged = append(merged, cand)
			}
		}
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
