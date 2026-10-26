package api

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"thomasdarimont.de/authz/pgauthzd/internal/authz"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"thomasdarimont.de/authz/pgauthzd/internal/metrics"
	"thomasdarimont.de/authz/pgauthzd/internal/telemetry"
	"thomasdarimont.de/authz/pgauthzd/pkg/issuers"
)

// InternalRoleHeader is the header OPA forwards the caller's per-app DB role in
// when calling the native callback surface (matches the Rego's X-PGAuthz-Role).
const InternalRoleHeader = "X-PGAuthz-Role"

// ServiceAuthMiddleware guards the internal native-callback listener with a
// shared SERVICE credential — NOT the end-user JWT. It verifies
// Authorization: Bearer <token> (constant-time) proving the call came from the
// trusted OPA sidecar, then trusts OPA's asserted per-app DB role
// (X-PGAuthz-Role header) and subject (request body) — the trusted-backend role
// PostgREST plays today. /healthz is exempt so liveness probes need no
// credential. app.Run refuses to start the internal listener without a token,
// so this never runs open.
func ServiceAuthMiddleware(token string) func(http.Handler) http.Handler {
	want := []byte(token)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" || r.URL.Path == "/livez" || r.URL.Path == "/readyz" {
				next.ServeHTTP(w, r)
				return
			}
			got := []byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			if len(want) == 0 || subtle.ConstantTimeCompare(got, want) != 1 {
				writeUnauthorized(w)
				return
			}
			ctx := r.Context()
			if role := r.Header.Get(InternalRoleHeader); role != "" {
				ctx = context.WithValue(ctx, ctxDBRole, role)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type contextKey int

const (
	ctxSubjectID contextKey = iota
	ctxSubjectType
	ctxRequestID
	ctxRoles
	ctxRawToken
	ctxIssuer
	ctxDBRole
	ctxNoCache
	ctxDetail
	ctxOnBehalfOf
	ctxClient
	ctxClaims     // the verified claims (the admin gate reads scopes and claim values)
	ctxClientCert // the verified client certificate (*x509.Certificate) of a token-less admin call
)

// onBehalfOf is the token subject a delegated actor acts for (ACTOR_CLAIM).
type onBehalfOf struct{ Type, ID string }

// OnBehalfOfFromContext returns the token's own subject when the request's
// principal is a delegated actor (ACTOR_CLAIM resolved on the verified token:
// RFC 8693 `act`, Keycloak token-exchange delegation). Empty strings when the
// caller is not acting on someone's behalf. Informational — the engine
// decides for the actor; this is carried into the decision log.
func OnBehalfOfFromContext(ctx context.Context) (subjectType, subjectID string) {
	if v, ok := ctx.Value(ctxOnBehalfOf).(onBehalfOf); ok {
		return v.Type, v.ID
	}
	return "", ""
}

// IssuerFromContext returns the verified token's issuer (`iss` claim, matched
// against a trusted issuer during verification). Empty if unauthenticated.
func IssuerFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxIssuer).(string); ok {
		return v
	}
	return ""
}

// DBRoleFromContext returns the per-app DB role derived from the verified
// token (DB_ROLE_CLAIM, or the azp → role map) for namespace enforcement.
// Empty when no role applies.
func DBRoleFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxDBRole).(string); ok {
		return v
	}
	return ""
}

// NoCacheFromContext reports whether the caller sent `Cache-Control: no-cache`
// — the standard request header for "do not serve me a cached answer". The
// OPA backend maps it to input.no_cache so the decision bypasses OPA's
// http.send cache for this request (the direct backend has no decision cache,
// so the semantics hold there trivially).
func NoCacheFromContext(ctx context.Context) bool {
	v, ok := ctx.Value(ctxNoCache).(bool)
	return ok && v
}

// DetailFromContext reports whether the caller asked for the rich decision
// result (X-PGAuthz-Detail header): state allow|deny|conditional plus missing
// condition-context keys in the AuthZEN response context field.
func DetailFromContext(ctx context.Context) bool {
	v, ok := ctx.Value(ctxDetail).(bool)
	return ok && v
}

// TokenFromContext returns the raw (verified) bearer token string, if present.
// Used by backends that re-forward the token to a downstream PDP (e.g. OPA) so it
// can re-validate rather than trust a forwarded subject.
func TokenFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxRawToken).(string); ok {
		return v
	}
	return ""
}

// ClientFromContext returns the token's client id — `azp`, else `client_id`
// (RFC 9068 / RFC 8693 service tokens) — or "" when the token names none. It
// identifies the calling application: the key of the per-issuer pep_clients
// map (ADR 0014) and the `client` field of every decision-log line.
func ClientFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxClient).(string); ok {
		return v
	}
	return ""
}

// SubjectFromContext extracts JWT-derived subject info from context.
func SubjectFromContext(ctx context.Context) (subjectType, subjectID string) {
	if v, ok := ctx.Value(ctxSubjectType).(string); ok {
		subjectType = v
	}
	if v, ok := ctx.Value(ctxSubjectID).(string); ok {
		subjectID = v
	}
	return
}

// RolesFromContext returns the JWT-derived roles aggregated across the configured
// roles claim(s). Empty if no roles claim is configured or the token carries none.
func RolesFromContext(ctx context.Context) []string {
	if v, ok := ctx.Value(ctxRoles).([]string); ok {
		return v
	}
	return nil
}

// AcceptedAudiences: the audience and the further audiences, in order.
func (c IssuerConfig) AcceptedAudiences() []string {
	var out []string
	if c.Audience != "" {
		out = append(out, c.Audience)
	}
	return append(out, c.Audiences...)
}

// IssuerConfig describes one trusted token issuer and where to find its signing
// keys. A deployment can trust several issuers at once (e.g. a demo IdP for tests
// and Keycloak for the playground); the token's "iss" claim selects the validator.
type IssuerConfig struct {
	Issuer    string
	Audience  string   // optional; if set, the token's "aud" must contain it (or one of Audiences)
	Audiences []string // further accepted audiences (any of)
	JWKSURL   string
	JWKSFile  string // alternative to JWKSURL: load JWKS from a local file
	// DBRoles: anchored regex patterns of the per-app DB roles this issuer's
	// tokens may yield (empty = unrestricted). Validated upstream in
	// config.Load; a violating token is rejected with 403.
	DBRoles []string
	// ClientDBRoles: issuer-scoped client-id (azp) → DB role map. Preferred
	// over the global JWTConfig.ClientDBRoles in multi-issuer setups (azp is
	// only unique within an issuer).
	ClientDBRoles map[string]string
	// Stores / PEPClients: the issuer's store binding and subject-assertion
	// clients (ADR 0014), applied by the handler; kept here so the whole
	// issuer set is one swappable value (api.Issuers).
	Stores     []string
	PEPClients map[string][]string
	// Disabled refuses every token of the issuer (a database binding's
	// enabled=false); BindingSource says where the bindings came from;
	// EnvStores is the environment's stores binding when a row replaced it.
	Disabled      bool
	BindingSource string
	EnvStores     []string
	// Admin: who of this issuer may call the management API.
	Admin issuers.AdminRules
}

// JWTConfig holds JWT verification configuration.
type JWTConfig struct {
	// Issuers is the set of trusted issuers. If empty, the single JWKSURL/JWKSFile/
	// Issuer/Audience fields below are used as one issuer (backward compatible).
	Issuers []IssuerConfig
	// Set, when given, is the shared issuer holder the daemon reloads
	// (ISSUERS_SOURCE=env+db); the middleware then reads it instead of
	// building its own from Issuers.
	Set *Issuers
	// AllowClientCert lets a request without a token through when the
	// listener verified a client certificate (the admin listener's mTLS);
	// the admin gate then matches the certificate (ADMIN_CLIENT_CERTS).
	AllowClientCert bool

	JWKSURL            string
	JWKSFile           string // Alternative: load JWKS from a local file
	Issuer             string
	Audience           string
	RequiredScope      string // If set, token must contain this scope (space-separated "scope" claim or "scp" array)
	SubjectIDClaim     string
	SubjectIDFallback  string
	SubjectTypeClaim   string
	SubjectTypeDefault string
	// ActorClaim: dot-separated path of a claim naming a DELEGATED ACTOR (RFC
	// 8693 `act.client_id`). When it resolves, the principal becomes
	// (ActorSubjectType, value) and the token's own subject is kept as
	// on_behalf_of. Empty = off. See config.Config.ActorClaim.
	ActorClaim       string
	ActorSubjectType string
	// RolesClaims is a comma-separated list of dot-separated claim paths whose
	// (string-array) values are aggregated into the caller's role set — mirrors
	// OPA's JWT_ROLES_CLAIM. E.g. "realm_access.roles,resource_access.authz-api.roles".
	RolesClaims string
	// DBRoleClaim: dot-separated claim path carrying the caller's per-app DB
	// role for pgauthz namespace enforcement (mirrors the write path's
	// DB_ROLE_CLAIM). E.g. "db_role".
	DBRoleClaim string
	// ClientDBRoles maps a client id (the verified token's `azp` claim) to a
	// per-app DB role — the fallback when DBRoleClaim is unset or absent from
	// the token, for IdPs where per-client claims can't be configured.
	ClientDBRoles map[string]string
}

// issuerValidator holds the per-issuer JWKS cache used to verify that issuer's
// tokens. Each trusted issuer gets its own key set and refresh state.
type issuerValidator struct {
	cfg  IssuerConfig
	keys sync.Map // kid -> crypto.PublicKey (either *ecdsa.PublicKey or *rsa.PublicKey)
	mu   sync.Mutex
	last time.Time
}

// JWTMiddleware verifies JWT tokens and injects claims into context. The
// trusted issuers — validators, role maps — are one swappable set
// (api.Issuers), shared with the handler.
type JWTMiddleware struct {
	cfg JWTConfig
	set *Issuers
}

func NewJWTMiddleware(cfg JWTConfig) *JWTMiddleware {
	m := &JWTMiddleware{cfg: cfg, set: cfg.Set}
	if m.set == nil {
		configs := cfg.Issuers
		if len(configs) == 0 { // legacy single-issuer form
			configs = []IssuerConfig{{
				Issuer: cfg.Issuer, Audience: cfg.Audience,
				JWKSURL: cfg.JWKSURL, JWKSFile: cfg.JWKSFile,
			}}
		}
		m.set = NewIssuers(configs)
	}
	return m
}

// Issuers is the middleware's issuer holder (shared with the handlers).
func (m *JWTMiddleware) Issuers() *Issuers { return m.set }

func (m *JWTMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Exempt routes (incl. the store-scoped discovery variant). The OpenAPI
		// document is public by design — it ships in the repository; serving it
		// unauthenticated lets tooling discover the contract.
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// A client certificate the listener verified (mTLS with
			// RequireAndVerifyClientCert — the admin listener) is a
			// credential of its own: the request goes on without a token,
			// and the admin gate decides from the certificate's identity.
			// Routes that need a token subject still refuse (no subject).
			if m.cfg.AllowClientCert && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxClientCert, r.TLS.PeerCertificates[0])))
				return
			}
			metrics.JWTFailures.WithLabelValues("missing").Inc()
			writeUnauthorized(w)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenStr == authHeader {
			metrics.JWTFailures.WithLabelValues("malformed").Inc()
			writeUnauthorized(w)
			return
		}

		claims, err := m.verifyToken(tokenStr)
		if err != nil {
			slog.Debug("JWT verification failed", "error", err)
			metrics.JWTFailures.WithLabelValues("invalid_token").Inc()
			writeUnauthorized(w)
			return
		}

		if m.cfg.RequiredScope != "" && !hasScope(claims, m.cfg.RequiredScope) {
			slog.Debug("required scope not present", "scope", m.cfg.RequiredScope)
			writeForbidden(w, "insufficient scope")
			return
		}

		ctx := r.Context()

		// Principal: the token subject — or, for a delegated token, the actor
		// named by ACTOR_CLAIM, with the token subject kept as on_behalf_of.
		subjectType, subjectID, oboType, oboID := m.deriveSubject(claims)
		if subjectID != "" {
			ctx = context.WithValue(ctx, ctxSubjectID, subjectID)
		}
		ctx = context.WithValue(ctx, ctxSubjectType, subjectType)
		if oboID != "" {
			ctx = context.WithValue(ctx, ctxOnBehalfOf, onBehalfOf{Type: oboType, ID: oboID})
		}

		// Aggregate roles across the configured claim paths (for role-gated endpoints).
		if m.cfg.RolesClaims != "" {
			ctx = context.WithValue(ctx, ctxRoles, extractRoles(claims, m.cfg.RolesClaims))
		}

		// Stash the verified token so a backend can re-forward it to the PDP,
		// and its (verified) issuer for per-issuer authorization (store binding).
		ctx = context.WithValue(ctx, ctxRawToken, tokenStr)
		ctx = context.WithValue(ctx, ctxClaims, claims)
		ctx = context.WithValue(ctx, ctxIssuer, claimString(claims, "iss"))
		if client := claimString(claims, "azp"); client != "" {
			ctx = context.WithValue(ctx, ctxClient, client)
		} else if client := claimString(claims, "client_id"); client != "" {
			ctx = context.WithValue(ctx, ctxClient, client)
		}

		// Standard freshness request: Cache-Control: no-cache asks the PDP not
		// to serve a cached decision (forwarded as input.no_cache to OPA).
		if strings.Contains(strings.ToLower(r.Header.Get("Cache-Control")), "no-cache") {
			ctx = context.WithValue(ctx, ctxNoCache, true)
		}

		// Opt-in rich decision result (state/missing_context in the response
		// context field). Header-based like X-PGAuthz-Store / Cache-Control.
		if v := r.Header.Get("X-PGAuthz-Detail"); v != "" && !strings.EqualFold(v, "false") {
			ctx = context.WithValue(ctx, ctxDetail, true)
		}

		iss := claimString(claims, "iss")
		dbRole := m.deriveDBRole(claims)
		if dbRole != "" {
			// Per-issuer db-role binding: a trusted issuer may only yield the
			// roles it is entitled to — otherwise any tenant's IdP could claim
			// another tenant's role. Violations are REJECTED (never silently
			// downgraded to the fixed connection role, which could widen access).
			if !m.dbRoleAllowed(iss, dbRole) {
				slog.Debug("issuer not allowed to yield db role", "role", dbRole)
				metrics.AuthzDenied.WithLabelValues("db_role_binding").Inc()
				writeForbidden(w, "issuer is not allowed to yield db role '"+dbRole+"'")
				return
			}
			ctx = context.WithValue(ctx, ctxDBRole, dbRole)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// deriveSubject resolves the request principal from verified claims.
//
// Plain token: (SubjectTypeClaim|SubjectTypeDefault, SubjectIDClaim|SubjectIDFallback).
//
// Delegated token (ActorClaim configured AND resolving to a non-empty string,
// e.g. `act.client_id` on a Keycloak token-exchange delegation token): the
// principal is (ActorSubjectType, <actor>) and the token's own subject is
// returned as on-behalf-of. The actor is then checked with ITS OWN authority
// in the graph (an agent's reach, task scope, gates) — a delegated token
// never lets the actor inherit the user's permissions. The binding "may this
// actor act for this user" was decided by the issuer (consent, may_act); the
// graph decides what the actor may do while it does.
func (m *JWTMiddleware) deriveSubject(claims jwt.MapClaims) (subjectType, subjectID, oboType, oboID string) {
	subjectID = claimString(claims, m.cfg.SubjectIDClaim)
	if subjectID == "" {
		subjectID = claimString(claims, m.cfg.SubjectIDFallback)
	}
	subjectType = claimString(claims, m.cfg.SubjectTypeClaim)
	if subjectType == "" {
		subjectType = m.cfg.SubjectTypeDefault
	}
	if m.cfg.ActorClaim == "" {
		return subjectType, subjectID, "", ""
	}
	actor := claimStringPath(claims, m.cfg.ActorClaim)
	if actor == "" {
		return subjectType, subjectID, "", ""
	}
	return m.cfg.ActorSubjectType, actor, subjectType, subjectID
}

func (m *JWTMiddleware) verifyToken(tokenStr string) (jwt.MapClaims, error) {
	v, err := m.pickValidator(tokenStr)
	if err != nil {
		return nil, err
	}

	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512"}),
	}
	if v.cfg.Issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(v.cfg.Issuer))
	}
	if auds := v.cfg.AcceptedAudiences(); len(auds) > 0 {
		parserOpts = append(parserOpts, jwt.WithAudience(auds...)) // any of
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		return v.getKey(kid)
	}, parserOpts...)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

// pickValidator selects the validator for a token by its unverified "iss" claim.
// Reading the issuer before verification is safe: the chosen validator still
// verifies the signature (against that issuer's JWKS), issuer, and audience, so a
// forged "iss" only routes to a validator whose keys won't match the signature.
func (m *JWTMiddleware) pickValidator(tokenStr string) (*issuerValidator, error) {
	var claims jwt.MapClaims
	if _, _, err := jwt.NewParser().ParseUnverified(tokenStr, &claims); err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}
	iss := claimString(claims, "iss")
	set := m.set.current()
	if set.disabled[iss] {
		return nil, fmt.Errorf("issuer %q is disabled (issuer binding enabled=false)", iss)
	}
	if v, ok := set.byIssuer[iss]; ok {
		return v, nil
	}
	// A single validator with no pinned issuer accepts any issuer (legacy mode).
	if len(set.validators) == 1 && set.validators[0].cfg.Issuer == "" {
		return set.validators[0], nil
	}
	return nil, fmt.Errorf("untrusted issuer %q", iss)
}

func (v *issuerValidator) getKey(kid string) (crypto.PublicKey, error) {
	if key, ok := v.keys.Load(kid); ok {
		if time.Since(v.last) < 5*time.Minute {
			return key.(crypto.PublicKey), nil
		}
	}
	return v.refreshAndGet(kid)
}

func (v *issuerValidator) refreshAndGet(kid string) (crypto.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Double-check after lock
	if key, ok := v.keys.Load(kid); ok {
		if time.Since(v.last) < 5*time.Minute {
			return key.(crypto.PublicKey), nil
		}
	}

	if err := v.fetchJWKS(); err != nil {
		// If we have a cached key, use it despite refresh failure
		if key, ok := v.keys.Load(kid); ok {
			return key.(crypto.PublicKey), nil
		}
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}

	key, ok := v.keys.Load(kid)
	if !ok {
		return nil, fmt.Errorf("key %q not found in JWKS", kid)
	}
	return key.(crypto.PublicKey), nil
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	KID string `json:"kid"`
	KTY string `json:"kty"`
	Crv string `json:"crv"`
	// EC fields
	X string `json:"x"`
	Y string `json:"y"`
	// RSA fields
	N string `json:"n"`
	E string `json:"e"`
}

func (v *issuerValidator) fetchJWKS() error {
	var body []byte
	var err error

	if v.cfg.JWKSFile != "" {
		body, err = os.ReadFile(v.cfg.JWKSFile)
		if err != nil {
			return fmt.Errorf("reading JWKS file: %w", err)
		}
	} else {
		resp, herr := http.Get(v.cfg.JWKSURL)
		if herr != nil {
			return herr
		}
		defer resp.Body.Close()
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
	}

	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return err
	}

	for _, k := range jwks.Keys {
		switch k.KTY {
		case "EC":
			pub, err := parseECPublicKey(k)
			if err != nil {
				slog.Warn("skipping invalid EC JWK", "kid", k.KID, "error", err)
				continue
			}
			v.keys.Store(k.KID, pub)
		case "RSA":
			pub, err := parseRSAPublicKey(k)
			if err != nil {
				slog.Warn("skipping invalid RSA JWK", "kid", k.KID, "error", err)
				continue
			}
			v.keys.Store(k.KID, pub)
		default:
			slog.Warn("skipping unsupported key type", "kid", k.KID, "kty", k.KTY)
		}
	}
	v.last = time.Now()
	return nil
}

func parseECPublicKey(k jwkKey) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", k.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decoding x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("decoding y: %w", err)
	}

	// SEC 1 uncompressed point 0x04 || X || Y, each coordinate the curve's
	// width (RFC 7518 §6.2.1.2 mandates fixed-length coordinates; a shorter
	// one is left-padded, a longer one is not a point on this curve).
	// ParseUncompressedPublicKey also rejects a point off the curve, which
	// the former struct literal never checked.
	size := (curve.Params().BitSize + 7) / 8
	if len(xBytes) > size || len(yBytes) > size {
		return nil, fmt.Errorf("coordinate longer than the %s field", k.Crv)
	}
	point := make([]byte, 1+2*size)
	point[0] = 0x04
	copy(point[1+size-len(xBytes):], xBytes)
	copy(point[1+2*size-len(yBytes):], yBytes)
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, fmt.Errorf("invalid EC point: %w", err)
	}
	return pub, nil
}

func parseRSAPublicKey(k jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decoding n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decoding e: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// hasScope checks whether the JWT "scope" claim (space-separated string,
// RFC 6749) contains the required scope value.
func hasScope(claims jwt.MapClaims, required string) bool {
	scopeStr := claimString(claims, "scope")
	for s := range strings.SplitSeq(scopeStr, " ") {
		if s == required {
			return true
		}
	}
	return false
}

// deriveDBRole resolves the per-app DB role for namespace enforcement from the
// verified claims. Derivation order:
//  1. the configured claim (DB_ROLE_CLAIM)
//  2. the ISSUER-scoped client map (azp is only unique within an issuer)
//  3. the global CLIENT_DB_ROLES map (single-issuer convenience)
func (m *JWTMiddleware) deriveDBRole(claims jwt.MapClaims) string {
	if m.cfg.DBRoleClaim != "" {
		if r := claimStringPath(claims, m.cfg.DBRoleClaim); r != "" {
			return r
		}
	}
	if cm := m.set.current().clientRole[claimString(claims, "iss")]; cm != nil {
		if r := cm[claimString(claims, "azp")]; r != "" {
			return r
		}
	}
	if len(m.cfg.ClientDBRoles) > 0 {
		return m.cfg.ClientDBRoles[claimString(claims, "azp")]
	}
	return ""
}

// dbRoleAllowed reports whether the issuer may yield the given per-app DB role.
// Issuers without a configured db_roles list are unrestricted.
func (m *JWTMiddleware) dbRoleAllowed(issuer, role string) bool {
	pats, restricted := m.set.current().dbRoles[issuer]
	if !restricted {
		return true
	}
	for _, p := range pats {
		if p.MatchString(role) {
			return true
		}
	}
	return false
}

// extractRoles aggregates string-array role claims across a comma-separated list
// of dot-separated claim paths (e.g. "realm_access.roles,resource_access.x.roles"),
// deduplicated. Missing/ill-typed paths are skipped. Mirrors OPA's JWT_ROLES_CLAIM.
func extractRoles(claims jwt.MapClaims, paths string) []string {
	seen := map[string]bool{}
	var out []string
	for p := range strings.SplitSeq(paths, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		var node any = map[string]any(claims)
		for seg := range strings.SplitSeq(p, ".") {
			m, ok := node.(map[string]any)
			if !ok {
				node = nil
				break
			}
			node = m[seg]
		}
		arr, ok := node.([]any)
		if !ok {
			continue
		}
		for _, v := range arr {
			if s, ok := v.(string); ok && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// claimStringPath resolves a dot-separated claim path to a string value
// (e.g. "resource_access.app.db_role"). Missing/ill-typed segments yield "".
func claimStringPath(claims jwt.MapClaims, path string) string {
	var node any = map[string]any(claims)
	for seg := range strings.SplitSeq(path, ".") {
		m, ok := node.(map[string]any)
		if !ok {
			return ""
		}
		node = m[seg]
	}
	s, _ := node.(string)
	return s
}

func claimString(claims jwt.MapClaims, key string) string {
	v, ok := claims[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// RequestID middleware adds a request ID to context and response headers:
// the caller's X-Request-ID, else the propagated trace id (OpenTelemetry:
// traceparent / B3, extracted by the server span), else a counter.
func RequestID(next http.Handler) http.Handler {
	var counter uint64
	var mu sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id, _ = telemetry.IDs(r.Context())
		}
		if id == "" {
			mu.Lock()
			counter++
			id = fmt.Sprintf("%d", counter)
			mu.Unlock()
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), ctxRequestID, id)
		ctx = authz.WithStoreIDSink(ctx) // the decision log's store incarnation (filled by the pgx backend)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Logging middleware logs HTTP requests. A SUCCESSFUL health probe
// (/livez, /readyz, /healthz) is logged at DEBUG: orchestrators poll them
// every few seconds, and at INFO they would be most of the log over time. A
// failing probe (any non-2xx) stays at INFO — that is the line an operator
// looks for.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		level := slog.LevelInfo
		if isHealthPath(r.URL.Path) && sw.status < 300 {
			level = slog.LevelDebug
		}
		slog.Log(r.Context(), level, "request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// isHealthPath: the liveness/readiness probes (and the deprecated alias).
func isHealthPath(path string) bool {
	return path == "/healthz" || path == "/livez" || path == "/readyz"
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Recovery middleware catches panics and returns 500.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				slog.Error("panic recovered", "error", err)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ClaimsFromContext returns the verified token's claims (nil without one).
func ClaimsFromContext(ctx context.Context) jwt.MapClaims {
	if c, ok := ctx.Value(ctxClaims).(jwt.MapClaims); ok {
		return c
	}
	return nil
}

// claimValues collects a claim's string values (a string, or an array of
// strings; a dot-separated path) as a set.
func claimValues(claims jwt.MapClaims, path string) map[string]bool {
	out := map[string]bool{}
	var v any = map[string]any(claims)
	for part := range strings.SplitSeq(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return out
		}
		v = m[part]
	}
	switch t := v.(type) {
	case string:
		out[t] = true
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				out[s] = true
			}
		}
	case []string:
		for _, s := range t {
			out[s] = true
		}
	}
	return out
}

// ClientCertFromContext returns the client certificate the listener
// verified for a token-less request (the admin listener under mTLS), or nil.
func ClientCertFromContext(ctx context.Context) *x509.Certificate {
	if c, ok := ctx.Value(ctxClientCert).(*x509.Certificate); ok {
		return c
	}
	return nil
}
