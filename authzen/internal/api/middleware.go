package api

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
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
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey int

const (
	ctxSubjectID contextKey = iota
	ctxSubjectType
	ctxRequestID
)

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

// JWTConfig holds JWT verification configuration.
type JWTConfig struct {
	JWKSURL            string
	JWKSFile           string // Alternative: load JWKS from a local file
	Issuer             string
	Audience           string
	RequiredScope      string // If set, token must contain this scope (space-separated "scope" claim or "scp" array)
	SubjectIDClaim     string
	SubjectIDFallback  string
	SubjectTypeClaim   string
	SubjectTypeDefault string
}

// JWTMiddleware verifies JWT tokens and injects claims into context.
type JWTMiddleware struct {
	cfg  JWTConfig
	keys sync.Map // kid -> crypto.PublicKey (either *ecdsa.PublicKey or *rsa.PublicKey)
	mu   sync.Mutex
	last time.Time
}

func NewJWTMiddleware(cfg JWTConfig) *JWTMiddleware {
	return &JWTMiddleware{cfg: cfg}
}

func (m *JWTMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Exempt routes
		if r.URL.Path == "/healthz" || strings.HasPrefix(r.URL.Path, "/.well-known/") {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeUnauthorized(w)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenStr == authHeader {
			writeUnauthorized(w)
			return
		}

		claims, err := m.verifyToken(tokenStr)
		if err != nil {
			slog.Debug("JWT verification failed", "error", err)
			writeUnauthorized(w)
			return
		}

		if m.cfg.RequiredScope != "" && !hasScope(claims, m.cfg.RequiredScope) {
			slog.Debug("required scope not present", "scope", m.cfg.RequiredScope)
			writeForbidden(w, "insufficient scope")
			return
		}

		ctx := r.Context()

		// Extract subject ID
		subjectID := claimString(claims, m.cfg.SubjectIDClaim)
		if subjectID == "" {
			subjectID = claimString(claims, m.cfg.SubjectIDFallback)
		}
		if subjectID != "" {
			ctx = context.WithValue(ctx, ctxSubjectID, subjectID)
		}

		// Extract subject type
		subjectType := claimString(claims, m.cfg.SubjectTypeClaim)
		if subjectType == "" {
			subjectType = m.cfg.SubjectTypeDefault
		}
		ctx = context.WithValue(ctx, ctxSubjectType, subjectType)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *JWTMiddleware) verifyToken(tokenStr string) (jwt.MapClaims, error) {
	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512"}),
	}
	if m.cfg.Issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(m.cfg.Issuer))
	}
	if m.cfg.Audience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(m.cfg.Audience))
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		return m.getKey(kid)
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

func (m *JWTMiddleware) getKey(kid string) (crypto.PublicKey, error) {
	if key, ok := m.keys.Load(kid); ok {
		if time.Since(m.last) < 5*time.Minute {
			return key.(crypto.PublicKey), nil
		}
	}
	return m.refreshAndGet(kid)
}

func (m *JWTMiddleware) refreshAndGet(kid string) (crypto.PublicKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after lock
	if key, ok := m.keys.Load(kid); ok {
		if time.Since(m.last) < 5*time.Minute {
			return key.(crypto.PublicKey), nil
		}
	}

	if err := m.fetchJWKS(); err != nil {
		// If we have a cached key, use it despite refresh failure
		if key, ok := m.keys.Load(kid); ok {
			return key.(crypto.PublicKey), nil
		}
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}

	key, ok := m.keys.Load(kid)
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

func (m *JWTMiddleware) fetchJWKS() error {
	var body []byte
	var err error

	if m.cfg.JWKSFile != "" {
		body, err = os.ReadFile(m.cfg.JWKSFile)
		if err != nil {
			return fmt.Errorf("reading JWKS file: %w", err)
		}
	} else {
		resp, herr := http.Get(m.cfg.JWKSURL)
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
			m.keys.Store(k.KID, pub)
		case "RSA":
			pub, err := parseRSAPublicKey(k)
			if err != nil {
				slog.Warn("skipping invalid RSA JWK", "kid", k.KID, "error", err)
				continue
			}
			m.keys.Store(k.KID, pub)
		default:
			slog.Warn("skipping unsupported key type", "kid", k.KID, "kty", k.KTY)
		}
	}
	m.last = time.Now()
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

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
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
	for _, s := range strings.Split(scopeStr, " ") {
		if s == required {
			return true
		}
	}
	return false
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

// RequestID middleware adds a request ID to context and response headers.
func RequestID(next http.Handler) http.Handler {
	var counter uint64
	var mu sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			mu.Lock()
			counter++
			id = fmt.Sprintf("%d", counter)
			mu.Unlock()
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), ctxRequestID, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Logging middleware logs HTTP requests.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
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
