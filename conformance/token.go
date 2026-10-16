package conformance

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// MintAPIKey mints the bearer credential the suite sends as `pdp.api_key`: an ES256 JWT signed
// with the PEM key at keyFile (PKCS #8 or SEC 1, the demo key in opa/keys/demo.key.txt), with
// the issuer, audience and key id the pgauthzd under test trusts, valid for ttl.
//
// The token names NO subject — no `sub`, no `preferred_username`. It identifies the PEP, and
// the suite names the principal (alice, bob) in every request body. With a subject on the
// token, pgauthzd's JWT-subject fallback would answer a request WITHOUT a body subject for
// the token's subject, where the suite expects a 400 (single evaluation) or a decision-false
// item (batch) — see docs: the conformance credential must stay subject-less.
func MintAPIKey(keyFile, keyID, issuer, audience string, ttl time.Duration) (string, error) {
	key, err := loadECPrivateKey(keyFile)
	if err != nil {
		return "", err
	}
	now := time.Now()
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": keyID})
	claims, _ := json.Marshal(map[string]any{
		"iss": issuer,
		"aud": audience,
		"iat": now.Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
		"exp": now.Add(ttl).Unix(),
		"jti": base64.RawURLEncoding.EncodeToString(jti),
	})
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", fmt.Errorf("could not sign the api_key: %w", err)
	}
	// JWS ES256: R || S, each left-padded to 32 bytes
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func loadECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read the signing key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("the signing key %s is not PEM", path)
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("the signing key %s is not a valid PKCS #8 key: %w", path, err)
		}
		key, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("the signing key %s is not an EC key (%T)", path, parsed)
		}
		return key, nil
	}
	return nil, fmt.Errorf("the signing key %s has an unexpected PEM type %q", path, block.Type)
}
