package conformance

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

// The api_key is an ES256 JWT the demo stack's pgauthzd verifies — and it must not name a
// subject, or pgauthzd's JWT-subject fallback would answer the suite's subject-less requests
// for the PEP instead of rejecting them.
func TestMintAPIKey(t *testing.T) {
	token, err := MintAPIKey(DefaultSigningKey, DefaultKeyID, DefaultIssuer, DefaultAudience, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %s", token)
	}
	var header map[string]string
	decode(t, parts[0], &header)
	if header["alg"] != "ES256" || header["kid"] != DefaultKeyID {
		t.Fatalf("header: %v", header)
	}
	var claims map[string]any
	decode(t, parts[1], &claims)
	if claims["iss"] != DefaultIssuer || claims["aud"] != DefaultAudience {
		t.Fatalf("claims: %v", claims)
	}
	for _, forbidden := range []string{"sub", "preferred_username", "subject_type"} {
		if _, has := claims[forbidden]; has {
			t.Fatalf("the api_key must not carry %q (JWT-subject fallback): %v", forbidden, claims)
		}
	}
	key, err := loadECPrivateKey(DefaultSigningKey)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		t.Fatalf("signature is not R||S of 64 bytes: %v %d", err, len(signature))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		t.Fatal("signature does not verify with the demo key")
	}
}

func decode(t *testing.T, segment string, into any) {
	t.Helper()
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatal(err)
	}
}

// The plan configuration points every endpoint at the PDP identifier and carries the key.
func TestPlanConfig(t *testing.T) {
	config, err := Evaluation.Config(PDP{BaseURL: "https://host.testcontainers.internal:9445/stores/authzen_cert", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		PDP map[string]string `json:"pdp"`
	}
	if err := json.Unmarshal(config, &parsed); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"policy_decision_point":       "https://host.testcontainers.internal:9445/stores/authzen_cert",
		"access_evaluation_endpoint":  "https://host.testcontainers.internal:9445/stores/authzen_cert/access/v1/evaluation",
		"access_evaluations_endpoint": "https://host.testcontainers.internal:9445/stores/authzen_cert/access/v1/evaluations",
		"search_subject_endpoint":     "https://host.testcontainers.internal:9445/stores/authzen_cert/access/v1/search/subject",
		"search_resource_endpoint":    "https://host.testcontainers.internal:9445/stores/authzen_cert/access/v1/search/resource",
		"search_action_endpoint":      "https://host.testcontainers.internal:9445/stores/authzen_cert/access/v1/search/action",
		"api_key":                     "k",
	}
	for name, value := range want {
		if parsed.PDP[name] != value {
			t.Fatalf("%s: want %q, got %q", name, value, parsed.PDP[name])
		}
	}
	if !strings.HasPrefix(string(config), "{") {
		t.Fatal("config is not a JSON object")
	}
}
