package conformance

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The suite images and ports, taken from environment variables (CTS_SUITE_IMAGE, ...). The
// images are release-v5.3.2 of 2026-10-09, pinned by the digest of its multi-platform image —
// the same pins as easyssf-go's conformance module; release-v5.3.2 contains the AuthZEN PDP
// test plans as they are on the suite's master of 2026-10-09. The single place to change them.
const (
	// DefaultSuiteImage is the conformance suite image.
	DefaultSuiteImage = "registry.gitlab.com/openid/conformance-suite@sha256:c795df1b151e0c2f2e40f17a2470991cc38bc91628449e9bb090e2372fe8b822"
	// DefaultSuiteNginxImage is its nginx image.
	DefaultSuiteNginxImage = "registry.gitlab.com/openid/conformance-suite/nginx@sha256:607458218abb58204201e4d283af90177d6b542535a99a21041d399a1505a6a0"
	// DefaultSuiteMongoDBImage is its MongoDB image: a current release (the suite itself runs
	// 6.0.13 in production, with far more known vulnerabilities), mongo:9.0.2-noble by digest.
	DefaultSuiteMongoDBImage = "mongo@sha256:61dd87ff554dc20386c63ebe1f7ede27314370ad5a7bf357c685fab424672158"
	// DefaultSuitePort is the host port the suite listens on. Fixed, as the suite has to know
	// its own URL before it starts. Not 18443, so that an easyssf suite can run alongside.
	DefaultSuitePort = 18444
	// DefaultPDPPort is the host port of the https front for pgauthzd, the PDP the suite tests.
	// Fixed, as the suite reaches it by the URL in the plan configuration.
	DefaultPDPPort = 9445
	// DefaultPGAuthzdURL is where the pgauthzd instance under test listens: pgauthzd-decision
	// of the demo stack (compose-authzen.yml), started with ALLOW_SUBJECT_OVERRIDE=true.
	DefaultPGAuthzdURL = "http://localhost:8090"
	// DefaultStore is the pgauthz store holding the certification fixture
	// (examples/models/authzen-cert).
	DefaultStore = "authzen_cert"
	// DefaultIssuer, DefaultAudience and DefaultKeyID are what the demo stack's pgauthzd
	// trusts (JWT_ISSUER / JWT_AUDIENCE, opa/data/jwks.json).
	DefaultIssuer   = "https://auth.example.com"
	DefaultAudience = "authz-api"
	DefaultKeyID    = "my-kid"
)

// DefaultSigningKey is the demo signing key (opa/keys/demo.key.txt), relative to this
// package, which is where `go test` runs.
var DefaultSigningKey = filepath.Join("..", "opa", "keys", "demo.key.txt")

// Settings say how the conformance tests start the suite and expose the PDP under test.
type Settings struct {
	SuiteImage        string
	SuiteNginxImage   string
	SuiteMongoDBImage string
	SuitePort         int
	// PDPPort is the host port of the https front the suite calls.
	PDPPort int
	// PGAuthzdURL is the pgauthzd instance the front forwards to.
	PGAuthzdURL string
	// Store is the pgauthz store the PDP identifier selects (/stores/<store>).
	Store string
	// SigningKey, KeyID, Issuer and Audience mint the api_key the suite authenticates with.
	SigningKey string
	KeyID      string
	Issuer     string
	Audience   string
	// Strict fails a module the suite finished with WARNING (certification tolerates
	// warnings; a regression in a SHOULD still deserves a look).
	Strict bool
}

// SettingsFromEnvironment are the settings from CTS_SUITE_IMAGE, CTS_SUITE_NGINX_IMAGE,
// CTS_SUITE_MONGODB_IMAGE, CTS_SUITE_PORT, CTS_PDP_PORT, CTS_PGAUTHZD_URL, CTS_STORE,
// CTS_SIGNING_KEY, CTS_KEY_ID, CTS_ISSUER, CTS_AUDIENCE and CTS_STRICT, with the defaults for
// what is not set.
func SettingsFromEnvironment() Settings {
	return Settings{
		SuiteImage:        env("CTS_SUITE_IMAGE", DefaultSuiteImage),
		SuiteNginxImage:   env("CTS_SUITE_NGINX_IMAGE", DefaultSuiteNginxImage),
		SuiteMongoDBImage: env("CTS_SUITE_MONGODB_IMAGE", DefaultSuiteMongoDBImage),
		SuitePort:         envInt("CTS_SUITE_PORT", DefaultSuitePort),
		PDPPort:           envInt("CTS_PDP_PORT", DefaultPDPPort),
		PGAuthzdURL:       strings.TrimRight(env("CTS_PGAUTHZD_URL", DefaultPGAuthzdURL), "/"),
		Store:             env("CTS_STORE", DefaultStore),
		SigningKey:        env("CTS_SIGNING_KEY", DefaultSigningKey),
		KeyID:             env("CTS_KEY_ID", DefaultKeyID),
		Issuer:            env("CTS_ISSUER", DefaultIssuer),
		Audience:          env("CTS_AUDIENCE", DefaultAudience),
		Strict:            env("CTS_STRICT", "") == "true",
	}
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	if value, err := strconv.Atoi(env(name, "")); err == nil && value > 0 {
		return value
	}
	return fallback
}
