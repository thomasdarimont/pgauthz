package authz

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

// Freshness tokens (ADR 0009): an opaque, HMAC-signed LSN watermark tagged with
// the WAL timeline (epoch). A write returns one; a later read presents it to
// demand read-your-writes on a replica. The token is a freshness ASSERTION, not
// a capability — it grants nothing on its own, so the signature only needs to
// stop a client fabricating a future position.

// ErrBadToken is returned when a freshness token is malformed, minted under an
// unknown key, or its signature does not verify (forged/tampered). Callers must
// fail closed (never serve as if fresh).
var ErrBadToken = errors.New("invalid or forged freshness token")

// Key is one entry in a freshness Keyring: an HMAC secret plus its derived key
// id — base64url(sha256(secret)[:4]) — which minted tokens embed so that
// verification can pick the right key during a rotation overlap window. The kid
// never has to be configured or coordinated: it is a pure function of the secret.
type Key struct {
	KID    string
	Secret []byte
}

// Keyring is the ordered freshness key set (FRESHNESS_TOKEN_KEYS): the FIRST
// key mints, EVERY key verifies. Rotation is three phases, each safe under
// mid-rollout instance skew (readers must accept a key before any writer mints
// with it): "old,new" everywhere → "new,old" everywhere → "new" once the old
// kid's verification metric drains (see PRODUCTION.md).
type Keyring []Key

// NewKeyring derives a Keyring from ordered secrets. Empty secrets are skipped;
// duplicate secrets are rejected by config validation before this runs.
func NewKeyring(secrets []string) Keyring {
	ring := make(Keyring, 0, len(secrets))
	for _, s := range secrets {
		if s == "" {
			continue
		}
		ring = append(ring, Key{KID: deriveKID(s), Secret: []byte(s)})
	}
	return ring
}

// KIDs returns the derived key ids in ring order (metrics pre-init).
func (k Keyring) KIDs() []string {
	ids := make([]string, len(k))
	for i, key := range k {
		ids[i] = key.KID
	}
	return ids
}

func (k Keyring) byKID(kid string) (Key, bool) {
	for _, key := range k {
		if key.KID == kid {
			return key, true
		}
	}
	return Key{}, false
}

// deriveKID is base64url(sha256(secret)[:4]) — 6 chars, no ':' (base64url
// alphabet), so it embeds safely in the colon-separated token payload.
func deriveKID(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return freshnessB64.EncodeToString(sum[:4])
}

// FreshnessMinter mints a freshness token on the PRIMARY (post-commit).
// Implemented by the direct pgx backend on a writable connection.
type FreshnessMinter interface {
	FreshnessToken(ctx context.Context) (epoch int32, lsn string, err error)
}

// FreshnessChecker evaluates whether THIS node satisfies a freshness token,
// returning the engine verdict: fresh | stale | wrong_epoch | unknown.
// Implemented by the direct pgx backend.
type FreshnessChecker interface {
	AssertFresh(ctx context.Context, epoch int32, lsn string) (verdict string, err error)
}

// FreshnessFallback lets the guard transparently serve a read from the PRIMARY
// when the local replica can't satisfy a freshness token (ADR 0009). The guard
// re-validates the token against the primary (AssertFreshPrimary) and only on a
// 'fresh' verdict stamps the request context with WithPrimaryFallback (the
// backend then routes that request's reads to the primary pool) — a promoted
// primary on a new timeline must still reject a cross-timeline token. Implemented
// by the direct pgx backend only when a fallback pool is configured.
type FreshnessFallback interface {
	HasPrimaryFallback() bool
	// AssertFreshPrimary runs the freshness verdict against the PRIMARY pool.
	AssertFreshPrimary(ctx context.Context, epoch int32, lsn string) (verdict string, err error)
}

type ctxKeyPrimaryFallback struct{}

// WithPrimaryFallback marks a request context so the backend routes its reads to
// the primary pool (the freshness guard sets this when the local replica is not
// fresh enough and a fallback pool exists).
func WithPrimaryFallback(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKeyPrimaryFallback{}, true)
}

// PrimaryFallback reports whether this request's reads should be routed to the
// primary pool.
func PrimaryFallback(ctx context.Context) bool {
	v, _ := ctx.Value(ctxKeyPrimaryFallback{}).(bool)
	return v
}

var freshnessB64 = base64.RawURLEncoding

// EncodeFreshnessToken signs {epoch, lsn} under key into an opaque,
// tamper-evident token "<base64url(kid:epoch:lsn)>.<base64url(hmac)>". The kid
// lets a verifier holding several keys (rotation overlap) pick the right one.
func EncodeFreshnessToken(key Key, epoch int32, lsn string) string {
	payload := key.KID + ":" + strconv.FormatInt(int64(epoch), 10) + ":" + lsn
	mac := freshnessMAC(key.Secret, payload)
	return freshnessB64.EncodeToString([]byte(payload)) + "." + freshnessB64.EncodeToString(mac)
}

// DecodeFreshnessToken verifies the signature against the keyring entry the
// token's kid selects and returns {epoch, lsn, kid}. It returns ErrBadToken on
// any malformed input, unknown kid, or signature mismatch — one opaque error,
// so a probe can't distinguish "key rotated away" from "forged".
func DecodeFreshnessToken(ring Keyring, token string) (epoch int32, lsn string, kid string, err error) {
	encPayload, encMAC, ok := strings.Cut(token, ".")
	if !ok {
		return 0, "", "", ErrBadToken
	}
	payload, err := freshnessB64.DecodeString(encPayload)
	if err != nil {
		return 0, "", "", ErrBadToken
	}
	gotMAC, err := freshnessB64.DecodeString(encMAC)
	if err != nil {
		return 0, "", "", ErrBadToken
	}
	kidStr, rest, ok := strings.Cut(string(payload), ":")
	if !ok {
		return 0, "", "", ErrBadToken
	}
	key, ok := ring.byKID(kidStr)
	if !ok {
		return 0, "", "", ErrBadToken
	}
	if !hmac.Equal(gotMAC, freshnessMAC(key.Secret, string(payload))) {
		return 0, "", "", ErrBadToken
	}
	epochStr, lsnStr, ok := strings.Cut(rest, ":")
	if !ok {
		return 0, "", "", ErrBadToken
	}
	n, err := strconv.ParseInt(epochStr, 10, 32)
	if err != nil {
		return 0, "", "", ErrBadToken
	}
	return int32(n), lsnStr, key.KID, nil
}

func freshnessMAC(key []byte, payload string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	return mac.Sum(nil)
}
