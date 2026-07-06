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

// ErrBadToken is returned when a freshness token is malformed or its signature
// does not verify (forged/tampered). Callers must fail closed (never serve as if
// fresh).
var ErrBadToken = errors.New("invalid or forged freshness token")

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

// EncodeFreshnessToken signs {epoch, lsn} into an opaque, tamper-evident token
// of the form "<base64url(payload)>.<base64url(hmac)>".
func EncodeFreshnessToken(key []byte, epoch int32, lsn string) string {
	payload := strconv.FormatInt(int64(epoch), 10) + ":" + lsn
	mac := freshnessMAC(key, payload)
	return freshnessB64.EncodeToString([]byte(payload)) + "." + freshnessB64.EncodeToString(mac)
}

// DecodeFreshnessToken verifies the signature and returns {epoch, lsn}. It
// returns ErrBadToken on any malformed input or signature mismatch.
func DecodeFreshnessToken(key []byte, token string) (epoch int32, lsn string, err error) {
	encPayload, encMAC, ok := strings.Cut(token, ".")
	if !ok {
		return 0, "", ErrBadToken
	}
	payload, err := freshnessB64.DecodeString(encPayload)
	if err != nil {
		return 0, "", ErrBadToken
	}
	gotMAC, err := freshnessB64.DecodeString(encMAC)
	if err != nil {
		return 0, "", ErrBadToken
	}
	if !hmac.Equal(gotMAC, freshnessMAC(key, string(payload))) {
		return 0, "", ErrBadToken
	}
	epochStr, lsnStr, ok := strings.Cut(string(payload), ":")
	if !ok {
		return 0, "", ErrBadToken
	}
	n, err := strconv.ParseInt(epochStr, 10, 32)
	if err != nil {
		return 0, "", ErrBadToken
	}
	return int32(n), lsnStr, nil
}

func freshnessMAC(key []byte, payload string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	return mac.Sum(nil)
}
