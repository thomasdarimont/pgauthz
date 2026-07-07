package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
)

// Cursor sealing (ADR 0011, filtered enumeration): a filtered page's keyset
// cursor is the last RAW consumed id — which may be an id the hooks
// deliberately removed from the results. A plain base64 cursor would hand
// that id to the caller (existence leak through pagination metadata), so
// filtered cursors are sealed with AES-GCM: opaque, integrity-protected, and
// free of observable identifiers.
//
// Key: CURSOR_SEAL_KEY — REQUIRED (same value) across replicas so a cursor
// minted by one instance unseals on another. ROTATION: a comma-separated
// keyring, mirroring FRESHNESS_TOKEN_KEYS — the FIRST key mints, every key
// accepts. Rotate by prepending the new key ("new,old"), rolling out, then
// dropping the old key once in-flight paginations have drained (cursors live
// seconds to minutes). Unset → a random per-process key: still opaque and
// leak-free, but filtered-page cursors then survive neither restarts nor
// replica hops (the request fails with an invalid-cursor error, never a
// leak).
var (
	cursorSealMu   sync.Mutex
	cursorSealKeys [][]byte // [0] mints; all accept
)

// InitCursorSeal derives the sealing keyring from the configured secret list.
// Called once at startup; an empty secret selects a random per-process key.
func InitCursorSeal(secrets string) {
	cursorSealMu.Lock()
	defer cursorSealMu.Unlock()
	cursorSealKeys = nil
	for _, sec := range strings.Split(secrets, ",") {
		sec = strings.TrimSpace(sec)
		if sec == "" {
			continue
		}
		sum := sha256.Sum256([]byte("pgauthz-cursor-seal-v1|" + sec))
		cursorSealKeys = append(cursorSealKeys, sum[:])
	}
	if len(cursorSealKeys) == 0 {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			panic("cursor seal: no entropy: " + err.Error())
		}
		cursorSealKeys = [][]byte{k}
	}
}

func sealAEADs() ([]cipher.AEAD, error) {
	cursorSealMu.Lock()
	if cursorSealKeys == nil {
		cursorSealMu.Unlock()
		InitCursorSeal("")
		cursorSealMu.Lock()
	}
	keys := cursorSealKeys
	cursorSealMu.Unlock()
	aeads := make([]cipher.AEAD, 0, len(keys))
	for _, key := range keys {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		aeads = append(aeads, aead)
	}
	return aeads, nil
}

// SealedCursorAAD binds a sealed cursor to its QUERY CONTEXT via AES-GCM
// additional authenticated data: a cursor minted for one (operation, store,
// ACTOR, subject, action, type, caller context) is rejected for any other —
// no cross-store/cross-query replay, no replay by a different caller
// (filtered results are actor-dependent through role exemptions), no
// position-oracle probing with someone else's cursor. Both the minting side
// (opabackend) and the decoding side (the search handlers) MUST build this
// from the same request fields. The actor's ROLE SET is deliberately not
// bound: role changes between pages fall under the documented no-cross-page-
// snapshot semantics.
func SealedCursorAAD(op, store, actorID, subjectType, subjectID, action, objectType, objectID, contextHash string) string {
	return strings.Join([]string{"pgauthz-cursor-v1", op, store, actorID, subjectType, subjectID, action, objectType, objectID, contextHash}, "|")
}

// CanonicalContextHash canonically hashes the caller-supplied context for
// cursor binding: encoding/json sorts map keys, so identical context maps
// hash identically. Empty/nil context hashes to "".
func CanonicalContextHash(m map[string]any) string {
	if len(m) == 0 {
		return ""
	}
	b, err := jsonMarshal(m)
	if err != nil {
		return "unhashable" // never matches the mint side of a valid cursor
	}
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

// sealCursorValue encrypts a raw keyset id into an opaque token (primary
// key), authenticated against the query-context AAD.
//
// CRYPTOGRAPHIC INVARIANTS: every cursor uses a FRESH 96-bit nonce from
// crypto/rand, generated independently of the raw key and query context —
// nonces never repeat under a sealing key (random per call, never derived).
// Keys are KDF'd (SHA-256) to exactly 32 bytes, so AES-256 key-length
// validity holds by construction; keyring PARSING is validated at startup
// (config.Load rejects empty segments — no silently skipped keys). The
// plaintext is NUL-padded to a 32-byte multiple before sealing so the token
// length reveals only a coarse length bucket, not the id length.
func sealCursorValue(after, aad string) (string, error) {
	aeads, err := sealAEADs()
	if err != nil {
		return "", err
	}
	aead := aeads[0]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	// Pad to the next 32-byte multiple (PostgreSQL text never contains NUL,
	// so trailing NULs are unambiguous padding).
	pt := []byte(after)
	pt = append(pt, make([]byte, 32-len(pt)%32)...)
	ct := aead.Seal(nonce, nonce, pt, []byte(aad))
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

// ErrInvalidSealedCursor: the sealed cursor failed to decode/authenticate —
// wrong instance key (set CURSOR_SEAL_KEY across replicas), tampering, or a
// stale token. Maps to 400, never a fallback to the embedded bytes.
var ErrInvalidSealedCursor = errors.New("invalid sealed page cursor")

// unsealCursorValue reverses sealCursorValue, trying every keyring entry —
// during a rotation, cursors minted under the retiring key keep working. The
// query-context AAD must match what the cursor was minted for.
func unsealCursorValue(sealed, aad string) (string, error) {
	aeads, err := sealAEADs()
	if err != nil {
		return "", err
	}
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		return "", ErrInvalidSealedCursor
	}
	for _, aead := range aeads {
		if len(raw) < aead.NonceSize() {
			continue
		}
		if pt, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(aad)); err == nil {
			return strings.TrimRight(string(pt), "\x00"), nil
		}
	}
	return "", ErrInvalidSealedCursor
}

// EncodeSealedPageAfter mints an OPAQUE keyset cursor (filtered enumeration)
// bound to the query context (see SealedCursorAAD).
func EncodeSealedPageAfter(after, aad string) string {
	sealed, err := sealCursorValue(after, aad)
	if err != nil {
		// no usable cipher — better no cursor (pagination ends) than a leak
		return ""
	}
	data, _ := jsonMarshal(pageState{S: sealed, V: 1})
	return base64.RawURLEncoding.EncodeToString(data)
}
