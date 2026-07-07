package api

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// A filtered-enumeration cursor carries a RAW keyset id that hooks may have
// hidden from the results — it must be opaque (no observable identifier) and
// integrity-protected (ADR 0011).
func TestSealedCursorOpaqueAndRoundTrips(t *testing.T) {
	InitCursorSeal("test-secret")
	aad := SealedCursorAAD("objects", "demo", "alice", "user", "alice", "can_read", "document", "", "")
	tok, _ := EncodeSealedPageAfter("classified_report_42", aad)
	if tok == "" {
		t.Fatal("no token minted")
	}
	// Opacity: the raw id must not be recoverable by simple decoding.
	if strings.Contains(tok, "classified") {
		t.Fatal("cursor leaks the raw id verbatim")
	}
	if raw, err := base64.RawURLEncoding.DecodeString(tok); err == nil {
		if strings.Contains(string(raw), "classified") {
			t.Fatalf("base64-decoded cursor leaks the raw id: %q", raw)
		}
	}
	// Round trip through the page decoder under the SAME query context.
	pr := decodePage(&PageToken{Token: tok, Size: 10}, aad)
	if pr.After != "classified_report_42" {
		t.Fatalf("round trip failed: %q", pr.After)
	}

	// Replayed against a DIFFERENT query context (other store) → rejected:
	// no cross-context position probing.
	other := SealedCursorAAD("objects", "tenant_b", "alice", "user", "alice", "can_read", "document", "", "")
	if pr := decodePage(&PageToken{Token: tok, Size: 10}, other); pr.After != invalidCursorSentinel {
		t.Fatalf("cross-context replay must fail closed, got %q", pr.After)
	}
}

// A sealed cursor minted under another key (other replica without a shared
// CURSOR_SEAL_KEY, or tampering) must surface as the invalid sentinel — never
// fall back to interpreting the sealed bytes as an id.
func TestSealedCursorWrongKeyFailsClosed(t *testing.T) {
	InitCursorSeal("key-A")
	aad := SealedCursorAAD("objects", "demo", "a", "u", "a", "r", "d", "", "")
	tok, _ := EncodeSealedPageAfter("doc_1", aad)
	InitCursorSeal("key-B")
	pr := decodePage(&PageToken{Token: tok, Size: 10}, aad)
	if pr.After != invalidCursorSentinel {
		t.Fatalf("expected invalid-cursor sentinel, got %q", pr.After)
	}
}

// Plain (unfiltered) cursors are untouched by the seal layer.
func TestPlainCursorStillWorks(t *testing.T) {
	tok := EncodePageAfter("doc_7")
	pr := decodePage(&PageToken{Token: tok, Size: 5}, "")
	if pr.After != "doc_7" {
		t.Fatalf("plain keyset cursor broken: %q", pr.After)
	}
}

// CURSOR_SEAL_KEY rotation: "new,old" accepts cursors minted under the old
// key while minting under the new one — in-flight paginations survive a
// rolling rotation.
func TestSealedCursorKeyRotation(t *testing.T) {
	aad := SealedCursorAAD("objects", "demo", "a", "u", "a", "r", "d", "", "")
	InitCursorSeal("old-key")
	oldTok, _ := EncodeSealedPageAfter("doc_9", aad)

	InitCursorSeal("new-key,old-key") // rotation window
	if pr := decodePage(&PageToken{Token: oldTok, Size: 5}, aad); pr.After != "doc_9" {
		t.Fatalf("old-key cursor must unseal during rotation, got %q", pr.After)
	}
	newTok, _ := EncodeSealedPageAfter("doc_10", aad)

	InitCursorSeal("new-key") // old key dropped
	if pr := decodePage(&PageToken{Token: newTok, Size: 5}, aad); pr.After != "doc_10" {
		t.Fatalf("new-key cursor must keep working, got %q", pr.After)
	}
	if pr := decodePage(&PageToken{Token: oldTok, Size: 5}, aad); pr.After != invalidCursorSentinel {
		t.Fatalf("dropped-key cursor must fail closed, got %q", pr.After)
	}
}

// A cursor minted for actor A must not be accepted for actor B — filtered
// results are actor-dependent (role exemptions), so cursor replay across
// callers would be a cross-caller position oracle.
func TestSealedCursorBoundToActor(t *testing.T) {
	InitCursorSeal("k")
	aliceAAD := SealedCursorAAD("objects", "demo", "alice", "user", "alice", "can_read", "document", "", "")
	bobAAD := SealedCursorAAD("objects", "demo", "bob", "user", "bob", "can_read", "document", "", "")
	tok, _ := EncodeSealedPageAfter("classified_9", aliceAAD)
	if pr := decodePage(&PageToken{Token: tok, Size: 5}, bobAAD); pr.After != invalidCursorSentinel {
		t.Fatalf("actor replay must fail closed, got %q", pr.After)
	}
}

// Different caller-supplied context = different cursor binding.
func TestSealedCursorBoundToContext(t *testing.T) {
	InitCursorSeal("k")
	h1 := CanonicalContextHash(map[string]any{"purpose": "audit"})
	h2 := CanonicalContextHash(map[string]any{"purpose": "browse"})
	if h1 == h2 {
		t.Fatal("distinct contexts must hash differently")
	}
	if CanonicalContextHash(map[string]any{"purpose": "audit"}) != h1 {
		t.Fatal("identical contexts must hash identically")
	}
	a1 := SealedCursorAAD("objects", "demo", "alice", "user", "alice", "r", "d", "", h1)
	a2 := SealedCursorAAD("objects", "demo", "alice", "user", "alice", "r", "d", "", h2)
	tok, _ := EncodeSealedPageAfter("doc_3", a1)
	if pr := decodePage(&PageToken{Token: tok, Size: 5}, a2); pr.After != invalidCursorSentinel {
		t.Fatalf("context replay must fail closed, got %q", pr.After)
	}
}

// Padding: token length reveals only a coarse 32-byte bucket, not the id
// length; padded ids round-trip exactly (PG text never contains NUL).
func TestSealedCursorLengthBucketsAndPadding(t *testing.T) {
	InitCursorSeal("k")
	aad := SealedCursorAAD("objects", "demo", "a", "u", "a", "r", "d", "", "")
	short, _ := EncodeSealedPageAfter("a", aad)
	longer, _ := EncodeSealedPageAfter("a_much_longer_id_29_chars_xx", aad)
	if len(short) != len(longer) {
		t.Fatalf("ids in the same bucket must yield equal-length tokens: %d vs %d", len(short), len(longer))
	}
	for _, id := range []string{"a", "exactly_32_bytes_long_id_00000!!", "a_33_byte_id_that_crosses_bucket!"} {
		tok, _ := EncodeSealedPageAfter(id, aad)
		if pr := decodePage(&PageToken{Token: tok, Size: 5}, aad); pr.After != id {
			t.Fatalf("padding round trip failed for %q: got %q", id, pr.After)
		}
	}
}

// Unknown envelope versions fail closed.
func TestSealedCursorUnknownEnvelopeVersion(t *testing.T) {
	InitCursorSeal("k")
	data, _ := jsonMarshal(pageState{S: "AAAA", V: 2})
	tok := base64.RawURLEncoding.EncodeToString(data)
	if pr := decodePage(&PageToken{Token: tok, Size: 5}, "x"); pr.After != invalidCursorSentinel {
		t.Fatalf("unknown envelope version must fail closed, got %q", pr.After)
	}
}

// AAD encoding is UNAMBIGUOUS (review #10): fields are length-prefixed, so a
// delimiter character inside one field can never make two structurally
// different tuples encode identically.
func TestSealedCursorAADUnambiguous(t *testing.T) {
	// the classic split collision under naive "|"-joining
	a := SealedCursorAAD("objects", "demo", "a|b", "user", "c", "r", "d", "", "")
	b := SealedCursorAAD("objects", "demo", "a", "b|user", "c", "r", "d", "", "")
	if a == b {
		t.Fatal("moving a delimiter across fields must change the AAD")
	}

	// property: randomized re-splits of concatenated fields never collide
	seen := map[string]string{}
	fields := []string{"objects", "demo", "actor", "user", "subj", "read", "doc", "obj", "ctx"}
	for i := 0; i < 500; i++ {
		f := make([]string, len(fields))
		copy(f, fields)
		// move a suffix of one field to the prefix of the next
		src := i % (len(f) - 1)
		if len(f[src]) > 1 {
			cut := 1 + i%(len(f[src])-1)
			moved := f[src][len(f[src])-cut:]
			f[src] = f[src][:len(f[src])-cut]
			f[src+1] = moved + "|" + f[src+1]
		}
		key := fmt.Sprintf("%q", f) // tuple identity (unambiguous by quoting)
		aad := SealedCursorAAD(f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8])
		if prevKey, dup := seen[aad]; dup && prevKey != key {
			t.Fatalf("AAD collision between %s and %s", prevKey, key)
		}
		seen[aad] = key
	}
}

// The context digest is the FULL SHA-256 (review #10): truncation would allow
// offline birthday collisions on caller-constructed contexts.
func TestContextHashFullLength(t *testing.T) {
	h := CanonicalContextHash(map[string]any{"k": "v"})
	if got := len(h); got != 43 { // base64url(32 bytes) without padding
		t.Fatalf("context hash must be the full 256-bit digest, got %d chars", got)
	}
}
