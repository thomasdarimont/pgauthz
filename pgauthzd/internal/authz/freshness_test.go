package authz

import (
	"errors"
	"strings"
	"testing"
)

func ring(secrets ...string) Keyring { return NewKeyring(secrets) }

func TestFreshnessTokenRoundTrip(t *testing.T) {
	r := ring("test-hmac-key")
	cases := []struct {
		epoch int32
		lsn   string
	}{
		{1, "0/3000F78"},
		{2, "16/B374D848"},
		{42, "0/0"},
	}
	for _, c := range cases {
		tok := EncodeFreshnessToken(r[0], c.epoch, c.lsn)
		epoch, lsn, kid, err := DecodeFreshnessToken(r, tok)
		if err != nil {
			t.Fatalf("decode(%q): unexpected error %v", tok, err)
		}
		if epoch != c.epoch || lsn != c.lsn || kid != r[0].KID {
			t.Fatalf("round trip: got {%d,%s,%s}, want {%d,%s,%s}", epoch, lsn, kid, c.epoch, c.lsn, r[0].KID)
		}
	}
}

func TestFreshnessTokenRejectsTamper(t *testing.T) {
	r := ring("test-hmac-key")
	tok := EncodeFreshnessToken(r[0], 1, "0/3000F78")

	// Flip the last character of the payload segment (before the "." ) so the
	// signature no longer matches.
	bad := []byte(tok)
	bad[0] ^= 0x01
	if _, _, _, err := DecodeFreshnessToken(r, string(bad)); !errors.Is(err, ErrBadToken) {
		t.Fatalf("tampered token: got err %v, want ErrBadToken", err)
	}
}

func TestFreshnessTokenRejectsWrongKey(t *testing.T) {
	tok := EncodeFreshnessToken(ring("key-a")[0], 7, "0/100")
	if _, _, _, err := DecodeFreshnessToken(ring("key-b"), tok); !errors.Is(err, ErrBadToken) {
		t.Fatalf("wrong key: got err %v, want ErrBadToken", err)
	}
}

func TestFreshnessTokenRejectsMalformed(t *testing.T) {
	r := ring("k")
	for _, bad := range []string{"", "no-dot", ".", "!!!.###", "abc.def"} {
		if _, _, _, err := DecodeFreshnessToken(r, bad); !errors.Is(err, ErrBadToken) {
			t.Fatalf("malformed %q: got err %v, want ErrBadToken", bad, err)
		}
	}
}

// Rotation overlap: a token minted under the OLD key verifies against a keyring
// that now mints with the NEW key — and vice versa (the accept-before-mint
// phase, where a not-yet-flipped writer still mints old).
func TestFreshnessKeyringRotationOverlap(t *testing.T) {
	oldKey, newKey := ring("old-secret")[0], ring("new-secret")[0]
	phases := []struct {
		name string
		ring Keyring
	}{
		{"accept-before-mint (old,new)", NewKeyring([]string{"old-secret", "new-secret"})},
		{"flipped (new,old)", NewKeyring([]string{"new-secret", "old-secret"})},
	}
	for _, p := range phases {
		for _, mintKey := range []Key{oldKey, newKey} {
			tok := EncodeFreshnessToken(mintKey, 3, "1/AB")
			epoch, lsn, kid, err := DecodeFreshnessToken(p.ring, tok)
			if err != nil || epoch != 3 || lsn != "1/AB" || kid != mintKey.KID {
				t.Fatalf("%s / mint kid=%s: got {%d,%s,%s} err=%v", p.name, mintKey.KID, epoch, lsn, kid, err)
			}
		}
	}
}

// A token whose key has been rotated OUT of the keyring is rejected with the
// same opaque error as a forgery.
func TestFreshnessKeyringRejectsRetiredKey(t *testing.T) {
	tok := EncodeFreshnessToken(ring("retired-secret")[0], 1, "0/50")
	if _, _, _, err := DecodeFreshnessToken(ring("current-secret"), tok); !errors.Is(err, ErrBadToken) {
		t.Fatalf("retired key: got err %v, want ErrBadToken", err)
	}
}

// A forged kid must not smuggle a payload past verification: the MAC covers the
// kid, so re-labelling a token to another keyring entry fails.
func TestFreshnessKeyringRejectsKIDSwap(t *testing.T) {
	r := NewKeyring([]string{"secret-one", "secret-two"})
	// Mint under key 1, then re-encode the payload claiming key 0's kid while
	// keeping key 1's MAC.
	tok := EncodeFreshnessToken(r[1], 9, "2/FF")
	payload := r[0].KID + ":9:2/FF"
	_, encMAC, _ := strings.Cut(tok, ".")
	forged := freshnessB64.EncodeToString([]byte(payload)) + "." + encMAC
	if _, _, _, err := DecodeFreshnessToken(r, forged); !errors.Is(err, ErrBadToken) {
		t.Fatalf("kid-swapped token: got err %v, want ErrBadToken", err)
	}
}

func TestKeyringDerivation(t *testing.T) {
	r := NewKeyring([]string{"a", "", "b"}) // empties skipped
	if len(r) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(r))
	}
	if r[0].KID == r[1].KID {
		t.Fatalf("distinct secrets must derive distinct kids")
	}
	// kid is a pure function of the secret (stable across processes/restarts)
	if again := NewKeyring([]string{"a"}); again[0].KID != r[0].KID {
		t.Fatalf("kid not stable: %s vs %s", again[0].KID, r[0].KID)
	}
	if got := r.KIDs(); len(got) != 2 || got[0] != r[0].KID || got[1] != r[1].KID {
		t.Fatalf("KIDs() mismatch: %v", got)
	}
	if _, ok := r.byKID("nope"); ok {
		t.Fatal("unknown kid must not resolve")
	}
}

// A kid collision between DISTINCT secrets (~2^-31 per pair; not constructible
// with real sha256 inputs here, so built literally) must be a deterministic
// startup error — byKID's first-match would otherwise silently shadow the
// second key and fail all its tokens.
func TestKeyringValidateRejectsKIDCollision(t *testing.T) {
	collided := Keyring{
		{KID: "AAAAAA", Secret: []byte("secret-one")},
		{KID: "AAAAAA", Secret: []byte("secret-two")},
	}
	if err := collided.Validate(); err == nil || !strings.Contains(err.Error(), "same key id") {
		t.Fatalf("expected kid-collision error, got %v", err)
	}
	if err := NewKeyring([]string{"a", "b"}).Validate(); err != nil {
		t.Fatalf("distinct kids must validate, got %v", err)
	}
}
