package authz

import "testing"

func TestFreshnessTokenRoundTrip(t *testing.T) {
	key := []byte("test-hmac-key")
	cases := []struct {
		epoch int32
		lsn   string
	}{
		{1, "0/3000F78"},
		{2, "16/B374D848"},
		{42, "0/0"},
	}
	for _, c := range cases {
		tok := EncodeFreshnessToken(key, c.epoch, c.lsn)
		epoch, lsn, err := DecodeFreshnessToken(key, tok)
		if err != nil {
			t.Fatalf("decode(%q): unexpected error %v", tok, err)
		}
		if epoch != c.epoch || lsn != c.lsn {
			t.Fatalf("round trip: got {%d,%s}, want {%d,%s}", epoch, lsn, c.epoch, c.lsn)
		}
	}
}

func TestFreshnessTokenRejectsTamper(t *testing.T) {
	key := []byte("test-hmac-key")
	tok := EncodeFreshnessToken(key, 1, "0/3000F78")

	// Flip the last character of the payload segment (before the "." ) so the
	// signature no longer matches.
	bad := []byte(tok)
	bad[0] ^= 0x01
	if _, _, err := DecodeFreshnessToken(key, string(bad)); err != ErrBadToken {
		t.Fatalf("tampered token: got err %v, want ErrBadToken", err)
	}
}

func TestFreshnessTokenRejectsWrongKey(t *testing.T) {
	tok := EncodeFreshnessToken([]byte("key-a"), 7, "0/100")
	if _, _, err := DecodeFreshnessToken([]byte("key-b"), tok); err != ErrBadToken {
		t.Fatalf("wrong key: got err %v, want ErrBadToken", err)
	}
}

func TestFreshnessTokenRejectsMalformed(t *testing.T) {
	key := []byte("k")
	for _, bad := range []string{"", "no-dot", ".", "!!!.###", "abc.def"} {
		if _, _, err := DecodeFreshnessToken(key, bad); err != ErrBadToken {
			t.Fatalf("malformed %q: got err %v, want ErrBadToken", bad, err)
		}
	}
}
