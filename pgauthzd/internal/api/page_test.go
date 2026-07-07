package api

import "testing"

// The AuthZEN next_token is opaque to clients. Internally it now carries a
// keyset cursor (the last id of the previous page) rather than an offset, so
// paging never re-runs the per-candidate access check on earlier pages. Old
// offset-encoded tokens must still decode (back-compat with in-flight tokens).
func TestDecodePageKeyset(t *testing.T) {
	// Keyset token round-trips into After (offset stays zero).
	tok := EncodePageAfter("doc_042")
	got := decodePage(&PageToken{Token: tok, Size: 10}, "")
	if got == nil {
		t.Fatal("decodePage returned nil")
	}
	if got.After != "doc_042" {
		t.Fatalf("After: want %q, got %q", "doc_042", got.After)
	}
	if got.Offset != 0 {
		t.Fatalf("Offset: want 0 for a keyset token, got %d", got.Offset)
	}
	if got.Limit != 10 {
		t.Fatalf("Limit: want 10, got %d", got.Limit)
	}
}

func TestDecodePageLegacyOffset(t *testing.T) {
	// A pre-keyset token (offset-encoded) must still decode for back-compat.
	tok := EncodePage(20)
	got := decodePage(&PageToken{Token: tok, Size: 5}, "")
	if got.Offset != 20 {
		t.Fatalf("Offset: want 20, got %d", got.Offset)
	}
	if got.After != "" {
		t.Fatalf("After: want empty for a legacy offset token, got %q", got.After)
	}
}

func TestDecodePageEmpty(t *testing.T) {
	got := decodePage(&PageToken{Size: 7}, "")
	if got.After != "" || got.Offset != 0 {
		t.Fatalf("want empty cursor, got After=%q Offset=%d", got.After, got.Offset)
	}
	if got.Limit != 7 {
		t.Fatalf("Limit: want 7, got %d", got.Limit)
	}
	if decodePage(nil, "") != nil {
		t.Fatal("decodePage(nil) should be nil")
	}
}
