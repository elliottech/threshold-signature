package frost

import (
	"encoding/hex"
	"testing"
)

// TestParseTxHash checks that proposals decode as a 40-byte Lighter tx hash (0x optional)
// and that anything else is rejected.
func TestParseTxHash(t *testing.T) {
	e := HashMessage([]byte("some lighter tx"))
	txHash := e.ToLittleEndianBytes()
	got, err := ParseTxHash([]byte("0x" + hex.EncodeToString(txHash)))
	if err != nil || got != e {
		t.Fatalf("0x-prefixed tx hash did not decode: %v", err)
	}
	got, err = ParseTxHash([]byte(hex.EncodeToString(txHash)))
	if err != nil || got != e {
		t.Fatalf("tx hash without 0x did not decode: %v", err)
	}
	for _, bad := range []string{"", "plain message", "0xzz", "0x" + hex.EncodeToString(txHash[:39])} {
		if _, err := ParseTxHash([]byte(bad)); err == nil {
			t.Fatalf("malformed proposal %q accepted", bad)
		}
	}
}
