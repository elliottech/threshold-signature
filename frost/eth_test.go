package frost

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// signPersonal reproduces MetaMask personal_sign for tests.
func signPersonal(priv *secp256k1.PrivateKey, msg string) string {
	prefixed := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(msg), msg)
	compact := ecdsa.SignCompact(priv, keccak256([]byte(prefixed)), false)
	// compact is v+27 || r || s; MetaMask returns r || s || v
	out := make([]byte, 65)
	copy(out, compact[1:])
	out[64] = compact[0]
	return "0x" + hex.EncodeToString(out)
}

func TestVerifyJoin(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := pubkeyToAddress(priv.PubKey())

	sig := signPersonal(priv, JoinStatement("roomA", 3, 4, nil, "aa", "bb", addr))
	if err := VerifyJoin("roomA", 3, 4, nil, "aa", "bb", addr, sig); err != nil {
		t.Fatalf("valid join rejected: %v", err)
	}
	if err := VerifyJoin("roomB", 3, 4, nil, "aa", "bb", addr, sig); err == nil {
		t.Fatal("join statement for wrong room accepted")
	}
	if err := VerifyJoin("roomA", 2, 4, nil, "aa", "bb", addr, sig); err == nil {
		t.Fatal("join statement for altered threshold accepted")
	}
	if err := VerifyJoin("roomA", 3, 5, nil, "aa", "bb", addr, sig); err == nil {
		t.Fatal("join statement for altered total accepted")
	}
	priv2, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyJoin("roomA", 3, 4, nil, "aa", "bb", pubkeyToAddress(priv2.PubKey()), sig); err == nil {
		t.Fatal("join statement for wrong address accepted")
	}
}

func TestVerifyJoinRoster(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := pubkeyToAddress(priv.PubKey())
	roster := []string{addr, "0x1111111111111111111111111111111111111111"}

	sig := signPersonal(priv, JoinStatement("roomA", 2, 2, roster, "aa", "bb", addr))
	if err := VerifyJoin("roomA", 2, 2, roster, "aa", "bb", addr, sig); err != nil {
		t.Fatalf("valid roster join rejected: %v", err)
	}
	altered := []string{addr, "0x2222222222222222222222222222222222222222"}
	if err := VerifyJoin("roomA", 2, 2, altered, "aa", "bb", addr, sig); err == nil {
		t.Fatal("join statement for altered roster accepted")
	}
	if err := VerifyJoin("roomA", 2, 2, nil, "aa", "bb", addr, sig); err == nil {
		t.Fatal("roster join accepted without roster")
	}
}
