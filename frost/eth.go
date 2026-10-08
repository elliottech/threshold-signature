package frost

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// JoinStatement is the exact text a participant signs with MetaMask (personal_sign) to bind
// their ceremony keys to an Ethereum address everyone recognizes.
// It also binds the room's signing policy (threshold-of-total) and, when the room was created
// with an address allowlist, the full roster — so a rogue server cannot silently alter the
// threshold rules or swap in unexpected participants after people agreed to join.
func JoinStatement(room string, threshold, total int, allowed []string, authPk, encPk, address string) string {
	roster := ""
	if len(allowed) > 0 {
		roster = fmt.Sprintf("\nroster: %s", strings.ToLower(strings.Join(allowed, ",")))
	}
	return fmt.Sprintf("Lighter threshold-sig ceremony.\nJoining room %s\npolicy: %d-of-%d%s\nauth key: %s\nenc key: %s\naddress: %s",
		room, threshold, total, roster, authPk, encPk, strings.ToLower(address))
}

// RecoverEthAddress recovers the 0x address from an EIP-191 personal_sign signature (65-byte
// r||s||v hex) over the given message, so both server and clients can verify join statements.
func RecoverEthAddress(message, sigHex string) (string, error) {
	sig, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
	if err != nil || len(sig) != 65 {
		return "", errors.New("bad eth signature encoding")
	}
	v := sig[64]
	if v >= 27 {
		v -= 27
	}
	// compact recovery format expected by decred: v+27 first, then r||s
	compact := make([]byte, 65)
	compact[0] = v + 27
	copy(compact[1:], sig[:64])

	prefixed := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	digest := keccak256([]byte(prefixed))
	pub, _, err := ecdsa.RecoverCompact(compact, digest)
	if err != nil {
		return "", fmt.Errorf("eth signature recovery failed: %w", err)
	}
	return pubkeyToAddress(pub), nil
}

// VerifyJoin checks that ethSig is a valid personal_sign of the join statement by address.
func VerifyJoin(room string, threshold, total int, allowed []string, authPk, encPk, address, ethSig string) error {
	recovered, err := RecoverEthAddress(JoinStatement(room, threshold, total, allowed, authPk, encPk, address), ethSig)
	if err != nil {
		return err
	}
	if !strings.EqualFold(recovered, address) {
		return fmt.Errorf("join statement signed by %s, not %s", recovered, address)
	}
	return nil
}

// EthKeyFromSeed derives a deterministic secp256k1 key for headless clients (CLI/bots) that
// have no MetaMask; it plays the same role as the wallet key in the join binding.
func EthKeyFromSeed(seed []byte) *secp256k1.PrivateKey {
	d := keccak256(append([]byte("tsig-poc/eth-key/"), seed...))
	priv := secp256k1.PrivKeyFromBytes(d)
	return priv
}

// EthAddress returns the 0x address for a secp256k1 private key.
func EthAddress(priv *secp256k1.PrivateKey) string {
	return pubkeyToAddress(priv.PubKey())
}

// SignPersonal produces a MetaMask-compatible personal_sign signature (r||s||v hex).
func SignPersonal(priv *secp256k1.PrivateKey, msg string) string {
	prefixed := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(msg), msg)
	compact := ecdsa.SignCompact(priv, keccak256([]byte(prefixed)), false)
	out := make([]byte, 65)
	copy(out, compact[1:])
	out[64] = compact[0]
	return "0x" + hex.EncodeToString(out)
}

func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

func pubkeyToAddress(pub *secp256k1.PublicKey) string {
	uncompressed := pub.SerializeUncompressed() // 0x04 || X || Y
	return "0x" + hex.EncodeToString(keccak256(uncompressed[1:])[12:])
}
