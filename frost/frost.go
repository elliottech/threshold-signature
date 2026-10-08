// Package frost implements a FROST-style threshold Schnorr signature scheme over the ECgFp5 curve,
// reusing the exact signature format and verification from poseidon_crypto (the same code the
// zklighter-sdk signer uses). A t-of-n group runs a Pedersen-style DKG (each participant deals a
// random degree t-1 polynomial); signing uses a two-round protocol (nonce commitments, then
// Lagrange-weighted partial signatures) that aggregates into a plain Schnorr signature verifiable
// with schnorr.IsSchnorrSignatureValid against the group public key.
package frost

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	curve "github.com/elliottech/poseidon_crypto/curve/ecgfp5"
	g "github.com/elliottech/poseidon_crypto/field/goldilocks"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
	p2 "github.com/elliottech/poseidon_crypto/hash/poseidon2_goldilocks_plonky2"
	schnorr "github.com/elliottech/poseidon_crypto/signature/schnorr"
)

// ScalarFromSeed derives a scalar deterministically from a seed and a domain separation tag.
// It mirrors the counter-based sha256 expansion used by the zklighter-sdk seed key manager.
func ScalarFromSeed(seed []byte, domain string) curve.ECgFp5Scalar {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write([]byte(domain))
	h.Write(seed)
	part1 := h.Sum(nil)

	h.Reset()
	h.Write([]byte{2})
	h.Write([]byte(domain))
	h.Write(seed)
	part2 := h.Sum(nil)

	val := new(big.Int).SetBytes(append(part1, part2...))
	val.Mod(val, curve.ORDER)
	return curve.FromNonCanonicalBigInt(val)
}

// HashMessage hashes an arbitrary byte message to an Fp5 element, the pre-hashed
// form expected by the SDK's Schnorr sign/verify.
func HashMessage(msg []byte) gFp5.Element {
	digest := sha256.Sum256(msg)
	limbs := p2.HashNToMNoPadBytes(digest[:], 5)
	var e gFp5.Element
	copy(e[:], limbs)
	return e
}

// ParseTxHash decodes a proposal message, which must be a 40-byte Lighter L2 transaction
// hash in hex (0x prefix optional). Rooms sign this hash directly, so the aggregate
// signature is a valid L2 signature for the transaction itself.
func ParseTxHash(msg []byte) (gFp5.Element, error) {
	hexStr := strings.TrimPrefix(strings.TrimSpace(string(msg)), "0x")
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return gFp5.Element{}, fmt.Errorf("proposal must be a hex-encoded 40-byte Lighter tx hash: %w", err)
	}
	if len(b) != 40 {
		return gFp5.Element{}, fmt.Errorf("proposal must be a 40-byte Lighter tx hash, got %d bytes", len(b))
	}
	e, err := gFp5.FromCanonicalLittleEndianBytes(b)
	if err != nil {
		return gFp5.Element{}, fmt.Errorf("invalid Lighter tx hash: %w", err)
	}
	return e, nil
}

// DealerPolynomial returns the t coefficients of participant i's DKG polynomial,
// derived deterministically from their seed so a participant can always re-derive
// their state from a fresh MetaMask signature.
func DealerPolynomial(seed []byte, room string, t int) []curve.ECgFp5Scalar {
	coeffs := make([]curve.ECgFp5Scalar, t)
	for k := 0; k < t; k++ {
		coeffs[k] = ScalarFromSeed(seed, fmt.Sprintf("tsig-poc/dkg/%s/coeff/%d", room, k))
	}
	return coeffs
}

// Commitments returns the public commitments A_k = a_k * G for a polynomial, encoded as 40-byte values.
func Commitments(coeffs []curve.ECgFp5Scalar) [][]byte {
	res := make([][]byte, len(coeffs))
	for k, c := range coeffs {
		enc := curve.GENERATOR_ECgFp5Point.Mul(c).Encode()
		res[k] = enc.ToLittleEndianBytes()
	}
	return res
}

// EvalShare evaluates the polynomial at x = j (1-based participant index).
func EvalShare(coeffs []curve.ECgFp5Scalar, j int) curve.ECgFp5Scalar {
	x := scalarFromInt(j)
	res := curve.ZERO
	for k := len(coeffs) - 1; k >= 0; k-- {
		res = res.Mul(x).Add(coeffs[k])
	}
	return res
}

// VerifyShare checks share*G == sum_k j^k * A_k against the dealer's commitments.
func VerifyShare(share curve.ECgFp5Scalar, j int, commitments [][]byte) error {
	lhs := curve.GENERATOR_ECgFp5Point.Mul(share)

	rhs, err := commitmentEval(commitments, j)
	if err != nil {
		return err
	}
	if !lhs.Equals(rhs) {
		return errors.New("share does not match commitments")
	}
	return nil
}

func commitmentEval(commitments [][]byte, j int) (curve.ECgFp5Point, error) {
	x := scalarFromInt(j)
	pow := curve.ONE
	sum := curve.ECgFp5Point{}
	first := true
	for _, cb := range commitments {
		pt, err := decodePoint(cb)
		if err != nil {
			return curve.ECgFp5Point{}, err
		}
		term := pt.Mul(pow)
		if first {
			sum = term
			first = false
		} else {
			sum = sum.Add(term)
		}
		pow = pow.Mul(x)
	}
	return sum, nil
}

// GroupPublicKey sums every dealer's constant-term commitment A_0 into the group public key,
// returned in the same 40-byte encoding the SDK uses for L2 public keys.
func GroupPublicKey(constantCommitments [][]byte) ([]byte, error) {
	var sum curve.ECgFp5Point
	for i, cb := range constantCommitments {
		pt, err := decodePoint(cb)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			sum = pt
		} else {
			sum = sum.Add(pt)
		}
	}
	enc := sum.Encode()
	return enc.ToLittleEndianBytes(), nil
}

// SigningShare computes participant j's long-term signing share x_j = sum_i f_i(j).
func SigningShare(shares []curve.ECgFp5Scalar) curve.ECgFp5Scalar {
	res := curve.ZERO
	for _, s := range shares {
		res = res.Add(s)
	}
	return res
}

// NonceCommitment returns R_j = k_j * G encoded as 40 bytes.
func NonceCommitment(k curve.ECgFp5Scalar) []byte {
	enc := curve.GENERATOR_ECgFp5Point.Mul(k).Encode()
	return enc.ToLittleEndianBytes()
}

// Challenge computes e = H(R || H(m)) where R is the aggregated nonce commitment,
// exactly as schnorr.SchnorrSignHashedMessage does.
func Challenge(aggR gFp5.Element, hashedMsg gFp5.Element) curve.ECgFp5Scalar {
	preImage := make([]g.GoldilocksField, 10)
	copy(preImage[:5], aggR[:])
	copy(preImage[5:], hashedMsg[:])
	return curve.FromGfp5(p2.HashToQuinticExtension(preImage))
}

// LagrangeCoefficient computes λ_j = prod_{m in set, m != j} m / (m - j) mod ORDER,
// the coefficient interpolating participant j's share at x = 0. Every value in set must be
// distinct: a repeated index would silently double-count that participant's contribution to
// the interpolation instead of raising an error, since m == j entries are skipped rather than
// causing a zero denominator.
func LagrangeCoefficient(j int, set []int) (curve.ECgFp5Scalar, error) {
	seen := make(map[int]bool, len(set))
	for _, m := range set {
		if seen[m] {
			return curve.ZERO, errors.New("duplicate indices in signer set")
		}
		seen[m] = true
	}
	num := big.NewInt(1)
	den := big.NewInt(1)
	for _, m := range set {
		if m == j {
			continue
		}
		num.Mul(num, big.NewInt(int64(m)))
		num.Mod(num, curve.ORDER)
		den.Mul(den, new(big.Int).Sub(big.NewInt(int64(m)), big.NewInt(int64(j))))
		den.Mod(den, curve.ORDER)
	}
	if den.Sign() == 0 {
		return curve.ZERO, errors.New("duplicate indices in signer set")
	}
	den.ModInverse(den, curve.ORDER)
	num.Mul(num, den)
	num.Mod(num, curve.ORDER)
	return curve.FromNonCanonicalBigInt(num), nil
}

// Aggregate sums the partial signatures and returns the final 80-byte signature (s || e),
// byte-compatible with schnorr.Signature.ToBytes.
func Aggregate(partials []curve.ECgFp5Scalar, e curve.ECgFp5Scalar) []byte {
	s := curve.ZERO
	for _, p := range partials {
		s = s.Add(p)
	}
	sig := schnorr.Signature{S: s, E: e}
	return sig.ToBytes()
}

// Verify checks the final signature against the group public key using the SDK's
// schnorr verification (schnorr.Validate).
func Verify(groupPk []byte, msg []byte, sig []byte) error {
	hashed, err := ParseTxHash(msg)
	if err != nil {
		return err
	}
	return schnorr.Validate(groupPk, hashed.ToLittleEndianBytes(), sig)
}

func scalarFromInt(j int) curve.ECgFp5Scalar {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(j))
	var buf [40]byte
	copy(buf[:8], b[:])
	return curve.ScalarElementFromLittleEndianBytes(buf[:])
}

func decodePoint(b []byte) (curve.ECgFp5Point, error) {
	if len(b) != 40 {
		return curve.ECgFp5Point{}, fmt.Errorf("encoded point must be 40 bytes, got %d", len(b))
	}
	el, err := gFp5.FromCanonicalLittleEndianBytes(b)
	if err != nil {
		return curve.ECgFp5Point{}, err
	}
	pt, ok := curve.Decode(el)
	if !ok {
		return curve.ECgFp5Point{}, errors.New("invalid point encoding")
	}
	return pt, nil
}
