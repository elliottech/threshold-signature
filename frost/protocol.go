package frost

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"

	curve "github.com/elliottech/poseidon_crypto/curve/ecgfp5"
	gFp5 "github.com/elliottech/poseidon_crypto/field/goldilocks_quintic_extension"
	schnorr "github.com/elliottech/poseidon_crypto/signature/schnorr"
)

// This file contains the hardened FROST protocol pieces (RFC 9591 structure) on top of the
// primitives in frost.go: DKG proofs of knowledge (rogue-key protection), two-nonce commitments
// with binding factors (concurrent-session safety), end-to-end encrypted shares (the server never
// sees key material), and per-participant request authentication keys.

// --- DKG proof of knowledge -------------------------------------------------------------------

// PoK is a Schnorr proof of knowledge of the dealer's constant term a_0 (rogue-key protection).
type PoK struct {
	R  string `json:"r"`  // commitment point rG, 40-byte hex
	Mu string `json:"mu"` // response mu = r + c*a_0, 40-byte hex scalar
}

func pokChallenge(room string, idx int, a0Commitment, rPoint []byte) curve.ECgFp5Scalar {
	transcript := fmt.Sprintf("tsig-poc/pok/%s/%d/%x/%x", room, idx, a0Commitment, rPoint)
	return ScalarFromSeed([]byte(transcript), "pok-challenge")
}

// ProveKnowledge produces a PoK for the dealer's constant coefficient. The commitment nonce is
// derived deterministically from the seed so re-running DKG yields the same proof.
func ProveKnowledge(seed []byte, room string, idx int, coeffs []curve.ECgFp5Scalar) PoK {
	r := ScalarFromSeed(seed, fmt.Sprintf("tsig-poc/pok-nonce/%s/%d", room, idx))
	rPt := curve.GENERATOR_ECgFp5Point.Mul(r).Encode().ToLittleEndianBytes()
	a0Comm := curve.GENERATOR_ECgFp5Point.Mul(coeffs[0]).Encode().ToLittleEndianBytes()
	c := pokChallenge(room, idx, a0Comm, rPt)
	mu := r.Add(c.Mul(coeffs[0]))
	return PoK{R: hex.EncodeToString(rPt), Mu: hex.EncodeToString(mu.ToLittleEndianBytes())}
}

// VerifyPoK checks mu*G == R + c*A_0 for the dealer's constant-term commitment.
func VerifyPoK(room string, idx int, a0Commitment []byte, pok PoK) error {
	rb, err := hex.DecodeString(pok.R)
	if err != nil {
		return fmt.Errorf("bad pok R: %w", err)
	}
	mb, err := hex.DecodeString(pok.Mu)
	if err != nil || len(mb) != 40 {
		return errors.New("bad pok mu")
	}
	rPt, err := decodePoint(rb)
	if err != nil {
		return fmt.Errorf("bad pok R point: %w", err)
	}
	a0, err := decodePoint(a0Commitment)
	if err != nil {
		return fmt.Errorf("bad a0 commitment: %w", err)
	}
	c := pokChallenge(room, idx, a0Commitment, rb)
	lhs := curve.GENERATOR_ECgFp5Point.Mul(curve.ScalarElementFromLittleEndianBytes(mb))
	rhs := rPt.Add(a0.Mul(c))
	if !lhs.Equals(rhs) {
		return errors.New("proof of knowledge fails: dealer does not know its secret coefficient")
	}
	return nil
}

// --- two-nonce commitments + binding factors --------------------------------------------------

// NoncePair is a signer's per-proposal hiding/binding nonce pair (FROST two-nonce scheme).
type NoncePair struct {
	D, E curve.ECgFp5Scalar
}

// RandomNonces returns a fresh random nonce pair. Nonces MUST be random and single-use: the
// caller stores the pair until the partial is produced and never signs the same proposal twice.
// Reusing (d, e) under different binding factors leaks the signing share.
func RandomNonces() (NoncePair, error) {
	buf := make([]byte, 80)
	if _, err := rand.Read(buf); err != nil {
		return NoncePair{}, err
	}
	return NoncePair{
		D: ScalarFromSeed(buf[:40], "tsig-poc/random-nonce/hiding"),
		E: ScalarFromSeed(buf[40:], "tsig-poc/random-nonce/binding"),
	}, nil
}

// Hex serializes the nonce pair for client-side persistence between the commit and partial
// rounds (it is secret material — store it locally, never send it anywhere).
func (n NoncePair) Hex() string {
	return hex.EncodeToString(n.D.ToLittleEndianBytes()) + hex.EncodeToString(n.E.ToLittleEndianBytes())
}

// NoncePairFromHex parses a pair serialized with Hex.
func NoncePairFromHex(s string) (NoncePair, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 80 {
		return NoncePair{}, errors.New("bad nonce pair encoding")
	}
	return NoncePair{
		D: curve.ScalarElementFromLittleEndianBytes(b[:40]),
		E: curve.ScalarElementFromLittleEndianBytes(b[40:]),
	}, nil
}

// Commit encodes D_j = d_j*G and E_j = e_j*G as hex.
func (n NoncePair) Commit() (dHex, eHex string) {
	d := curve.GENERATOR_ECgFp5Point.Mul(n.D).Encode().ToLittleEndianBytes()
	e := curve.GENERATOR_ECgFp5Point.Mul(n.E).Encode().ToLittleEndianBytes()
	return hex.EncodeToString(d), hex.EncodeToString(e)
}

// Commitment is one signer's public nonce commitment pair.
type Commitment struct {
	Idx  int
	D, E string // 40-byte hex points
}

// bindingTranscript serializes (msg, sorted commitment list) — the FROST binding-factor input.
func bindingTranscript(msg []byte, commits []Commitment) string {
	sorted := append([]Commitment(nil), commits...)
	sort.Slice(sorted, func(a, b int) bool { return sorted[a].Idx < sorted[b].Idx })
	var sb strings.Builder
	h := sha256.Sum256(msg)
	sb.WriteString(hex.EncodeToString(h[:]))
	for _, c := range sorted {
		sb.WriteString("/" + strconv.Itoa(c.Idx) + ":" + c.D + ":" + c.E)
	}
	return sb.String()
}

// BindingFactor computes rho_j = H(j, msg, all commitments), binding each signer's nonce to the
// exact message and signer set so concurrent signing sessions cannot be mixed.
func BindingFactor(j int, msg []byte, commits []Commitment) curve.ECgFp5Scalar {
	t := fmt.Sprintf("tsig-poc/binding/%d/%s", j, bindingTranscript(msg, commits))
	return ScalarFromSeed([]byte(t), "binding-factor")
}

// GroupCommitment computes R = sum_j (D_j + rho_j * E_j) over the signer set.
func GroupCommitment(msg []byte, commits []Commitment) (gFp5.Element, error) {
	var sum curve.ECgFp5Point
	for i, c := range commits {
		dPt, err := decodeHexPoint(c.D)
		if err != nil {
			return gFp5.Element{}, fmt.Errorf("signer %d: bad D: %w", c.Idx, err)
		}
		ePt, err := decodeHexPoint(c.E)
		if err != nil {
			return gFp5.Element{}, fmt.Errorf("signer %d: bad E: %w", c.Idx, err)
		}
		rho := BindingFactor(c.Idx, msg, commits)
		term := dPt.Add(ePt.Mul(rho))
		if i == 0 {
			sum = term
		} else {
			sum = sum.Add(term)
		}
	}
	return sum.Encode(), nil
}

// PartialSignature computes z_j = d_j + rho_j*e_j - c*lambda_j*x_j (two-nonce FROST share).
func PartialSignature(n NoncePair, rho, challenge, lambda, signingShare curve.ECgFp5Scalar) curve.ECgFp5Scalar {
	nonce := n.D.Add(rho.Mul(n.E))
	return nonce.Sub(challenge.Mul(lambda).Mul(signingShare))
}

// PublicShare computes participant j's public verification share X_j = sum_i f_i(j)*G from every
// dealer's commitments, letting anyone verify partial signatures without secrets.
func PublicShare(j int, allCommitments [][][]byte) (curve.ECgFp5Point, error) {
	var sum curve.ECgFp5Point
	for i, comms := range allCommitments {
		pt, err := commitmentEval(comms, j)
		if err != nil {
			return curve.ECgFp5Point{}, err
		}
		if i == 0 {
			sum = pt
		} else {
			sum = sum.Add(pt)
		}
	}
	return sum, nil
}

// VerifyPartial checks z_j*G == D_j + rho_j*E_j - c*lambda_j*X_j, so the coordinator (or any
// observer) can attribute a bad partial signature to a specific signer.
func VerifyPartial(z curve.ECgFp5Scalar, com Commitment, rho, challenge, lambda curve.ECgFp5Scalar, pubShare curve.ECgFp5Point) error {
	dPt, err := decodeHexPoint(com.D)
	if err != nil {
		return err
	}
	ePt, err := decodeHexPoint(com.E)
	if err != nil {
		return err
	}
	lhs := curve.GENERATOR_ECgFp5Point.Mul(z)
	zero := curve.ZERO
	rhs := dPt.Add(ePt.Mul(rho)).Add(pubShare.Mul(zero.Sub(challenge.Mul(lambda))))
	if !lhs.Equals(rhs) {
		return errors.New("partial signature fails verification")
	}
	return nil
}

// --- end-to-end encrypted shares (ECgFp5 ECDH + AES-GCM) --------------------------------------

// EncKey derives a participant's long-term encryption keypair for a room.
func EncKey(seed []byte, room string) curve.ECgFp5Scalar {
	return ScalarFromSeed(seed, "tsig-poc/enc-key/"+room)
}

// PubPoint returns the public point sk*G encoded as hex.
func PubPoint(sk curve.ECgFp5Scalar) string {
	return hex.EncodeToString(curve.GENERATOR_ECgFp5Point.Mul(sk).Encode().ToLittleEndianBytes())
}

func dhKey(shared curve.ECgFp5Point) []byte {
	b := shared.Encode().ToLittleEndianBytes()
	k := sha256.Sum256(append([]byte("tsig-poc/ecies-key/"), b...))
	return k[:]
}

// EncryptShare encrypts a 40-byte share to the recipient's encryption public key using an
// ephemeral ECgFp5 ECDH exchange and AES-GCM. Output format: hex(ephPub40 || nonce12 || ct).
func EncryptShare(recipientPubHex string, share curve.ECgFp5Scalar) (string, error) {
	recipient, err := decodeHexPoint(recipientPubHex)
	if err != nil {
		return "", fmt.Errorf("bad recipient enc key: %w", err)
	}
	var buf [64]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	eph := curve.FromNonCanonicalBigInt(new(big.Int).Mod(new(big.Int).SetBytes(buf[:]), curve.ORDER))
	ephPub := curve.GENERATOR_ECgFp5Point.Mul(eph).Encode().ToLittleEndianBytes()

	block, err := aes.NewCipher(dhKey(recipient.Mul(eph)))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, share.ToLittleEndianBytes(), ephPub)
	out := append(append(append([]byte{}, ephPub...), nonce...), ct...)
	return hex.EncodeToString(out), nil
}

// DecryptShare reverses EncryptShare with the recipient's encryption secret key.
func DecryptShare(encSk curve.ECgFp5Scalar, blobHex string) (curve.ECgFp5Scalar, error) {
	blob, err := hex.DecodeString(blobHex)
	if err != nil || len(blob) < 40+12+16 {
		return curve.ZERO, errors.New("bad encrypted share blob")
	}
	ephPub, err := decodePoint(blob[:40])
	if err != nil {
		return curve.ZERO, fmt.Errorf("bad ephemeral key: %w", err)
	}
	block, err := aes.NewCipher(dhKey(ephPub.Mul(encSk)))
	if err != nil {
		return curve.ZERO, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return curve.ZERO, err
	}
	ns := gcm.NonceSize()
	pt, err := gcm.Open(nil, blob[40:40+ns], blob[40+ns:], blob[:40])
	if err != nil {
		return curve.ZERO, fmt.Errorf("share decryption failed: %w", err)
	}
	if len(pt) != 40 {
		return curve.ZERO, errors.New("decrypted share has wrong length")
	}
	return curve.ScalarElementFromLittleEndianBytes(pt), nil
}

// --- request authentication (per-participant ECgFp5 API key) ----------------------------------

// AuthKey derives a participant's long-term request-signing keypair for a room.
func AuthKey(seed []byte, room string) curve.ECgFp5Scalar {
	return ScalarFromSeed(seed, "tsig-poc/auth-key/"+room)
}

// SignPayload signs an arbitrary payload string with the participant's auth key using the SDK's
// Schnorr scheme; the server verifies it against the auth public key stored at join.
func SignPayload(authSk curve.ECgFp5Scalar, payload string) string {
	sig := schnorr.SchnorrSignHashedMessage(HashMessage([]byte(payload)), authSk)
	return hex.EncodeToString(sig.ToBytes())
}

// VerifyPayload checks a payload signature against a participant's auth public key.
func VerifyPayload(authPkHex, payload, sigHex string) error {
	pk, err := hex.DecodeString(authPkHex)
	if err != nil || len(pk) != 40 {
		return errors.New("bad auth public key")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return errors.New("bad signature encoding")
	}
	hashed := HashMessage([]byte(payload))
	if err := schnorr.Validate(pk, hashed.ToLittleEndianBytes(), sig); err != nil {
		return fmt.Errorf("request signature invalid: %w", err)
	}
	return nil
}

// --- canonical request payloads (signed by the auth key, verified by the server) --------------

// DkgPayload serializes a DKG submission deterministically for signing.
func DkgPayload(room string, idx int, commitments []string, pok PoK, shares map[string]string) string {
	keys := make([]string, 0, len(shares))
	for k := range shares {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("dkg/%s/%d/%s/%s/%s", room, idx, strings.Join(commitments, ","), pok.R, pok.Mu))
	for _, k := range keys {
		sb.WriteString("/" + k + ":" + shares[k])
	}
	return sb.String()
}

// ProposePayload serializes a proposal submission deterministically for signing. nonce is a
// client-chosen random value that makes each signed submission unique, so a captured request
// cannot be replayed to create a duplicate proposal (see RandomRequestNonce).
func ProposePayload(room string, proposer int, message, nonce string) string {
	return fmt.Sprintf("propose/%s/%d/%s/%s", room, proposer, message, nonce)
}

// RandomRequestNonce returns a fresh random hex nonce for a signed, replay-sensitive request.
func RandomRequestNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// CommitPayload serializes a nonce-commitment submission deterministically for signing.
func CommitPayload(proposalID int64, idx int, d, e string) string {
	return fmt.Sprintf("commit/%d/%d/%s/%s", proposalID, idx, d, e)
}

// PartialPayload serializes a partial-signature submission deterministically for signing.
func PartialPayload(proposalID int64, idx int, z string) string {
	return fmt.Sprintf("partial/%d/%d/%s", proposalID, idx, z)
}

func decodeHexPoint(h string) (curve.ECgFp5Point, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return curve.ECgFp5Point{}, err
	}
	return decodePoint(b)
}
