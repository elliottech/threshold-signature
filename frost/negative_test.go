package frost

import (
	"encoding/hex"
	"strings"
	"testing"

	curve "github.com/elliottech/poseidon_crypto/curve/ecgfp5"
)

// TestVerifyShareRejectsCorruption checks that a share which does not match the dealer's public
// commitments is caught, both when the share itself is wrong and when it is evaluated against
// the wrong recipient index or a different dealer's commitments entirely.
func TestVerifyShareRejectsCorruption(t *testing.T) {
	coeffs := DealerPolynomial([]byte("dealer seed"), "room", 3)
	comms := Commitments(coeffs)
	share := EvalShare(coeffs, 2)
	if err := VerifyShare(share, 2, comms); err != nil {
		t.Fatalf("valid share rejected: %v", err)
	}
	if err := VerifyShare(share, 3, comms); err == nil {
		t.Fatal("share accepted at the wrong recipient index")
	}
	if err := VerifyShare(share.Add(curve.ONE), 2, comms); err == nil {
		t.Fatal("corrupted share accepted")
	}
	other := Commitments(DealerPolynomial([]byte("different dealer seed"), "room", 3))
	if err := VerifyShare(share, 2, other); err == nil {
		t.Fatal("share accepted against a different dealer's commitments")
	}
}

// TestGroupPublicKeyRejectsMalformedCommitment ensures a corrupted or wrong-length commitment
// cannot silently poison the group public key derivation.
func TestGroupPublicKeyRejectsMalformedCommitment(t *testing.T) {
	valid := Commitments(DealerPolynomial([]byte("seed"), "room", 1))
	if _, err := GroupPublicKey([][]byte{valid[0], {0x01, 0x02}}); err == nil {
		t.Fatal("wrong-length commitment accepted")
	}
	if _, err := GroupPublicKey([][]byte{valid[0], []byte("not valid hex point data!!!!!!!!!!!!!!!")}); err == nil {
		t.Fatal("undecodable point bytes accepted as a valid commitment")
	}
}

// TestLagrangeCoefficientRejectsDuplicateIndex checks the guard against a degenerate signer set
// (the same index appearing twice), which would otherwise divide by zero silently.
func TestLagrangeCoefficientRejectsDuplicateIndex(t *testing.T) {
	if _, err := LagrangeCoefficient(1, []int{1, 2, 2}); err == nil {
		t.Fatal("duplicate index in signer set accepted")
	}
}

// TestLagrangeCoefficientDiffersByPosition is a sanity check that swapping which index is being
// interpolated for actually changes the coefficient — a same-coefficient bug would let one
// signer's partial be miscredited to another under Lagrange interpolation.
func TestLagrangeCoefficientDiffersByPosition(t *testing.T) {
	set := []int{1, 2, 4}
	l1, err := LagrangeCoefficient(1, set)
	if err != nil {
		t.Fatal(err)
	}
	l2, err := LagrangeCoefficient(2, set)
	if err != nil {
		t.Fatal(err)
	}
	if l1.Equals(l2) {
		t.Fatal("distinct signer indices produced the same Lagrange coefficient")
	}
}

// TestNoncePairFromHexRejectsCorruption checks the hex nonce-pair decoder used to persist client
// nonce state between the commit and partial rounds.
func TestNoncePairFromHexRejectsCorruption(t *testing.T) {
	if _, err := NoncePairFromHex("not hex at all!!"); err == nil {
		t.Fatal("non-hex string accepted")
	}
	if _, err := NoncePairFromHex(""); err == nil {
		t.Fatal("empty string accepted")
	}
	np, err := RandomNonces()
	if err != nil {
		t.Fatal(err)
	}
	truncated := np.Hex()[:len(np.Hex())-2]
	if _, err := NoncePairFromHex(truncated); err == nil {
		t.Fatal("truncated (odd-length after trim) nonce hex accepted")
	}
}

// TestDecryptShareRejectsTamperedCiphertext exercises the AEAD authentication on encrypted DKG
// shares: any bitflip anywhere in the blob (not just using the wrong key) must be caught, since
// share confidentiality alone is not enough — integrity matters too.
func TestDecryptShareRejectsTamperedCiphertext(t *testing.T) {
	sk := EncKey([]byte("recipient"), "room")
	pk := PubPoint(sk)
	share := ScalarFromSeed([]byte("dealer"), "share")
	blob, err := EncryptShare(pk, share)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(blob)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		at   int
	}{
		{"flip byte in ephemeral pubkey", 0},
		{"flip byte in nonce", 41},
		{"flip byte in ciphertext", len(raw) - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := append([]byte(nil), raw...)
			tampered[tc.at] ^= 0xFF
			if _, err := DecryptShare(sk, hex.EncodeToString(tampered)); err == nil {
				t.Fatalf("tampered blob (%s) decrypted successfully", tc.name)
			}
		})
	}
	if _, err := DecryptShare(sk, blob[:20]); err == nil {
		t.Fatal("truncated blob (too short to contain nonce+tag) accepted")
	}
}

// TestVerifyPartialRejectsWrongTranscriptInputs checks that VerifyPartial actually depends on
// every one of its transcript inputs — a coordinator or observer using a stale/wrong binding
// factor, challenge, Lagrange coefficient, or public share must not be fooled into accepting a
// partial that does not actually match that exact transcript.
func TestVerifyPartialRejectsWrongTranscriptInputs(t *testing.T) {
	coeffs := DealerPolynomial([]byte("dealer"), "room", 1)
	signingShare := EvalShare(coeffs, 1)
	pubShare := curve.GENERATOR_ECgFp5Point.Mul(signingShare)

	np, err := RandomNonces()
	if err != nil {
		t.Fatal(err)
	}
	d, e := np.Commit()
	commit := Commitment{Idx: 1, D: d, E: e}
	msg := []byte("some message")
	rho := BindingFactor(1, msg, []Commitment{commit})
	challenge := ScalarFromSeed([]byte("challenge"), "test")
	lambda := ScalarFromSeed([]byte("lambda"), "test")

	z := PartialSignature(np, rho, challenge, lambda, signingShare)
	if err := VerifyPartial(z, commit, rho, challenge, lambda, pubShare); err != nil {
		t.Fatalf("valid partial rejected: %v", err)
	}

	wrongRho := BindingFactor(2, msg, []Commitment{commit})
	if err := VerifyPartial(z, commit, wrongRho, challenge, lambda, pubShare); err == nil {
		t.Fatal("partial accepted with the wrong binding factor")
	}
	wrongChallenge := ScalarFromSeed([]byte("different challenge"), "test")
	if err := VerifyPartial(z, commit, rho, wrongChallenge, lambda, pubShare); err == nil {
		t.Fatal("partial accepted with the wrong challenge")
	}
	wrongLambda := ScalarFromSeed([]byte("different lambda"), "test")
	if err := VerifyPartial(z, commit, rho, challenge, wrongLambda, pubShare); err == nil {
		t.Fatal("partial accepted with the wrong Lagrange coefficient")
	}
	wrongPubShare := curve.GENERATOR_ECgFp5Point.Mul(ScalarFromSeed([]byte("someone else"), "test"))
	if err := VerifyPartial(z, commit, rho, challenge, lambda, wrongPubShare); err == nil {
		t.Fatal("partial accepted against the wrong signer's public share")
	}
}

// TestAggregateSignatureRejectsWrongGroupKeyAndTamper checks the final verification step: a
// correctly-aggregated signature must fail against the wrong group public key, and any bit
// flipped in the signature bytes after aggregation must be caught.
func TestAggregateSignatureRejectsWrongGroupKeyAndTamper(t *testing.T) {
	coeffs := DealerPolynomial([]byte("solo dealer"), "room", 1)
	comms := Commitments(coeffs)
	groupPk, err := GroupPublicKey([][]byte{comms[0]})
	if err != nil {
		t.Fatal(err)
	}
	signingShare := EvalShare(coeffs, 1)

	hashedMsg := HashMessage([]byte("a transaction"))
	msg := []byte("0x" + hex.EncodeToString(hashedMsg.ToLittleEndianBytes()))

	np, err := RandomNonces()
	if err != nil {
		t.Fatal(err)
	}
	d, e := np.Commit()
	commit := Commitment{Idx: 1, D: d, E: e}
	aggR, err := GroupCommitment(msg, []Commitment{commit})
	if err != nil {
		t.Fatal(err)
	}
	challenge := Challenge(aggR, hashedMsg)
	rho := BindingFactor(1, msg, []Commitment{commit})
	z := PartialSignature(np, rho, challenge, curve.ONE, signingShare)
	sig := Aggregate([]curve.ECgFp5Scalar{z}, challenge)

	if err := Verify(groupPk, msg, sig); err != nil {
		t.Fatalf("valid aggregated signature rejected: %v", err)
	}

	otherPk, err := GroupPublicKey(Commitments(DealerPolynomial([]byte("other dealer"), "room", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(otherPk, msg, sig); err == nil {
		t.Fatal("signature verified against the wrong group public key")
	}

	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0xFF
	if err := Verify(groupPk, msg, tampered); err == nil {
		t.Fatal("tampered signature bytes verified")
	}
}

// TestVerifyPayloadRejectsWrongKeyAndTruncation extends the existing tampered-payload coverage
// with the other ways a forged auth-key signature could slip through: the wrong signer's key,
// and malformed (too-short/non-hex) signature encodings.
func TestVerifyPayloadRejectsWrongKeyAndTruncation(t *testing.T) {
	sk := AuthKey([]byte("me"), "room")
	otherSk := AuthKey([]byte("someone else"), "room")
	sig := SignPayload(sk, "payload")

	if err := VerifyPayload(PubPoint(otherSk), "payload", sig); err == nil {
		t.Fatal("signature verified against the wrong signer's public key")
	}
	if err := VerifyPayload(PubPoint(sk), "payload", sig[:len(sig)-4]); err == nil {
		t.Fatal("truncated signature accepted")
	}
	if err := VerifyPayload(PubPoint(sk), "payload", strings.ToUpper(sig)+"zz"); err == nil {
		t.Fatal("non-hex signature accepted")
	}
	if err := VerifyPayload("not-a-valid-pubkey", "payload", sig); err == nil {
		t.Fatal("malformed public key accepted")
	}
}

// TestBindingFactorRejectsMalformedCommitmentPoints checks GroupCommitment's decoding of every
// signer's D/E points, since these come from an untrusted transcript (the coordinator relays
// them without itself understanding the curve).
func TestGroupCommitmentRejectsMalformedPoints(t *testing.T) {
	commits := []Commitment{{Idx: 1, D: "not-hex", E: hex.EncodeToString(make([]byte, 40))}}
	if _, err := GroupCommitment([]byte("msg"), commits); err == nil {
		t.Fatal("non-hex D point accepted")
	}
	commits2 := []Commitment{{Idx: 1, D: hex.EncodeToString(make([]byte, 40)), E: "deadbeef"}}
	if _, err := GroupCommitment([]byte("msg"), commits2); err == nil {
		t.Fatal("wrong-length E point accepted")
	}
}
