package frost

import (
	"encoding/hex"
	"testing"

	curve "github.com/elliottech/poseidon_crypto/curve/ecgfp5"
)

func TestPoK(t *testing.T) {
	seed := []byte("seed-1")
	coeffs := DealerPolynomial(seed, "roomX", 3)
	comms := Commitments(coeffs)
	pok := ProveKnowledge(seed, "roomX", 1, coeffs)
	if err := VerifyPoK("roomX", 1, comms[0], pok); err != nil {
		t.Fatalf("valid PoK rejected: %v", err)
	}
	if err := VerifyPoK("roomX", 2, comms[0], pok); err == nil {
		t.Fatal("PoK for wrong index accepted")
	}
	other := Commitments(DealerPolynomial([]byte("seed-2"), "roomX", 3))
	if err := VerifyPoK("roomX", 1, other[0], pok); err == nil {
		t.Fatal("PoK for wrong commitment accepted (rogue key)")
	}
}

func TestEncryptDecryptShare(t *testing.T) {
	recvSeed := []byte("recipient")
	sk := EncKey(recvSeed, "roomY")
	pk := PubPoint(sk)

	share := ScalarFromSeed([]byte("dealer"), "some-share")
	blob, err := EncryptShare(pk, share)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptShare(sk, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equals(share) {
		t.Fatal("roundtrip mismatch")
	}
	wrong := EncKey([]byte("other"), "roomY")
	if _, err := DecryptShare(wrong, blob); err == nil {
		t.Fatal("decryption with wrong key succeeded")
	}
}

func TestAuthSignVerify(t *testing.T) {
	sk := AuthKey([]byte("me"), "roomZ")
	pk := PubPoint(sk)
	sig := SignPayload(sk, "hello")
	if err := VerifyPayload(pk, "hello", sig); err != nil {
		t.Fatalf("valid payload sig rejected: %v", err)
	}
	if err := VerifyPayload(pk, "tampered", sig); err == nil {
		t.Fatal("tampered payload accepted")
	}
}

// TestFullFrostCeremony runs a complete 3-of-4 DKG + two-nonce signing round and verifies the
// aggregate with the SDK verifier, plus per-partial verification and binding-factor safety.
func TestFullFrostCeremony(t *testing.T) {
	const n, th = 4, 3
	room := "ceremony"
	hashedMsg := HashMessage([]byte("test message to sign"))
	msg := []byte(hex.EncodeToString(hashedMsg.ToLittleEndianBytes()))

	seeds := make([][]byte, n+1)
	coeffs := make([][]curve.ECgFp5Scalar, n+1)
	comms := make([][][]byte, n+1)
	for i := 1; i <= n; i++ {
		seeds[i] = []byte{byte(i), 'x'}
		coeffs[i] = DealerPolynomial(seeds[i], room, th)
		comms[i] = Commitments(coeffs[i])
		pok := ProveKnowledge(seeds[i], room, i, coeffs[i])
		if err := VerifyPoK(room, i, comms[i][0], pok); err != nil {
			t.Fatal(err)
		}
	}

	// encrypted share distribution + local verification
	signingShares := make([]curve.ECgFp5Scalar, n+1)
	for j := 1; j <= n; j++ {
		encSk := EncKey(seeds[j], room)
		received := []curve.ECgFp5Scalar{}
		for i := 1; i <= n; i++ {
			blob, err := EncryptShare(PubPoint(encSk), EvalShare(coeffs[i], j))
			if err != nil {
				t.Fatal(err)
			}
			sh, err := DecryptShare(encSk, blob)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyShare(sh, j, comms[i]); err != nil {
				t.Fatalf("dealer %d -> %d: %v", i, j, err)
			}
			received = append(received, sh)
		}
		signingShares[j] = SigningShare(received)
	}

	constants := make([][]byte, 0, n)
	allComms := make([][][]byte, 0, n)
	for i := 1; i <= n; i++ {
		constants = append(constants, comms[i][0])
		allComms = append(allComms, comms[i])
	}
	groupPk, err := GroupPublicKey(constants)
	if err != nil {
		t.Fatal(err)
	}

	set := []int{1, 2, 4}
	commits := make([]Commitment, 0, th)
	nonces := map[int]NoncePair{}
	for _, j := range set {
		np, err := RandomNonces()
		if err != nil {
			t.Fatal(err)
		}
		nonces[j] = np
		d, e := np.Commit()
		commits = append(commits, Commitment{Idx: j, D: d, E: e})
	}

	aggR, err := GroupCommitment(msg, commits)
	if err != nil {
		t.Fatal(err)
	}
	c := Challenge(aggR, hashedMsg)

	partials := []curve.ECgFp5Scalar{}
	for i, j := range set {
		lambda, err := LagrangeCoefficient(j, set)
		if err != nil {
			t.Fatal(err)
		}
		rho := BindingFactor(j, msg, commits)
		z := PartialSignature(nonces[j], rho, c, lambda, signingShares[j])

		ps, err := PublicShare(j, allComms)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyPartial(z, commits[i], rho, c, lambda, ps); err != nil {
			t.Fatalf("partial %d: %v", j, err)
		}
		// a corrupted partial must be caught
		if err := VerifyPartial(z.Add(curve.ONE), commits[i], rho, c, lambda, ps); err == nil {
			t.Fatal("corrupted partial accepted")
		}
		partials = append(partials, z)
	}

	sig := Aggregate(partials, c)
	if err := Verify(groupPk, msg, sig); err != nil {
		t.Fatalf("aggregate signature invalid: %v", err)
	}
	other := HashMessage([]byte("other msg"))
	if err := Verify(groupPk, []byte(hex.EncodeToString(other.ToLittleEndianBytes())), sig); err == nil {
		t.Fatal("signature valid for wrong message")
	}
}

// TestRandomNoncesFreshAndRoundtrip checks nonces are unique per call and survive the hex
// persistence roundtrip used by clients between the commit and partial rounds.
func TestRandomNoncesFreshAndRoundtrip(t *testing.T) {
	n1, err := RandomNonces()
	if err != nil {
		t.Fatal(err)
	}
	n2, err := RandomNonces()
	if err != nil {
		t.Fatal(err)
	}
	if n1.D.Equals(n2.D) || n1.E.Equals(n2.E) {
		t.Fatal("RandomNonces returned repeated nonces")
	}
	got, err := NoncePairFromHex(n1.Hex())
	if err != nil {
		t.Fatal(err)
	}
	if !got.D.Equals(n1.D) || !got.E.Equals(n1.E) {
		t.Fatal("hex roundtrip mismatch")
	}
	if _, err := NoncePairFromHex("abcd"); err == nil {
		t.Fatal("short encoding accepted")
	}
}

// TestBindingFactorChangesWithTranscript ensures rho differs when the message or the commitment
// set changes, which is what prevents concurrent-session (ROS) mixing.
func TestBindingFactorChangesWithTranscript(t *testing.T) {
	commits := []Commitment{
		{Idx: 1, D: hex.EncodeToString(make([]byte, 40)), E: hex.EncodeToString(make([]byte, 40))},
		{Idx: 2, D: hex.EncodeToString(make([]byte, 40)), E: hex.EncodeToString(make([]byte, 40))},
	}
	r1 := BindingFactor(1, []byte("m1"), commits)
	r2 := BindingFactor(1, []byte("m2"), commits)
	if r1.Equals(r2) {
		t.Fatal("binding factor ignores message")
	}
	altered := append([]Commitment(nil), commits...)
	altered[1].Idx = 3
	r3 := BindingFactor(1, []byte("m1"), altered)
	if r1.Equals(r3) {
		t.Fatal("binding factor ignores signer set")
	}
}
