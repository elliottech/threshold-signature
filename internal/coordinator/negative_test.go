package coordinator

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/elliottech/threshold-sig-poc/frost"
)

// TestCreateRoomRejectsInvalidPolicy checks every boundary of the t-of-n policy validation, not
// just the one case (threshold > total) exercised by TestRequestValidation.
func TestCreateRoomRejectsInvalidPolicy(t *testing.T) {
	s := testServer(t)
	for _, tc := range []struct {
		name             string
		threshold, total int
	}{
		{"zero threshold", 0, 3},
		{"negative threshold", -1, 3},
		{"threshold exceeds total", 3, 2},
		{"total exceeds the 8-participant cap", 2, 9},
		{"zero total", 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, resp := doJSON(t, s.http.Handler, "POST", "/api/rooms", map[string]any{"threshold": tc.threshold, "total": tc.total})
			if w.Code != 400 {
				t.Fatalf("invalid policy (t=%d, n=%d) accepted: %d %v", tc.threshold, tc.total, w.Code, resp)
			}
		})
	}
	// The boundary itself (total == 8) must still be accepted.
	if w, resp := doJSON(t, s.http.Handler, "POST", "/api/rooms", map[string]any{"threshold": 1, "total": 8}); w.Code != 200 {
		t.Fatalf("total=8 (the documented maximum) rejected: %d %v", w.Code, resp)
	}
}

// TestJoinRejectsWrongKeyLength checks that malformed (wrong-length) auth/enc public keys are
// rejected before ever reaching signature verification.
func TestJoinRejectsWrongKeyLength(t *testing.T) {
	s := testServer(t)
	w, resp := doJSON(t, s.http.Handler, "POST", "/api/rooms", map[string]any{"threshold": 1, "total": 1})
	if w.Code != 200 {
		t.Fatalf("create room failed: %d %v", w.Code, resp)
	}
	room := resp["room"].(string)
	seed := []byte("wrong key length regression seed")
	ethKey := frost.EthKeyFromSeed(seed)
	address := frost.EthAddress(ethKey)
	encPk := frost.PubPoint(frost.EncKey(seed, room))
	sig := frost.SignPersonal(ethKey, frost.JoinStatement(room, 1, 1, nil, "deadbeef", encPk, address))
	w, resp = doJSON(t, s.http.Handler, "POST", "/api/rooms/"+room+"/join", map[string]any{
		"address": address, "authPk": "deadbeef", "encPk": encPk, "ethSig": sig,
	})
	if w.Code != 400 {
		t.Fatalf("short authPk accepted: %d %v", w.Code, resp)
	}
}

// TestJoinRejectsMismatchedRejoinKey checks that an address which already joined cannot silently
// swap in a different auth key on a "rejoin" — that would let a second party impersonate an
// existing participant's slot.
func TestJoinRejectsMismatchedRejoinKey(t *testing.T) {
	s := testServer(t)
	room, seeds := setupCeremony(t, s.http.Handler, 1, 1)
	seed := seeds[0]
	ethKey := frost.EthKeyFromSeed(seed)
	address := frost.EthAddress(ethKey)
	// Same address, but a different auth key this time (as if an attacker who somehow controls
	// the address's eth key tries to rebind it to a different ceremony key).
	differentAuthPk := frost.PubPoint(frost.AuthKey([]byte("a completely different seed"), room))
	encPk := frost.PubPoint(frost.EncKey(seed, room))
	sig := frost.SignPersonal(ethKey, frost.JoinStatement(room, 1, 1, nil, differentAuthPk, encPk, address))
	w, resp := doJSON(t, s.http.Handler, "POST", "/api/rooms/"+room+"/join", map[string]any{
		"address": address, "authPk": differentAuthPk, "encPk": encPk, "ethSig": sig,
	})
	if w.Code != 400 {
		t.Fatalf("rejoin with a different auth key accepted: %d %v", w.Code, resp)
	}
}

// TestJoinRejectsWhenRoomIsFull checks the capacity guard independently of signature validity.
func TestJoinRejectsWhenRoomIsFull(t *testing.T) {
	s := testServer(t)
	room, _ := setupCeremony(t, s.http.Handler, 1, 1) // room is now full (total=1, 1 joined)
	seed := []byte("overflow participant seed")
	ethKey := frost.EthKeyFromSeed(seed)
	address := frost.EthAddress(ethKey)
	authPk := frost.PubPoint(frost.AuthKey(seed, room))
	encPk := frost.PubPoint(frost.EncKey(seed, room))
	sig := frost.SignPersonal(ethKey, frost.JoinStatement(room, 1, 1, nil, authPk, encPk, address))
	w, resp := doJSON(t, s.http.Handler, "POST", "/api/rooms/"+room+"/join", map[string]any{
		"address": address, "authPk": authPk, "encPk": encPk, "ethSig": sig,
	})
	if w.Code != 400 {
		t.Fatalf("join to a full room accepted: %d %v", w.Code, resp)
	}
}

// TestPostDkgRejectsForgedSignature checks that postDkg actually verifies the submission
// signature against the participant's registered auth key, not just its shape.
func TestPostDkgRejectsForgedSignature(t *testing.T) {
	s := testServer(t)
	const threshold, total = 1, 1
	room, seeds := setupCeremony(t, s.http.Handler, threshold, total)
	coeffs := frost.DealerPolynomial(seeds[0], room, threshold)
	comms := frost.Commitments(coeffs)
	commsHex := []string{hex.EncodeToString(comms[0])}
	pok := frost.ProveKnowledge(seeds[0], room, 1, coeffs)
	ct, err := frost.EncryptShare(frost.PubPoint(frost.EncKey(seeds[0], room)), frost.EvalShare(coeffs, 1))
	if err != nil {
		t.Fatal(err)
	}
	shares := map[string]string{"1": ct}
	// Signed with a different key than the one registered for this participant at join.
	forgedSig := frost.SignPayload(frost.AuthKey([]byte("attacker key"), room), frost.DkgPayload(room, 1, commsHex, pok, shares))
	w, resp := doJSON(t, s.http.Handler, "POST", "/api/rooms/"+room+"/dkg", map[string]any{
		"idx": 1, "commitments": commsHex, "pok": pok, "shares": shares, "sig": forgedSig,
	})
	if w.Code != 401 {
		t.Fatalf("DKG round forged with the wrong auth key accepted: %d %v", w.Code, resp)
	}
}

// TestPostDkgRejectsBadPoK checks that a dealer cannot skip proving knowledge of their constant
// coefficient (the rogue-key protection) even with a correctly-signed request.
func TestPostDkgRejectsBadPoK(t *testing.T) {
	s := testServer(t)
	const threshold, total = 1, 1
	room, seeds := setupCeremony(t, s.http.Handler, threshold, total)
	coeffs := frost.DealerPolynomial(seeds[0], room, threshold)
	comms := frost.Commitments(coeffs)
	commsHex := []string{hex.EncodeToString(comms[0])}
	// A PoK proven for a completely different (unrelated) polynomial's constant term.
	otherCoeffs := frost.DealerPolynomial([]byte("rogue key attempt"), room, threshold)
	badPok := frost.ProveKnowledge([]byte("rogue key attempt"), room, 1, otherCoeffs)
	ct, err := frost.EncryptShare(frost.PubPoint(frost.EncKey(seeds[0], room)), frost.EvalShare(coeffs, 1))
	if err != nil {
		t.Fatal(err)
	}
	shares := map[string]string{"1": ct}
	sig := frost.SignPayload(frost.AuthKey(seeds[0], room), frost.DkgPayload(room, 1, commsHex, badPok, shares))
	w, resp := doJSON(t, s.http.Handler, "POST", "/api/rooms/"+room+"/dkg", map[string]any{
		"idx": 1, "commitments": commsHex, "pok": badPok, "shares": shares, "sig": sig,
	})
	if w.Code != 400 {
		t.Fatalf("DKG round with a PoK for the wrong polynomial accepted: %d %v", w.Code, resp)
	}
}

// TestPostDkgRejectsWrongCommitmentOrShareCount checks the structural guard that every dealer
// must submit exactly `threshold` commitments and exactly `total` shares.
func TestPostDkgRejectsWrongCommitmentOrShareCount(t *testing.T) {
	s := testServer(t)
	const threshold, total = 2, 3
	room, seeds := setupCeremony(t, s.http.Handler, threshold, total)
	coeffs := frost.DealerPolynomial(seeds[0], room, threshold)
	comms := frost.Commitments(coeffs)
	// Only one commitment submitted, but threshold=2 requires two.
	commsHex := []string{hex.EncodeToString(comms[0])}
	pok := frost.ProveKnowledge(seeds[0], room, 1, coeffs)
	shares := map[string]string{}
	for j := 1; j <= total; j++ {
		ct, err := frost.EncryptShare(frost.PubPoint(frost.EncKey(seeds[j-1], room)), frost.EvalShare(coeffs, j))
		if err != nil {
			t.Fatal(err)
		}
		shares[fmt.Sprintf("%d", j)] = ct
	}
	sig := frost.SignPayload(frost.AuthKey(seeds[0], room), frost.DkgPayload(room, 1, commsHex, pok, shares))
	w, resp := doJSON(t, s.http.Handler, "POST", "/api/rooms/"+room+"/dkg", map[string]any{
		"idx": 1, "commitments": commsHex, "pok": pok, "shares": shares, "sig": sig,
	})
	if w.Code != 400 {
		t.Fatalf("DKG round with too few commitments accepted: %d %v", w.Code, resp)
	}
}

// TestPostPartialRejectsSignerNotInLockedSet checks that only participants in the locked signer
// set may submit a partial, even with an otherwise perfectly valid signature.
func TestPostPartialRejectsSignerNotInLockedSet(t *testing.T) {
	s := testServer(t)
	const threshold, total = 1, 2
	room, seeds := setupCeremony(t, s.http.Handler, threshold, total)
	runDkg(t, s.http.Handler, room, threshold, total, seeds)

	msg := "0x" + hex.EncodeToString(frost.HashMessage([]byte("locked set test")).ToLittleEndianBytes()[:])
	nonce, err := frost.RandomRequestNonce()
	if err != nil {
		t.Fatal(err)
	}
	sig := frost.SignPayload(frost.AuthKey(seeds[0], room), frost.ProposePayload(room, 1, msg, nonce))
	w, resp := doJSON(t, s.http.Handler, "POST", "/api/rooms/"+room+"/proposals", map[string]any{
		"message": msg, "proposer": 1, "nonce": nonce, "sig": sig,
	})
	if w.Code != 200 {
		t.Fatalf("createProposal failed: %d %v", w.Code, resp)
	}
	id := int64(resp["id"].(float64))

	// Participant 1 commits and (since threshold=1) locks the signer set alone.
	np, err := frost.RandomNonces()
	if err != nil {
		t.Fatal(err)
	}
	d, e := np.Commit()
	csig := frost.SignPayload(frost.AuthKey(seeds[0], room), frost.CommitPayload(id, 1, d, e))
	if w, resp := doJSON(t, s.http.Handler, "POST", fmt.Sprintf("/api/proposals/%d/commit", id), map[string]any{
		"idx": 1, "d": d, "e": e, "sig": csig,
	}); w.Code != 200 {
		t.Fatalf("postCommit failed: %d %v", w.Code, resp)
	}

	// Participant 2, who is not in the locked set, attempts to post a partial anyway with a
	// validly-signed request.
	bogusZ := hex.EncodeToString(make([]byte, 40))
	psig := frost.SignPayload(frost.AuthKey(seeds[1], room), frost.PartialPayload(id, 2, bogusZ))
	w, resp = doJSON(t, s.http.Handler, "POST", fmt.Sprintf("/api/proposals/%d/partial", id), map[string]any{
		"idx": 2, "s": bogusZ, "sig": psig,
	})
	if w.Code != 400 {
		t.Fatalf("partial from a signer outside the locked set accepted: %d %v", w.Code, resp)
	}
}

// TestPostCommitRejectsAfterSignerSetLocked checks that the signer set, once locked, cannot be
// reopened by a late commitment from an excluded participant.
func TestPostCommitRejectsAfterSignerSetLocked(t *testing.T) {
	s := testServer(t)
	const threshold, total = 1, 2
	room, seeds := setupCeremony(t, s.http.Handler, threshold, total)
	runDkg(t, s.http.Handler, room, threshold, total, seeds)

	msg := "0x" + hex.EncodeToString(frost.HashMessage([]byte("late commit test")).ToLittleEndianBytes()[:])
	nonce, err := frost.RandomRequestNonce()
	if err != nil {
		t.Fatal(err)
	}
	sig := frost.SignPayload(frost.AuthKey(seeds[0], room), frost.ProposePayload(room, 1, msg, nonce))
	w, resp := doJSON(t, s.http.Handler, "POST", "/api/rooms/"+room+"/proposals", map[string]any{
		"message": msg, "proposer": 1, "nonce": nonce, "sig": sig,
	})
	if w.Code != 200 {
		t.Fatalf("createProposal failed: %d %v", w.Code, resp)
	}
	id := int64(resp["id"].(float64))

	np1, err := frost.RandomNonces()
	if err != nil {
		t.Fatal(err)
	}
	d1, e1 := np1.Commit()
	c1sig := frost.SignPayload(frost.AuthKey(seeds[0], room), frost.CommitPayload(id, 1, d1, e1))
	if w, resp := doJSON(t, s.http.Handler, "POST", fmt.Sprintf("/api/proposals/%d/commit", id), map[string]any{
		"idx": 1, "d": d1, "e": e1, "sig": c1sig,
	}); w.Code != 200 {
		t.Fatalf("first commit (locks the set at threshold=1) failed: %d %v", w.Code, resp)
	}

	np2, err := frost.RandomNonces()
	if err != nil {
		t.Fatal(err)
	}
	d2, e2 := np2.Commit()
	c2sig := frost.SignPayload(frost.AuthKey(seeds[1], room), frost.CommitPayload(id, 2, d2, e2))
	w, resp = doJSON(t, s.http.Handler, "POST", fmt.Sprintf("/api/proposals/%d/commit", id), map[string]any{
		"idx": 2, "d": d2, "e": e2, "sig": c2sig,
	})
	if w.Code != 400 {
		t.Fatalf("commit accepted after the signer set was already locked: %d %v", w.Code, resp)
	}
}

// TestExecuteRejectsBeforeAllPartialsSubmitted checks that aggregation cannot proceed with a
// partial signature still missing from the locked signer set.
func TestExecuteRejectsBeforeAllPartialsSubmitted(t *testing.T) {
	s := testServer(t)
	const threshold, total = 2, 2
	room, seeds := setupCeremony(t, s.http.Handler, threshold, total)
	runDkg(t, s.http.Handler, room, threshold, total, seeds)

	msg := "0x" + hex.EncodeToString(frost.HashMessage([]byte("missing partial test")).ToLittleEndianBytes()[:])
	nonce, err := frost.RandomRequestNonce()
	if err != nil {
		t.Fatal(err)
	}
	sig := frost.SignPayload(frost.AuthKey(seeds[0], room), frost.ProposePayload(room, 1, msg, nonce))
	w, resp := doJSON(t, s.http.Handler, "POST", "/api/rooms/"+room+"/proposals", map[string]any{
		"message": msg, "proposer": 1, "nonce": nonce, "sig": sig,
	})
	if w.Code != 200 {
		t.Fatalf("createProposal failed: %d %v", w.Code, resp)
	}
	id := int64(resp["id"].(float64))

	for _, j := range []int{1, 2} {
		np, err := frost.RandomNonces()
		if err != nil {
			t.Fatal(err)
		}
		d, e := np.Commit()
		csig := frost.SignPayload(frost.AuthKey(seeds[j-1], room), frost.CommitPayload(id, j, d, e))
		if w, resp := doJSON(t, s.http.Handler, "POST", fmt.Sprintf("/api/proposals/%d/commit", id), map[string]any{
			"idx": j, "d": d, "e": e, "sig": csig,
		}); w.Code != 200 {
			t.Fatalf("commit %d failed: %d %v", j, w.Code, resp)
		}
	}
	// Neither signer has posted a partial yet — execute must refuse to aggregate.
	w, resp = doJSON(t, s.http.Handler, "POST", fmt.Sprintf("/api/proposals/%d/execute", id), map[string]any{})
	if w.Code != 400 {
		t.Fatalf("execute with no partials submitted accepted: %d %v", w.Code, resp)
	}
}

// TestExecuteRejectsUnknownProposal checks the not-found path independently of any ceremony
// state.
func TestExecuteRejectsUnknownProposal(t *testing.T) {
	s := testServer(t)
	w, resp := doJSON(t, s.http.Handler, "POST", "/api/proposals/999999/execute", map[string]any{})
	if w.Code != 404 {
		t.Fatalf("execute for a nonexistent proposal id returned %d, want 404: %v", w.Code, resp)
	}
}

// TestCreateProposalRejectsBeforeDKGCompletes checks that a proposal cannot be created (and thus
// signed) before the group key exists.
func TestCreateProposalRejectsBeforeDKGCompletes(t *testing.T) {
	s := testServer(t)
	room, seeds := setupCeremony(t, s.http.Handler, 1, 2) // 2 participants, neither has run DKG
	msg := "0x" + hex.EncodeToString(frost.HashMessage([]byte("premature proposal")).ToLittleEndianBytes()[:])
	nonce, err := frost.RandomRequestNonce()
	if err != nil {
		t.Fatal(err)
	}
	sig := frost.SignPayload(frost.AuthKey(seeds[0], room), frost.ProposePayload(room, 1, msg, nonce))
	w, resp := doJSON(t, s.http.Handler, "POST", "/api/rooms/"+room+"/proposals", map[string]any{
		"message": msg, "proposer": 1, "nonce": nonce, "sig": sig,
	})
	if w.Code != 400 {
		t.Fatalf("proposal accepted before DKG completed: %d %v", w.Code, resp)
	}
}

// TestCreateProposalRejectsNonTxHashMessage checks the message-format restriction (a 40-byte
// Lighter tx hash) at the API layer, not just in frost.ParseTxHash's own unit tests.
func TestCreateProposalRejectsNonTxHashMessage(t *testing.T) {
	s := testServer(t)
	const threshold, total = 1, 1
	room, seeds := setupCeremony(t, s.http.Handler, threshold, total)
	runDkg(t, s.http.Handler, room, threshold, total, seeds)
	for _, bad := range []string{"", "hello world", "0xnothex", "0x" + hex.EncodeToString(make([]byte, 39))} {
		nonce, err := frost.RandomRequestNonce()
		if err != nil {
			t.Fatal(err)
		}
		sig := frost.SignPayload(frost.AuthKey(seeds[0], room), frost.ProposePayload(room, 1, bad, nonce))
		w, resp := doJSON(t, s.http.Handler, "POST", "/api/rooms/"+room+"/proposals", map[string]any{
			"message": bad, "proposer": 1, "nonce": nonce, "sig": sig,
		})
		if w.Code != 400 {
			t.Fatalf("non-tx-hash message %q accepted: %d %v", bad, w.Code, resp)
		}
	}
}
