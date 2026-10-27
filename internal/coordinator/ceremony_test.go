package coordinator

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	curve "github.com/elliottech/poseidon_crypto/curve/ecgfp5"
	"github.com/elliottech/threshold-signature/frost"
)

func doJSON(t *testing.T, h http.Handler, method, path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, path, &buf))
	var out map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: bad JSON response: %v (%s)", method, path, err, w.Body.String())
		}
	}
	return w, out
}

// setupCeremony creates a room and joins n participants with real signed join statements,
// exercising createRoom and joinRoom exactly as an honest CLI/browser client would.
func setupCeremony(t *testing.T, h http.Handler, threshold, total int) (room string, seeds [][]byte) {
	t.Helper()
	_, resp := doJSON(t, h, "POST", "/api/rooms", map[string]any{"threshold": threshold, "total": total})
	room, ok := resp["room"].(string)
	if !ok || room == "" {
		t.Fatalf("room creation did not return a room code: %v", resp)
	}
	seeds = make([][]byte, total)
	for i := 0; i < total; i++ {
		seed := []byte(fmt.Sprintf("ceremony participant seed #%d for %s", i, t.Name()))
		seeds[i] = seed
		ethKey := frost.EthKeyFromSeed(seed)
		address := frost.EthAddress(ethKey)
		authPk := frost.PubPoint(frost.AuthKey(seed, room))
		encPk := frost.PubPoint(frost.EncKey(seed, room))
		ethSig := frost.SignPersonal(ethKey, frost.JoinStatement(room, threshold, total, nil, authPk, encPk, address))
		w, joinResp := doJSON(t, h, "POST", "/api/rooms/"+room+"/join", map[string]any{
			"address": address, "authPk": authPk, "encPk": encPk, "ethSig": ethSig,
		})
		if w.Code != 200 {
			t.Fatalf("join %d failed: %d %v", i, w.Code, joinResp)
		}
	}
	return room, seeds
}

// runDkg posts every participant's DKG round through the real HTTP handler, exercising postDkg's
// signature verification, PoK verification, and share persistence end to end.
func runDkg(t *testing.T, h http.Handler, room string, threshold, total int, seeds [][]byte) (groupPk string) {
	t.Helper()
	encPks := make(map[int]string, total)
	for j := 1; j <= total; j++ {
		encPks[j] = frost.PubPoint(frost.EncKey(seeds[j-1], room))
	}
	for i := 0; i < total; i++ {
		idx := i + 1
		coeffs := frost.DealerPolynomial(seeds[i], room, threshold)
		comms := frost.Commitments(coeffs)
		commsHex := make([]string, len(comms))
		for k, c := range comms {
			commsHex[k] = hex.EncodeToString(c)
		}
		pok := frost.ProveKnowledge(seeds[i], room, idx, coeffs)
		shares := map[string]string{}
		for j := 1; j <= total; j++ {
			ct, err := frost.EncryptShare(encPks[j], frost.EvalShare(coeffs, j))
			if err != nil {
				t.Fatal(err)
			}
			shares[fmt.Sprintf("%d", j)] = ct
		}
		sig := frost.SignPayload(frost.AuthKey(seeds[i], room), frost.DkgPayload(room, idx, commsHex, pok, shares))
		w, resp := doJSON(t, h, "POST", "/api/rooms/"+room+"/dkg", map[string]any{
			"idx": idx, "commitments": commsHex, "pok": pok, "shares": shares, "sig": sig,
		})
		if w.Code != 200 {
			t.Fatalf("dkg %d failed: %d %v", idx, w.Code, resp)
		}
	}
	w, resp := doJSON(t, h, "GET", "/api/rooms/"+room, nil)
	if w.Code != 200 {
		t.Fatalf("room fetch failed: %d %v", w.Code, resp)
	}
	groupPk, _ = resp["groupPk"].(string)
	if groupPk == "" {
		t.Fatal("DKG did not complete: no group public key")
	}
	return groupPk
}

func TestFullCeremonyOverHTTP(t *testing.T) {
	s := testServer(t)
	const threshold, total = 2, 3
	room, seeds := setupCeremony(t, s.http.Handler, threshold, total)
	runDkg(t, s.http.Handler, room, threshold, total, seeds)

	// listRooms and getRoom (0% covered before this test) both reflect the ceremony so far.
	if w, resp := doJSON(t, s.http.Handler, "GET", "/api/rooms", nil); w.Code != 200 {
		t.Fatalf("listRooms failed: %d %v", w.Code, resp)
	} else if rooms, _ := resp["rooms"].([]any); len(rooms) != 1 {
		t.Fatalf("expected 1 room, got %v", resp)
	}

	msg := "0x" + hex.EncodeToString(frost.HashMessage([]byte("full ceremony test tx")).ToLittleEndianBytes()[:])
	nonce, err := frost.RandomRequestNonce()
	if err != nil {
		t.Fatal(err)
	}
	proposer := 1
	sig := frost.SignPayload(frost.AuthKey(seeds[proposer-1], room), frost.ProposePayload(room, proposer, msg, nonce))
	w, resp := doJSON(t, s.http.Handler, "POST", "/api/rooms/"+room+"/proposals", map[string]any{
		"message": msg, "proposer": proposer, "nonce": nonce, "sig": sig,
	})
	if w.Code != 200 {
		t.Fatalf("createProposal failed: %d %v", w.Code, resp)
	}
	idFloat, ok := resp["id"].(float64)
	if !ok {
		t.Fatalf("no proposal id returned: %v", resp)
	}
	id := int64(idFloat)

	// Two signers (meets the 2-of-3 threshold) post nonce commitments to lock the signer set.
	signers := []int{1, 2}
	nonces := map[int]frost.NoncePair{}
	for _, j := range signers {
		np, err := frost.RandomNonces()
		if err != nil {
			t.Fatal(err)
		}
		nonces[j] = np
		d, e := np.Commit()
		csig := frost.SignPayload(frost.AuthKey(seeds[j-1], room), frost.CommitPayload(id, j, d, e))
		w, resp := doJSON(t, s.http.Handler, "POST", fmt.Sprintf("/api/proposals/%d/commit", id), map[string]any{
			"idx": j, "d": d, "e": e, "sig": csig,
		})
		if w.Code != 200 {
			t.Fatalf("postCommit %d failed: %d %v", j, w.Code, resp)
		}
	}

	// getRoom now exposes the locked signer set and commitments needed to build partials.
	w, resp = doJSON(t, s.http.Handler, "GET", "/api/rooms/"+room, nil)
	if w.Code != 200 {
		t.Fatalf("room fetch after commit failed: %d %v", w.Code, resp)
	}
	proposalsRaw, _ := resp["proposals"].([]any)
	var commits map[string]any
	for _, p := range proposalsRaw {
		pm, _ := p.(map[string]any)
		if int64(pm["id"].(float64)) == id {
			commits, _ = pm["commits"].(map[string]any)
		}
	}
	if commits == nil {
		t.Fatal("locked proposal missing commits in room state")
	}
	frostCommits := make([]frost.Commitment, 0, len(signers))
	for _, j := range signers {
		c := commits[fmt.Sprintf("%d", j)].(map[string]any)
		frostCommits = append(frostCommits, frost.Commitment{Idx: j, D: c["d"].(string), E: c["e"].(string)})
	}

	// Recompute each signer's real partial and post it — exercises postPartial's full
	// cryptographic verification path (binding factor, challenge, Lagrange coefficient, public
	// share), not just its plumbing.
	allDkgComms := make([][][]byte, total)
	for i := 0; i < total; i++ {
		coeffs := frost.DealerPolynomial(seeds[i], room, threshold)
		allDkgComms[i] = frost.Commitments(coeffs)
	}
	for _, j := range signers {
		encSk := frost.EncKey(seeds[j-1], room)
		received := make([]curve.ECgFp5Scalar, 0, total)
		for i := 0; i < total; i++ {
			ct, err := frost.EncryptShare(frost.PubPoint(frost.EncKey(seeds[j-1], room)), frost.EvalShare(frost.DealerPolynomial(seeds[i], room, threshold), j))
			if err != nil {
				t.Fatal(err)
			}
			sh, err := frost.DecryptShare(encSk, ct)
			if err != nil {
				t.Fatal(err)
			}
			received = append(received, sh)
		}
		signingShare := frost.SigningShare(received)
		aggR, err := frost.GroupCommitment([]byte(msg), frostCommits)
		if err != nil {
			t.Fatal(err)
		}
		hashed, err := frost.ParseTxHash([]byte(msg))
		if err != nil {
			t.Fatal(err)
		}
		challenge := frost.Challenge(aggR, hashed)
		lambda, err := frost.LagrangeCoefficient(j, signers)
		if err != nil {
			t.Fatal(err)
		}
		rho := frost.BindingFactor(j, []byte(msg), frostCommits)
		z := frost.PartialSignature(nonces[j], rho, challenge, lambda, signingShare)
		zHex := hex.EncodeToString(z.ToLittleEndianBytes())
		psig := frost.SignPayload(frost.AuthKey(seeds[j-1], room), frost.PartialPayload(id, j, zHex))
		w, resp := doJSON(t, s.http.Handler, "POST", fmt.Sprintf("/api/proposals/%d/partial", id), map[string]any{
			"idx": j, "s": zHex, "sig": psig,
		})
		if w.Code != 200 {
			t.Fatalf("postPartial %d failed: %d %v", j, w.Code, resp)
		}
	}

	w, resp = doJSON(t, s.http.Handler, "POST", fmt.Sprintf("/api/proposals/%d/execute", id), map[string]any{})
	if w.Code != 200 {
		t.Fatalf("executeProposal failed: %d %v", w.Code, resp)
	}
	if valid, _ := resp["valid"].(bool); !valid {
		t.Fatalf("aggregated signature invalid: %v", resp)
	}
	if _, ok := resp["sig"].(string); !ok {
		t.Fatalf("no signature returned: %v", resp)
	}
}

// TestProposalReplayIsDeduplicated regression-tests the replay-protection fix: resubmitting the
// exact same signed (room, proposer, nonce, message, sig) must return the original proposal
// instead of creating a duplicate, and the duplicate must be marked "replayed" in the response.
func TestProposalReplayIsDeduplicated(t *testing.T) {
	s := testServer(t)
	const threshold, total = 1, 1
	room, seeds := setupCeremony(t, s.http.Handler, threshold, total)
	runDkg(t, s.http.Handler, room, threshold, total, seeds)

	msg := "0x" + hex.EncodeToString(frost.HashMessage([]byte("replay test tx")).ToLittleEndianBytes()[:])
	nonce, err := frost.RandomRequestNonce()
	if err != nil {
		t.Fatal(err)
	}
	sig := frost.SignPayload(frost.AuthKey(seeds[0], room), frost.ProposePayload(room, 1, msg, nonce))
	body := map[string]any{"message": msg, "proposer": 1, "nonce": nonce, "sig": sig}

	w1, resp1 := doJSON(t, s.http.Handler, "POST", "/api/rooms/"+room+"/proposals", body)
	if w1.Code != 200 {
		t.Fatalf("first proposal failed: %d %v", w1.Code, resp1)
	}
	firstID := resp1["id"]
	if replayed, _ := resp1["replayed"].(bool); replayed {
		t.Fatal("first submission was marked as a replay")
	}

	w2, resp2 := doJSON(t, s.http.Handler, "POST", "/api/rooms/"+room+"/proposals", body)
	if w2.Code != 200 {
		t.Fatalf("replayed proposal was rejected instead of deduplicated: %d %v", w2.Code, resp2)
	}
	if resp2["id"] != firstID {
		t.Fatalf("replay returned a different proposal id: got %v, want %v", resp2["id"], firstID)
	}
	if replayed, _ := resp2["replayed"].(bool); !replayed {
		t.Fatal("replayed submission was not marked as a replay")
	}

	var count int
	if err := s.db.QueryRow("SELECT count(*) FROM proposals WHERE room=?", room).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("replay created a duplicate proposal: %d rows", count)
	}

	// A genuinely new nonce for the same message must still be accepted as a distinct proposal.
	nonce2, err := frost.RandomRequestNonce()
	if err != nil {
		t.Fatal(err)
	}
	sig2 := frost.SignPayload(frost.AuthKey(seeds[0], room), frost.ProposePayload(room, 1, msg, nonce2))
	w3, resp3 := doJSON(t, s.http.Handler, "POST", "/api/rooms/"+room+"/proposals", map[string]any{
		"message": msg, "proposer": 1, "nonce": nonce2, "sig": sig2,
	})
	if w3.Code != 200 {
		t.Fatalf("second distinct proposal failed: %d %v", w3.Code, resp3)
	}
	if resp3["id"] == firstID {
		t.Fatal("distinct nonce reused the first proposal's id")
	}
}

// TestCreateProposalRejectsShortNonce checks the server-side minimum length guard on the
// replay-protection nonce, so a client can't opt out of collision resistance with a tiny value.
func TestCreateProposalRejectsShortNonce(t *testing.T) {
	s := testServer(t)
	const threshold, total = 1, 1
	room, seeds := setupCeremony(t, s.http.Handler, threshold, total)
	runDkg(t, s.http.Handler, room, threshold, total, seeds)

	msg := "0x" + hex.EncodeToString(frost.HashMessage([]byte("short nonce test")).ToLittleEndianBytes()[:])
	shortNonce := "short"
	sig := frost.SignPayload(frost.AuthKey(seeds[0], room), frost.ProposePayload(room, 1, msg, shortNonce))
	w, resp := doJSON(t, s.http.Handler, "POST", "/api/rooms/"+room+"/proposals", map[string]any{
		"message": msg, "proposer": 1, "nonce": shortNonce, "sig": sig,
	})
	if w.Code != 400 {
		t.Fatalf("short nonce accepted: %d %v", w.Code, resp)
	}
}

// TestJoinRejectsForgedSignature regression-tests that joinRoom actually verifies the EIP-191
// join statement rather than trusting the submitted address/keys, closing the gap that let a
// participant (or a malicious coordinator relaying forged data) register under a false identity.
func TestJoinRejectsForgedSignature(t *testing.T) {
	s := testServer(t)
	const threshold, total = 1, 2
	w, resp := doJSON(t, s.http.Handler, "POST", "/api/rooms", map[string]any{"threshold": threshold, "total": total})
	if w.Code != 200 {
		t.Fatalf("create room failed: %d %v", w.Code, resp)
	}
	room := resp["room"].(string)

	victimSeed := []byte("victim seed for forged-join regression test")
	attackerSeed := []byte("attacker seed for forged-join regression test")
	victimEth := frost.EthKeyFromSeed(victimSeed)
	victimAddr := frost.EthAddress(victimEth)
	attackerAuthPk := frost.PubPoint(frost.AuthKey(attackerSeed, room))
	attackerEncPk := frost.PubPoint(frost.EncKey(attackerSeed, room))

	// The attacker signs a join statement for their own keys, but claims the victim's address
	// without holding the victim's private key — RecoverEthAddress must catch the mismatch.
	attackerEth := frost.EthKeyFromSeed(attackerSeed)
	forgedSig := frost.SignPersonal(attackerEth, frost.JoinStatement(room, threshold, total, nil, attackerAuthPk, attackerEncPk, victimAddr))

	w, resp = doJSON(t, s.http.Handler, "POST", "/api/rooms/"+room+"/join", map[string]any{
		"address": victimAddr, "authPk": attackerAuthPk, "encPk": attackerEncPk, "ethSig": forgedSig,
	})
	if w.Code != 400 {
		t.Fatalf("forged join statement accepted: %d %v", w.Code, resp)
	}
	var count int
	if err := s.db.QueryRow("SELECT count(*) FROM participants WHERE room=?", room).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("forged join was persisted despite rejection")
	}
}

// TestJoinRejectsUnlistedAddress checks the allowlist gate independently of signature validity:
// a participant with a perfectly valid signature must still be turned away if their address is
// not on the room's roster.
func TestJoinRejectsUnlistedAddress(t *testing.T) {
	s := testServer(t)
	seed := []byte("unlisted address regression seed")
	ethKey := frost.EthKeyFromSeed(seed)
	address := frost.EthAddress(ethKey)

	otherAddr := "0x1111111111111111111111111111111111111111"
	w, resp := doJSON(t, s.http.Handler, "POST", "/api/rooms", map[string]any{
		"threshold": 1, "total": 1, "addresses": []string{otherAddr},
	})
	if w.Code != 200 {
		t.Fatalf("create room failed: %d %v", w.Code, resp)
	}
	room := resp["room"].(string)

	authPk := frost.PubPoint(frost.AuthKey(seed, room))
	encPk := frost.PubPoint(frost.EncKey(seed, room))
	sig := frost.SignPersonal(ethKey, frost.JoinStatement(room, 1, 1, []string{otherAddr}, authPk, encPk, address))
	w, resp = doJSON(t, s.http.Handler, "POST", "/api/rooms/"+room+"/join", map[string]any{
		"address": address, "authPk": authPk, "encPk": encPk, "ethSig": sig,
	})
	if w.Code != 403 {
		t.Fatalf("unlisted address accepted: %d %v", w.Code, resp)
	}
}

// TestPartialRejectsWrongSigner checks that postPartial's cryptographic verification actually
// catches a bad partial (here: a signer submitting a value that does not match the transcript)
// rather than trusting whatever is posted once the request signature checks out.
func TestPartialRejectsBadValue(t *testing.T) {
	s := testServer(t)
	const threshold, total = 1, 1
	room, seeds := setupCeremony(t, s.http.Handler, threshold, total)
	runDkg(t, s.http.Handler, room, threshold, total, seeds)

	msg := "0x" + hex.EncodeToString(frost.HashMessage([]byte("bad partial test")).ToLittleEndianBytes()[:])
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

	// A validly-signed request wrapping an arbitrary (wrong) scalar must still be rejected by
	// the server's own cryptographic check, not just its signature check.
	bogus := curve.ONE.ToLittleEndianBytes()
	bogusHex := hex.EncodeToString(bogus)
	psig := frost.SignPayload(frost.AuthKey(seeds[0], room), frost.PartialPayload(id, 1, bogusHex))
	w, resp = doJSON(t, s.http.Handler, "POST", fmt.Sprintf("/api/proposals/%d/partial", id), map[string]any{
		"idx": 1, "s": bogusHex, "sig": psig,
	})
	if w.Code != 400 {
		t.Fatalf("bogus partial signature accepted: %d %v", w.Code, resp)
	}
	var count int
	if err := s.db.QueryRow("SELECT count(*) FROM partials WHERE proposal_id=?", id).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("rejected partial was persisted")
	}
}
