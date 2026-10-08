// Command e2e exercises the full FROST HTTP flow against a running server: create room,
// join 4 participants (signed join statements), run the DKG (PoK + encrypted shares),
// propose a message, sign with 3 participants (two-nonce commitments, binding factors),
// execute and check the aggregated signature verifies with the SDK verifier.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"strconv"

	curve "github.com/elliottech/poseidon_crypto/curve/ecgfp5"

	"github.com/elliottech/threshold-sig-poc/frost"
	"github.com/elliottech/threshold-sig-poc/tsigclient"
)

var base = flag.String("base", "http://localhost:9000", "server base URL")

func main() {
	flag.Parse()
	const n, t = 4, 3
	cl := tsigclient.New(*base)

	// Generate identities first so the room can be created with an address allowlist.
	seeds := make([][]byte, n+1)
	addrs := make([]string, 0, n)
	for j := 1; j <= n; j++ {
		seeds[j] = make([]byte, 64)
		_, _ = rand.Read(seeds[j])
		addrs = append(addrs, frost.EthAddress(frost.EthKeyFromSeed(seeds[j])))
	}

	room, err := cl.CreateRoom(t, n, addrs)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("room:", room)

	// An address not on the allowlist must be rejected even with a valid join signature.
	introSeed := make([]byte, 64)
	_, _ = rand.Read(introSeed)
	introKey := frost.EthKeyFromSeed(introSeed)
	introAddr := frost.EthAddress(introKey)
	introAuth := frost.PubPoint(frost.AuthKey(introSeed, room))
	introEnc := frost.PubPoint(frost.EncKey(introSeed, room))
	introSig := frost.SignPersonal(introKey, frost.JoinStatement(room, t, n, addrs, introAuth, introEnc, introAddr))
	if _, _, err := cl.Join(room, introAddr, introAuth, introEnc, introSig); err == nil {
		log.Fatal("unlisted address was allowed to join an allowlisted room")
	}
	fmt.Println("unlisted address rejected OK")

	for j := 1; j <= n; j++ {
		ethKey := frost.EthKeyFromSeed(seeds[j])
		addr := frost.EthAddress(ethKey)
		authPk := frost.PubPoint(frost.AuthKey(seeds[j], room))
		encPk := frost.PubPoint(frost.EncKey(seeds[j], room))
		ethSig := frost.SignPersonal(ethKey, frost.JoinStatement(room, t, n, addrs, authPk, encPk, addr))
		idx, _, err := cl.Join(room, addr, authPk, encPk, ethSig)
		if err != nil {
			log.Fatal(err)
		}
		if idx != j {
			log.Fatalf("expected idx %d, got %d", j, idx)
		}
	}

	st, err := cl.Room(room)
	if err != nil {
		log.Fatal(err)
	}
	for j := 1; j <= n; j++ {
		coeffs := frost.DealerPolynomial(seeds[j], room, t)
		comms := frost.Commitments(coeffs)
		commsHex := make([]string, len(comms))
		for i, c := range comms {
			commsHex[i] = hex.EncodeToString(c)
		}
		pok := frost.ProveKnowledge(seeds[j], room, j, coeffs)
		shares := map[string]string{}
		for k := 1; k <= n; k++ {
			ct, err := frost.EncryptShare(st.Participants[k-1].EncPk, frost.EvalShare(coeffs, k))
			if err != nil {
				log.Fatal(err)
			}
			shares[strconv.Itoa(k)] = ct
		}
		sig := frost.SignPayload(frost.AuthKey(seeds[j], room), frost.DkgPayload(room, j, commsHex, pok, shares))
		if err := cl.PostDkg(room, j, commsHex, pok, shares, sig); err != nil {
			log.Fatal(err)
		}
	}

	if st, err = cl.Room(room); err != nil {
		log.Fatal(err)
	}
	if st.State != "ready" || st.GroupPk == "" {
		log.Fatalf("room not ready: %+v", st)
	}
	fmt.Println("group pk:", st.GroupPk)

	// Client-side verification: PoKs, decrypted shares, recomputed group key.
	constants := make([][]byte, 0, n)
	for _, p := range st.Participants {
		cb, _ := hex.DecodeString(p.Commitments[0])
		if err := frost.VerifyPoK(room, p.Idx, cb, *p.Pok); err != nil {
			log.Fatalf("participant %d PoK: %v", p.Idx, err)
		}
		if err := frost.VerifyJoin(room, t, n, addrs, p.AuthPk, p.EncPk, p.Address, p.EthSig); err != nil {
			log.Fatalf("participant %d join statement: %v", p.Idx, err)
		}
		constants = append(constants, cb)
	}
	groupPk, err := frost.GroupPublicKey(constants)
	if err != nil {
		log.Fatal(err)
	}
	if hex.EncodeToString(groupPk) != st.GroupPk {
		log.Fatal("server group pk does not match locally recomputed one")
	}
	fmt.Println("client-side verification OK (join sigs, PoKs, group pk)")

	// Ceremony fingerprint must be non-empty and stable across independent fetches.
	parts := make([]frost.DkgParticipant, 0, n)
	for _, p := range st.Participants {
		parts = append(parts, frost.DkgParticipant{
			Idx: p.Idx, Address: p.Address, AuthPk: p.AuthPk, EncPk: p.EncPk,
			Commitments: p.Commitments, PoK: *p.Pok,
		})
	}
	fp := frost.DkgFingerprint(room, t, n, st.Allowed, parts)
	st2, err := cl.Room(room)
	if err != nil {
		log.Fatal(err)
	}
	parts2 := make([]frost.DkgParticipant, 0, n)
	for _, p := range st2.Participants {
		parts2 = append(parts2, frost.DkgParticipant{
			Idx: p.Idx, Address: p.Address, AuthPk: p.AuthPk, EncPk: p.EncPk,
			Commitments: p.Commitments, PoK: *p.Pok,
		})
	}
	if fp == "" || fp != frost.DkgFingerprint(room, t, n, st2.Allowed, parts2) {
		log.Fatal("ceremony fingerprint empty or unstable across fetches")
	}
	fmt.Println("ceremony fingerprint:", fp)

	hashedMsg := frost.HashMessage([]byte("hello from e2e"))
	msg := "0x" + hex.EncodeToString(hashedMsg.ToLittleEndianBytes())
	forgedNonce, err := frost.RandomRequestNonce()
	if err != nil {
		log.Fatal(err)
	}
	// A proposal forged in another participant's name must be rejected by the server.
	forgedSig := frost.SignPayload(frost.AuthKey(seeds[1], room), frost.ProposePayload(room, 2, msg, forgedNonce))
	if _, err := cl.Propose(room, msg, 2, forgedNonce, forgedSig); err == nil {
		log.Fatal("forged proposal (wrong proposer key) was accepted")
	}
	fmt.Println("forged proposal rejected OK")
	nonce, err := frost.RandomRequestNonce()
	if err != nil {
		log.Fatal(err)
	}
	sig := frost.SignPayload(frost.AuthKey(seeds[1], room), frost.ProposePayload(room, 1, msg, nonce))
	pid, err := cl.Propose(room, msg, 1, nonce, sig)
	if err != nil {
		log.Fatal(err)
	}
	// A replayed proposal (same signed request) must not create a duplicate.
	if replayedID, err := cl.Propose(room, msg, 1, nonce, sig); err != nil || replayedID != pid {
		log.Fatalf("replayed proposal was not deduplicated: id=%d err=%v", replayedID, err)
	}
	fmt.Println("replayed proposal deduplicated OK")

	signers := []int{1, 3, 4}
	noncePairs := map[int]frost.NoncePair{}
	for _, j := range signers {
		np, err := frost.RandomNonces()
		if err != nil {
			log.Fatal(err)
		}
		noncePairs[j] = np
		d, e := np.Commit()
		sig := frost.SignPayload(frost.AuthKey(seeds[j], room), frost.CommitPayload(pid, j, d, e))
		if err := cl.Commit(pid, j, d, e, sig); err != nil {
			log.Fatal(err)
		}
	}

	if st, err = cl.Room(room); err != nil {
		log.Fatal(err)
	}
	prop := st.Proposals[0]
	set := prop.SignerSet
	fmt.Println("locked signer set:", set)

	commits := make([]frost.Commitment, 0, len(set))
	for _, m := range set {
		c := prop.Commits[strconv.Itoa(m)]
		commits = append(commits, frost.Commitment{Idx: m, D: c["d"], E: c["e"]})
	}
	aggR, err := frost.GroupCommitment([]byte(msg), commits)
	if err != nil {
		log.Fatal(err)
	}
	hashed, err := frost.ParseTxHash([]byte(msg))
	if err != nil {
		log.Fatal(err)
	}
	challenge := frost.Challenge(aggR, hashed)

	for _, j := range set {
		encSk := frost.EncKey(seeds[j], room)
		received := []curve.ECgFp5Scalar{}
		for i := 1; i <= n; i++ {
			sh, err := frost.DecryptShare(encSk, st.Shares[fmt.Sprintf("%d-%d", i, j)])
			if err != nil {
				log.Fatalf("share %d->%d: %v", i, j, err)
			}
			received = append(received, sh)
		}
		x := frost.SigningShare(received)
		lambda, err := frost.LagrangeCoefficient(j, set)
		if err != nil {
			log.Fatal(err)
		}
		rho := frost.BindingFactor(j, []byte(msg), commits)
		z := frost.PartialSignature(noncePairs[j], rho, challenge, lambda, x)
		zHex := hex.EncodeToString(z.ToLittleEndianBytes())
		sig := frost.SignPayload(frost.AuthKey(seeds[j], room), frost.PartialPayload(pid, j, zHex))
		if err := cl.Partial(pid, j, zHex, sig); err != nil {
			log.Fatal(err)
		}
	}

	sig, valid, verifyErr, err := cl.Execute(pid)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("final sig:", sig)
	if !valid {
		log.Fatal("aggregated signature INVALID: ", verifyErr)
	}
	fmt.Println("aggregated signature VALID — e2e OK")
}
