//go:build js && wasm

// WASM bridge exposing the frost threshold crypto to the browser, mirroring the
// zklighter-sdk wasm bridge pattern (js.Global().Set + syscall/js).
// Long-term secrets derive from a random browser-local seed kept encrypted in a keystore that a
// domain-bound wallet signature unlocks; signing nonces are random and one-shot. Shares travel
// encrypted, requests are signed with the per-room auth key, and everything is verified client-side.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"syscall/js"

	curve "github.com/elliottech/poseidon_crypto/curve/ecgfp5"
	"golang.org/x/crypto/hkdf"

	"github.com/elliottech/threshold-sig-poc/frost"
)

func main() {
	c := make(chan struct{})
	println("threshold-sig-poc wasm started")
	js.Global().Set("_tsKeystoreSeal", js.FuncOf(keystoreSeal))
	js.Global().Set("_tsKeystoreOpen", js.FuncOf(keystoreOpen))
	js.Global().Set("_tsKeys", js.FuncOf(keys))
	js.Global().Set("_tsJoinStatement", js.FuncOf(joinStatement))
	js.Global().Set("_tsVerifyJoin", js.FuncOf(verifyJoin))
	js.Global().Set("_tsDkg", js.FuncOf(dkg))
	js.Global().Set("_tsVerifyRoom", js.FuncOf(verifyRoom))
	js.Global().Set("_tsDkgFingerprint", js.FuncOf(dkgFingerprint))
	js.Global().Set("_tsProposalFingerprint", js.FuncOf(proposalFingerprint))
	js.Global().Set("_tsSignPropose", js.FuncOf(signPropose))
	js.Global().Set("_tsVerifyProposal", js.FuncOf(verifyProposal))
	js.Global().Set("_tsSignCommit", js.FuncOf(signCommit))
	js.Global().Set("_tsSignPartial", js.FuncOf(signPartial))
	<-c
}

func fail(err error) any {
	return map[string]any{"error": err.Error()}
}

func seedBytes(seedHex string) ([]byte, error) {
	if len(seedHex) >= 2 && seedHex[:2] == "0x" {
		seedHex = seedHex[2:]
	}
	b, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, fmt.Errorf("bad seed hex: %w", err)
	}
	if len(b) < 32 {
		return nil, fmt.Errorf("seed too short")
	}
	return b, nil
}

func keystoreAEAD(unlockSig string) (cipher.AEAD, error) {
	sig, err := hex.DecodeString(strings.TrimPrefix(unlockSig, "0x"))
	if err != nil || len(sig) == 0 {
		return nil, fmt.Errorf("bad unlock signature")
	}
	var key [32]byte
	if _, err := io.ReadFull(hkdf.New(sha256.New, sig, nil, []byte("tsig-poc/keystore-key")), key[:]); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// keystoreSeal(unlockSig) -> {seed, blob}
//
// Generates a random 32-byte seed and encrypts it under a key derived from the wallet's
// domain-bound unlock signature. The blob is safe to persist in localStorage; the seed is not.
func keystoreSeal(_ js.Value, args []js.Value) any {
	aead, err := keystoreAEAD(args[0].String())
	if err != nil {
		return fail(err)
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return fail(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fail(err)
	}
	ct := aead.Seal(nil, nonce, seed, nil)
	return map[string]any{
		"seed": hex.EncodeToString(seed),
		"blob": hex.EncodeToString(append(nonce, ct...)),
	}
}

// keystoreOpen(unlockSig, blob) -> {seed}
func keystoreOpen(_ js.Value, args []js.Value) any {
	aead, err := keystoreAEAD(args[0].String())
	if err != nil {
		return fail(err)
	}
	blob, err := hex.DecodeString(args[1].String())
	if err != nil || len(blob) <= aead.NonceSize() {
		return fail(fmt.Errorf("bad keystore blob"))
	}
	seed, err := aead.Open(nil, blob[:aead.NonceSize()], blob[aead.NonceSize():], nil)
	if err != nil {
		return fail(fmt.Errorf("keystore could not be decrypted with this wallet signature"))
	}
	return map[string]any{"seed": hex.EncodeToString(seed)}
}

// keys(seed, room) -> {authPk, encPk}
func keys(_ js.Value, args []js.Value) any {
	seed, err := seedBytes(args[0].String())
	if err != nil {
		return fail(err)
	}
	room := args[1].String()
	return map[string]any{
		"authPk": frost.PubPoint(frost.AuthKey(seed, room)),
		"encPk":  frost.PubPoint(frost.EncKey(seed, room)),
	}
}

// splitCSV turns a comma-joined allowlist into a slice (nil when empty/open room).
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// joinStatement(room, threshold, total, allowedCSV, authPk, encPk, address) -> {statement}
func joinStatement(_ js.Value, args []js.Value) any {
	return map[string]any{
		"statement": frost.JoinStatement(args[0].String(), args[1].Int(), args[2].Int(), splitCSV(args[3].String()),
			args[4].String(), args[5].String(), args[6].String()),
	}
}

// verifyJoin(room, threshold, total, allowedCSV, authPk, encPk, address, ethSig) -> {ok, error?}
// Lets every client re-verify another participant's membership binding locally, including the
// t-of-n policy and roster the participant agreed to.
func verifyJoin(_ js.Value, args []js.Value) any {
	err := frost.VerifyJoin(args[0].String(), args[1].Int(), args[2].Int(), splitCSV(args[3].String()),
		args[4].String(), args[5].String(), args[6].String(), args[7].String())
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	return map[string]any{"ok": true}
}

// dkg(seed, room, threshold, total, myIdx, encPks {j: hex}) ->
//
//	{commitments: [hex...], pok: {r, mu}, shares: {"1": ciphertextHex, ...}, sig}
//
// Shares are ECIES-encrypted to each recipient; the returned sig authenticates the submission.
func dkg(_ js.Value, args []js.Value) any {
	seed, err := seedBytes(args[0].String())
	if err != nil {
		return fail(err)
	}
	room := args[1].String()
	threshold := args[2].Int()
	total := args[3].Int()
	myIdx := args[4].Int()
	encPks := args[5]

	coeffs := frost.DealerPolynomial(seed, room, threshold)
	comms := frost.Commitments(coeffs)
	commsHex := make([]string, len(comms))
	commsAny := make([]any, len(comms))
	for i, c := range comms {
		commsHex[i] = hex.EncodeToString(c)
		commsAny[i] = commsHex[i]
	}
	pok := frost.ProveKnowledge(seed, room, myIdx, coeffs)

	shares := map[string]string{}
	sharesAny := map[string]any{}
	for j := 1; j <= total; j++ {
		pk := encPks.Get(strconv.Itoa(j)).String()
		ct, err := frost.EncryptShare(pk, frost.EvalShare(coeffs, j))
		if err != nil {
			return fail(fmt.Errorf("encrypting share for %d: %w", j, err))
		}
		shares[strconv.Itoa(j)] = ct
		sharesAny[strconv.Itoa(j)] = ct
	}
	sig := frost.SignPayload(frost.AuthKey(seed, room), frost.DkgPayload(room, myIdx, commsHex, pok, shares))
	return map[string]any{
		"commitments": commsAny,
		"pok":         map[string]any{"r": pok.R, "mu": pok.Mu},
		"shares":      sharesAny,
		"sig":         sig,
	}
}

// verifyRoom(seed, room, myIdx, allCommitments {i: [hex...]}, myEncShares {i: ct},
//
//	poks {i: {r, mu}}) -> {ok, bad: [i...], groupPk}
//
// Decrypts our shares, verifies each against the dealer's commitments, checks every dealer's
// proof of knowledge, and recomputes the group public key locally (never trust the server's).
func verifyRoom(_ js.Value, args []js.Value) any {
	seed, err := seedBytes(args[0].String())
	if err != nil {
		return fail(err)
	}
	room := args[1].String()
	myIdx := args[2].Int()
	allComms := args[3]
	myShares := args[4]
	poks := args[5]

	encSk := frost.EncKey(seed, room)
	bad := []any{}
	constants := [][]byte{}
	keys := js.Global().Get("Object").Call("keys", allComms)
	for i := 0; i < keys.Length(); i++ {
		from := keys.Index(i).String()
		fromIdx, _ := strconv.Atoi(from)
		commsVal := allComms.Get(from)
		comms := make([][]byte, commsVal.Length())
		ok := true
		for k := 0; k < commsVal.Length(); k++ {
			cb, err := hex.DecodeString(commsVal.Index(k).String())
			if err != nil {
				ok = false
				break
			}
			comms[k] = cb
		}
		if !ok {
			bad = append(bad, from)
			continue
		}
		pokVal := poks.Get(from)
		pok := frost.PoK{R: pokVal.Get("r").String(), Mu: pokVal.Get("mu").String()}
		if err := frost.VerifyPoK(room, fromIdx, comms[0], pok); err != nil {
			bad = append(bad, from)
			continue
		}
		share, err := frost.DecryptShare(encSk, myShares.Get(from).String())
		if err != nil {
			bad = append(bad, from)
			continue
		}
		if err := frost.VerifyShare(share, myIdx, comms); err != nil {
			bad = append(bad, from)
			continue
		}
		constants = append(constants, comms[0])
	}
	if len(bad) > 0 {
		return map[string]any{"ok": false, "bad": bad}
	}
	groupPk, err := frost.GroupPublicKey(constants)
	if err != nil {
		return fail(err)
	}
	return map[string]any{"ok": true, "bad": bad, "groupPk": hex.EncodeToString(groupPk)}
}

// dkgFingerprint(room, threshold, total, allowedCSV,
//
//	participants {i: {address, authPk, encPk, commitments: [hex...], pok: {r, mu}}}) -> {fp}
func dkgFingerprint(_ js.Value, args []js.Value) any {
	room := args[0].String()
	threshold := args[1].Int()
	total := args[2].Int()
	allowed := splitCSV(args[3].String())
	partsVal := args[4]
	var parts []frost.DkgParticipant
	keys := js.Global().Get("Object").Call("keys", partsVal)
	for i := 0; i < keys.Length(); i++ {
		k := keys.Index(i).String()
		idx, _ := strconv.Atoi(k)
		pv := partsVal.Get(k)
		commsVal := pv.Get("commitments")
		comms := make([]string, commsVal.Length())
		for j := 0; j < commsVal.Length(); j++ {
			comms[j] = commsVal.Index(j).String()
		}
		parts = append(parts, frost.DkgParticipant{
			Idx:         idx,
			Address:     pv.Get("address").String(),
			AuthPk:      pv.Get("authPk").String(),
			EncPk:       pv.Get("encPk").String(),
			Commitments: comms,
			PoK:         frost.PoK{R: pv.Get("pok").Get("r").String(), Mu: pv.Get("pok").Get("mu").String()},
		})
	}
	return map[string]any{"fp": frost.DkgFingerprint(room, threshold, total, allowed, parts)}
}

// proposalFingerprint(room, proposalID, message, signerSet [i...], commits {i: {d, e}}) -> {fp}
func proposalFingerprint(_ js.Value, args []js.Value) any {
	room := args[0].String()
	pid := int64(args[1].Int())
	msg := args[2].String()
	setVal := args[3]
	signers := make([]int, setVal.Length())
	for i := 0; i < setVal.Length(); i++ {
		signers[i] = setVal.Index(i).Int()
	}
	commitsVal := args[4]
	var commits []frost.Commitment
	keys := js.Global().Get("Object").Call("keys", commitsVal)
	for i := 0; i < keys.Length(); i++ {
		k := keys.Index(i).String()
		idx, _ := strconv.Atoi(k)
		cv := commitsVal.Get(k)
		commits = append(commits, frost.Commitment{Idx: idx, D: cv.Get("d").String(), E: cv.Get("e").String()})
	}
	return map[string]any{"fp": frost.ProposalFingerprint(room, pid, msg, signers, commits)}
}

// signPropose(seed, room, message, myIdx) -> {sig, nonce}
// nonce is a fresh random value included in the signed payload so a captured request cannot be
// replayed to create a duplicate proposal; the caller submits it alongside the signature.
func signPropose(_ js.Value, args []js.Value) any {
	seed, err := seedBytes(args[0].String())
	if err != nil {
		return fail(err)
	}
	room := args[1].String()
	msg := args[2].String()
	myIdx := args[3].Int()
	nonce, err := frost.RandomRequestNonce()
	if err != nil {
		return fail(err)
	}
	sig := frost.SignPayload(frost.AuthKey(seed, room), frost.ProposePayload(room, myIdx, msg, nonce))
	return map[string]any{"sig": sig, "nonce": nonce}
}

// verifyProposal(room, message, proposer, nonce, sig, proposerAuthPk) -> {ok} | {error}
func verifyProposal(_ js.Value, args []js.Value) any {
	room := args[0].String()
	msg := args[1].String()
	proposer := args[2].Int()
	nonce := args[3].String()
	sig := args[4].String()
	authPk := args[5].String()
	if err := frost.VerifyPayload(authPk, frost.ProposePayload(room, proposer, msg, nonce), sig); err != nil {
		return fail(err)
	}
	return map[string]any{"ok": true}
}

// signCommit(seed, room, proposalID, myIdx) -> {d, e, sig, nonces}
//
// Generates a fresh RANDOM nonce pair; the caller must persist `nonces` locally until the
// partial is produced and must never sign the same proposal twice.
func signCommit(_ js.Value, args []js.Value) any {
	seed, err := seedBytes(args[0].String())
	if err != nil {
		return fail(err)
	}
	room := args[1].String()
	proposalID := int64(args[2].Int())
	myIdx := args[3].Int()

	np, err := frost.RandomNonces()
	if err != nil {
		return fail(err)
	}
	d, e := np.Commit()
	sig := frost.SignPayload(frost.AuthKey(seed, room), frost.CommitPayload(proposalID, myIdx, d, e))
	return map[string]any{"d": d, "e": e, "sig": sig, "nonces": np.Hex()}
}

// signPartial(seed, room, proposalID, message, myIdx, signerSet [i...],
//
//	myEncShares {i: ct}, commits {i: {d, e}}, noncesHex) -> {s, sig}
//
// Decrypts our shares, recomputes binding factors + group commitment + challenge from the
// transcript, and produces the two-nonce FROST partial signature plus the request signature.
func signPartial(_ js.Value, args []js.Value) any {
	seed, err := seedBytes(args[0].String())
	if err != nil {
		return fail(err)
	}
	room := args[1].String()
	proposalID := int64(args[2].Int())
	msg := []byte(args[3].String())
	myIdx := args[4].Int()
	setVal := args[5]
	mySharesVal := args[6]
	commitsVal := args[7]
	np, err := frost.NoncePairFromHex(args[8].String())
	if err != nil {
		return fail(fmt.Errorf("stored nonce pair: %w", err))
	}

	set := make([]int, setVal.Length())
	for i := range set {
		set[i] = setVal.Index(i).Int()
	}

	// Long-term signing share x_j = sum of decrypted shares received from every dealer.
	encSk := frost.EncKey(seed, room)
	received := []curve.ECgFp5Scalar{}
	keys := js.Global().Get("Object").Call("keys", mySharesVal)
	for i := 0; i < keys.Length(); i++ {
		sh, err := frost.DecryptShare(encSk, mySharesVal.Get(keys.Index(i).String()).String())
		if err != nil {
			return fail(fmt.Errorf("bad share from dealer %s: %w", keys.Index(i).String(), err))
		}
		received = append(received, sh)
	}
	x := frost.SigningShare(received)

	commits := make([]frost.Commitment, 0, len(set))
	for _, j := range set {
		cv := commitsVal.Get(strconv.Itoa(j))
		commits = append(commits, frost.Commitment{Idx: j, D: cv.Get("d").String(), E: cv.Get("e").String()})
		if j == myIdx {
			// The transcript must contain exactly the commitment of OUR stored nonces; anything
			// else means the server swapped it and signing would leak the share.
			d, e := np.Commit()
			if cv.Get("d").String() != d || cv.Get("e").String() != e {
				return fail(fmt.Errorf("server-reported nonce commitment does not match our stored nonces — refusing to sign"))
			}
		}
	}
	aggR, err := frost.GroupCommitment(msg, commits)
	if err != nil {
		return fail(err)
	}
	hashed, err := frost.ParseTxHash(msg)
	if err != nil {
		return fail(err)
	}
	challenge := frost.Challenge(aggR, hashed)
	lambda, err := frost.LagrangeCoefficient(myIdx, set)
	if err != nil {
		return fail(err)
	}
	rho := frost.BindingFactor(myIdx, msg, commits)
	z := frost.PartialSignature(np, rho, challenge, lambda, x)
	zHex := hex.EncodeToString(z.ToLittleEndianBytes())
	sig := frost.SignPayload(frost.AuthKey(seed, room), frost.PartialPayload(proposalID, myIdx, zHex))
	return map[string]any{"s": zHex, "sig": sig}
}
