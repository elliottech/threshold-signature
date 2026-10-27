// Command tsig is a CLI client for the threshold-signature server. It reads its config from a
// .env file (see .env.example) and drives the whole ceremony over the REST API: create/list
// rooms, join, run the DKG round, propose messages, sign and execute proposals.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	curve "github.com/elliottech/poseidon_crypto/curve/ecgfp5"

	"github.com/elliottech/threshold-signature/frost"
	"github.com/elliottech/threshold-signature/tsigclient"
)

const usage = `tsig - threshold signature ceremony CLI

Usage: tsig [-env path] <command> [args]

Config (.env, default ./.env, or plain environment variables):
  TSIG_SERVER    base URL of the coordination server (required), e.g. https://tsig.example.com
  TSIG_KEY_FILE  path to your exported key file (create one with 'tsig keygen')
  TSIG_SEED      legacy: secret seed string; prefer TSIG_KEY_FILE

Identity & keys:
  keygen [-o <file>]                     generate a new key file (default tsig-key.json)
  export-key [-o <file>]                 export the current identity to a portable key file
  whoami                                 print the address of the configured identity

Rooms & signing:
  create -t <threshold> -n <total>       create a room, prints the room code
  list                                   list all rooms on the server
  status <room>                          show room state, participants and proposals
  pending <room>                         list pending proposals and their full contents
  join <room>                            join a room with this identity
  dkg <room>                             run your DKG round (commitments + shares)
  propose <room> <tx-hash>               propose a 40-byte Lighter tx hash to sign (hex, 0x optional)
  sign <room> <proposal-id>              commit nonce + post partial signature
  execute <proposal-id>                  aggregate + verify the final signature
  watch <room> --allow-auto-sign         explicitly approve unattended signing of all proposals
`

func main() { os.Exit(run()) }

func run() (exitCode int) {
	envPath := flag.String("env", ".env", "path to .env file")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		return 2
	}

	env := loadEnv(*envPath)
	id, idErr := identityFromEnv(env)
	// The one-shot nonce journal lives next to the key file so identities never share state.
	statePath := *envPath + ".state.json"
	if kf := env["TSIG_KEY_FILE"]; kf != "" {
		statePath = kf + ".state.json"
	}
	var ns *nonceStore
	if args[0] == "sign" || args[0] == "watch" {
		// An exclusive sidecar prevents two CLI processes from consuming the same nonces.
		lock, err := os.OpenFile(statePath+".lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot lock nonce journal:", err)
			return 1
		}
		_ = lock.Close()
		defer os.Remove(statePath + ".lock")
		ns, err = openNonceStore(statePath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot load nonce journal:", err)
			return 1
		}
	}

	var err error
	if cmd := args[0]; cmd == "keygen" || cmd == "export-key" || cmd == "whoami" {
		switch cmd {
		case "keygen":
			err = cmdKeygen(args[1:])
		case "export-key":
			err = cmdExportKey(id, idErr, args[1:])
		case "whoami":
			err = cmdWhoami(id, idErr)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		return 0
	}

	if idErr != nil {
		fmt.Fprintln(os.Stderr, "error:", idErr)
		return 1
	}
	server := env["TSIG_SERVER"]
	if server == "" {
		fmt.Fprintln(os.Stderr, "error: TSIG_SERVER is not set — point it at your coordination server (see .env.example)")
		return 1
	}
	cl := tsigclient.New(server)

	switch cmd := args[0]; cmd {
	case "create":
		err = cmdCreate(cl, args[1:])
	case "list":
		err = cmdList(cl)
	case "status":
		err = cmdStatus(cl, args[1:])
	case "join":
		err = cmdJoin(cl, id, args[1:])
	case "dkg":
		err = cmdDkg(cl, id, args[1:])
	case "propose":
		err = cmdPropose(cl, id, args[1:])
	case "sign":
		err = cmdSign(cl, id, ns, args[1:])
	case "pending":
		err = cmdPending(cl, args[1:])
	case "execute":
		err = cmdExecute(cl, args[1:])
	case "watch":
		err = cmdWatch(cl, id, ns, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

// loadEnv parses simple KEY=VALUE lines; missing file is fine (env vars still apply).
func loadEnv(path string) map[string]string {
	env := map[string]string{}
	for _, k := range []string{"TSIG_SERVER", "TSIG_SEED", "TSIG_KEY_FILE"} {
		if v := os.Getenv(k); v != "" {
			env[k] = v
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return env
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		env[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return env
}

// nonceStore persists one-shot signing nonces between the commit and partial rounds, plus a
// signed flag, so the same proposal is never signed twice (nonce reuse leaks the share).
type nonceStore struct {
	path    string
	Entries map[string]*nonceEntry `json:"entries"`
}

type nonceEntry struct {
	Nonces string `json:"nonces,omitempty"`
	Signed bool   `json:"signed,omitempty"`
}

func openNonceStore(path string) (*nonceStore, error) {
	ns := &nonceStore{path: path, Entries: map[string]*nonceEntry{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ns, nil
	}
	if err != nil {
		return nil, err
	}
	ns.Entries = nil
	if err := json.Unmarshal(b, ns); err != nil {
		return nil, fmt.Errorf("invalid nonce journal: %w", err)
	}
	if ns.Entries == nil {
		return nil, errors.New("nonce journal has no entries map")
	}
	for _, ent := range ns.Entries {
		if ent == nil {
			return nil, errors.New("nonce journal contains a null entry")
		}
	}
	return ns, nil
}

func (s *nonceStore) entry(room string, pid int64) *nonceEntry {
	k := fmt.Sprintf("%s/%d", room, pid)
	if s.Entries[k] == nil {
		s.Entries[k] = &nonceEntry{}
	}
	return s.Entries[k]
}

func (s *nonceStore) save() error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".tsig-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), s.path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

type identity struct {
	seed    []byte // 64 bytes: loaded from the key file, or derived from the legacy TSIG_SEED
	ethKey  *secp256k1.PrivateKey
	address string
}

// keyFile is the portable exported-identity format: a random 64-byte seed from which the
// Ethereum key and all per-room ceremony keys derive deterministically. Anyone holding this
// file fully controls the identity — store it like a private key.
type keyFile struct {
	Version int    `json:"version"`
	Seed    string `json:"seed"` // 128 hex chars (64 bytes)
	Address string `json:"address"`
}

func identityFromSeed(seed []byte) *identity {
	ethKey := frost.EthKeyFromSeed(seed)
	return &identity{seed: seed, ethKey: ethKey, address: frost.EthAddress(ethKey)}
}

func identityFromEnv(env map[string]string) (*identity, error) {
	if path := env["TSIG_KEY_FILE"]; path != "" {
		return loadKeyFile(path)
	}
	if s := env["TSIG_SEED"]; s != "" {
		d1 := sha256.Sum256([]byte("tsig-cli-seed/1/" + s))
		d2 := sha256.Sum256([]byte("tsig-cli-seed/2/" + s))
		return identityFromSeed(append(d1[:], d2[:]...)), nil
	}
	return nil, nil
}

func loadKeyFile(path string) (*identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	var kf keyFile
	if err := json.Unmarshal(b, &kf); err != nil {
		return nil, fmt.Errorf("parsing key file %s: %w", path, err)
	}
	seed, err := hex.DecodeString(kf.Seed)
	if err != nil || len(seed) != 64 {
		return nil, fmt.Errorf("key file %s: seed must be 128 hex characters (64 bytes)", path)
	}
	id := identityFromSeed(seed)
	if kf.Address != "" && !strings.EqualFold(kf.Address, id.address) {
		return nil, fmt.Errorf("key file %s: stored address %s does not match derived address %s",
			path, kf.Address, id.address)
	}
	return id, nil
}

func writeKeyFile(path string, id *identity) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists — refusing to overwrite a key file", path)
	}
	b, err := json.MarshalIndent(keyFile{Version: 1, Seed: hex.EncodeToString(id.seed), Address: id.address}, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("o", "tsig-key.json", "output key file path")
	_ = fs.Parse(args)
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	id := identityFromSeed(seed)
	if err := writeKeyFile(*out, id); err != nil {
		return err
	}
	fmt.Printf("key file written to %s (mode 0600)\n", *out)
	fmt.Printf("address: %s\n", id.address)
	fmt.Println("Set TSIG_KEY_FILE=" + *out + " in your .env to use it.")
	fmt.Println("Back this file up somewhere safe and never share it: it fully controls this identity,")
	fmt.Println("and losing it loses your share in every room this identity joined.")
	return nil
}

func cmdExportKey(id *identity, idErr error, args []string) error {
	if idErr != nil {
		return idErr
	}
	if id == nil {
		return errors.New("no identity configured — set TSIG_KEY_FILE or TSIG_SEED, or run 'tsig keygen'")
	}
	fs := flag.NewFlagSet("export-key", flag.ExitOnError)
	out := fs.String("o", "tsig-key.json", "output key file path")
	_ = fs.Parse(args)
	if err := writeKeyFile(*out, id); err != nil {
		return err
	}
	fmt.Printf("identity %s exported to %s (mode 0600)\n", id.address, *out)
	fmt.Println("Back this file up somewhere safe and never share it.")
	return nil
}

// joinCreds derives the per-room ceremony keys and signs the join statement with the eth key,
// exactly like the browser does with MetaMask. The room's t-of-n policy is bound into the
// signed statement so the server cannot alter it after participants agreed to join.
func (id *identity) joinCreds(cl *tsigclient.Client, room string) (authPk, encPk, ethSig string, err error) {
	st, err := cl.Room(room)
	if err != nil {
		return "", "", "", err
	}
	authPk = frost.PubPoint(frost.AuthKey(id.seed, room))
	encPk = frost.PubPoint(frost.EncKey(id.seed, room))
	ethSig = frost.SignPersonal(id.ethKey, frost.JoinStatement(room, st.Threshold, st.Total, st.Allowed, authPk, encPk, id.address))
	return authPk, encPk, ethSig, nil
}

func needID(id *identity) error {
	if id == nil {
		return fmt.Errorf("no identity configured — run 'tsig keygen' and set TSIG_KEY_FILE in your .env")
	}
	return nil
}

func cmdWhoami(id *identity, idErr error) error {
	if idErr != nil {
		return idErr
	}
	if err := needID(id); err != nil {
		return err
	}
	fmt.Println(id.address)
	return nil
}

func cmdCreate(cl *tsigclient.Client, args []string) error {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	t := fs.Int("t", 2, "threshold")
	n := fs.Int("n", 3, "total participants")
	addrs := fs.String("addresses", "", "optional comma-separated allowlist of exactly n ETH addresses")
	_ = fs.Parse(args)
	var allowlist []string
	if *addrs != "" {
		allowlist = strings.Split(*addrs, ",")
	}
	room, err := cl.CreateRoom(*t, *n, allowlist)
	if err != nil {
		return err
	}
	fmt.Printf("room created: %s (%d-of-%d)\n", room, *t, *n)
	fmt.Printf("web: %s/room/%s\n", cl.Base, room)
	return nil
}

func cmdList(cl *tsigclient.Client) error {
	rooms, err := cl.ListRooms()
	if err != nil {
		return err
	}
	if len(rooms) == 0 {
		fmt.Println("no rooms yet")
		return nil
	}
	fmt.Printf("%-42s %-7s %-8s %-9s %s\n", "ROOM", "T-OF-N", "JOINED", "PROPOSALS", "DKG")
	for _, r := range rooms {
		dkg := "pending"
		if r.GroupPk != "" {
			dkg = "done"
		}
		fmt.Printf("%-42s %d-of-%-3d %-8d %-9d %s\n", r.Room, r.Threshold, r.Total, r.Joined, r.Proposals, dkg)
	}
	return nil
}

func cmdStatus(cl *tsigclient.Client, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: tsig status <room>")
	}
	st, err := cl.Room(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("room %s — %d-of-%d, state: %s\n", args[0], st.Threshold, st.Total, st.State)
	if st.GroupPk != "" {
		fmt.Printf("group public key: %s\n", st.GroupPk)
		if fp := dkgFingerprint(args[0], st); fp != "" {
			fmt.Printf("ceremony fingerprint (compare out-of-band): %s\n", fp)
		}
	}
	fmt.Println("participants:")
	for _, p := range st.Participants {
		dkg := ""
		if len(p.Commitments) > 0 {
			dkg = " [dkg done]"
		}
		fmt.Printf("  #%d %s%s\n", p.Idx, p.Address, dkg)
	}
	if len(st.Proposals) > 0 {
		fmt.Println("proposals:")
		for _, p := range st.Proposals {
			line := fmt.Sprintf("  #%d %q — %s", p.ID, p.Message, p.Status)
			if len(p.SignerSet) > 0 {
				line += fmt.Sprintf(", signers %v (%d/%d partials)", p.SignerSet, len(p.Partials), len(p.SignerSet))
				if fp := proposalFingerprint(args[0], &p); fp != "" {
					line += ", fingerprint " + fp
				}
			} else {
				line += fmt.Sprintf(", %d commits", len(p.Commits))
			}
			if p.Valid != nil {
				if *p.Valid {
					line += ", signature VALID"
				} else {
					line += ", signature INVALID"
				}
			}
			fmt.Println(line)
		}
	}
	return nil
}

// dkgFingerprint digests the room's public DKG transcript into five words that participants
// compare out-of-band; an equivocating server produces different words for different clients.
func dkgFingerprint(room string, st *tsigclient.RoomState) string {
	parts := make([]frost.DkgParticipant, 0, len(st.Participants))
	for _, p := range st.Participants {
		if len(p.Commitments) == 0 || p.Pok == nil {
			return ""
		}
		parts = append(parts, frost.DkgParticipant{
			Idx: p.Idx, Address: p.Address, AuthPk: p.AuthPk, EncPk: p.EncPk,
			Commitments: p.Commitments, PoK: *p.Pok,
		})
	}
	return frost.DkgFingerprint(room, st.Threshold, st.Total, st.Allowed, parts)
}

func proposalFingerprint(room string, p *tsigclient.Proposal) string {
	if len(p.SignerSet) == 0 {
		return ""
	}
	commits := make([]frost.Commitment, 0, len(p.SignerSet))
	for _, m := range p.SignerSet {
		c, ok := p.Commits[strconv.Itoa(m)]
		if !ok {
			return ""
		}
		commits = append(commits, frost.Commitment{Idx: m, D: c["d"], E: c["e"]})
	}
	return frost.ProposalFingerprint(room, p.ID, p.Message, p.SignerSet, commits)
}

// cmdPending prints every proposal that has not yet been executed, with its full contents:
// the exact message being signed, who proposed it, the signing progress, and the fingerprint
// to compare out-of-band once the signer set is locked.
func cmdPending(cl *tsigclient.Client, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: tsig pending <room>")
	}
	room := args[0]
	st, err := cl.Room(room)
	if err != nil {
		return err
	}
	addrOf := map[int]string{}
	for _, p := range st.Participants {
		addrOf[p.Idx] = p.Address
	}
	count := 0
	for i := range st.Proposals {
		p := &st.Proposals[i]
		if p.Status == "executed" {
			continue
		}
		count++
		fmt.Printf("proposal #%d [%s]\n", p.ID, p.Status)
		fmt.Printf("  message:  %s\n", p.Message)
		fmt.Printf("  proposer: #%d %s\n", p.Proposer, addrOf[p.Proposer])
		if len(p.SignerSet) > 0 {
			fmt.Printf("  signers:  %v (%d/%d partials posted)\n", p.SignerSet, len(p.Partials), len(p.SignerSet))
			if fp := proposalFingerprint(room, p); fp != "" {
				fmt.Printf("  fingerprint (compare out-of-band): %s\n", fp)
			}
			if len(p.Partials) == len(p.SignerSet) {
				fmt.Printf("  ready to execute: tsig execute %d\n", p.ID)
			}
		} else {
			fmt.Printf("  commits:  %d/%d (signer set not locked yet)\n", len(p.Commits), st.Threshold)
		}
	}
	if count == 0 {
		fmt.Println("no pending proposals")
	}
	return nil
}

func cmdJoin(cl *tsigclient.Client, id *identity, args []string) error {
	if err := needID(id); err != nil {
		return err
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: tsig join <room>")
	}
	authPk, encPk, ethSig, err := id.joinCreds(cl, args[0])
	if err != nil {
		return err
	}
	idx, rejoined, err := cl.Join(args[0], id.address, authPk, encPk, ethSig)
	if err != nil {
		return err
	}
	if rejoined {
		fmt.Printf("already joined %s as participant #%d\n", args[0], idx)
	} else {
		fmt.Printf("joined %s as participant #%d (%s)\n", args[0], idx, id.address)
	}
	return nil
}

func cmdDkg(cl *tsigclient.Client, id *identity, args []string) error {
	if err := needID(id); err != nil {
		return err
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: tsig dkg <room>")
	}
	room := args[0]
	st, err := cl.Room(room)
	if err != nil {
		return err
	}
	idx, err := myIdx(st, id)
	if err != nil {
		return err
	}
	if st.State == "joining" {
		return fmt.Errorf("room is still joining (%d/%d participants)", len(st.Participants), st.Total)
	}
	if err := postDkgRound(cl, id, room, st, idx); err != nil {
		return err
	}
	fmt.Println("DKG round posted (commitments + shares for every participant)")
	return nil
}

func postDkgRound(cl *tsigclient.Client, id *identity, room string, st *tsigclient.RoomState, idx int) error {
	coeffs := frost.DealerPolynomial(id.seed, room, st.Threshold)
	comms := frost.Commitments(coeffs)
	commsHex := make([]string, len(comms))
	for i, c := range comms {
		commsHex[i] = hex.EncodeToString(c)
	}
	pok := frost.ProveKnowledge(id.seed, room, idx, coeffs)
	shares := map[string]string{}
	for k := 1; k <= st.Total; k++ {
		var encPk string
		for _, p := range st.Participants {
			if p.Idx == k {
				encPk = p.EncPk
			}
		}
		ct, err := frost.EncryptShare(encPk, frost.EvalShare(coeffs, k))
		if err != nil {
			return fmt.Errorf("encrypting share for participant %d: %w", k, err)
		}
		shares[strconv.Itoa(k)] = ct
	}
	sig := frost.SignPayload(frost.AuthKey(id.seed, room), frost.DkgPayload(room, idx, commsHex, pok, shares))
	return cl.PostDkg(room, idx, commsHex, pok, shares, sig)
}

func cmdPropose(cl *tsigclient.Client, id *identity, args []string) error {
	if err := needID(id); err != nil {
		return err
	}
	if len(args) != 2 {
		return fmt.Errorf("usage: tsig propose <room> <tx-hash>")
	}
	room, msg := args[0], strings.TrimSpace(args[1])
	if _, err := frost.ParseTxHash([]byte(msg)); err != nil {
		return err
	}
	st, err := cl.Room(room)
	if err != nil {
		return err
	}
	idx, err := myIdx(st, id)
	if err != nil {
		return err
	}
	nonce, err := frost.RandomRequestNonce()
	if err != nil {
		return err
	}
	sig := frost.SignPayload(frost.AuthKey(id.seed, room), frost.ProposePayload(room, idx, msg, nonce))
	pid, err := cl.Propose(room, msg, idx, nonce, sig)
	if err != nil {
		return err
	}
	fmt.Printf("proposal #%d created: %q — now run: tsig sign %s %d\n", pid, msg, room, pid)
	return nil
}

func cmdSign(cl *tsigclient.Client, id *identity, ns *nonceStore, args []string) error {
	if err := needID(id); err != nil {
		return err
	}
	if len(args) < 2 {
		return fmt.Errorf("usage: tsig sign <room> <proposal-id>")
	}
	room := args[0]
	pid, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		return fmt.Errorf("bad proposal id: %w", err)
	}
	st, err := cl.Room(room)
	if err != nil {
		return err
	}
	idx, err := myIdx(st, id)
	if err != nil {
		return err
	}
	prop := findProposal(st, pid)
	if prop == nil {
		return fmt.Errorf("proposal %d not found in room %s", pid, room)
	}

	if len(prop.SignerSet) == 0 {
		if err := postCommit(cl, id, ns, room, prop, idx); err != nil {
			return err
		}
		fmt.Printf("nonce commitment posted for %q\n", prop.Message)
		// Refresh: our commit may have locked the signer set.
		if st, err = cl.Room(room); err != nil {
			return err
		}
		prop = findProposal(st, pid)
	}
	if prop == nil || len(prop.SignerSet) == 0 {
		fmt.Println("waiting for more signers — the signer set is not locked yet; re-run once it is")
		return nil
	}
	if !contains(prop.SignerSet, idx) {
		return fmt.Errorf("signer set %v locked without you", prop.SignerSet)
	}
	if _, ok := prop.Partials[strconv.Itoa(idx)]; ok {
		fmt.Println("partial signature already posted")
		return nil
	}
	if err := postPartial(cl, id, ns, room, st, prop, idx); err != nil {
		return err
	}
	fmt.Printf("partial signature posted (signer set %v) — run: tsig execute %d when all partials are in\n", prop.SignerSet, pid)
	return nil
}

// postCommit generates fresh random nonces, persists them, and posts the commitment pair
// signed with the auth key.
func postCommit(cl *tsigclient.Client, id *identity, ns *nonceStore, room string, prop *tsigclient.Proposal, idx int) error {
	ent := ns.entry(room, prop.ID)
	if ent.Signed {
		return fmt.Errorf("proposal %d was already signed by this identity — refusing to sign again", prop.ID)
	}
	if ent.Nonces == "" {
		np, err := frost.RandomNonces()
		if err != nil {
			return err
		}
		ent.Nonces = np.Hex()
		if err := ns.save(); err != nil {
			return fmt.Errorf("persisting nonces: %w", err)
		}
	}
	np, err := frost.NoncePairFromHex(ent.Nonces)
	if err != nil {
		return err
	}
	d, e := np.Commit()
	sig := frost.SignPayload(frost.AuthKey(id.seed, room), frost.CommitPayload(prop.ID, idx, d, e))
	return cl.Commit(prop.ID, idx, d, e, sig)
}

// postPartial decrypts and verifies our DKG shares, recomputes the transcript (binding factors,
// group commitment, challenge), and posts the signed two-nonce partial signature.
func postPartial(cl *tsigclient.Client, id *identity, ns *nonceStore, room string, st *tsigclient.RoomState, prop *tsigclient.Proposal, idx int) error {
	ent := ns.entry(room, prop.ID)
	if ent.Signed {
		return fmt.Errorf("proposal %d was already signed by this identity — refusing to sign again", prop.ID)
	}
	if ent.Nonces == "" {
		return fmt.Errorf("no stored nonces for proposal %d (state lost?) — refusing to sign", prop.ID)
	}
	np, err := frost.NoncePairFromHex(ent.Nonces)
	if err != nil {
		return err
	}
	encSk := frost.EncKey(id.seed, room)
	received := make([]curve.ECgFp5Scalar, 0, st.Total)
	for i := 1; i <= st.Total; i++ {
		sh, err := frost.DecryptShare(encSk, st.Shares[fmt.Sprintf("%d-%d", i, idx)])
		if err != nil {
			return fmt.Errorf("share %d->%d: %w (has everyone run `tsig dkg`?)", i, idx, err)
		}
		var comms [][]byte
		for _, p := range st.Participants {
			if p.Idx != i {
				continue
			}
			for _, c := range p.Commitments {
				cb, err := hex.DecodeString(c)
				if err != nil {
					return err
				}
				comms = append(comms, cb)
			}
		}
		if err := frost.VerifyShare(sh, idx, comms); err != nil {
			return fmt.Errorf("dealer %d sent a share inconsistent with their commitments: %w", i, err)
		}
		received = append(received, sh)
	}
	x := frost.SigningShare(received)

	commits := make([]frost.Commitment, 0, len(prop.SignerSet))
	for _, m := range prop.SignerSet {
		c, ok := prop.Commits[strconv.Itoa(m)]
		if !ok {
			return fmt.Errorf("missing nonce commitment from participant %d", m)
		}
		commits = append(commits, frost.Commitment{Idx: m, D: c["d"], E: c["e"]})
	}
	aggR, err := frost.GroupCommitment([]byte(prop.Message), commits)
	if err != nil {
		return err
	}
	hashed, err := frost.ParseTxHash([]byte(prop.Message))
	if err != nil {
		return err
	}
	challenge := frost.Challenge(aggR, hashed)
	lambda, err := frost.LagrangeCoefficient(idx, prop.SignerSet)
	if err != nil {
		return err
	}
	// The transcript must contain exactly our stored nonce commitment; anything else means the
	// server swapped it and signing would leak the share.
	myD, myE := np.Commit()
	if c := prop.Commits[strconv.Itoa(idx)]; c["d"] != myD || c["e"] != myE {
		return fmt.Errorf("server-reported nonce commitment does not match our stored nonces — refusing to sign")
	}
	if fp := proposalFingerprint(room, prop); fp != "" {
		fmt.Printf("proposal %d fingerprint (compare out-of-band): %s\n", prop.ID, fp)
	}
	rho := frost.BindingFactor(idx, []byte(prop.Message), commits)
	z := frost.PartialSignature(np, rho, challenge, lambda, x)
	zHex := hex.EncodeToString(z.ToLittleEndianBytes())
	sig := frost.SignPayload(frost.AuthKey(id.seed, room), frost.PartialPayload(prop.ID, idx, zHex))
	ent.Signed = true
	ent.Nonces = ""
	if err := ns.save(); err != nil {
		return fmt.Errorf("persisting signed flag: %w", err)
	}
	return cl.Partial(prop.ID, idx, zHex, sig)
}

func cmdExecute(cl *tsigclient.Client, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: tsig execute <proposal-id>")
	}
	pid, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("bad proposal id: %w", err)
	}
	sig, valid, verifyErr, err := cl.Execute(pid)
	if err != nil {
		return err
	}
	fmt.Printf("final signature: %s\n", sig)
	if valid {
		fmt.Println("aggregated signature VALID ✔")
	} else {
		fmt.Printf("aggregated signature INVALID: %s\n", verifyErr)
	}
	return nil
}

// cmdWatch joins the room and then plays along forever: posts its DKG round as soon as the
// room is full, commits to every new proposal, and posts partial signatures when selected.
func cmdWatch(cl *tsigclient.Client, id *identity, ns *nonceStore, args []string) error {
	if err := needID(id); err != nil {
		return err
	}
	if len(args) != 2 || args[1] != "--allow-auto-sign" {
		return fmt.Errorf("usage: tsig watch <room> --allow-auto-sign (approves every proposal without review)")
	}
	room := args[0]
	authPk, encPk, ethSig, err := id.joinCreds(cl, room)
	if err != nil {
		return err
	}
	idx, rejoined, err := cl.Join(room, id.address, authPk, encPk, ethSig)
	if err != nil {
		return err
	}
	verb := "joined"
	if rejoined {
		verb = "rejoined"
	}
	fmt.Printf("%s %s as participant #%d (%s) — watching...\n", verb, room, idx, id.address)

	dkgPosted := false
	for {
		st, err := cl.Room(room)
		if err != nil {
			fmt.Fprintln(os.Stderr, "poll:", err)
			time.Sleep(2 * time.Second)
			continue
		}
		if st.State != "joining" && !dkgPosted {
			mine := false
			for _, p := range st.Participants {
				if p.Idx == idx && len(p.Commitments) > 0 {
					mine = true
				}
			}
			if !mine {
				if err := postDkgRound(cl, id, room, st, idx); err != nil {
					fmt.Fprintln(os.Stderr, "dkg:", err)
				} else {
					fmt.Println("DKG round posted")
				}
			}
			dkgPosted = true
		}
		for i := range st.Proposals {
			p := &st.Proposals[i]
			if p.Status != "signing" {
				continue
			}
			if len(p.SignerSet) == 0 {
				if _, ok := p.Commits[strconv.Itoa(idx)]; !ok {
					if err := postCommit(cl, id, ns, room, p, idx); err != nil {
						fmt.Fprintln(os.Stderr, "commit:", err)
					} else {
						fmt.Printf("proposal #%d: nonce committed for %q\n", p.ID, p.Message)
					}
				}
				continue
			}
			if !contains(p.SignerSet, idx) {
				continue
			}
			if _, ok := p.Partials[strconv.Itoa(idx)]; ok {
				continue
			}
			if err := postPartial(cl, id, ns, room, st, p, idx); err != nil {
				fmt.Fprintln(os.Stderr, "partial:", err)
			} else {
				fmt.Printf("proposal #%d: partial signature posted\n", p.ID)
			}
		}
		time.Sleep(2 * time.Second)
	}
}

func myIdx(st *tsigclient.RoomState, id *identity) (int, error) {
	for _, p := range st.Participants {
		if strings.EqualFold(p.Address, id.address) {
			return p.Idx, nil
		}
	}
	return 0, fmt.Errorf("this identity (%s) has not joined — run `tsig join <room>` first", id.address)
}

func findProposal(st *tsigclient.RoomState, pid int64) *tsigclient.Proposal {
	for i := range st.Proposals {
		if st.Proposals[i].ID == pid {
			return &st.Proposals[i]
		}
	}
	return nil
}

func contains(set []int, j int) bool {
	for _, m := range set {
		if m == j {
			return true
		}
	}
	return false
}
