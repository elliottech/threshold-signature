package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/elliottech/threshold-signature/frost"
	"github.com/elliottech/threshold-signature/tsigclient"
)

func TestLoadEnvPrefersFileOverEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	content := "TSIG_SERVER=http://file-value\n# a comment\n\nTSIG_KEY_FILE = \"quoted-value\" \n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TSIG_SERVER", "http://env-value")
	t.Setenv("TSIG_SEED", "env-seed")
	env := loadEnv(path)
	if env["TSIG_SERVER"] != "http://file-value" {
		t.Fatalf("file did not override environment: %v", env)
	}
	if env["TSIG_KEY_FILE"] != "quoted-value" {
		t.Fatalf("quotes/whitespace not trimmed: %q", env["TSIG_KEY_FILE"])
	}
	if env["TSIG_SEED"] != "env-seed" {
		t.Fatalf("environment-only key dropped: %v", env)
	}
}

func TestLoadEnvMissingFileFallsBackToEnvironment(t *testing.T) {
	t.Setenv("TSIG_SERVER", "http://env-only")
	env := loadEnv(filepath.Join(t.TempDir(), "does-not-exist.env"))
	if env["TSIG_SERVER"] != "http://env-only" {
		t.Fatalf("missing file did not fall back to environment: %v", env)
	}
}

func TestIdentityFromEnvKeyFileTakesPriority(t *testing.T) {
	dir := t.TempDir()
	id := identityFromSeed(make([]byte, 64))
	path := filepath.Join(dir, "key.json")
	if err := writeKeyFile(path, id); err != nil {
		t.Fatal(err)
	}
	got, err := identityFromEnv(map[string]string{"TSIG_KEY_FILE": path, "TSIG_SEED": "ignored"})
	if err != nil {
		t.Fatal(err)
	}
	if got.address != id.address {
		t.Fatalf("key file identity not used: %s != %s", got.address, id.address)
	}
}

func TestIdentityFromEnvLegacySeedIsDeterministic(t *testing.T) {
	a, err := identityFromEnv(map[string]string{"TSIG_SEED": "same-secret"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := identityFromEnv(map[string]string{"TSIG_SEED": "same-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if a.address != b.address {
		t.Fatal("legacy seed derivation is not deterministic")
	}
	c, err := identityFromEnv(map[string]string{"TSIG_SEED": "different-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if a.address == c.address {
		t.Fatal("different legacy seeds produced the same identity")
	}
}

func TestIdentityFromEnvNoConfigReturnsNil(t *testing.T) {
	id, err := identityFromEnv(map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if id != nil {
		t.Fatalf("expected no identity, got %+v", id)
	}
}

func TestWriteAndLoadKeyFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}
	id := identityFromSeed(seed)
	if err := writeKeyFile(path, id); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("key file is not private: %v", info.Mode())
	}
	loaded, err := loadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.address != id.address || hex.EncodeToString(loaded.seed) != hex.EncodeToString(id.seed) {
		t.Fatalf("round trip changed identity: %+v vs %+v", loaded, id)
	}
}

func TestWriteKeyFileRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")
	id := identityFromSeed(make([]byte, 64))
	if err := writeKeyFile(path, id); err != nil {
		t.Fatal(err)
	}
	if err := writeKeyFile(path, id); err == nil {
		t.Fatal("second write silently overwrote an existing key file")
	}
}

func TestLoadKeyFileRejectsTamperedAddress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")
	id := identityFromSeed(make([]byte, 64))
	if err := writeKeyFile(path, id); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), id.address, "0x0000000000000000000000000000000000dead", 1)
	if err := os.WriteFile(path, []byte(tampered), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKeyFile(path); err == nil {
		t.Fatal("mismatched stored address accepted")
	}
}

func TestLoadKeyFileRejectsBadSeedLength(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"seed":"abcd","address":"0x0"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKeyFile(path); err == nil {
		t.Fatal("short seed accepted")
	}
}

func TestMyIdxFindsCaseInsensitiveMatch(t *testing.T) {
	st := &tsigclient.RoomState{Participants: []tsigclient.Participant{
		{Idx: 1, Address: "0xABCDEF"},
		{Idx: 2, Address: "0x123456"},
	}}
	id := &identity{address: "0xabcdef"}
	idx, err := myIdx(st, id)
	if err != nil || idx != 1 {
		t.Fatalf("expected idx 1, got %d, %v", idx, err)
	}
}

func TestMyIdxErrorsWhenNotJoined(t *testing.T) {
	st := &tsigclient.RoomState{Participants: []tsigclient.Participant{{Idx: 1, Address: "0xabc"}}}
	id := &identity{address: "0xnotjoined"}
	if _, err := myIdx(st, id); err == nil {
		t.Fatal("unjoined identity resolved to a participant index")
	}
}

func TestFindProposal(t *testing.T) {
	st := &tsigclient.RoomState{Proposals: []tsigclient.Proposal{{ID: 1}, {ID: 2}}}
	if p := findProposal(st, 2); p == nil || p.ID != 2 {
		t.Fatalf("expected proposal 2, got %v", p)
	}
	if p := findProposal(st, 99); p != nil {
		t.Fatalf("expected nil for missing proposal, got %v", p)
	}
}

func TestContains(t *testing.T) {
	set := []int{1, 3, 5}
	if !contains(set, 3) {
		t.Fatal("expected 3 to be found")
	}
	if contains(set, 4) {
		t.Fatal("expected 4 to be absent")
	}
	if contains(nil, 1) {
		t.Fatal("expected nil set to contain nothing")
	}
}

func TestDkgFingerprintEmptyUntilEveryoneHasCommitted(t *testing.T) {
	pok := frost.PoK{R: "r", Mu: "mu"}
	st := &tsigclient.RoomState{Threshold: 2, Total: 2, Participants: []tsigclient.Participant{
		{Idx: 1, Commitments: []string{"c0"}, Pok: &pok},
		{Idx: 2}, // has not posted DKG yet
	}}
	if fp := dkgFingerprint("room", st); fp != "" {
		t.Fatalf("expected empty fingerprint before DKG completes, got %q", fp)
	}
}

func TestProposalFingerprintEmptyBeforeSignerSetLocks(t *testing.T) {
	p := &tsigclient.Proposal{ID: 1, Message: "0xabc"}
	if fp := proposalFingerprint("room", p); fp != "" {
		t.Fatalf("expected empty fingerprint before signer set locks, got %q", fp)
	}
}
