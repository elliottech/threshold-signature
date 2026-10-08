package main

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestCmdDkgRequiresJoiningFirst checks that a DKG round cannot be posted for an identity that
// never joined the room — myIdx must fail closed rather than guessing a slot.
func TestCmdDkgRequiresJoiningFirst(t *testing.T) {
	cl := startTestCoordinator(t)
	if err := cmdCreate(cl, []string{"-t", "1", "-n", "1"}); err != nil {
		t.Fatal(err)
	}
	rooms, _ := cl.ListRooms()
	room := rooms[0].Room
	outsider := newTestIdentity(99)
	if err := cmdDkg(cl, outsider, []string{room}); err == nil {
		t.Fatal("DKG posted for an identity that never joined")
	}
}

// TestCmdSignRequiresJoiningFirst mirrors the DKG case for the signing command.
func TestCmdSignRequiresJoiningFirst(t *testing.T) {
	cl := startTestCoordinator(t)
	if err := cmdCreate(cl, []string{"-t", "1", "-n", "1"}); err != nil {
		t.Fatal(err)
	}
	rooms, _ := cl.ListRooms()
	room := rooms[0].Room
	joined := newTestIdentity(1)
	if err := cmdJoin(cl, joined, []string{room}); err != nil {
		t.Fatal(err)
	}
	if err := cmdDkg(cl, joined, []string{room}); err != nil {
		t.Fatal(err)
	}
	outsider := newTestIdentity(2)
	ns, err := openNonceStore(filepath.Join(t.TempDir(), "outsider.state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdSign(cl, outsider, ns, []string{room, "1"}); err == nil {
		t.Fatal("sign succeeded for an identity that never joined")
	}
}

// TestCmdDkgRejectsWhileRoomStillJoining checks that a participant cannot jump ahead to DKG
// before the room has reached its full participant count.
func TestCmdDkgRejectsWhileRoomStillJoining(t *testing.T) {
	cl := startTestCoordinator(t)
	if err := cmdCreate(cl, []string{"-t", "1", "-n", "2"}); err != nil {
		t.Fatal(err)
	}
	rooms, _ := cl.ListRooms()
	room := rooms[0].Room
	id := newTestIdentity(1)
	if err := cmdJoin(cl, id, []string{room}); err != nil {
		t.Fatal(err)
	}
	// Only 1 of 2 participants has joined.
	if err := cmdDkg(cl, id, []string{room}); err == nil {
		t.Fatal("DKG posted before the room finished joining")
	}
}

// TestCmdSignRejectsUnknownProposal checks the not-found path for a proposal id that does not
// exist in the room.
func TestCmdSignRejectsUnknownProposal(t *testing.T) {
	cl := startTestCoordinator(t)
	if err := cmdCreate(cl, []string{"-t", "1", "-n", "1"}); err != nil {
		t.Fatal(err)
	}
	rooms, _ := cl.ListRooms()
	room := rooms[0].Room
	id := newTestIdentity(1)
	if err := cmdJoin(cl, id, []string{room}); err != nil {
		t.Fatal(err)
	}
	if err := cmdDkg(cl, id, []string{room}); err != nil {
		t.Fatal(err)
	}
	ns, err := openNonceStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdSign(cl, id, ns, []string{room, "999999"}); err == nil {
		t.Fatal("sign succeeded for a nonexistent proposal id")
	}
}

// TestCmdSignRejectsBadProposalID checks that a non-numeric proposal id argument is rejected by
// argument parsing rather than reaching the server.
func TestCmdSignRejectsBadProposalID(t *testing.T) {
	cl := startTestCoordinator(t)
	id := newTestIdentity(1)
	ns, err := openNonceStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdSign(cl, id, ns, []string{"some-room", "not-a-number"}); err == nil {
		t.Fatal("non-numeric proposal id accepted")
	}
}

// TestCmdSignRefusesWhenNonceJournalMissingEntry simulates a lost/corrupted nonce journal (the
// commit round happened, but the local state file backing it is gone) — the CLI must refuse to
// sign rather than generating a fresh nonce and potentially double-signing.
func TestCmdSignRefusesWhenNonceJournalMissingEntry(t *testing.T) {
	cl := startTestCoordinator(t)
	const threshold, total = 2, 2
	if err := cmdCreate(cl, []string{"-t", strconv.Itoa(threshold), "-n", strconv.Itoa(total)}); err != nil {
		t.Fatal(err)
	}
	rooms, _ := cl.ListRooms()
	room := rooms[0].Room
	ids := []*identity{newTestIdentity(1), newTestIdentity(2)}
	for _, id := range ids {
		if err := cmdJoin(cl, id, []string{room}); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range ids {
		if err := cmdDkg(cl, id, []string{room}); err != nil {
			t.Fatal(err)
		}
	}
	txHash := "0x" + strings.Repeat("ab", 40)
	if err := cmdPropose(cl, ids[0], []string{room, txHash}); err != nil {
		t.Fatal(err)
	}
	st, err := cl.Room(room)
	if err != nil {
		t.Fatal(err)
	}
	pid := st.Proposals[0].ID

	journalPath := filepath.Join(t.TempDir(), "state.json")
	ns, err := openNonceStore(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	// Signer 1 posts a commitment, persisting its nonce in the journal.
	if err := cmdSign(cl, ids[0], ns, []string{room, strconv.FormatInt(pid, 10)}); err != nil {
		t.Fatal(err)
	}
	// Signer 2 also commits, which locks the set (threshold == total == 2).
	ns2, err := openNonceStore(filepath.Join(t.TempDir(), "state2.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdSign(cl, ids[1], ns2, []string{room, strconv.FormatInt(pid, 10)}); err != nil {
		t.Fatal(err)
	}

	// Simulate the journal being lost/corrupted between the commit and partial rounds by
	// reopening a fresh, empty store at the same identity instead of reusing `ns`.
	freshNs, err := openNonceStore(filepath.Join(t.TempDir(), "amnesiac.state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdSign(cl, ids[0], freshNs, []string{room, strconv.FormatInt(pid, 10)}); err == nil {
		t.Fatal("signing proceeded with no locally stored nonce for an already-locked proposal")
	}
}
