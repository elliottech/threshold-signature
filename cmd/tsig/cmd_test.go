package main

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/elliottech/threshold-signature/internal/coordinator"
	"github.com/elliottech/threshold-signature/tsigclient"
)

// startTestCoordinator runs a real coordinator server in-process on a loopback port and returns
// a client pointed at it, so the actual cmd* functions can be exercised against real HTTP
// handlers instead of reimplementing the protocol in the test.
//
// coordinator.Server only exposes Run, which does its own net.Listen internally, so the port
// can't be reserved and handed to it atomically from here. Probing a free port, closing that
// probe, and asking Run to bind the same address is a TOCTOO race — on a loaded machine (e.g. a
// shared CI runner) something else can grab the port in that gap, Run's bind then fails, and the
// error is otherwise invisible since Run's return value isn't observable before the request that
// needs it runs. Retry with a fresh port on bind failure instead of trusting a single attempt.
func startTestCoordinator(t *testing.T) *tsigclient.Client {
	t.Helper()
	for attempt := 0; attempt < 10; attempt++ {
		addr, ok := startCoordinatorAttempt(t)
		if ok {
			return tsigclient.New("http://" + addr)
		}
	}
	t.Fatal("could not start an in-process test coordinator after repeated port races")
	return nil
}

// startCoordinatorAttempt makes one attempt: reserve a port, start Run in the background, and
// confirm it is actually accepting connections before the deadline. Returns ok=false (without
// failing the test) if the bind lost the race, so the caller can retry on a new port.
func startCoordinatorAttempt(t *testing.T) (addr string, ok bool) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = listener.Addr().String()
	listener.Close()

	s, err := coordinator.New(coordinator.Config{Addr: addr, DBPath: filepath.Join(t.TempDir(), "test.db")}, fstest.MapFS{
		"room.html":  &fstest.MapFile{Data: []byte("room page")},
		"index.html": &fstest.MapFile{Data: []byte("home page")},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- s.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-runErr:
			// Run returned already (almost certainly a lost bind race): this attempt is dead.
			_ = err
			cancel()
			_ = s.Close()
			return addr, false
		default:
		}
		if conn, err := net.Dial("tcp", addr); err == nil {
			conn.Close()
			t.Cleanup(func() {
				cancel()
				<-runErr
				_ = s.Close()
			})
			return addr, true
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	_ = s.Close()
	return addr, false
}

func newTestIdentity(seedByte byte) *identity {
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = seedByte
	}
	return identityFromSeed(seed)
}

func TestCmdCreateAndListAndStatus(t *testing.T) {
	cl := startTestCoordinator(t)
	if err := cmdCreate(cl, []string{"-t", "1", "-n", "1"}); err != nil {
		t.Fatal(err)
	}
	rooms, err := cl.ListRooms()
	if err != nil {
		t.Fatal(err)
	}
	if len(rooms) != 1 {
		t.Fatalf("expected 1 room, got %d", len(rooms))
	}
	if err := cmdList(cl); err != nil {
		t.Fatal(err)
	}
	if err := cmdStatus(cl, []string{rooms[0].Room}); err != nil {
		t.Fatal(err)
	}
	if err := cmdStatus(cl, []string{"does-not-exist"}); err == nil {
		t.Fatal("status for a missing room succeeded")
	}
}

func TestCmdJoinRequiresIdentity(t *testing.T) {
	cl := startTestCoordinator(t)
	if err := cmdCreate(cl, []string{"-t", "1", "-n", "1"}); err != nil {
		t.Fatal(err)
	}
	rooms, _ := cl.ListRooms()
	if err := cmdJoin(cl, nil, []string{rooms[0].Room}); err == nil {
		t.Fatal("join without an identity succeeded")
	}
}

func TestCmdJoinAndRejoinIsIdempotent(t *testing.T) {
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
	// Rejoining with the same identity must succeed and keep the same index rather than erroring
	// or allocating a second slot.
	if err := cmdJoin(cl, id, []string{room}); err != nil {
		t.Fatal(err)
	}
	st, err := cl.Room(room)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Participants) != 1 {
		t.Fatalf("rejoin allocated a duplicate participant: %d", len(st.Participants))
	}
}

// TestFullCeremonyThroughCLICommands drives create/join/dkg/propose/sign/execute entirely
// through the real cmd* functions against a real in-process coordinator — the same code path
// `tsig` runs from the terminal, exercised here without a subprocess or a live server.
func TestFullCeremonyThroughCLICommands(t *testing.T) {
	cl := startTestCoordinator(t)
	const threshold, total = 2, 2
	if err := cmdCreate(cl, []string{"-t", strconv.Itoa(threshold), "-n", strconv.Itoa(total)}); err != nil {
		t.Fatal(err)
	}
	rooms, err := cl.ListRooms()
	if err != nil {
		t.Fatal(err)
	}
	room := rooms[0].Room

	ids := []*identity{newTestIdentity(1), newTestIdentity(2)}
	for _, id := range ids {
		if err := cmdJoin(cl, id, []string{room}); err != nil {
			t.Fatalf("join %s: %v", id.address, err)
		}
	}
	for _, id := range ids {
		if err := cmdDkg(cl, id, []string{room}); err != nil {
			t.Fatalf("dkg %s: %v", id.address, err)
		}
	}
	st, err := cl.Room(room)
	if err != nil {
		t.Fatal(err)
	}
	if st.GroupPk == "" {
		t.Fatal("DKG did not complete")
	}

	proposer := ids[0]
	txHash := "0x" + strings.Repeat("ab", 40)
	if err := cmdPropose(cl, proposer, []string{room, txHash}); err != nil {
		t.Fatal(err)
	}
	st, err = cl.Room(room)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Proposals) != 1 {
		t.Fatalf("expected 1 proposal, got %d", len(st.Proposals))
	}
	pid := st.Proposals[0].ID

	nsPaths := make([]*nonceStore, len(ids))
	for i, id := range ids {
		ns, err := openNonceStore(filepath.Join(t.TempDir(), id.address+".state.json"))
		if err != nil {
			t.Fatal(err)
		}
		nsPaths[i] = ns
		// First call posts the nonce commitment; with both signers required (threshold==total)
		// the set locks only once everyone has committed, so an early call reports "waiting".
		if err := cmdSign(cl, id, ns, []string{room, strconv.FormatInt(pid, 10)}); err != nil {
			t.Fatalf("sign (commit round) %s: %v", id.address, err)
		}
	}
	// Now the signer set is locked; re-running sign for each identity posts its partial.
	for i, id := range ids {
		if err := cmdSign(cl, id, nsPaths[i], []string{room, strconv.FormatInt(pid, 10)}); err != nil {
			t.Fatalf("sign (partial round) %s: %v", id.address, err)
		}
		// A signer must not be able to sign the same proposal twice with the same journal.
		if err := cmdSign(cl, id, nsPaths[i], []string{room, strconv.FormatInt(pid, 10)}); err != nil {
			t.Fatalf("re-running sign after completion should be a no-op, got error: %v", err)
		}
	}

	if err := cmdExecute(cl, []string{strconv.FormatInt(pid, 10)}); err != nil {
		t.Fatal(err)
	}
	st, err = cl.Room(room)
	if err != nil {
		t.Fatal(err)
	}
	if st.Proposals[0].Valid == nil || !*st.Proposals[0].Valid {
		t.Fatalf("expected a valid aggregated signature, got %+v", st.Proposals[0])
	}
}

func TestCmdProposeRejectsNonTxHash(t *testing.T) {
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
	if err := cmdPropose(cl, id, []string{room, "not a tx hash"}); err == nil {
		t.Fatal("non-hash proposal message accepted")
	}
}

func TestCmdExecuteRejectsBadProposalID(t *testing.T) {
	cl := startTestCoordinator(t)
	if err := cmdExecute(cl, []string{"not-a-number"}); err == nil {
		t.Fatal("non-numeric proposal id accepted")
	}
	if err := cmdExecute(cl, []string{"999999"}); err == nil {
		t.Fatal("execute for a nonexistent proposal succeeded")
	}
}
