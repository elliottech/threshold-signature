package tsigclient

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/elliottech/threshold-sig-poc/frost"
)

func TestRejectsErrorStatusWithoutErrorField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	if err := New(srv.URL+"/").call("GET", "/", nil, nil); err == nil {
		t.Fatal("error status treated as success")
	}
}

func TestRejectsMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	err := New(srv.URL).call("GET", "/", nil, nil)
	if err == nil {
		t.Fatal("malformed JSON response accepted")
	}
}

func TestSurfacesServerErrorMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"specific reason"}`))
	}))
	defer srv.Close()
	err := New(srv.URL).call("GET", "/", nil, nil)
	if err == nil {
		t.Fatal("error status accepted")
	}
	if got := err.Error(); !strings.Contains(got, "specific reason") {
		t.Fatalf("error message dropped server detail: %q", got)
	}
}

func TestDecodesSuccessBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"room":"apple-carrot","threshold":2,"total":3}`))
	}))
	defer srv.Close()
	var out RoomSummary
	if err := New(srv.URL).call("GET", "/", nil, &out); err != nil {
		t.Fatal(err)
	}
	if out.Room != "apple-carrot" || out.Threshold != 2 || out.Total != 3 {
		t.Fatalf("unexpected decode: %+v", out)
	}
}

func TestBaseURLTrailingSlashTrimmed(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	if err := New(srv.URL+"/").call("GET", "/api/rooms", nil, nil); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/rooms" {
		t.Fatalf("trailing slash on base produced double slash: %q", gotPath)
	}
}

// echoServer records the last request body it received (as raw JSON) and the path, and replies
// with the given response for every call — enough to assert each typed Client method sends the
// right shape and parses the right response, without a real coordinator.
func echoServer(t *testing.T, response string) (cl *Client, lastBody func() map[string]any, lastPath func() string) {
	t.Helper()
	var body map[string]any
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.Method + " " + r.URL.Path
		body = nil
		if r.ContentLength != 0 || r.Method == http.MethodPost {
			data, _ := io.ReadAll(r.Body)
			if len(data) > 0 {
				_ = json.Unmarshal(data, &body)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL), func() map[string]any { return body }, func() string { return path }
}

func TestCreateRoomRequestAndResponse(t *testing.T) {
	cl, body, path := echoServer(t, `{"room":"apple-carrot-thumbs-fjord-cedar"}`)
	room, err := cl.CreateRoom(2, 3, []string{"0xabc"})
	if err != nil {
		t.Fatal(err)
	}
	if room != "apple-carrot-thumbs-fjord-cedar" {
		t.Fatalf("unexpected room: %q", room)
	}
	if path() != "POST /api/rooms" {
		t.Fatalf("unexpected route: %q", path())
	}
	b := body()
	if b["threshold"] != float64(2) || b["total"] != float64(3) {
		t.Fatalf("unexpected request body: %v", b)
	}
	addrs, _ := b["addresses"].([]any)
	if len(addrs) != 1 || addrs[0] != "0xabc" {
		t.Fatalf("addresses not sent: %v", b)
	}
}

func TestJoinRequestAndResponse(t *testing.T) {
	cl, body, path := echoServer(t, `{"idx":2,"rejoined":true}`)
	idx, rejoined, err := cl.Join("room1", "0xAAA", "authpk", "encpk", "0xsig")
	if err != nil {
		t.Fatal(err)
	}
	if idx != 2 || !rejoined {
		t.Fatalf("unexpected result: idx=%d rejoined=%v", idx, rejoined)
	}
	if path() != "POST /api/rooms/room1/join" {
		t.Fatalf("unexpected route: %q", path())
	}
	b := body()
	if b["address"] != "0xAAA" || b["authPk"] != "authpk" || b["encPk"] != "encpk" || b["ethSig"] != "0xsig" {
		t.Fatalf("unexpected request body: %v", b)
	}
}

func TestPostDkgRequestShape(t *testing.T) {
	cl, body, path := echoServer(t, `{}`)
	pok := frost.PoK{R: "r-hex", Mu: "mu-hex"}
	err := cl.PostDkg("room1", 1, []string{"c0", "c1"}, pok, map[string]string{"1": "ct1"}, "sig")
	if err != nil {
		t.Fatal(err)
	}
	if path() != "POST /api/rooms/room1/dkg" {
		t.Fatalf("unexpected route: %q", path())
	}
	b := body()
	if b["idx"] != float64(1) || b["sig"] != "sig" {
		t.Fatalf("unexpected request body: %v", b)
	}
	pokBody, _ := b["pok"].(map[string]any)
	if pokBody["r"] != "r-hex" || pokBody["mu"] != "mu-hex" {
		t.Fatalf("pok not sent correctly: %v", b)
	}
}

func TestProposeRequestAndResponse(t *testing.T) {
	cl, body, path := echoServer(t, `{"id":7}`)
	id, err := cl.Propose("room1", "0xdeadbeef", 1, "nonce123", "sig")
	if err != nil {
		t.Fatal(err)
	}
	if id != 7 {
		t.Fatalf("unexpected id: %d", id)
	}
	if path() != "POST /api/rooms/room1/proposals" {
		t.Fatalf("unexpected route: %q", path())
	}
	b := body()
	if b["message"] != "0xdeadbeef" || b["proposer"] != float64(1) || b["nonce"] != "nonce123" || b["sig"] != "sig" {
		t.Fatalf("unexpected request body: %v", b)
	}
}

func TestCommitAndPartialRequestShapes(t *testing.T) {
	cl, body, path := echoServer(t, `{}`)
	if err := cl.Commit(7, 1, "dhex", "ehex", "sig1"); err != nil {
		t.Fatal(err)
	}
	if path() != "POST /api/proposals/7/commit" {
		t.Fatalf("unexpected route: %q", path())
	}
	if b := body(); b["d"] != "dhex" || b["e"] != "ehex" {
		t.Fatalf("unexpected commit body: %v", b)
	}

	if err := cl.Partial(7, 1, "shex", "sig2"); err != nil {
		t.Fatal(err)
	}
	if path() != "POST /api/proposals/7/partial" {
		t.Fatalf("unexpected route: %q", path())
	}
	if b := body(); b["s"] != "shex" || b["sig"] != "sig2" {
		t.Fatalf("unexpected partial body: %v", b)
	}
}

func TestExecuteRequestAndResponse(t *testing.T) {
	cl, _, path := echoServer(t, `{"sig":"abcd","valid":true,"verifyError":""}`)
	sig, valid, verifyErr, err := cl.Execute(7)
	if err != nil {
		t.Fatal(err)
	}
	if sig != "abcd" || !valid || verifyErr != "" {
		t.Fatalf("unexpected result: sig=%q valid=%v verifyErr=%q", sig, valid, verifyErr)
	}
	if path() != "POST /api/proposals/7/execute" {
		t.Fatalf("unexpected route: %q", path())
	}
}

func TestExecuteSurfacesVerifyError(t *testing.T) {
	cl, _, _ := echoServer(t, `{"sig":"abcd","valid":false,"verifyError":"bad signature"}`)
	_, valid, verifyErr, err := cl.Execute(7)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("invalid signature reported as valid")
	}
	if verifyErr != "bad signature" {
		t.Fatalf("verify error dropped: %q", verifyErr)
	}
}

func TestListRoomsAndRoomDecode(t *testing.T) {
	cl, _, path := echoServer(t, `{"rooms":[{"room":"r1","threshold":2,"total":3,"joined":1,"proposals":0}]}`)
	rooms, err := cl.ListRooms()
	if err != nil {
		t.Fatal(err)
	}
	if len(rooms) != 1 || rooms[0].Room != "r1" || rooms[0].Joined != 1 {
		t.Fatalf("unexpected rooms: %+v", rooms)
	}
	if path() != "GET /api/rooms" {
		t.Fatalf("unexpected route: %q", path())
	}
}

func TestRoomDecodesNestedParticipantsAndProposals(t *testing.T) {
	cl, _, path := echoServer(t, `{
		"room":"r1","threshold":1,"total":1,"state":"ready","groupPk":"pk",
		"participants":[{"idx":1,"address":"0xaaa","authPk":"a","encPk":"e","ethSig":"s"}],
		"proposals":[{"id":1,"message":"0xdead","proposer":1,"status":"signing","commits":{},"partials":{}}]
	}`)
	st, err := cl.Room("r1")
	if err != nil {
		t.Fatal(err)
	}
	if path() != "GET /api/rooms/r1" {
		t.Fatalf("unexpected route: %q", path())
	}
	if len(st.Participants) != 1 || st.Participants[0].Address != "0xaaa" {
		t.Fatalf("participants not decoded: %+v", st.Participants)
	}
	if len(st.Proposals) != 1 || st.Proposals[0].Message != "0xdead" {
		t.Fatalf("proposals not decoded: %+v", st.Proposals)
	}
}
