package coordinator

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/elliottech/threshold-signature/frost"
)

func TestRequestValidation(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mux := http.NewServeMux()
	(&apiServer{db: db}).routes(mux)
	handler := secureHandler(mux)
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"valid", `{"threshold":2,"total":3}`, 200},
		{"invalid policy", `{"threshold":4,"total":3}`, 400},
		{"unknown field", `{"threshold":2,"total":3,"typo":1}`, 400},
		{"trailing JSON", `{"threshold":2,"total":3} {}`, 400},
		{"oversized", `{"threshold":2,"total":3,"addresses":["` + strings.Repeat("a", 65<<10) + `"]}`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("POST", "/api/rooms", strings.NewReader(tc.body)))
			if w.Code != tc.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing security header")
			}
		})
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM rooms").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("invalid requests persisted: %d rooms", count)
	}
}

func TestLegacyDatabaseIsNotMutated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE participants (idx INTEGER); INSERT INTO participants VALUES (7)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if db, err := openDB(path); err == nil {
		db.Close()
		t.Fatal("legacy database accepted")
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var idx int
	if err := db.QueryRow("SELECT idx FROM participants").Scan(&idx); err != nil || idx != 7 {
		t.Fatalf("legacy data changed: %d, %v", idx, err)
	}
}

func TestInternalErrorsAreRedacted(t *testing.T) {
	w := httptest.NewRecorder()
	writeErr(w, 500, sql.ErrConnDone)
	if strings.Contains(w.Body.String(), sql.ErrConnDone.Error()) {
		t.Fatal("internal error leaked")
	}
}

func TestDKGWriteFailureRollsBack(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const room = "rollback"
	seed := []byte("disposable regression identity")
	auth := frost.AuthKey(seed, room)
	if _, err := db.Exec("INSERT INTO rooms(id,threshold,total) VALUES(?,1,1)", room); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO participants(room,idx,address,auth_pk,enc_pk,eth_sig) VALUES(?,1,'test',?,'test','test')", room, frost.PubPoint(auth)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TRIGGER reject_share BEFORE INSERT ON shares BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
		t.Fatal(err)
	}
	coeffs := frost.DealerPolynomial(seed, room, 1)
	comms := []string{frost.PubPoint(coeffs[0])}
	pok := frost.ProveKnowledge(seed, room, 1, coeffs)
	shares := map[string]string{"1": "unused ciphertext"}
	body, err := json.Marshal(map[string]any{"idx": 1, "commitments": comms, "pok": pok, "shares": shares, "sig": frost.SignPayload(auth, frost.DkgPayload(room, 1, comms, pok, shares))})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&apiServer{db: db}).routes(mux)
	w := httptest.NewRecorder()
	secureHandler(mux).ServeHTTP(w, httptest.NewRequest("POST", "/api/rooms/"+room+"/dkg", bytes.NewReader(body)))
	if w.Code != 500 {
		t.Fatalf("expected injected failure, got %d: %s", w.Code, w.Body.String())
	}
	var commitments sql.NullString
	if err := db.QueryRow("SELECT commitments FROM participants WHERE room=?", room).Scan(&commitments); err != nil {
		t.Fatal(err)
	}
	if commitments.Valid {
		t.Fatal("partial DKG state persisted")
	}
}

func TestSignerSetWriteFailureRollsBackCommit(t *testing.T) {
	s := testServer(t)
	const room = "commit-rollback"
	auth := frost.AuthKey([]byte("disposable signing regression identity"), room)
	if _, err := s.db.Exec("INSERT INTO rooms(id,threshold,total) VALUES(?,1,1)", room); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("INSERT INTO participants(room,idx,address,auth_pk,enc_pk,eth_sig) VALUES(?,1,'test',?,'test','test')", room, frost.PubPoint(auth)); err != nil {
		t.Fatal(err)
	}
	result, err := s.db.Exec("INSERT INTO proposals(room,message,proposer) VALUES(?,'test',1)", room)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("CREATE TRIGGER reject_lock BEFORE UPDATE OF signer_set ON proposals BEGIN SELECT RAISE(ABORT, 'injected lock failure'); END"); err != nil {
		t.Fatal(err)
	}
	nonces, err := frost.RandomNonces()
	if err != nil {
		t.Fatal(err)
	}
	d, e := nonces.Commit()
	body, err := json.Marshal(map[string]any{"idx": 1, "d": d, "e": e, "sig": frost.SignPayload(auth, frost.CommitPayload(id, 1, d, e))})
	if err != nil {
		t.Fatal(err)
	}
	post := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.http.Handler.ServeHTTP(w, httptest.NewRequest("POST", fmt.Sprintf("/api/proposals/%d/commit", id), bytes.NewReader(body)))
		return w
	}
	if w := post(); w.Code != 500 {
		t.Fatalf("expected injected failure: %d %s", w.Code, w.Body.String())
	}
	var count int
	if err := s.db.QueryRow("SELECT count(*) FROM nonce_commits WHERE proposal_id=?", id).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("nonce commitment persisted without signer set")
	}
	if _, err := s.db.Exec("DROP TRIGGER reject_lock"); err != nil {
		t.Fatal(err)
	}
	if w := post(); w.Code != 200 {
		t.Fatalf("retry failed: %d %s", w.Code, w.Body.String())
	}
	var set string
	if err := s.db.QueryRow("SELECT signer_set FROM proposals WHERE id=?", id).Scan(&set); err != nil {
		t.Fatal(err)
	}
	if set != "[1]" {
		t.Fatalf("unexpected signer set: %s", set)
	}
}

func TestMigrationFailureRollsBackSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// A view occupying a table name makes the final additive migration fail.
	_, err = db.Exec(`CREATE TABLE rooms (id TEXT PRIMARY KEY, threshold INTEGER, total INTEGER, group_pk TEXT, created_at TIMESTAMP);
 CREATE TABLE participants (auth_pk TEXT);
 CREATE VIEW proposals AS SELECT 1 AS id;`)
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := openDB(path); err == nil {
		opened.Close()
		t.Fatal("incompatible schema accepted")
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM pragma_table_info('rooms') WHERE name='allowed'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failed migration left an added column")
	}
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='shares'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failed migration left a new table")
	}
}
