package coordinator

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	curve "github.com/elliottech/poseidon_crypto/curve/ecgfp5"
	"github.com/elliottech/threshold-sig-poc/frost"
	"log"
	"net/http"
	"sort"
	"strconv"
)

// postCommit records a signer's two-nonce commitment pair (D_j, E_j), signed with the signer's
// auth key. Once `threshold` commitments exist, the signer set is locked (first t by index).
func (a *apiServer) postCommit(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var req struct {
		Idx int    `json:"idx"`
		D   string `json:"d"`
		E   string `json:"e"`
		Sig string `json:"sig"`
	}
	if err := decodeRequest(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	var room, status string
	var set sql.NullString
	if err := a.db.QueryRow("SELECT room, status, signer_set FROM proposals WHERE id=?", id).Scan(&room, &status, &set); err != nil {
		writeErr(w, 404, errors.New("proposal not found"))
		return
	}
	if set.Valid && set.String != "" {
		writeErr(w, 400, errors.New("signer set already locked"))
		return
	}
	for _, v := range []string{req.D, req.E} {
		if _, err := hex.DecodeString(v); err != nil || len(v) != 80 {
			writeErr(w, 400, errors.New("d and e must be 40-byte hex"))
			return
		}
	}
	authPk, err := a.authPkFor(room, req.Idx)
	if err != nil {
		writeErr(w, 404, err)
		return
	}
	if err := frost.VerifyPayload(authPk, frost.CommitPayload(id, req.Idx, req.D, req.E), req.Sig); err != nil {
		writeErr(w, 401, err)
		return
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT OR IGNORE INTO nonce_commits(proposal_id, idx, d, e) VALUES(?,?,?,?)", id, req.Idx, req.D, req.E); err != nil {
		writeErr(w, 500, err)
		return
	}

	var threshold int
	if err := tx.QueryRow("SELECT threshold FROM rooms WHERE id=?", room).Scan(&threshold); err != nil {
		writeErr(w, 500, err)
		return
	}
	rows, err := tx.Query("SELECT idx FROM nonce_commits WHERE proposal_id=? ORDER BY idx", id)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	var idxs []int
	for rows.Next() {
		var i int
		if err := rows.Scan(&i); err != nil {
			rows.Close()
			writeErr(w, 500, err)
			return
		}
		idxs = append(idxs, i)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		writeErr(w, 500, err)
		return
	}
	rows.Close()
	if len(idxs) >= threshold {
		sort.Ints(idxs)
		locked := idxs[:threshold]
		b, _ := json.Marshal(locked)
		if _, err := tx.Exec("UPDATE proposals SET signer_set=? WHERE id=?", string(b), id); err != nil {
			writeErr(w, 500, err)
			return
		}
		log.Printf("proposal %d: signer set locked: %v", id, locked)
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// postPartial records a signer's partial signature z_j. The submission is signed with the auth
// key, and the partial itself is verified against the signer's public verification share, the
// binding factor, and the group challenge — a bad partial is rejected and attributed on the spot.
func (a *apiServer) postPartial(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var req struct {
		Idx int    `json:"idx"`
		S   string `json:"s"`
		Sig string `json:"sig"`
	}
	if err := decodeRequest(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	var room, message string
	var set sql.NullString
	if err := a.db.QueryRow("SELECT room, message, signer_set FROM proposals WHERE id=?", id).Scan(&room, &message, &set); err != nil {
		writeErr(w, 404, errors.New("proposal not found"))
		return
	}
	if !set.Valid || set.String == "" {
		writeErr(w, 400, errors.New("signer set not locked yet"))
		return
	}
	var idxs []int
	_ = json.Unmarshal([]byte(set.String), &idxs)
	found := false
	for _, i := range idxs {
		if i == req.Idx {
			found = true
		}
	}
	if !found {
		writeErr(w, 400, errors.New("not part of the locked signer set"))
		return
	}
	if _, err := hex.DecodeString(req.S); err != nil || len(req.S) != 80 {
		writeErr(w, 400, errors.New("s must be 40-byte hex"))
		return
	}
	authPk, err := a.authPkFor(room, req.Idx)
	if err != nil {
		writeErr(w, 404, err)
		return
	}
	if err := frost.VerifyPayload(authPk, frost.PartialPayload(id, req.Idx, req.S), req.Sig); err != nil {
		writeErr(w, 401, err)
		return
	}

	commits, allComms, err := a.signingTranscript(room, id, idxs)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	msg := []byte(message)
	aggR, err := frost.GroupCommitment(msg, commits)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	hashed, err := frost.ParseTxHash(msg)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	challenge := frost.Challenge(aggR, hashed)
	lambda, err := frost.LagrangeCoefficient(req.Idx, idxs)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	pubShare, err := frost.PublicShare(req.Idx, allComms)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	var myCommit frost.Commitment
	for _, c := range commits {
		if c.Idx == req.Idx {
			myCommit = c
		}
	}
	sb, _ := hex.DecodeString(req.S)
	z := curve.ScalarElementFromLittleEndianBytes(sb)
	rho := frost.BindingFactor(req.Idx, msg, commits)
	if err := frost.VerifyPartial(z, myCommit, rho, challenge, lambda, pubShare); err != nil {
		writeErr(w, 400, fmt.Errorf("participant %d: %w", req.Idx, err))
		return
	}

	if _, err := a.db.Exec("INSERT OR IGNORE INTO partials(proposal_id, idx, s) VALUES(?,?,?)", id, req.Idx, req.S); err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// authPkFor returns the stored auth public key for a participant.
func (a *apiServer) authPkFor(room string, idx int) (string, error) {
	var pk string
	err := a.db.QueryRow("SELECT auth_pk FROM participants WHERE room=? AND idx=?", room, idx).Scan(&pk)
	if err != nil {
		return "", fmt.Errorf("unknown participant %d in room %s", idx, room)
	}
	return pk, nil
}

// signingTranscript loads the locked signer set's nonce commitments and every dealer's DKG
// commitments, the shared inputs for binding factors, challenges, and partial verification.
func (a *apiServer) signingTranscript(room string, proposalID int64, set []int) ([]frost.Commitment, [][][]byte, error) {
	commits := make([]frost.Commitment, 0, len(set))
	for _, j := range set {
		var d, e string
		if err := a.db.QueryRow("SELECT d, e FROM nonce_commits WHERE proposal_id=? AND idx=?", proposalID, j).Scan(&d, &e); err != nil {
			return nil, nil, fmt.Errorf("missing nonce commitment from participant %d", j)
		}
		commits = append(commits, frost.Commitment{Idx: j, D: d, E: e})
	}
	parts, err := a.loadParticipants(room)
	if err != nil {
		return nil, nil, err
	}
	allComms := make([][][]byte, 0, len(parts))
	for _, p := range parts {
		if len(p.Commitments) == 0 {
			return nil, nil, fmt.Errorf("participant %d has not finished DKG", p.Idx)
		}
		comms := make([][]byte, len(p.Commitments))
		for k, c := range p.Commitments {
			b, err := hex.DecodeString(c)
			if err != nil {
				return nil, nil, err
			}
			comms[k] = b
		}
		allComms = append(allComms, comms)
	}
	return commits, allComms, nil
}
