package coordinator

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	curve "github.com/elliottech/poseidon_crypto/curve/ecgfp5"
	"github.com/elliottech/threshold-signature/frost"
	"log"
	"net/http"
	"strconv"
)

// executeProposal aggregates the partial signatures into a single Schnorr signature and
// verifies it against the group public key using the SDK's schnorr verification.
func (a *apiServer) executeProposal(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
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

	var groupPkHex string
	if err := a.db.QueryRow("SELECT group_pk FROM rooms WHERE id=?", room).Scan(&groupPkHex); err != nil {
		writeErr(w, 500, err)
		return
	}
	groupPk, err := hex.DecodeString(groupPkHex)
	if err != nil {
		writeErr(w, 500, err)
		return
	}

	commits, _, err := a.signingTranscript(room, id, idxs)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	partials := make([]curve.ECgFp5Scalar, 0, len(idxs))
	for _, j := range idxs {
		var sHex string
		if err := a.db.QueryRow("SELECT s FROM partials WHERE proposal_id=? AND idx=?", id, j).Scan(&sHex); err != nil {
			writeErr(w, 400, fmt.Errorf("missing partial signature from participant %d", j))
			return
		}
		sb, _ := hex.DecodeString(sHex)
		partials = append(partials, curve.ScalarElementFromLittleEndianBytes(sb))
	}

	msg := []byte(message)
	aggR, err := frost.GroupCommitment(msg, commits)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	hashed, err := frost.ParseTxHash(msg)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	e := frost.Challenge(aggR, hashed)
	sig := frost.Aggregate(partials, e)

	valid := 1
	verifyErr := frost.Verify(groupPk, []byte(message), sig)
	if verifyErr != nil {
		valid = 0
	}
	if _, err := a.db.Exec("UPDATE proposals SET status='executed', final_sig=?, valid=? WHERE id=?", hex.EncodeToString(sig), valid, id); err != nil {
		writeErr(w, 500, err)
		return
	}
	log.Printf("proposal %d executed: valid=%d sig=%x", id, valid, sig)
	resp := map[string]any{"sig": hex.EncodeToString(sig), "valid": valid == 1}
	if verifyErr != nil {
		resp["verifyError"] = verifyErr.Error()
	}
	writeJSON(w, 200, resp)
}
