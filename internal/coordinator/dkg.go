package coordinator

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/elliottech/threshold-signature/frost"
	"log"
	"net/http"
	"strconv"
)

// postDkg stores a participant's polynomial commitments, DKG proof of knowledge, and the
// per-recipient ENCRYPTED shares. The submission must be signed with the participant's auth key,
// and the PoK must verify against the constant-term commitment (rogue-key protection).
func (a *apiServer) postDkg(w http.ResponseWriter, r *http.Request) {
	room := r.PathValue("room")
	var req struct {
		Idx         int               `json:"idx"`
		Commitments []string          `json:"commitments"`
		Pok         frost.PoK         `json:"pok"`
		Shares      map[string]string `json:"shares"` // recipient idx -> ECIES ciphertext hex
		Sig         string            `json:"sig"`
	}
	if err := decodeRequest(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	var threshold, total int
	if err := a.db.QueryRow("SELECT threshold, total FROM rooms WHERE id=?", room).Scan(&threshold, &total); err != nil {
		writeErr(w, 404, errors.New("room not found"))
		return
	}
	if len(req.Commitments) != threshold || len(req.Shares) != total {
		writeErr(w, 400, fmt.Errorf("need %d commitments and %d shares", threshold, total))
		return
	}

	authPk, err := a.authPkFor(room, req.Idx)
	if err != nil {
		writeErr(w, 404, err)
		return
	}
	payload := frost.DkgPayload(room, req.Idx, req.Commitments, req.Pok, req.Shares)
	if err := frost.VerifyPayload(authPk, payload, req.Sig); err != nil {
		writeErr(w, 401, err)
		return
	}

	a0, err := hex.DecodeString(req.Commitments[0])
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	if err := frost.VerifyPoK(room, req.Idx, a0, req.Pok); err != nil {
		writeErr(w, 400, err)
		return
	}
	for j := 1; j <= total; j++ {
		if _, ok := req.Shares[strconv.Itoa(j)]; !ok {
			writeErr(w, 400, fmt.Errorf("missing encrypted share for participant %d", j))
			return
		}
	}

	tx, err := a.db.Begin()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	defer tx.Rollback()
	commsJSON, _ := json.Marshal(req.Commitments)
	pokJSON, _ := json.Marshal(req.Pok)
	res, err := tx.Exec("UPDATE participants SET commitments=?, pok=? WHERE room=? AND idx=? AND commitments IS NULL",
		string(commsJSON), string(pokJSON), room, req.Idx)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeJSON(w, 200, map[string]any{"ok": true, "already": true})
		return
	}
	for j := 1; j <= total; j++ {
		if _, err := tx.Exec("INSERT INTO shares(room, from_idx, to_idx, share) VALUES(?,?,?,?)", room, req.Idx, j, req.Shares[strconv.Itoa(j)]); err != nil {
			writeErr(w, 500, err)
			return
		}
	}

	// If everyone posted, compute the group public key from the constant-term commitments.
	parts, err := loadParticipants(tx, room)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	done := 0
	constants := make([][]byte, 0, total)
	for _, p := range parts {
		if len(p.Commitments) > 0 {
			done++
			b, _ := hex.DecodeString(p.Commitments[0])
			constants = append(constants, b)
		}
	}
	if done == total {
		pk, err := frost.GroupPublicKey(constants)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		if _, err := tx.Exec("UPDATE rooms SET group_pk=? WHERE id=?", hex.EncodeToString(pk), room); err != nil {
			writeErr(w, 500, err)
			return
		}
		log.Printf("room %s: DKG complete, group pk %x", room, pk)
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
