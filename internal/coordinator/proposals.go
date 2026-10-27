package coordinator

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/elliottech/threshold-signature/frost"
	"log"
	"net/http"
	"strconv"
)

type proposalView struct {
	ID        int64                        `json:"id"`
	Message   string                       `json:"message"`
	Proposer  int                          `json:"proposer"`
	Sig       string                       `json:"sig"`
	Nonce     string                       `json:"nonce"`
	Status    string                       `json:"status"`
	SignerSet []int                        `json:"signerSet,omitempty"`
	FinalSig  string                       `json:"finalSig,omitempty"`
	Valid     *bool                        `json:"valid,omitempty"`
	CreatedAt string                       `json:"createdAt"`
	Commits   map[string]map[string]string `json:"commits"` // idx -> {d, e}
	Partials  map[string]string            `json:"partials"`
}

func (a *apiServer) loadProposals(room string) ([]proposalView, error) {
	rows, err := a.db.Query(`SELECT id, message, proposer, COALESCE(sig,''), COALESCE(nonce,''), status, COALESCE(signer_set,''), COALESCE(final_sig,''), valid, created_at
		FROM proposals WHERE room=? ORDER BY id DESC`, room)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []proposalView
	for rows.Next() {
		var p proposalView
		var set string
		var valid sql.NullInt64
		if err := rows.Scan(&p.ID, &p.Message, &p.Proposer, &p.Sig, &p.Nonce, &p.Status, &set, &p.FinalSig, &valid, &p.CreatedAt); err != nil {
			return nil, err
		}
		if set != "" {
			if err := json.Unmarshal([]byte(set), &p.SignerSet); err != nil {
				return nil, err
			}
		}
		if valid.Valid {
			v := valid.Int64 == 1
			p.Valid = &v
		}
		p.Commits = map[string]map[string]string{}
		p.Partials = map[string]string{}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := a.loadRoundData(&out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (a *apiServer) loadRoundData(p *proposalView) error {
	rows, err := a.db.Query("SELECT idx, d, e FROM nonce_commits WHERE proposal_id=?", p.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var idx int
		var d, e string
		if err := rows.Scan(&idx, &d, &e); err != nil {
			rows.Close()
			return err
		}
		p.Commits[strconv.Itoa(idx)] = map[string]string{"d": d, "e": e}
	}
	rows.Close()
	rows, err = a.db.Query("SELECT idx, s FROM partials WHERE proposal_id=?", p.ID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var idx int
		var v string
		if err := rows.Scan(&idx, &v); err != nil {
			rows.Close()
			return err
		}
		p.Partials[strconv.Itoa(idx)] = v
	}
	rows.Close()
	return nil
}

func (a *apiServer) createProposal(w http.ResponseWriter, r *http.Request) {
	room := r.PathValue("room")
	var req struct {
		Message  string `json:"message"`
		Proposer int    `json:"proposer"`
		Nonce    string `json:"nonce"`
		Sig      string `json:"sig"`
	}
	if err := decodeRequest(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if _, err := frost.ParseTxHash([]byte(req.Message)); err != nil {
		writeErr(w, 400, err)
		return
	}
	if len(req.Nonce) < 16 {
		writeErr(w, 400, errors.New("nonce must be at least 16 characters"))
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var groupPk sql.NullString
	if err := a.db.QueryRow("SELECT group_pk FROM rooms WHERE id=?", room).Scan(&groupPk); err != nil {
		writeErr(w, 404, errors.New("room not found"))
		return
	}
	if !groupPk.Valid || groupPk.String == "" {
		writeErr(w, 400, errors.New("DKG not finished yet"))
		return
	}
	authPk, err := a.authPkFor(room, req.Proposer)
	if err != nil {
		writeErr(w, 404, err)
		return
	}
	if err := frost.VerifyPayload(authPk, frost.ProposePayload(room, req.Proposer, req.Message, req.Nonce), req.Sig); err != nil {
		writeErr(w, 403, fmt.Errorf("proposal signature: %w", err))
		return
	}
	// UNIQUE(room, proposer, nonce) rejects a replayed request as a duplicate rather than
	// creating a second proposal for it.
	var existing int64
	err = a.db.QueryRow("SELECT id FROM proposals WHERE room=? AND proposer=? AND nonce=?", room, req.Proposer, req.Nonce).Scan(&existing)
	if err == nil {
		writeJSON(w, 200, map[string]any{"id": existing, "replayed": true})
		return
	} else if !errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 500, err)
		return
	}
	res, err := a.db.Exec("INSERT INTO proposals(room, message, proposer, sig, nonce) VALUES(?,?,?,?,?)",
		room, req.Message, req.Proposer, req.Sig, req.Nonce)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	id, _ := res.LastInsertId()
	log.Printf("room %s: proposal %d created by participant %d: %q", room, id, req.Proposer, req.Message)
	writeJSON(w, 200, map[string]any{"id": id})
}
