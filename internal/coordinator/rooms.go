package coordinator

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/elliottech/threshold-signature/frost"
	"log"
	"net/http"
	"slices"
	"strings"
)

func (a *apiServer) createRoom(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Threshold int      `json:"threshold"`
		Total     int      `json:"total"`
		Addresses []string `json:"addresses"`
	}
	if err := decodeRequest(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if req.Threshold < 1 || req.Total < req.Threshold || req.Total > 8 {
		writeErr(w, 400, errors.New("need 1 <= threshold <= total <= 8"))
		return
	}
	allowed, err := normalizeAllowlist(req.Addresses, req.Total)
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	id := generateRoomID()
	if _, err := a.db.Exec("INSERT INTO rooms(id, threshold, total, allowed) VALUES(?,?,?,?)",
		id, req.Threshold, req.Total, strings.Join(allowed, ",")); err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"room": id, "threshold": req.Threshold, "total": req.Total, "allowed": allowed})
}

// normalizeAllowlist validates an optional address allowlist: exactly total entries, valid
// unique 0x addresses, lowercased. Empty input means an open room.
func normalizeAllowlist(addrs []string, total int) ([]string, error) {
	if len(addrs) == 0 {
		return nil, nil
	}
	if len(addrs) != total {
		return nil, fmt.Errorf("allowlist must have exactly %d addresses, got %d", total, len(addrs))
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addr = strings.ToLower(strings.TrimSpace(addr))
		if !strings.HasPrefix(addr, "0x") || len(addr) != 42 {
			return nil, fmt.Errorf("invalid address in allowlist: %q", addr)
		}
		if _, err := hex.DecodeString(addr[2:]); err != nil {
			return nil, fmt.Errorf("invalid address in allowlist: %q", addr)
		}
		if seen[addr] {
			return nil, fmt.Errorf("duplicate address in allowlist: %s", addr)
		}
		seen[addr] = true
		out = append(out, addr)
	}
	return out, nil
}

// splitAllowlist turns the stored comma-joined allowlist back into a slice (nil when open).
func splitAllowlist(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// listRooms returns rooms with participant/proposal counts, newest first.
// With ?address=0x..., only rooms that address has joined are returned.
func (a *apiServer) listRooms(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	q := `SELECT r.id, r.threshold, r.total, COALESCE(r.group_pk,''), r.created_at,
			(SELECT COUNT(*) FROM participants p WHERE p.room=r.id),
			(SELECT COUNT(*) FROM proposals q WHERE q.room=r.id)
		FROM rooms r`
	var args []any
	if addr := strings.ToLower(r.URL.Query().Get("address")); addr != "" {
		q += " WHERE EXISTS (SELECT 1 FROM participants p WHERE p.room=r.id AND p.address=?)"
		args = append(args, addr)
	}
	q += " ORDER BY r.created_at DESC, r.id DESC"
	rows, err := a.db.Query(q, args...)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	defer rows.Close()
	type roomRow struct {
		Room      string `json:"room"`
		Threshold int    `json:"threshold"`
		Total     int    `json:"total"`
		GroupPk   string `json:"groupPk,omitempty"`
		CreatedAt string `json:"createdAt"`
		Joined    int    `json:"joined"`
		Proposals int    `json:"proposals"`
	}
	out := []roomRow{}
	for rows.Next() {
		var rr roomRow
		if err := rows.Scan(&rr.Room, &rr.Threshold, &rr.Total, &rr.GroupPk, &rr.CreatedAt, &rr.Joined, &rr.Proposals); err != nil {
			writeErr(w, 500, err)
			return
		}
		out = append(out, rr)
	}
	if err := rows.Err(); err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"rooms": out})
}

type participant struct {
	Idx         int        `json:"idx"`
	Address     string     `json:"address"`
	AuthPk      string     `json:"authPk"`
	EncPk       string     `json:"encPk"`
	EthSig      string     `json:"ethSig"`
	Commitments []string   `json:"commitments,omitempty"`
	Pok         *frost.PoK `json:"pok,omitempty"`
	JoinedAt    string     `json:"joinedAt"`
}

func (a *apiServer) loadParticipants(room string) ([]participant, error) {
	return loadParticipants(a.db, room)
}

type participantQuerier interface {
	Query(string, ...any) (*sql.Rows, error)
}

func loadParticipants(db participantQuerier, room string) ([]participant, error) {
	rows, err := db.Query(`SELECT idx, address, auth_pk, enc_pk, eth_sig, COALESCE(commitments,''), COALESCE(pok,'')
		FROM participants WHERE room=? ORDER BY idx`, room)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []participant
	for rows.Next() {
		var p participant
		var comms, pok string
		if err := rows.Scan(&p.Idx, &p.Address, &p.AuthPk, &p.EncPk, &p.EthSig, &comms, &pok); err != nil {
			return nil, err
		}
		if comms != "" {
			if err := json.Unmarshal([]byte(comms), &p.Commitments); err != nil {
				return nil, err
			}
		}
		if pok != "" {
			p.Pok = &frost.PoK{}
			if err := json.Unmarshal([]byte(pok), p.Pok); err != nil {
				return nil, err
			}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (a *apiServer) getRoom(w http.ResponseWriter, r *http.Request) {
	room := r.PathValue("room")
	a.mu.Lock()
	defer a.mu.Unlock()

	var threshold, total int
	var allowedStr string
	var groupPk sql.NullString
	err := a.db.QueryRow("SELECT threshold, total, allowed, group_pk FROM rooms WHERE id=?", room).Scan(&threshold, &total, &allowedStr, &groupPk)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, 404, errors.New("room not found"))
		return
	} else if err != nil {
		writeErr(w, 500, err)
		return
	}

	parts, err := a.loadParticipants(room)
	if err != nil {
		writeErr(w, 500, err)
		return
	}

	// Shares: map "from-to" -> ECIES ciphertext, only decryptable by the recipient's enc key.
	shares := map[string]string{}
	rows, err := a.db.Query("SELECT from_idx, to_idx, share FROM shares WHERE room=?", room)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	for rows.Next() {
		var f, t int
		var s string
		if err := rows.Scan(&f, &t, &s); err != nil {
			rows.Close()
			writeErr(w, 500, err)
			return
		}
		shares[fmt.Sprintf("%d-%d", f, t)] = s
	}
	rows.Close()

	proposals, err := a.loadProposals(room)
	if err != nil {
		writeErr(w, 500, err)
		return
	}

	state := "joining"
	if len(parts) == total {
		state = "dkg"
		done := 0
		for _, p := range parts {
			if len(p.Commitments) > 0 {
				done++
			}
		}
		if done == total {
			state = "ready"
		}
	}

	writeJSON(w, 200, map[string]any{
		"room": room, "threshold": threshold, "total": total, "allowed": splitAllowlist(allowedStr),
		"state": state, "groupPk": groupPk.String,
		"participants": parts, "shares": shares, "proposals": proposals,
	})
}

// joinRoom registers a participant. The request carries the participant's ceremony keys plus a
// MetaMask personal_sign of frost.JoinStatement, which binds those keys to the ETH address.
// The server verifies the signature and stores it so every client can re-verify membership.
func (a *apiServer) joinRoom(w http.ResponseWriter, r *http.Request) {
	room := r.PathValue("room")
	var req struct {
		Address string `json:"address"`
		AuthPk  string `json:"authPk"`
		EncPk   string `json:"encPk"`
		EthSig  string `json:"ethSig"`
	}
	if err := decodeRequest(r, &req); err != nil {
		writeErr(w, 400, err)
		return
	}
	req.Address = strings.ToLower(req.Address)
	if !strings.HasPrefix(req.Address, "0x") || len(req.Address) != 42 {
		writeErr(w, 400, errors.New("invalid address"))
		return
	}
	for _, pk := range []string{req.AuthPk, req.EncPk} {
		if b, err := hex.DecodeString(pk); err != nil || len(b) != 40 {
			writeErr(w, 400, errors.New("authPk and encPk must be 40-byte hex"))
			return
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	var threshold, total int
	var allowedStr string
	if err := a.db.QueryRow("SELECT threshold, total, allowed FROM rooms WHERE id=?", room).Scan(&threshold, &total, &allowedStr); err != nil {
		writeErr(w, 404, errors.New("room not found"))
		return
	}
	allowed := splitAllowlist(allowedStr)
	if len(allowed) > 0 && !slices.Contains(allowed, req.Address) {
		writeErr(w, 403, fmt.Errorf("address %s is not on this room's allowlist", req.Address))
		return
	}
	if err := frost.VerifyJoin(room, threshold, total, allowed, req.AuthPk, req.EncPk, req.Address, req.EthSig); err != nil {
		writeErr(w, 400, fmt.Errorf("join statement verification failed: %w", err))
		return
	}

	var idx int
	var storedAuthPk string
	err := a.db.QueryRow("SELECT idx, auth_pk FROM participants WHERE room=? AND address=?", room, req.Address).Scan(&idx, &storedAuthPk)
	if err == nil {
		if storedAuthPk != req.AuthPk {
			writeErr(w, 400, errors.New("address already joined with a different key"))
			return
		}
		writeJSON(w, 200, map[string]any{"idx": idx, "rejoined": true})
		return
	}

	var count int
	if err := a.db.QueryRow("SELECT COUNT(*) FROM participants WHERE room=?", room).Scan(&count); err != nil {
		writeErr(w, 500, err)
		return
	}
	if count >= total {
		writeErr(w, 400, errors.New("room is full"))
		return
	}
	idx = count + 1
	if _, err := a.db.Exec("INSERT INTO participants(room, idx, address, auth_pk, enc_pk, eth_sig) VALUES(?,?,?,?,?,?)",
		room, idx, req.Address, req.AuthPk, req.EncPk, req.EthSig); err != nil {
		writeErr(w, 500, err)
		return
	}
	log.Printf("room %s: %s joined as participant %d/%d", room, req.Address, idx, total)
	writeJSON(w, 200, map[string]any{"idx": idx})
}
