// Package tsigclient is a small typed HTTP client for the threshold-signature REST API,
// shared by the CLI and the e2e tests.
package tsigclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/elliottech/threshold-signature/frost"
)

type Client struct {
	Base string
	http *http.Client
}

func New(base string) *Client {
	return &Client{Base: strings.TrimRight(base, "/"), http: &http.Client{Timeout: 15 * time.Second}}
}

func (c *Client) call(method, path string, body, out any) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequest(method, c.Base+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(&raw); err != nil {
		return fmt.Errorf("%s %s: HTTP %d (bad JSON: %w)", method, path, res.StatusCode, err)
	}
	if e, ok := raw["error"]; ok {
		var msg string
		_ = json.Unmarshal(e, &msg)
		return fmt.Errorf("%s %s: %s", method, path, msg)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("%s %s: HTTP %d", method, path, res.StatusCode)
	}
	if out != nil {
		b, _ := json.Marshal(raw)
		return json.Unmarshal(b, out)
	}
	return nil
}

type RoomSummary struct {
	Room      string `json:"room"`
	Threshold int    `json:"threshold"`
	Total     int    `json:"total"`
	GroupPk   string `json:"groupPk"`
	CreatedAt string `json:"createdAt"`
	Joined    int    `json:"joined"`
	Proposals int    `json:"proposals"`
}

type Participant struct {
	Idx         int        `json:"idx"`
	Address     string     `json:"address"`
	AuthPk      string     `json:"authPk"`
	EncPk       string     `json:"encPk"`
	EthSig      string     `json:"ethSig"`
	Commitments []string   `json:"commitments"`
	Pok         *frost.PoK `json:"pok"`
	JoinedAt    string     `json:"joinedAt"`
}

type Proposal struct {
	ID        int64                        `json:"id"`
	Message   string                       `json:"message"`
	Proposer  int                          `json:"proposer"`
	Sig       string                       `json:"sig"`
	Nonce     string                       `json:"nonce"`
	Status    string                       `json:"status"`
	SignerSet []int                        `json:"signerSet"`
	FinalSig  string                       `json:"finalSig"`
	Valid     *bool                        `json:"valid"`
	Commits   map[string]map[string]string `json:"commits"` // idx -> {d, e}
	Partials  map[string]string            `json:"partials"`
}

type RoomState struct {
	Room         string            `json:"room"`
	Threshold    int               `json:"threshold"`
	Total        int               `json:"total"`
	Allowed      []string          `json:"allowed"`
	State        string            `json:"state"`
	GroupPk      string            `json:"groupPk"`
	Participants []Participant     `json:"participants"`
	Shares       map[string]string `json:"shares"`
	Proposals    []Proposal        `json:"proposals"`
}

// CreateRoom creates a room; addresses is an optional allowlist of exactly `total` ETH
// addresses that are allowed to join (nil for an open room).
func (c *Client) CreateRoom(threshold, total int, addresses []string) (string, error) {
	var out struct {
		Room string `json:"room"`
	}
	err := c.call("POST", "/api/rooms", map[string]any{"threshold": threshold, "total": total, "addresses": addresses}, &out)
	return out.Room, err
}

func (c *Client) ListRooms() ([]RoomSummary, error) {
	var out struct {
		Rooms []RoomSummary `json:"rooms"`
	}
	err := c.call("GET", "/api/rooms", nil, &out)
	return out.Rooms, err
}

func (c *Client) Room(room string) (*RoomState, error) {
	var out RoomState
	if err := c.call("GET", "/api/rooms/"+room, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Join(room, address, authPk, encPk, ethSig string) (idx int, rejoined bool, err error) {
	var out struct {
		Idx      int  `json:"idx"`
		Rejoined bool `json:"rejoined"`
	}
	err = c.call("POST", "/api/rooms/"+room+"/join",
		map[string]string{"address": address, "authPk": authPk, "encPk": encPk, "ethSig": ethSig}, &out)
	return out.Idx, out.Rejoined, err
}

func (c *Client) PostDkg(room string, idx int, commitments []string, pok frost.PoK, shares map[string]string, sig string) error {
	return c.call("POST", "/api/rooms/"+room+"/dkg",
		map[string]any{"idx": idx, "commitments": commitments, "pok": pok, "shares": shares, "sig": sig}, nil)
}

func (c *Client) Propose(room, message string, proposer int, nonce, sig string) (int64, error) {
	var out struct {
		ID int64 `json:"id"`
	}
	err := c.call("POST", "/api/rooms/"+room+"/proposals",
		map[string]any{"message": message, "proposer": proposer, "nonce": nonce, "sig": sig}, &out)
	return out.ID, err
}

func (c *Client) Commit(proposalID int64, idx int, d, e, sig string) error {
	return c.call("POST", fmt.Sprintf("/api/proposals/%d/commit", proposalID),
		map[string]any{"idx": idx, "d": d, "e": e, "sig": sig}, nil)
}

func (c *Client) Partial(proposalID int64, idx int, sHex, sig string) error {
	return c.call("POST", fmt.Sprintf("/api/proposals/%d/partial", proposalID),
		map[string]any{"idx": idx, "s": sHex, "sig": sig}, nil)
}

func (c *Client) Execute(proposalID int64) (sig string, valid bool, verifyErr string, err error) {
	var out struct {
		Sig         string `json:"sig"`
		Valid       bool   `json:"valid"`
		VerifyError string `json:"verifyError"`
	}
	err = c.call("POST", fmt.Sprintf("/api/proposals/%d/execute", proposalID), map[string]any{}, &out)
	return out.Sig, out.Valid, out.VerifyError, err
}
