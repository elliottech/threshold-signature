package coordinator

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"sync"
)

type apiServer struct {
	db *sql.DB
	mu sync.Mutex
}

func (a *apiServer) routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/rooms", a.createRoom)
	mux.HandleFunc("GET /api/rooms", a.listRooms)
	mux.HandleFunc("GET /api/rooms/{room}", a.getRoom)
	mux.HandleFunc("POST /api/rooms/{room}/join", a.joinRoom)
	mux.HandleFunc("POST /api/rooms/{room}/dkg", a.postDkg)
	mux.HandleFunc("POST /api/rooms/{room}/proposals", a.createProposal)
	mux.HandleFunc("POST /api/proposals/{id}/commit", a.postCommit)
	mux.HandleFunc("POST /api/proposals/{id}/partial", a.postPartial)
	mux.HandleFunc("POST /api/proposals/{id}/execute", a.executeProposal)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeRequest(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("body must contain exactly one JSON value")
	}
	return nil
}

func writeErr(w http.ResponseWriter, status int, err error) {
	if status >= 500 {
		log.Printf("API error: %v", err)
		err = errors.New("internal server error")
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
