// Package coordinator implements the HTTP bulletin board and its SQLite lifecycle.
// Run one Server per database; ceremony mutations are serialized within the process.
package coordinator

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"time"
)

// Config specifies process-local resources. Clients and protocol encodings do not
// depend on these settings.
type Config struct {
	Addr   string
	DBPath string
}

// Server owns the database and HTTP server. Call Close after Run returns.
// Do not copy Server or run it more than once.
type Server struct {
	db   *sql.DB
	http *http.Server
}

// New validates the embedded UI and initializes persistence before accepting traffic.
// assets is the filesystem rooted at the static directory.
func New(cfg Config, assets fs.FS) (*Server, error) {
	if cfg.Addr == "" || cfg.DBPath == "" {
		return nil, errors.New("listen address and database path are required")
	}
	if assets == nil {
		return nil, errors.New("static assets are required")
	}
	roomPage, err := fs.ReadFile(assets, "room.html")
	if err != nil {
		return nil, fmt.Errorf("load room page: %w", err)
	}
	db, err := openDB(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	s := &Server{db: db}
	mux := http.NewServeMux()
	(&apiServer{db: db}).routes(mux)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", s.ready)
	mux.Handle("GET /", http.FileServer(http.FS(assets)))
	mux.HandleFunc("GET /room/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(roomPage)
	})
	s.http = &http.Server{
		Addr: cfg.Addr, Handler: secureHandler(mux),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
	return s, nil
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	if err := s.db.PingContext(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// Run accepts requests until cancellation, draining active requests before returning.
// Bind failures are returned to the caller; the caller retains database ownership.
func (s *Server) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.http.Addr)
	if err != nil {
		return err
	}
	return s.serve(ctx, listener)
}

func (s *Server) serve(ctx context.Context, listener net.Listener) error {
	stopped := make(chan struct{})
	shutdown := make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
			drain, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			err := s.http.Shutdown(drain)
			if err != nil {
				_ = s.http.Close()
			}
			shutdown <- err
		case <-stopped:
			shutdown <- nil
		}
	}()
	err := s.http.Serve(listener)
	close(stopped)
	shutdownErr := <-shutdown
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return shutdownErr
}

// Close releases resources. Normally Run should first be stopped via its context.
func (s *Server) Close() error {
	return errors.Join(s.http.Close(), s.db.Close())
}

func secureHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		next.ServeHTTP(w, r)
	})
}
