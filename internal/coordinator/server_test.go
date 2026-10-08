package coordinator

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(Config{Addr: "127.0.0.1:0", DBPath: filepath.Join(t.TempDir(), "test.db")}, fstest.MapFS{
		"room.html":  &fstest.MapFile{Data: []byte("room page")},
		"index.html": &fstest.MapFile{Data: []byte("home page")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestHealthAndStaticRoutes(t *testing.T) {
	s := testServer(t)
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/healthz", `"ok"`, 200},
		{"GET", "/readyz", `"ready"`, 200},
		{"GET", "/room/example", "room page", 200},
		{"GET", "/", "home page", 200},
		{"POST", "/room/example", "", 405},
	} {
		w := httptest.NewRecorder()
		s.http.Handler.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.status {
			t.Fatalf("%s %s: %d", tc.method, tc.path, w.Code)
		}
		if tc.body != "" && !strings.Contains(w.Body.String(), tc.body) {
			t.Fatalf("unexpected response: %s", w.Body.String())
		}
	}
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
	if w.Code != 503 {
		t.Fatalf("closed database reported ready: %d", w.Code)
	}
}

func TestShutdownDrainsActiveRequest(t *testing.T) {
	s := testServer(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	s.http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = w.Write([]byte("completed"))
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.serve(ctx, listener) }()
	response := make(chan error, 1)
	go func() {
		client := &http.Client{Timeout: 5 * time.Second}
		res, err := client.Get("http://" + listener.Addr().String())
		if err != nil {
			response <- err
			return
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		if err == nil && string(data) != "completed" {
			err = fmt.Errorf("truncated response: %q", data)
		}
		response <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request never reached handler")
	}
	cancel()
	select {
	case err := <-done:
		t.Fatalf("server returned before draining: %v", err)
	default:
	}
	unblock()
	select {
	case err := <-response:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request did not finish")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not finish")
	}
}

func TestBindFailureReturns(t *testing.T) {
	s := testServer(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	s.http.Addr = listener.Addr().String()
	if err := s.Run(context.Background()); err == nil {
		t.Fatal("occupied address accepted")
	}
}

func TestMissingAssetsFailBeforeDatabaseCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unused.db")
	if _, err := New(Config{Addr: "127.0.0.1:0", DBPath: path}, fstest.MapFS{}); err == nil {
		t.Fatal("missing room page accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("database created despite asset failure: %v", err)
	}
}
