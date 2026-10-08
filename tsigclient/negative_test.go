package tsigclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestConnectionRefusedIsAnError checks that a client pointed at a server that isn't listening
// returns an error rather than hanging or panicking.
func TestConnectionRefusedIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	base := srv.URL
	srv.Close() // now nothing is listening on this address
	if err := New(base).call("GET", "/", nil, nil); err == nil {
		t.Fatal("request to a closed connection succeeded")
	}
}

// TestEmptyBodyIsRejected checks that a response with no body at all (not even `{}`) is treated
// as an error rather than silently succeeding with a zero-value result.
func TestEmptyBodyIsRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := New(srv.URL).call("GET", "/", nil, nil); err == nil {
		t.Fatal("empty response body accepted")
	}
}

// TestNonJSONContentTypeStillParsedAsJSON documents that the client parses the body as JSON
// regardless of Content-Type, so a plain-text error page from a misconfigured proxy is reported
// as a decode failure rather than silently misinterpreted.
func TestNonJSONContentTypeStillParsedAsJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html><body>502 Bad Gateway</body></html>"))
	}))
	defer srv.Close()
	if err := New(srv.URL).call("GET", "/", nil, nil); err == nil {
		t.Fatal("HTML error page from a proxy was accepted as a valid API response")
	}
}

// TestOutParameterUntouchedOnError checks that a failed call does not partially populate the
// caller's out struct with a zero-value result that could be mistaken for a real response.
func TestOutParameterUntouchedOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	out := RoomSummary{Room: "sentinel-value"}
	if err := New(srv.URL).call("GET", "/", nil, &out); err == nil {
		t.Fatal("server error treated as success")
	}
	if out.Room != "sentinel-value" {
		t.Fatalf("out struct was mutated despite the call failing: %+v", out)
	}
}
