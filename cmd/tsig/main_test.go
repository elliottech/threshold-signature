package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNonceJournalFailsClosed(t *testing.T) {
	for _, content := range []string{`{`, `null`, `{}`, `{"entries":null}`, `{"entries":{"room/1":null}}`} {
		t.Run(content, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := openNonceStore(path); err == nil {
				t.Fatal("invalid journal accepted")
			}
		})
	}
}

func TestNonceJournalPersistsConsumedNonce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	ns, err := openNonceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ns.entry("room", 1).Nonces = "secret"
	if err := ns.save(); err != nil {
		t.Fatal(err)
	}
	ns, err = openNonceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ent := ns.entry("room", 1)
	if ent.Nonces != "secret" {
		t.Fatal("lost nonce")
	}
	ent.Nonces, ent.Signed = "", true
	if err := ns.save(); err != nil {
		t.Fatal(err)
	}
	ns, err = openNonceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if ent := ns.entry("room", 1); !ent.Signed || ent.Nonces != "" {
		t.Fatal("consumed nonce restored")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("journal is not private")
	}
}
