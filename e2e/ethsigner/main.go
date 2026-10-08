// Test helper: HTTP service that does MetaMask-style personal_sign for the UI smoke test.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"

	"github.com/elliottech/threshold-sig-poc/frost"
)

func main() {
	http.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			return
		}
		var in struct{ Key, Msg string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		d := sha256.Sum256([]byte("ui-test-key/" + in.Key))
		seed := append(d[:], d[:]...)
		priv := frost.EthKeyFromSeed(seed)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"address": frost.EthAddress(priv),
			"sig":     frost.SignPersonal(priv, in.Msg),
		})
	})
	_ = http.ListenAndServe(":9199", nil)
}
