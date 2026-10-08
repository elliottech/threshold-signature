#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist
# The runtime shim must come from the same Go toolchain as the WASM binary.
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" static/wasm_exec.js
GOOS=js GOARCH=wasm go build -trimpath -o static/main.wasm ./wasmclient
go build -trimpath -o dist/tsig-server .
go build -trimpath -o dist/tsig ./cmd/tsig
