#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
pid=''
cleanup() {
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" || true
  fi
  cat "$work/server.log"
  rm -rf "$work"
}
trap cleanup EXIT
./dist/tsig-server -addr 127.0.0.1:19000 -db "$work/tsig.db" > "$work/server.log" 2>&1 &
pid=$!
for attempt in $(seq 1 30); do
  if curl --fail --silent http://127.0.0.1:19000/readyz > /dev/null; then break; fi
  if ! kill -0 "$pid" 2>/dev/null; then exit 1; fi
  sleep 1
done
go run ./e2e -base http://127.0.0.1:19000
