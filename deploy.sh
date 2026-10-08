#!/usr/bin/env bash
# The old SSH/pkill deployment has been retired. Build artifacts locally; install
# them through your deployment system using deploy/tsig.service as a starting point.
set -euo pipefail
printf '%s\n' 'Use ./scripts/build.sh and follow README.md. No remote changes were made.' >&2
exit 1
