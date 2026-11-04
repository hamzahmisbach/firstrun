#!/usr/bin/env bash
# Go/no-go G4 (docs/ARCHITECTURE.md 7.5 and 14.2): trace points from a runsc container must reach
# the sidecar and land in /srv/firstrun/trace/<container_id>.jsonl. Run with sudo.
#   --fail-closed   also check that runsc refuses to start while the sidecar is stopped
set -euo pipefail

TRACE_DIR=/srv/firstrun/trace
SOCK=/run/firstrun/gvisor-sink.sock
WORK="$(mktemp -d /tmp/firstrun-trace.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

[[ -S "$SOCK" ]] || { echo "FAIL sidecar socket $SOCK is missing (systemctl status firstrun-sink)"; exit 1; }

# Benign probe: read a file, write a file, attempt one TCP connect, call one shim.
docker run --rm --runtime=runsc --network none --cidfile "$WORK/cid" \
  --entrypoint /bin/bash firstrun/sandbox:latest -c \
  'cat /etc/hostname >/dev/null; echo probe > /tmp/probe.txt; (exec 3<>/dev/tcp/10.0.0.1/80) 2>/dev/null || true; /opt/firstrun/shims/crontab -l >/dev/null || true'

CID="$(cat "$WORK/cid")"
FILE="$TRACE_DIR/$CID.jsonl"
for _ in $(seq 30); do [[ -s "$FILE" ]] && grep -q '"sink.closed"' "$FILE" && break; sleep 0.1; done
[[ -s "$FILE" ]] || { echo "FAIL no trace file $FILE"; exit 1; }

result=0
count() { jq -s "map(select(.type == $1)) | length" "$FILE"; }
check() { # name, actual, minimum, severity
  if (( $2 >= $3 )); then
    echo "PASS $1: $2"
  else
    echo "$4 $1: $2 (expected >= $3)"
    if [[ $4 == FAIL ]]; then result=1; fi
  fi
}
check "container/start" "$(count 1)" 1 FAIL
# Two, not three: the entrypoint bash arrives as container/start, so only cat and the shim exec.
check "sentry/execve" "$(count 3)" 2 FAIL
check "syscall/open*" "$(count 7)" 1 FAIL
check "syscall/connect (unverified with --network none)" "$(count 10)" 1 WARN
check "open of /tmp/probe.txt" "$(jq -s '[.[] | select(.type == 7) | select((.msg.pathname // "") | endswith("probe.txt"))] | length' "$FILE")" 1 FAIL
dropped="$(jq -s 'map(.dropped // 0) | max' "$FILE")"
check "no dropped points" "$(( dropped == 0 ? 1 : 0 ))" 1 FAIL

echo "--- raw execve record of the shim (locks the shim rule in 7.3) ---"
jq -c 'select(.type == 3) | select(((.msg.execfn // "") + (.msg.binary_path // "") + ((.msg.argv // [""])[0])) | contains("crontab")) | {execfn: .msg.execfn, binary_path: .msg.binary_path, argv: .msg.argv, context: .msg.context_data}' "$FILE" | head -n 2

if [[ "${1:-}" == "--fail-closed" ]]; then
  systemctl stop firstrun-sink
  if docker run --rm --runtime=runsc --network none --entrypoint /bin/true firstrun/sandbox:latest >/dev/null 2>&1; then
    echo "FAIL runsc started while the sidecar was down"; result=1
  else
    echo "PASS runsc refused to start without the sidecar (fail closed)"
  fi
  systemctl start firstrun-sink
fi

rm -f "$FILE"
exit $result
