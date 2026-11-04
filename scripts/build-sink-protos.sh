#!/usr/bin/env bash
# Fetch gVisor's trace-point .proto files for the installed runsc release and generate the
# Python modules the sidecar imports (docs/ARCHITECTURE.md 7.1).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SINK_DIR="$REPO_DIR/infra/gvisor-sink"
PROTO_ROOT="$SINK_DIR/proto"
PROTO_DIR="$PROTO_ROOT/pkg/sentry/seccheck/points"  # imports in syscall.proto etc. expect this layout
OUT_DIR="$SINK_DIR/pb"
RAW="https://raw.githubusercontent.com/google/gvisor"

ref="$(runsc --version 2>/dev/null | sed -n 's/^runsc version \(release-[0-9.]*\).*/\1/p' | head -n1 || true)"
ref="${ref:-master}"
echo "gVisor proto ref: $ref"

mkdir -p "$PROTO_DIR"
for name in common container sentry syscall; do
  if ! curl -fsSL "$RAW/$ref/pkg/sentry/seccheck/points/$name.proto" -o "$PROTO_DIR/$name.proto"; then
    echo "no $name.proto at $ref, falling back to master" >&2
    curl -fsSL "$RAW/master/pkg/sentry/seccheck/points/$name.proto" -o "$PROTO_DIR/$name.proto"
  fi
done

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
(cd "$PROTO_ROOT" && protoc -I . --python_out="$OUT_DIR" pkg/sentry/seccheck/points/*.proto)

echo "protoc $(protoc --version | awk '{print $2}'), python protobuf $(python3 -c 'import google.protobuf as p; print(p.__version__)')"
python3 -I - "$OUT_DIR" <<'EOF'
import sys
sys.path.insert(0, sys.argv[1])
from pkg.sentry.seccheck.points import common_pb2, container_pb2, sentry_pb2, syscall_pb2
assert common_pb2.MESSAGE_SYSCALL_CONNECT == 10, "unexpected MessageType numbering"
print("generated modules import fine")
EOF
