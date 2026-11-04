#!/usr/bin/env bash
# Build firstrun/sandbox and firstrun/sinkhole together so both carry the same test CA (docs 6.4),
# and copy each curated sample's canned.json into the sinkhole image.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "$REPO_DIR/sinkhole/ca/mitmproxy-ca.pem" && -f "$REPO_DIR/sandbox/build/firstrun-test-ca.crt" ]] \
  || { echo "missing test CA: run scripts/gen-test-ca.sh first" >&2; exit 1; }

CANNED="$REPO_DIR/sinkhole/canned"
rm -rf "$CANNED"
mkdir -p "$CANNED"
echo '[]' > "$CANNED/none.json"
for file in "$REPO_DIR"/fixtures/samples/*/canned.json; do
  [[ -e "$file" ]] || continue
  id="$(basename "$(dirname "$file")")"
  [[ "$id" =~ ^[a-z0-9][a-z0-9-]{0,39}$ ]] || { echo "skipping sample with invalid id: $id" >&2; continue; }
  cp "$file" "$CANNED/$id.json"
done

docker build --pull -t firstrun/sandbox:latest --build-arg "INSTALL_PWSH=${INSTALL_PWSH:-0}" "$REPO_DIR/sandbox"
docker build --pull -t firstrun/sinkhole:latest "$REPO_DIR/sinkhole"
docker image ls --filter 'reference=firstrun/*'
