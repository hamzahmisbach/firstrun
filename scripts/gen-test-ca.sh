#!/usr/bin/env bash
# Create the throwaway test CA the sinkhole uses to terminate TLS (docs/ARCHITECTURE.md 6.4).
# It is trusted only inside disposable sandboxes. Outputs are gitignored; never commit them.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CA_DIR="$REPO_DIR/sinkhole/ca"
mkdir -p "$CA_DIR" "$REPO_DIR/sandbox/build"

(
  umask 077
  openssl genrsa -out "$CA_DIR/ca.key" 2048
  # Ubuntu's default openssl.cnf adds basicConstraints CA:TRUE via v3_ca; keyUsage is added here.
  openssl req -x509 -new -nodes -key "$CA_DIR/ca.key" -sha256 -days 3650 \
    -subj "/CN=FirstRun Test CA (untrusted)" \
    -addext "keyUsage=critical,keyCertSign" \
    -out "$CA_DIR/ca.crt"
  # mitmproxy expects key and certificate concatenated in one PEM.
  cat "$CA_DIR/ca.key" "$CA_DIR/ca.crt" > "$CA_DIR/mitmproxy-ca.pem"
)

install -m 0644 "$CA_DIR/ca.crt" "$REPO_DIR/sandbox/build/firstrun-test-ca.crt"
openssl x509 -in "$CA_DIR/ca.crt" -noout -subject -ext basicConstraints,keyUsage
