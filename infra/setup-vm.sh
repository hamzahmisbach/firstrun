#!/usr/bin/env bash
# Idempotent VM setup for FirstRun on Ubuntu 24.04 (docs/ARCHITECTURE.md section 12, steps 7-13 and 17-18).
# Run from the repo checkout (normally /opt/firstrun):  sudo bash infra/setup-vm.sh
# Step 6 (deploy user, SSH hardening, ufw) stays manual. Optional env:
#   FIRSTRUN_HOSTNAME=firstrun.duckdns.org   also installs Caddy and renders infra/caddy/Caddyfile
#   INSTALL_PWSH=1                           builds the sandbox image with PowerShell (slower)
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export DEBIAN_FRONTEND=noninteractive

log() { printf '\n==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run with sudo"
# shellcheck source=/dev/null
. /etc/os-release
[[ "${VERSION_ID:-}" == "24.04" ]] || printf 'warning: tested on Ubuntu 24.04, found %s\n' "${VERSION_ID:-?}" >&2
case "$REPO_DIR" in *[!A-Za-z0-9/._-]*) die "repo path contains unusual characters: $REPO_DIR" ;; esac

log "base packages"
apt-get update -y
apt-get install -y ca-certificates curl gnupg git jq unattended-upgrades python3 python3-protobuf protobuf-compiler

log "Docker Engine from Docker's apt repo"
if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${UBUNTU_CODENAME:-$VERSION_CODENAME}
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin
fi
docker_version="$(docker version --format '{{.Server.Version}}')"
(( ${docker_version%%.*} >= 28 )) || die "Docker >= 28 is required for gateway_mode_ipv4=isolated (found $docker_version)"
echo "docker $docker_version"

log "gVisor runsc from gvisor.dev"
if ! command -v runsc >/dev/null 2>&1; then
  curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor --yes -o /usr/share/keyrings/gvisor-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
    > /etc/apt/sources.list.d/gvisor.list
  apt-get update -y
  apt-get install -y runsc
fi
RUNSC="$(command -v runsc)"
runsc --version | head -n1

log "Docker runtimes: runsc (trace), runsc-strace (fallback), runsc-plain (netcheck)"
install -d -m 0755 /etc/firstrun /var/log/firstrun /var/log/firstrun/runsc
install -m 0644 "$REPO_DIR/infra/gvisor-sink/trace-session.json" /etc/firstrun/trace-session.json
sed "s#/usr/bin/runsc#${RUNSC}#g" "$REPO_DIR/infra/docker/daemon.json" > /etc/docker/daemon.json.firstrun
if ! cmp -s /etc/docker/daemon.json.firstrun /etc/docker/daemon.json 2>/dev/null; then
  [[ -f /etc/docker/daemon.json && ! -f /etc/docker/daemon.json.orig ]] && cp /etc/docker/daemon.json /etc/docker/daemon.json.orig
  mv /etc/docker/daemon.json.firstrun /etc/docker/daemon.json
  systemctl restart docker
else
  rm -f /etc/docker/daemon.json.firstrun
fi
docker info --format '{{range $name, $_ := .Runtimes}}{{$name}} {{end}}'

log "service user and directories"
id -u firstrun >/dev/null 2>&1 || useradd --system --home-dir /srv/firstrun --shell /usr/sbin/nologin firstrun
install -d -m 0750 -o firstrun -g firstrun /srv/firstrun /srv/firstrun/runs /srv/firstrun/trace /srv/firstrun/spool
if [[ ! -f /etc/firstrun/firstrun.env ]]; then
  install -m 0640 -o root -g firstrun "$REPO_DIR/.env.example" /etc/firstrun/firstrun.env
  echo "created /etc/firstrun/firstrun.env from .env.example: fill in the keys"
fi

log "Node.js 24 from NodeSource (manual repo, no setup script)"
if ! node --version 2>/dev/null | grep -q '^v24\.'; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg
  cat > /etc/apt/sources.list.d/nodesource.sources <<EOF
Types: deb
URIs: https://deb.nodesource.com/node_24.x/
Suites: nodistro
Components: main
Signed-By: /etc/apt/keyrings/nodesource.gpg
EOF
  apt-get update -y
  apt-get install -y nodejs
fi
node --version

log "gVisor trace protos for the sidecar"
bash "$REPO_DIR/scripts/build-sink-protos.sh"

log "test CA and container images"
[[ -f "$REPO_DIR/sinkhole/ca/mitmproxy-ca.pem" ]] || bash "$REPO_DIR/scripts/gen-test-ca.sh"
INSTALL_PWSH="${INSTALL_PWSH:-0}" bash "$REPO_DIR/scripts/build-images.sh"

if [[ -f "$REPO_DIR/server/package-lock.json" ]]; then
  log "server dependencies"
  (cd "$REPO_DIR/server" && npm ci --omit=dev)
fi

log "systemd units and journald limits"
for unit in firstrun-sink.service firstrun.service; do
  sed "s#/opt/firstrun#${REPO_DIR}#g" "$REPO_DIR/infra/systemd/$unit" > "/etc/systemd/system/$unit"
done
install -d -m 0755 /etc/systemd/journald.conf.d
install -m 0644 "$REPO_DIR/infra/journald/firstrun.conf" /etc/systemd/journald.conf.d/firstrun.conf
systemctl restart systemd-journald
systemctl daemon-reload
systemctl enable --now firstrun-sink.service
systemctl enable firstrun.service
if [[ -f "$REPO_DIR/server/main.mjs" ]]; then
  systemctl restart firstrun.service || echo "firstrun.service did not start yet: check journalctl -u firstrun"
fi

if [[ -n "${FIRSTRUN_HOSTNAME:-}" ]]; then
  [[ "$FIRSTRUN_HOSTNAME" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || die "FIRSTRUN_HOSTNAME is not a valid hostname"
  log "Caddy for $FIRSTRUN_HOSTNAME"
  if ! command -v caddy >/dev/null 2>&1; then
    apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
    chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -y
    apt-get install -y caddy
  fi
  sed "s#__FIRSTRUN_HOSTNAME__#${FIRSTRUN_HOSTNAME}#g" "$REPO_DIR/infra/caddy/Caddyfile" > /etc/caddy/Caddyfile
  caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
  systemctl reload caddy || systemctl restart caddy
fi

log "done"
cat <<EOF
Next (day-1 go/no-go, docs/ARCHITECTURE.md 14.2):
  G1  docker run --rm --runtime=runsc-plain ubuntu:24.04 dmesg     # should mention gVisor
  G2  sudo bash $REPO_DIR/scripts/netcheck.sh
  G3  node --env-file=/etc/firstrun/firstrun.env $REPO_DIR/scripts/probe-vultr-inference.mjs
  G4  sudo bash $REPO_DIR/scripts/trace-selftest.sh
Fill in /etc/firstrun/firstrun.env before G3.
EOF
