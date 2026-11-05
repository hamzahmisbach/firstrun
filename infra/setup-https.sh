#!/usr/bin/env bash
# Puts the site on public HTTPS: nginx in front of the orchestrator and a Let's Encrypt certificate
# from certbot. Safe to run again. The hostname's DNS record and ports 80 and 443 must be ready.
#   sudo bash infra/setup-https.sh firstrun.example.org
# Set CERTBOT_EMAIL to get expiry warnings from Let's Encrypt; without it no address is registered.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE=/etc/firstrun/firstrun.env
HOST="${1:-${FIRSTRUN_HOSTNAME:-}}"

log() { printf '\n== %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root"
[[ "$HOST" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || die "usage: sudo bash infra/setup-https.sh <hostname>"

render() {
  sed "s#__FIRSTRUN_HOSTNAME__#${HOST}#g" "$REPO_DIR/infra/nginx/$1" > "/etc/nginx/sites-available/$1"
  ln -sf "/etc/nginx/sites-available/$1" "/etc/nginx/sites-enabled/$1"
}

log "nginx and certbot"
export DEBIAN_FRONTEND=noninteractive
apt-get install -y nginx certbot
systemctl enable --now nginx
install -d -m 0755 /var/www/certbot

log "port 80 for $HOST"
rm -f /etc/nginx/sites-enabled/default
render firstrun-http.conf
nginx -t
systemctl reload nginx

if [[ -e "/etc/letsencrypt/live/$HOST/fullchain.pem" ]]; then
  log "certificate already there; certbot.timer renews it"
else
  CONTACT=(--register-unsafely-without-email)
  [[ -n "${CERTBOT_EMAIL:-}" ]] && CONTACT=(--email "$CERTBOT_EMAIL")
  ISSUE=(certonly --webroot -w /var/www/certbot -d "$HOST" --non-interactive --agree-tos "${CONTACT[@]}" --deploy-hook 'systemctl reload nginx')
  # A dry run uses the staging server, so a blocked port does not eat into the real failure limit.
  log "trying the certificate request on the Let's Encrypt staging server"
  certbot "${ISSUE[@]}" --dry-run || die "check the DNS record of $HOST and that port 80 is open in the Vultr firewall group"
  log "requesting the certificate"
  certbot "${ISSUE[@]}"
fi
systemctl enable --now certbot.timer

log "port 443 for $HOST"
render firstrun-https.conf
nginx -t
systemctl reload nginx

if [[ -f "$ENV_FILE" ]]; then
  log "FIRSTRUN_PUBLIC_URL=https://$HOST"
  if grep -q '^FIRSTRUN_PUBLIC_URL=' "$ENV_FILE"; then
    sed -i "s#^FIRSTRUN_PUBLIC_URL=.*#FIRSTRUN_PUBLIC_URL=https://${HOST}#" "$ENV_FILE"
  else
    printf 'FIRSTRUN_PUBLIC_URL=https://%s\n' "$HOST" >> "$ENV_FILE"
  fi
  systemctl try-restart firstrun.service
fi

log "done: https://$HOST"
