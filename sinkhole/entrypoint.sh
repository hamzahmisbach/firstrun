#!/bin/sh
# Wire the sinkhole inside its per-run network namespace, then drop privileges (docs/ARCHITECTURE.md 6.3).
# Runs as root with only NET_ADMIN, NET_BIND_SERVICE, SETUID and SETGID. /sinkhole is a host bind
# mount the orchestrator creates with mode 0777, because root here has no CAP_DAC_OVERRIDE.
set -eu

OUT=/sinkhole
SELF_IP="$(ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1)"
[ -n "$SELF_IP" ] || { echo "sinkhole: no IPv4 address on eth0" >&2; exit 1; }

# Everything that reaches this namespace is aimed at us (DNS answers our own IP); split it by port.
iptables -t nat -A PREROUTING -i eth0 -p tcp -m multiport \
  --dports 80,443,8080,8443,8000,8888,3000,5000,9443 -j REDIRECT --to-ports 8080
iptables -t nat -A PREROUTING -i eth0 -p tcp ! --dport 53 -j REDIRECT --to-ports 9009
iptables -t nat -A PREROUTING -i eth0 -p udp ! --dport 53 -j REDIRECT --to-ports 9009

# Wildcard DNS with no upstream at all: every name resolves to the sinkhole.
cat > /tmp/dnsmasq.conf <<EOF
port=53
interface=eth0
bind-interfaces
no-resolv
no-hosts
no-poll
address=/#/${SELF_IP}
local-ttl=0
log-queries
log-facility=-
pid-file=
EOF
dnsmasq --keep-in-foreground --conf-file=/tmp/dnsmasq.conf >>"$OUT/dns.log" 2>&1 &

gosu mitmproxy python3 /opt/firstrun/tcpsink.py --out "$OUT/tcp.jsonl" --port 9009 &

# mitmproxy writes helper files (dhparam) next to its CA, so give it a writable copy on tmpfs.
gosu mitmproxy sh -c 'mkdir -p /tmp/mitmca && cp /opt/firstrun/ca/mitmproxy-ca.pem /tmp/mitmca/'

SAMPLE="${FIRSTRUN_SAMPLE:-none}"
case "$SAMPLE" in ""|*[!a-z0-9-]*) SAMPLE=none ;; esac
CANNED="/opt/firstrun/canned/${SAMPLE}.json"
[ -f "$CANNED" ] || CANNED=/opt/firstrun/canned/none.json

exec gosu mitmproxy mitmdump --mode transparent --listen-host 0.0.0.0 --listen-port 8080 \
  --set confdir=/tmp/mitmca --set upstream_cert=false --set connection_strategy=lazy \
  --set body_size_limit=2m --set flow_detail=0 \
  -s /opt/firstrun/addon/sinkhole.py --set sinkhole_dir="$OUT" --set canned="$CANNED"
