#!/usr/bin/env bash
# Go/no-go G2 (docs/ARCHITECTURE.md 6.1 and 14.2): from a gVisor container on a per-run internal
# network, HTTPS must be answered by the sinkhole, while the host and the internet must fail at once
# (no route), not after a timeout. Exit code 0 = contained.
set -euo pipefail

ID="NETCHECK$(date +%s)"
NET="fr-${ID}"
WORK="$(mktemp -d /tmp/firstrun-netcheck.XXXXXX)"
cleanup() {
  docker rm -f "${NET}-sink" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/sinkhole"
chmod 0777 "$WORK/sinkhole"  # root inside the sinkhole has no CAP_DAC_OVERRIDE

docker network create --internal \
  -o com.docker.network.bridge.gateway_mode_ipv4=isolated \
  --label "firstrun.run=${ID}" "$NET" >/dev/null

docker run -d --name "${NET}-sink" --network "$NET" --hostname sink \
  --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE --cap-add SETUID --cap-add SETGID \
  --security-opt no-new-privileges \
  --read-only --tmpfs /tmp:rw,size=64m --tmpfs /run:rw,size=8m \
  --mount "type=bind,src=$WORK/sinkhole,dst=/sinkhole" \
  --memory 256m --memory-swap 256m --cpus 0.5 --pids-limit 64 \
  --label "firstrun.run=${ID}" --label firstrun.phase=sinkhole \
  firstrun/sinkhole:latest >/dev/null

for _ in $(seq 50); do [[ -f "$WORK/sinkhole/ready" ]] && break; sleep 0.2; done
if [[ ! -f "$WORK/sinkhole/ready" ]]; then
  echo "FAIL sinkhole did not become ready"
  docker logs "${NET}-sink" 2>&1 | tail -n 40
  exit 1
fi

SINK_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "${NET}-sink")"
printf 'nameserver %s\noptions timeout:1 attempts:1 ndots:1\n' "$SINK_IP" > "$WORK/resolv.conf"
HOST_IP="$(hostname -I | awk '{print $1}')"
echo "sinkhole $SINK_IP, host $HOST_IP"

result=0
docker run --rm --runtime=runsc-plain --network "$NET" \
  --mount "type=bind,src=$WORK/resolv.conf,dst=/etc/resolv.conf,ro" \
  -e "HOST_IP=$HOST_IP" --entrypoint /bin/bash firstrun/sandbox:latest -c '
    fail=0
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 https://example.test/ || true)
    if [ "$code" = 200 ]; then echo "PASS https://example.test/ answered by the sinkhole (200)"
    else echo "FAIL https://example.test/ returned $code"; fail=1; fi
    for url in "http://$HOST_IP:3000/" "http://1.1.1.1/"; do
      start=$(date +%s%N)
      if curl -s -o /dev/null --connect-timeout 2 --max-time 3 "$url"; then
        echo "FAIL $url is reachable"; fail=1; continue
      fi
      ms=$(( ($(date +%s%N) - start) / 1000000 ))
      if [ "$ms" -lt 1000 ]; then echo "PASS $url unreachable after ${ms} ms"
      else echo "FAIL $url failed only after ${ms} ms (timeout instead of no route)"; fail=1; fi
    done
    exit $fail' || result=1

if grep -q '"host":"example.test"' "$WORK/sinkhole/events.jsonl" 2>/dev/null; then
  echo "PASS sinkhole recorded the HTTPS request"
else
  echo "FAIL sinkhole has no record of the HTTPS request"; result=1
fi
if grep -q 'query\[A\] example.test' "$WORK/sinkhole/dns.log" 2>/dev/null; then
  echo "PASS dnsmasq logged the lookup"
else
  echo "FAIL dnsmasq did not log the lookup"; result=1
fi

if [[ $result -ne 0 ]]; then
  echo "--- sinkhole logs ---"
  docker logs "${NET}-sink" 2>&1 | tail -n 40
fi
exit $result
