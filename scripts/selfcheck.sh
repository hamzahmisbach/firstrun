#!/usr/bin/env bash
# Orchestrator startup self-test (docs/ARCHITECTURE.md 11, 12 step 18): docker reachable, runsc
# runtime registered, sidecar socket + heartbeat alive, and the network containment check from
# scripts/netcheck.sh (6.1) rebuilt here because the service runs with PrivateTmp: a bind mount
# under /tmp would point dockerd at a path that does not exist outside the unit's namespace.
# Runs as the service user (docker group). Exit 0 = every check passed.
#   --work-dir DIR     scratch directory for the throwaway run (default: $FIRSTRUN_RUNS_DIR/_selfcheck)
#   --sink-socket P    sidecar socket (default: $FIRSTRUN_SINK_SOCKET or /run/firstrun/gvisor-sink.sock)
#   --quick            skip the containment check (only docker, runsc, sidecar)
set -uo pipefail

WORK_BASE="${FIRSTRUN_RUNS_DIR:-/srv/firstrun/runs}/_selfcheck"
SOCK="${FIRSTRUN_SINK_SOCKET:-/run/firstrun/gvisor-sink.sock}"
TRACE_DIR="${FIRSTRUN_TRACE_DIR:-/srv/firstrun/trace}"
RUNSC_LOG_DIR="${FIRSTRUN_RUNSC_LOG_DIR:-/var/log/firstrun/runsc}"
QUICK=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --work-dir) WORK_BASE="$2"; shift 2 ;;
    --sink-socket) SOCK="$2"; shift 2 ;;
    --quick) QUICK=1; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

result=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; result=1; }

if ver="$(docker version --format '{{.Server.Version}}' 2>/dev/null)"; then pass "docker $ver"; else fail "docker is not reachable"; fi
if docker info --format '{{range $n, $_ := .Runtimes}}{{$n}} {{end}}' 2>/dev/null | grep -qw runsc; then
  pass "runsc runtime registered"
else
  fail "runsc runtime is not registered in dockerd"
fi
if [[ -S "$SOCK" ]]; then pass "sidecar socket $SOCK"; else fail "sidecar socket $SOCK is missing"; fi
if [[ -f "$SOCK.heartbeat" ]]; then
  age=$(( $(date +%s) - $(stat -c %Y "$SOCK.heartbeat") ))
  if (( age < 60 )); then pass "sidecar heartbeat ${age}s old"; else fail "sidecar heartbeat is ${age}s old"; fi
else
  fail "sidecar heartbeat file is missing"
fi
for img in firstrun/sandbox:latest firstrun/sinkhole:latest; do
  if docker image inspect "$img" >/dev/null 2>&1; then pass "image $img"; else fail "image $img is missing"; fi
done

if (( QUICK == 1 || result != 0 )); then exit $result; fi

ID="SELFCHECK$(date +%s)$$"
NET="fr-${ID}"
WORK="$WORK_BASE/$ID"
cleanup() {
  docker rm -f "${NET}-sink" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  # The probe container's trace file and runsc logs would otherwise sit there until the janitor's sweep.
  if [[ -s "$WORK/cid" ]]; then
    cid="$(cat "$WORK/cid")"
    if [[ "$cid" =~ ^[0-9a-f]{64}$ ]]; then rm -f "$TRACE_DIR/$cid.jsonl" "$RUNSC_LOG_DIR/$cid".*.log; fi
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT
mkdir -p "$WORK/sinkhole" && chmod 0755 "$WORK_BASE" "$WORK" && chmod 0777 "$WORK/sinkhole" || { fail "cannot create $WORK"; exit 1; }

docker network create --internal \
  -o com.docker.network.bridge.gateway_mode_ipv4=isolated \
  --label "firstrun.run=${ID}" "$NET" >/dev/null || { fail "network create"; exit 1; }

docker run -d --name "${NET}-sink" --network "$NET" --hostname sink \
  --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE --cap-add SETUID --cap-add SETGID \
  --security-opt no-new-privileges \
  --read-only --tmpfs /tmp:rw,size=64m --tmpfs /run:rw,size=8m \
  --mount "type=bind,src=$WORK/sinkhole,dst=/sinkhole" \
  --memory 256m --memory-swap 256m --cpus 0.5 --pids-limit 64 \
  --label "firstrun.run=${ID}" --label firstrun.phase=sinkhole \
  --log-driver none --stop-timeout 1 \
  firstrun/sinkhole:latest >/dev/null || { fail "sinkhole start"; exit 1; }

for _ in $(seq 75); do [[ -f "$WORK/sinkhole/ready" ]] && break; sleep 0.2; done
[[ -f "$WORK/sinkhole/ready" ]] || { fail "sinkhole did not become ready in 15 s"; exit 1; }

SINK_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "${NET}-sink")"
printf 'nameserver %s\noptions timeout:1 attempts:1 ndots:1\n' "$SINK_IP" > "$WORK/resolv.conf"
chmod 0644 "$WORK/resolv.conf"
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
HOST_IP="${HOST_IP:-10.255.255.254}"

# runsc (not runsc-plain): this also proves the trace session attaches and the sidecar accepts it.
out="$(docker run --rm --runtime=runsc --network "$NET" --user 1000:1000 --cap-drop ALL --cidfile "$WORK/cid" \
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
    exit $fail' 2>&1)"
rc=$?
echo "$out"
(( rc == 0 )) || result=1
if grep -q '"host":"example.test"' "$WORK/sinkhole/events.jsonl" 2>/dev/null; then
  pass "sinkhole recorded the HTTPS request"
else
  fail "sinkhole has no record of the HTTPS request"
fi
exit $result
