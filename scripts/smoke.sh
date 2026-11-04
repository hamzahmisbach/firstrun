#!/usr/bin/env bash
# Smoke test (docs/ARCHITECTURE.md 12, step 19): the parts that can be automated, in order.
# Run on the VM with sudo, against the local orchestrator or the public URL:
#   sudo bash scripts/smoke.sh                      # http://127.0.0.1:3000
#   sudo bash scripts/smoke.sh https://<host>
# Options:
#   --with-rate-limit   step 8: spend the per-IP POST budget (5 per 10 min) and expect a 429
#   --skip-fail-closed  step 2: do not stop firstrun-sink for the fail-closed check
# Steps 9 (Wi-Fi reconnect) and 11 (reboot) stay manual. The access code is read from
# /etc/firstrun/firstrun.env and never printed.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE=/etc/firstrun/firstrun.env
KILL_SWITCH=/srv/firstrun/KILL_SWITCH
BASE=http://127.0.0.1:3000
WITH_RATE_LIMIT=0
FAIL_CLOSED=1
for arg in "$@"; do
  case "$arg" in
    --with-rate-limit) WITH_RATE_LIMIT=1 ;;
    --skip-fail-closed) FAIL_CLOSED=0 ;;
    http://*|https://*) BASE="${arg%/}" ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

PASS=0; FAILED=0
pass() { PASS=$((PASS + 1)); echo "PASS $*"; }
fail() { FAILED=$((FAILED + 1)); echo "FAIL $*"; }
skip() { echo "SKIP $*"; }
step() { printf '\n== step %s: %s\n' "$1" "$2"; }

post() { # body -> "<status>\n<body>"
  curl -s -o /tmp/smoke-body.$$ -w '%{http_code}' -X POST -H 'content-type: application/json' "$@" "$BASE/api/runs" --data "$1"
}

# Poll GET /api/runs/:id until done/error; prints the final JSON.
wait_run() {
  local id="$1" deadline=$(( $(date +%s) + 240 )) body status
  while :; do
    body="$(curl -s "$BASE/api/runs/$id")"
    status="$(jq -r '.status // empty' <<<"$body")"
    case "$status" in
      done|error) printf '%s' "$body"; return 0 ;;
    esac
    (( $(date +%s) < deadline )) || { printf '%s' "$body"; return 1; }
    sleep 2
  done
}

step 1 "gVisor kernel under runsc-plain"
host_kernel="$(uname -r)"
sb_kernel="$(docker run --rm --runtime=runsc-plain ubuntu:24.04 uname -r 2>&1)"
if [[ -n "$sb_kernel" && "$sb_kernel" != "$host_kernel" ]]; then pass "sandbox kernel '$sb_kernel' differs from host '$host_kernel'"
else fail "sandbox kernel '$sb_kernel' (host '$host_kernel')"; fi

step 2 "trace points reach the sidecar"
trace_args=(); (( FAIL_CLOSED )) && trace_args=(--fail-closed)
if bash "$REPO_DIR/scripts/trace-selftest.sh" "${trace_args[@]}"; then pass "trace-selftest"; else fail "trace-selftest"; fi

step 3 "network containment"
if bash "$REPO_DIR/scripts/netcheck.sh"; then pass "netcheck"; else fail "netcheck"; fi

step 4 "healthz and security headers"
if [[ "$(curl -s "$BASE/healthz" | jq -r '.ok')" == "true" ]]; then pass "healthz ok"; else fail "healthz not ok"; fi
if [[ "$BASE" == https://* ]]; then
  headers="$(curl -sI "$BASE/")"
  for h in strict-transport-security content-security-policy x-frame-options x-content-type-options; do
    if grep -qi "^$h:" <<<"$headers"; then pass "header $h"; else fail "header $h missing"; fi
  done
else
  skip "security headers (local URL, no Caddy in front)"
fi

step 5-6 "curated samples nvm (CLEAN) and canary (MALICIOUS, alert, decoy aws_secret)"
fixture_out="$(node "$REPO_DIR/scripts/fixture-check.mjs" --base "$BASE" --only nvm,canary 2>&1)"
echo "$fixture_out"
if grep -q '^PASS' <<<"$fixture_out"; then pass "fixture-check nvm,canary"; else fail "fixture-check nvm,canary"; fi
canary_run="$(sed -n 's/^ok   canary [A-Z]* \([0-9A-Z]\{26\}\) .*/\1/p' <<<"$fixture_out" | head -n1)"

step 7 "free-form with access code, 401 without, clean teardown"
ACCESS_CODE="$(sed -n 's/^FIRSTRUN_ACCESS_CODE=//p' "$ENV_FILE" 2>/dev/null | tail -n1 | tr -d '"\r')"
if [[ -z "$ACCESS_CODE" ]]; then
  skip "FIRSTRUN_ACCESS_CODE is empty in $ENV_FILE"
else
  code="$(post '{"command":"echo hello","claim":"prints hello"}' -H "x-firstrun-access-code: $ACCESS_CODE")"
  if [[ "$code" == 202 ]]; then
    id="$(jq -r '.run_id' /tmp/smoke-body.$$)"
    final="$(wait_run "$id")"
    level="$(jq -r '.report.verdict.level // .error.code // "?"' <<<"$final")"
    if [[ "$level" == CLEAN ]]; then pass "echo hello -> CLEAN ($id)"; else fail "echo hello -> $level ($id)"; fi
  else
    fail "free-form POST with access code -> $code $(cat /tmp/smoke-body.$$)"
  fi
fi
code="$(post '{"command":"echo hello","claim":"prints hello"}')"
if [[ "$code" == 401 ]]; then pass "free-form without header -> 401"; else fail "free-form without header -> $code"; fi
sleep 10
leftovers="$(docker ps -a --filter label=firstrun.run --format '{{.Names}}')"
if [[ -z "$leftovers" ]]; then pass "no containers with label firstrun.run 10 s after the runs"; else fail "leftover containers: $leftovers"; fi
nets="$(docker network ls --format '{{.Name}}' | grep '^fr-' || true)"
if [[ -z "$nets" ]]; then pass "no fr-* networks left"; else fail "leftover networks: $nets"; fi

step 10 "kill switch file"
touch "$KILL_SWITCH"
code="$(post '{"sample_id":"nvm"}')"
if [[ "$code" == 503 && "$(jq -r '.error' /tmp/smoke-body.$$)" == runs_disabled ]]; then pass "POST with kill switch -> 503 runs_disabled"
else fail "POST with kill switch -> $code $(cat /tmp/smoke-body.$$)"; fi
rm -f "$KILL_SWITCH"
if [[ "$(curl -s "$BASE/healthz" | jq -r '.accepting_runs')" == "true" ]]; then pass "accepting_runs true after removing the file"
else fail "accepting_runs not true after removing the file"; fi

if (( WITH_RATE_LIMIT )); then
  step 8 "sample shim, then the 6th POST in 10 minutes -> 429"
  shim_out="$(node "$REPO_DIR/scripts/fixture-check.mjs" --base "$BASE" --only shim 2>&1)"
  echo "$shim_out"
  if grep -q '^PASS' <<<"$shim_out"; then pass "fixture-check shim"; else fail "fixture-check shim"; fi
  code="$(curl -s -o /tmp/smoke-body.$$ -D /tmp/smoke-head.$$ -w '%{http_code}' -X POST -H 'content-type: application/json' "$BASE/api/runs" --data '{"sample_id":"shim"}')"
  if [[ "$code" == 429 ]] && grep -qi '^retry-after:' /tmp/smoke-head.$$; then pass "6th POST -> 429 with Retry-After"
  else fail "6th POST -> $code (expected 429; was the budget already spent or reset?)"; fi
  rm -f /tmp/smoke-head.$$
else
  skip "step 8 rate limit (pass --with-rate-limit)"
fi

step 12 "no canary value in the orchestrator journal"
if [[ -n "$canary_run" ]]; then
  curl -s "$BASE/api/runs/$canary_run" | jq -r '.report.decoys[]?.value // empty' > /tmp/smoke-canary.$$
  if [[ -s /tmp/smoke-canary.$$ ]]; then
    hits="$(journalctl -u firstrun --since '-2h' --no-pager 2>/dev/null | grep -c -F -f /tmp/smoke-canary.$$ || true)"
    if [[ "$hits" == 0 ]]; then pass "0 journal lines contain a canary value"; else fail "$hits journal lines contain a canary value"; fi
  else
    fail "canary report has no decoys[].value"
  fi
  rm -f /tmp/smoke-canary.$$
else
  skip "canary run id not available"
fi

rm -f /tmp/smoke-body.$$
printf '\nsmoke: %d passed, %d failed (manual: step 9 Wi-Fi reconnect, step 11 reboot)\n' "$PASS" "$FAILED"
(( FAILED == 0 ))
