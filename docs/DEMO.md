# FirstRun demo: video script and demo-day checklist

The video is assembled from recordings, never played live. Screen at 1080p, browser on the public
URL (not localhost, so it is visibly running on Vultr), one SSH terminal to the VM on the right for
the containment moment. English narration, short text overlays. Long runs are jump-cut; the 15-20 s
containment moment plays in real time. Target length 3:00.

## Script (3 minutes)

| Time | On screen | Narration (gist) |
|---|---|---|
| 0:00-0:15 | Mock chat/forum message "just paste this in your terminal", command blurred | The problem in one sentence: copy-paste command scams (ClickFix and friends). People have no safe way to learn what a command does before running it on their own laptop. |
| 0:15-0:35 | Clean architecture slide, highlighted in turn: Vultr VM, gVisor sandbox, sinkhole, Serverless Inference, Object Storage | FirstRun runs it for you in a disposable sandbox on Vultr, with fake credentials and a network that leads nowhere, then compares the claim with what actually happened. An LLM agent unwraps encoding layers and writes the contract; the verdict is computed by deterministic rules. |
| 0:35-1:10 | Run (a) `nvm`: pick the sample, claim "installs nvm"; timeline: contract, execution, hosts contacted, files written; verdict **CLEAN** | A real installer everyone knows. What you see: nvm's official host and writes to `~/.nvm` and `~/.bashrc`, all matching the contract. Nothing else. (Say honestly that the sample uses nvm's script-only install method so the sinkhole can answer the downloads.) |
| 1:10-2:10 | Run (b) `canary`: paste the encoded command with the harmless claim; the base64 layer opens; execution; **containment moment** (below); verdict **MALICIOUS** with the claim-vs-behaviour table and the explanation | The claim says one thing, the behaviour says another: a decoy credentials file was opened and its token shows up in a POST to a host that only exists inside the sinkhole. Not one byte left the VM; the sandbox is destroyed; every secret in it was fake. |
| 2:10-2:35 | Run (c) `shim` (from a cached report, sped up): the `shim.call` list with OS-specific tool names; verdict **SUSPICIOUS** | A script aimed at macOS or Windows still shows its intent in a Linux sandbox: every call to another OS's tool is recorded from outside the sandbox, not from inside. |
| 2:35-2:50 | Share link `/r/<id>` in a private window; Vultr console: Compute (1 VM), Serverless Inference (the model in use), Object Storage (`reports/<id>.json`) | The report is stored in Object Storage and can be shared with whoever sent the command. |
| 2:50-3:00 | Closing slide: URL, repo, team, one line of business value | For IT helpdesks, community moderators, and anyone told to paste something. |

If it runs long, cut the Vultr console segment to three 1-second screenshots first, then replace
segment (c) with the cached report.

## The containment moment (15-20 s, real time, in this order)

1. **Alert banner** (SSE `alert`) appears red above the timeline: "Fake credential from
   `~/.aws/credentials` was sent to `updates.acme-cli.test`" with the matched form (`raw`).
2. **Sinkhole record**: the `http.request` row in the event list (host, path, `body_len`, canary
   match), and in the right-hand terminal the same line arriving in the run's sinkhole log, plus the
   `dns.log` line `query[A] updates.acme-cli.test` answered with the sinkhole's own IP. Narration:
   this host does not exist on the internet; it resolves only inside this disposable network.
3. **Sandbox destroyed**: the `teardown` step in the timeline, and in the terminal
   `docker ps -a --filter label=firstrun.run=<id>` empty, `docker network ls | grep fr-` empty.
4. **Zero real secrets**: the decoy panel in the report ("N decoy files generated for this run") and
   one line of `~/.aws/credentials` from the report showing a random `FR...` token. Sentence: no
   container ever held a real credential; the Inference and Object Storage keys exist only on the host.

Terminal commands for the right-hand pane (as `deploy`, in `/opt/firstrun`):

```bash
sudo tail -F /srv/firstrun/runs/<run_id>/sinkhole/events.jsonl | jq -c '{kind, method, host, path, body_len}'
sudo docker ps -a --filter label=firstrun.run; sudo docker network ls | grep fr- || echo "no fr-* networks"
```

Never on screen: raw fixture contents, the host `.env`, any console page that shows a key.

## Recording settings

Browser zoom 125%, light theme, terminal font 16, 1080p, clear microphone. Check the first take
before continuing. Record 2-3 takes per segment; pick the best one in the edit.

## Demo-day morning checklist (before anyone else touches the VM)

```bash
curl -s https://<host>/healthz | jq .                       # ok: true, accepting_runs: true
sudo docker ps -a --filter label=firstrun.run              # must be empty outside a run
df -h /srv                                                 # > 2 GB free, or POST answers 503
sudo journalctl -u firstrun --since -12h -p err --no-pager # no errors
ss -tnp state established                                  # outbound only to Inference and Object Storage
node scripts/fixture-check.mjs --base https://<host>       # nvm CLEAN, canary MALICIOUS, shim SUSPICIOUS
```

Then open the public URL from a different network (phone tethering), run the `nvm` sample to a
report, and open its share link in a private window. If `fixture-check` fails on a verdict, do not
patch rules on demo day: fall back to the cached report links (below) and the video.

## Backup plan

| Problem | Fallback |
|---|---|
| A run fails or is slow while recording | Record 2-3 takes per fixture; the video is always cut from recordings |
| Serverless Inference slow or down | Explanation falls back to the deterministic template and the decoder still shows deterministic layers; the verdict never depends on the LLM |
| Public site down while judges try it | Three cached report share links in the README and the submission text; restore per `docs/RUNBOOK.md` |
| Trace points fail on the day | Restore the snapshot and rerun `scripts/trace-selftest.sh`; otherwise cached reports and the video (there is no strace fallback) |
| Video over 3:00 | Console segment becomes screenshots; segment (c) becomes the cached report |

## Cached report links

<!-- TODO (day 5): generate one run per sample on the public instance and paste the /r/<id> links
here and in fixtures/samples/*/report-url.txt. -->

- nvm: `https://<PUBLIC_URL>/r/<RUN_ID>` (placeholder)
- canary: `https://<PUBLIC_URL>/r/<RUN_ID>` (placeholder)
- shim: `https://<PUBLIC_URL>/r/<RUN_ID>` (placeholder)
