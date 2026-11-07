# FirstRun runbook

Operations on the Vultr VM, one command each. Everything runs as the `deploy` user with `sudo`.
The repo checkout on the VM is `/opt/firstrun`; services are `firstrun` (orchestrator, Node) and
`firstrun-sink` (gVisor trace sidecar, Python). Host secrets live only in
`/etc/firstrun/firstrun.env` (root:firstrun 0640): never print, copy or paste that file.

## Restart the orchestrator

```bash
sudo systemctl restart firstrun
```

Queued runs are failed with `run.error`, active runs get 10 s to finish, then the process exits and
systemd starts it again (`Restart=always`). The sidecar keeps running; restart it only if
`scripts/trace-selftest.sh` fails: `sudo systemctl restart firstrun-sink firstrun` (in that order,
because runsc refuses to start a sandbox while the sidecar socket is missing: fail closed).

Sending new files to the VM does not change the trace session: the live copy is
`/etc/firstrun/trace-session.json`. After changing `infra/gvisor-sink/trace-session.json`, install it
with `sudo install -m 0644 /opt/firstrun/infra/gvisor-sink/trace-session.json /etc/firstrun/trace-session.json`.
Each new sandbox reads it when it starts. After changing `gvisor-sink.py`, restart both services as
above. Check either change with `sudo bash /opt/firstrun/scripts/trace-selftest.sh`.

## Check that it is healthy

```bash
curl -s http://127.0.0.1:3000/healthz | jq .
```

`ok: true` and `accepting_runs: true` is the normal state. Full check, including a real sandbox run
and network containment: `sudo bash scripts/smoke.sh` (see the header of the script for options).
Demo regression only: `node scripts/fixture-check.mjs` (add `--repeat 3` before a demo; note that
the per-IP POST limit is 5 per 10 minutes, so larger repeats wait on `Retry-After`).

## Rotate the access code

Free-form commands need the `x-firstrun-access-code` header; curated samples never do. The code
must be at least 24 characters. This writes a fresh 32-character hex code and restarts:

```bash
sudo sed -i "s/^FIRSTRUN_ACCESS_CODE=.*/FIRSTRUN_ACCESS_CODE=$(openssl rand -hex 16)/" /etc/firstrun/firstrun.env && sudo systemctl restart firstrun
```

The site sends a public copy of this code from `PUBLIC_ACCESS_CODE` in `web/app.js`, so anyone can run
their own commands. Rotating closes free-form runs on the site straight away, which makes this the
off switch. To open them again, put the new value in `web/app.js` and deploy it.

## Curated-only mode (disable free-form commands)

```bash
sudo sed -i 's/^FIRSTRUN_FREEFORM=.*/FIRSTRUN_FREEFORM=0/' /etc/firstrun/firstrun.env && sudo systemctl restart firstrun
```

Free-form `POST /api/runs` then answers `403 freeform_disabled`; the three samples keep working.
Set it back to `1` and restart to re-enable.

## Stop all new runs without a restart (kill switch)

```bash
sudo touch /srv/firstrun/KILL_SWITCH      # POST /api/runs -> 503 runs_disabled, UI shows a banner
sudo rm /srv/firstrun/KILL_SWITCH         # back to normal on the next request
```

Running sandboxes are allowed to finish. Total stop: `sudo systemctl stop firstrun` and then
`sudo docker rm -f $(sudo docker ps -aq --filter label=firstrun.run)`.

## Clean up leftovers

Outside a run there must be no containers or networks of ours:

```bash
sudo docker ps -a --filter label=firstrun.run; sudo docker network ls | grep fr- || echo "clean"
```

The janitor removes anything older than 10 minutes by itself; to force it:
`sudo docker rm -f $(sudo docker ps -aq --filter label=firstrun.run); sudo docker network prune -f`.

## Rebuild the sandbox and sinkhole images

Needed after changing `sandbox/`, `sinkhole/`, or any `fixtures/samples/*/canned.json` (the canned
responses are copied into the sinkhole image at build time):

```bash
cd /opt/firstrun && sudo bash scripts/build-images.sh
```

No service restart is needed: every run starts fresh containers from `firstrun/sandbox:latest` and
`firstrun/sinkhole:latest`.

## Public HTTPS

nginx is the only public entry (ports 80 and 443); the orchestrator stays on `127.0.0.1:3000`. To set
it up or repair it, run this; it is safe to run again and restarts the orchestrator:

```bash
sudo bash infra/setup-https.sh firstrun.makmurlab.com
```

To check it:

```bash
sudo certbot certificates                                  # expiry date
systemctl list-timers certbot.timer                        # next renewal check
sudo certbot renew --dry-run --no-random-sleep-on-renew    # try a renewal, changes nothing
sudo nginx -t && sudo systemctl reload nginx               # after editing /etc/nginx/sites-available/firstrun-*
```

The certificate was requested without an email address, so Let's Encrypt sends no expiry warnings.
`certbot.timer` renews it on its own. To add an address: `sudo certbot update_account --email <address>`.

## Logs

```bash
sudo journalctl -u firstrun -f            # orchestrator (JSON lines; never command text, claims or canary values)
sudo journalctl -u firstrun-sink -f       # trace sidecar
```

## Delete a report

`node server/bin/report.mjs delete <run_id>` removes the object from Object Storage and the local
spool (the admin tool is part of the engine work; until it exists, delete `reports/<run_id>.json` in
the bucket from the Vultr console). The in-memory copy expires within an hour, or immediately after
`sudo systemctl restart firstrun`.

## Restore from a snapshot

There is no snapshot yet; take one in the Vultr console before the feature freeze (plan: name it
`v1-freeze`). To restore: console, Products, Compute, the instance, Snapshots, Restore, then on the
restored VM:

```bash
cd /opt/firstrun && sudo bash infra/setup-vm.sh && sudo bash scripts/smoke.sh
```

`setup-vm.sh` is idempotent (packages, Docker runtimes, images, systemd units); `smoke.sh` proves
containment and trace capture before the site is announced healthy again. If the public IP changed,
update the DNS record; the certificate keeps working because it belongs to the hostname.

## If the VM looks compromised

Do not repair in place. In order: kill switch and `sudo systemctl stop firstrun firstrun-sink nginx`;
restrict the Vultr firewall group to SSH from the team IP; rotate every credential from the console
(Serverless Inference key, Object Storage keys, access code, DNS token); copy `journalctl -o export`
and `docker ps -a` to a laptop; destroy the instance; deploy a fresh one with `infra/setup-vm.sh` and
new credentials. Nothing on the VM is worth keeping; that is the design (docs/ARCHITECTURE.md 11).
