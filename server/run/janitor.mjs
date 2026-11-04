// Periodic sweeps (section 4 step 10, 10.4): containers and networks with label firstrun.run older
// than 10 minutes (a crashed orchestrator left them), orphan trace files, leftovers in the runs dir
// (seed/ and work/ at 10 minutes, the whole dir at 24 hours), spooled reports to retry, and the
// daily Object Storage retention. Every step is independent: one failure never stops the others.
import { readdir, rm, stat, unlink } from 'node:fs/promises';
import path from 'node:path';
import { LIMITS } from '../config.mjs';
import { inspectCreatedArgs, networkInspectArgs, networkLsArgs, psArgs, rmArgs, networkRmArgs } from './docker.mjs';
import { RUN_ID_RE } from './ids.mjs';

const CID_RE = /^[0-9a-f]{64}$/;

/** Docker prints RFC3339 for containers and Go's "2006-01-02 15:04:05.999 +0000 UTC" for networks. */
export function parseDockerTime(text) {
  const s = String(text).trim();
  const go = /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(\.\d+)? ([+-]\d{4}) \w+$/.exec(s);
  const iso = go ? `${go[1]}T${go[2]}${(go[3] ?? '').slice(0, 4)}${go[4].slice(0, 3)}:${go[4].slice(3)}` : s.replace(/(\.\d{3})\d+/, '$1');
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? null : ms;
}

/**
 * @param {object} opts
 * @param {ReturnType<import('../config.mjs').loadConfig>} opts.config
 * @param {object} opts.docker
 * @param {object} [opts.storage]
 * @param {(runId: string) => boolean} [opts.isActive]  queued or running in this process
 * @param {Function} [opts.log]
 * @param {() => number} [opts.now]
 */
export function createJanitor({ config, docker, storage = null, isActive = () => false, log = () => {}, now = Date.now }) {
  const J = LIMITS.janitor;
  let timer = null;
  let retentionTimer = null;
  let sweeping = false;

  async function sweepContainers(summary) {
    const { stdout } = await docker.run(psArgs());
    const stale = [];
    for (const line of stdout.split('\n')) {
      const [cid, name, runId] = line.split('\t');
      if (!cid || !name) continue;
      if (runId && RUN_ID_RE.test(runId) && isActive(runId)) continue;
      let created = null;
      try {
        created = parseDockerTime((await docker.run(inspectCreatedArgs(cid))).stdout);
      } catch {
        continue;
      }
      if (created !== null && now() - created > J.orphanAgeMs) stale.push(name);
    }
    if (stale.length) {
      await docker.run(rmArgs(stale));
      summary.containers = stale.length;
      log({ level: 'warn', msg: 'janitor.containers_removed', count: stale.length });
    }
  }

  async function sweepNetworks(summary) {
    const { stdout } = await docker.run(networkLsArgs());
    for (const line of stdout.split('\n')) {
      const [nid, name] = line.split('\t');
      if (!nid || !name) continue;
      const runId = name.startsWith('fr-') ? name.slice(3) : '';
      if (RUN_ID_RE.test(runId) && isActive(runId)) continue;
      let created = null;
      let attached = 0;
      try {
        const [c, n] = (await docker.run(networkInspectArgs(nid))).stdout.trim().split('\t');
        created = parseDockerTime(c);
        attached = Number(n) || 0;
      } catch {
        continue;
      }
      if (attached > 0 || created === null || now() - created <= J.orphanAgeMs) continue;
      if (!RUN_ID_RE.test(runId)) continue; // not ours to name
      await docker.run(networkRmArgs(runId)).catch(() => {});
      summary.networks += 1;
    }
    if (summary.networks) log({ level: 'warn', msg: 'janitor.networks_removed', count: summary.networks });
  }

  async function sweepTraceFiles(summary) {
    let entries;
    try {
      entries = await readdir(config.traceDir);
    } catch (err) {
      if (err.code === 'ENOENT') return;
      throw err;
    }
    for (const name of entries) {
      if (!name.endsWith('.jsonl')) continue;
      const file = path.join(config.traceDir, name);
      let info;
      try {
        info = await stat(file);
      } catch {
        continue;
      }
      if (now() - info.mtimeMs <= J.orphanAgeMs) continue;
      const cid = name.slice(0, -6);
      if (!CID_RE.test(cid) && !name.startsWith('unknown-')) continue;
      await unlink(file).catch(() => {});
      summary.trace_files += 1;
    }
  }

  async function sweepRunDirs(summary) {
    let entries;
    try {
      entries = await readdir(config.runsDir, { withFileTypes: true });
    } catch (err) {
      if (err.code === 'ENOENT') return;
      throw err;
    }
    for (const entry of entries) {
      if (!entry.isDirectory() || !RUN_ID_RE.test(entry.name) || isActive(entry.name)) continue;
      const dir = path.join(config.runsDir, entry.name);
      let info;
      try {
        info = await stat(dir);
      } catch {
        continue;
      }
      const age = now() - info.mtimeMs;
      if (age > J.failedRunKeepMs) {
        await rm(dir, { recursive: true, force: true }).catch(() => {});
        summary.run_dirs += 1;
      } else if (age > J.orphanAgeMs) {
        for (const leftover of ['seed', 'work', 'resolv.conf', 'sb.cid']) {
          await rm(path.join(dir, leftover), { recursive: true, force: true }).catch(() => {});
        }
      }
    }
  }

  /** One full sweep; returns counts. Safe to call while a run is active. */
  async function sweep() {
    if (sweeping) return null;
    sweeping = true;
    const summary = { containers: 0, networks: 0, trace_files: 0, run_dirs: 0, spool: null };
    const steps = [
      ['containers', () => sweepContainers(summary)],
      ['networks', () => sweepNetworks(summary)],
      ['trace', () => sweepTraceFiles(summary)],
      ['run_dirs', () => sweepRunDirs(summary)],
      ['spool', async () => storage && (summary.spool = await storage.retrySpool())],
    ];
    try {
      for (const [name, step] of steps) {
        try {
          await step();
        } catch (err) {
          log({ level: 'warn', msg: 'janitor.step_failed', step: name, err: err?.message ?? String(err) });
        }
      }
    } finally {
      sweeping = false;
    }
    return summary;
  }

  async function retention() {
    if (!storage) return null;
    try {
      const r = await storage.retention(config.reportTtlDays);
      log({ msg: 'janitor.retention', deleted: r.deleted, ttl_days: config.reportTtlDays });
      return r;
    } catch (err) {
      log({ level: 'warn', msg: 'janitor.retention_failed', err: err?.message ?? String(err) });
      return null;
    }
  }

  function start() {
    if (timer) return;
    timer = setInterval(() => void sweep(), J.sweepEveryMs);
    timer.unref();
    retentionTimer = setInterval(() => void retention(), LIMITS.storage.retentionEveryMs);
    retentionTimer.unref();
    void sweep();
    void retention();
  }

  function stop() {
    clearInterval(timer);
    clearInterval(retentionTimer);
    timer = retentionTimer = null;
  }

  return { sweep, retention, start, stop };
}
