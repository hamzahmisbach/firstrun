// run/janitor.mjs with a fake docker: stale containers/networks removed, active runs spared,
// orphan trace files and run dirs cleaned, spool retried.
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { loadConfig } from '../config.mjs';
import { createJanitor, parseDockerTime } from '../run/janitor.mjs';

const OLD = 'ABCDEFGHJKMNPQRSTVWXYZ0OLD';
const ACTIVE = 'ABCDEFGHJKMNPQRSTVWXYZ0ACT';
const NEW = 'ABCDEFGHJKMNPQRSTVWXYZ0NEW';
const CID_OLD = 'a'.repeat(64);
const CID_NEW = 'b'.repeat(64);

test('parseDockerTime handles RFC3339 (containers) and Go time.String (networks)', () => {
  assert.equal(parseDockerTime('2026-11-04T12:00:00.123456789Z'), Date.UTC(2026, 10, 4, 12, 0, 0, 123));
  assert.equal(parseDockerTime('2026-11-04 12:00:00.123456789 +0000 UTC'), Date.UTC(2026, 10, 4, 12, 0, 0, 123));
  assert.equal(parseDockerTime('2026-11-04 12:00:00 +0700 WIB'), Date.UTC(2026, 10, 4, 5, 0, 0));
  assert.equal(parseDockerTime('garbage'), null);
});

test('sweep: removes stale containers/networks, keeps active and young ones, cleans files', async () => {
  const now = Date.UTC(2026, 10, 4, 12, 0, 0);
  const iso = (agoMs) => new Date(now - agoMs).toISOString();
  const goTime = (agoMs) => `${iso(agoMs).replace('T', ' ').replace('Z', '')} +0000 UTC`;
  const calls = [];
  const docker = {
    async run(argv) {
      calls.push(argv.join(' '));
      const key = argv.slice(0, 2).join(' ');
      if (key === 'ps -a') return { stdout: `c1\tfr-${OLD}-sb\t${OLD}\nc2\tfr-${ACTIVE}-sb\t${ACTIVE}\nc3\tfr-${NEW}-sink\t${NEW}\nc4\tfr-${OLD}-sink\t${OLD}\n` };
      if (key === 'network ls') return { stdout: `n1\tfr-${OLD}\nn2\tfr-${ACTIVE}\nn3\tfr-${NEW}\n` };
      if (key === 'inspect -f') {
        const ref = argv.at(-1);
        return { stdout: `${ref === 'c3' ? iso(60_000) : iso(20 * 60_000)}\n` };
      }
      if (key === 'network inspect') {
        const ref = argv.at(-1);
        if (ref === 'n1') return { stdout: `${goTime(20 * 60_000)}\t0\n` };
        if (ref === 'n2') return { stdout: `${goTime(20 * 60_000)}\t2\n` };
        return { stdout: `${goTime(60_000)}\t0\n` };
      }
      return { stdout: '' };
    },
  };
  const dir = mkdtempSync(path.join(tmpdir(), 'firstrun-janitor-'));
  try {
    const config = loadConfig({
      FIRSTRUN_RUNS_DIR: path.join(dir, 'runs'),
      FIRSTRUN_TRACE_DIR: path.join(dir, 'trace'),
      FIRSTRUN_SPOOL_DIR: path.join(dir, 'spool'),
      FIRSTRUN_RUNSC_LOG_DIR: path.join(dir, 'runsc'),
    });
    mkdirSync(config.traceDir, { recursive: true });
    mkdirSync(config.runscLogDir, { recursive: true });
    const touch = (file, agoMs, body = 'x') => {
      writeFileSync(file, body);
      utimesSync(file, new Date(now - agoMs), new Date(now - agoMs));
    };
    touch(path.join(config.traceDir, `${CID_OLD}.jsonl`), 20 * 60_000);
    touch(path.join(config.traceDir, `${CID_NEW}.jsonl`), 60_000);
    touch(path.join(config.traceDir, 'notes.txt'), 20 * 60_000);
    // runsc --debug-log files (7.6): old <cid> logs go, young ones stay, <unknown> goes when old or bloated.
    touch(path.join(config.runscLogDir, `${CID_OLD}.boot.log`), 20 * 60_000);
    touch(path.join(config.runscLogDir, `${CID_OLD}.gofer.log`), 20 * 60_000);
    touch(path.join(config.runscLogDir, `${CID_NEW}.boot.log`), 60_000);
    touch(path.join(config.runscLogDir, 'README'), 20 * 60_000);
    let unknownLogs = 2;
    try {
      touch(path.join(config.runscLogDir, '<unknown>.features.log'), 20 * 60_000);
      touch(path.join(config.runscLogDir, '<unknown>.delete.log'), 60_000, 'x'.repeat(5 * 1024 * 1024));
    } catch {
      unknownLogs = 0; // "<" is not a legal file name character on Windows
    }
    for (const [id, agoMs] of [
      [OLD, 25 * 3600_000],
      [ACTIVE, 25 * 3600_000],
      [NEW, 20 * 60_000],
    ]) {
      const d = path.join(config.runsDir, id);
      mkdirSync(path.join(d, 'seed'), { recursive: true });
      mkdirSync(path.join(d, 'sinkhole'), { recursive: true });
      writeFileSync(path.join(d, 'sb.cid'), 'c');
      utimesSync(d, new Date(now - agoMs), new Date(now - agoMs));
    }
    let retried = 0;
    const storage = { async retrySpool() { retried += 1; return { uploaded: 0, dropped: 0, pending: 0 }; }, async retention() { return { deleted: 0 }; } };
    const logs = [];
    const janitor = createJanitor({ config, docker, storage, isActive: (id) => id === ACTIVE, log: (r) => logs.push(r), now: () => now });
    const summary = await janitor.sweep();
    assert.equal(summary.containers, 2);
    assert.equal(summary.networks, 1);
    assert.equal(summary.trace_files, 1);
    assert.equal(summary.runsc_logs, 2 + unknownLogs);
    assert.deepEqual(readdirSync(config.runscLogDir).sort(), ['README', `${CID_NEW}.boot.log`].sort());
    assert.equal(summary.run_dirs, 1);
    assert.equal(retried, 1);
    assert.ok(calls.includes(`rm -f fr-${OLD}-sb fr-${OLD}-sink`), calls.join('\n'));
    assert.ok(calls.includes(`network rm fr-${OLD}`));
    assert.ok(!calls.some((c) => c.includes(`fr-${ACTIVE}`) && (c.startsWith('rm') || c.startsWith('network rm'))), 'active run untouched');
    assert.deepEqual(readdirSync(config.traceDir).sort(), [`${CID_NEW}.jsonl`, 'notes.txt']);
    assert.deepEqual(readdirSync(config.runsDir).sort(), [ACTIVE, NEW].sort());
    assert.deepEqual(readdirSync(path.join(config.runsDir, NEW)).sort(), ['sinkhole'], 'seed/ and sb.cid removed, sinkhole/ kept for a day');
    assert.deepEqual(readdirSync(path.join(config.runsDir, ACTIVE)).sort(), ['seed', 'sinkhole', 'sb.cid'].sort());
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a failing docker step does not stop the file sweeps', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'firstrun-janitor-'));
  try {
    const config = loadConfig({ FIRSTRUN_RUNS_DIR: path.join(dir, 'runs'), FIRSTRUN_TRACE_DIR: path.join(dir, 'trace'), FIRSTRUN_RUNSC_LOG_DIR: path.join(dir, 'runsc') });
    mkdirSync(config.traceDir, { recursive: true });
    const old = path.join(config.traceDir, `${CID_OLD}.jsonl`);
    writeFileSync(old, 'x');
    utimesSync(old, new Date(0), new Date(0));
    const logs = [];
    const janitor = createJanitor({ config, docker: { run: async () => { throw new Error('docker down'); } }, log: (r) => logs.push(r) });
    const summary = await janitor.sweep();
    assert.equal(summary.trace_files, 1);
    assert.equal(logs.filter((l) => l.msg === 'janitor.step_failed').length, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
