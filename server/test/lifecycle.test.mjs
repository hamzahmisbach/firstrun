// run/lifecycle.mjs with a fake docker: event order, files, teardown, watchdog, failure codes,
// the harness path, and one pass through the real peer modules on the captured fixture.
import assert from 'node:assert/strict';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { loadConfig } from '../config.mjs';
import { applyReview } from '../review/apply.mjs';
import { newRunId } from '../run/ids.mjs';
import { RunError, createLifecycle, loadModules } from '../run/lifecycle.mjs';
import { createStorage } from '../storage/index.mjs';

const CAPTURE = fileURLToPath(new URL('../../fixtures/captures/basic/', import.meta.url));
const CAP_CID = readFileSync(path.join(CAPTURE, 'container_id.txt'), 'utf8').trim();
const CID = 'c'.repeat(64);

function makeRun(command = 'echo hello\n', claim = 'prints hello', sampleId = null) {
  const created = Date.now();
  return {
    run_id: newRunId(),
    created_at: new Date(created).toISOString(),
    created_ms: created,
    sample_id: sampleId,
    input: sampleId ? { command, claim, sample_id: sampleId } : { command, claim },
    command_sha256: 'x'.repeat(64),
  };
}

function makeCtx() {
  const events = [];
  const phases = [];
  let report = null;
  return {
    events,
    phases,
    get report() {
      return report;
    },
    ctx: {
      emit: (event, fields) => events.push({ name: event, ...fields }),
      phase: (p) => phases.push(p),
      done: (r) => (report = r),
    },
  };
}

/**
 * Fake docker: the sinkhole "starts" by writing ready (and optionally sinkhole files), the sandbox
 * "runs" by writing sb.cid (and optionally a trace file) and exiting with `exit`.
 */
function fakeDocker(config, { exit = { code: 0, stdout: 'hello\n', stderr: '' }, sinkholeReady = true, onSandbox = null, onSinkhole = null, hang = false } = {}) {
  const calls = [];
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const runDirOf = (argv) => {
    const i = argv.indexOf('--name');
    return path.join(config.runsDir, argv[i + 1].slice(3, 29));
  };
  let killResolve = null;
  const docker = {
    calls,
    async run(argv) {
      calls.push(argv.join(' '));
      if (argv[0] === 'network' && argv[1] === 'create') return { stdout: 'nid\n', stderr: '' };
      if (argv[0] === 'run' && argv[1] === '-d') {
        const runDir = runDirOf(argv);
        onSinkhole?.(runDir);
        if (sinkholeReady) setTimeout(() => writeFileSync(path.join(runDir, 'sinkhole', 'ready'), 'ok'), 10);
        return { stdout: 'sinkid\n', stderr: '' };
      }
      if (argv[0] === 'inspect' && argv[2].includes('IPAddress')) return { stdout: '10.213.0.3\n', stderr: '' };
      if (argv[0] === 'inspect' && argv[2].includes('OOMKilled')) return { stdout: 'false\n', stderr: '' };
      return { stdout: '', stderr: '' };
    },
    runAttached(argv) {
      calls.push(argv.join(' '));
      const runDir = runDirOf(argv);
      const unwrap = argv.includes('FIRSTRUN_PHASE=unwrap');
      const cidfile = argv[argv.indexOf('--cidfile') + 1];
      const done = (async () => {
        await sleep(5);
        if (!unwrap) {
          // The sandbox must see cmd.sh, seed and resolv.conf as the orchestrator leaves them.
          assert.ok(existsSync(path.join(runDir, 'work', 'cmd.sh')), 'cmd.sh present while running');
          assert.ok(existsSync(path.join(runDir, 'resolv.conf')));
          onSandbox?.(runDir);
        }
        writeFileSync(cidfile, unwrap ? 'd'.repeat(64) : CID);
        if (hang && !unwrap) {
          await new Promise((resolve) => (killResolve = resolve));
          return { code: 137, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), stdoutBytes: 0, stderrBytes: 0, truncated: false };
        }
        await sleep(unwrap ? 5 : 30);
        const out = Buffer.from(unwrap ? 'echo decoded-layer\n' : exit.stdout);
        const err = Buffer.from(unwrap ? '' : exit.stderr);
        return { code: unwrap ? 0 : exit.code, signal: null, stdout: out, stderr: err, stdoutBytes: out.length, stderrBytes: err.length, truncated: false };
      })();
      return { pid: 1, done };
    },
    rmForce: async (names) => void calls.push(`rm -f ${names.join(' ')}`),
    networkRm: async (id) => void calls.push(`network rm fr-${id}`),
    kill: async (name) => {
      calls.push(`kill ${name}`);
      killResolve?.();
    },
    oomKilled: async () => false,
  };
  return docker;
}

/** Peer-module fakes in the shapes of the brief's contract. */
function fakeModules(config, { needsHarness = false, t0 = true, contract = null } = {}) {
  const decoys = [{ id: 'aws_secret', path: '~/.aws/credentials', category: 'cloud_credentials', value: 'FRTESTTOKEN', forms: ['raw'] }];
  const seen = { evidence: [], harnessRuns: 0 };
  return {
    seen,
    modules: {
      canary: () => ({ runSecret: 's', decoys }),
      seed: async (seedDir) => {
        mkdirSync(path.join(seedDir, 'home', '.aws'), { recursive: true });
        writeFileSync(path.join(seedDir, 'home', '.aws', 'credentials'), 'aws_secret_access_key = FRTESTTOKEN\n');
        writeFileSync(path.join(seedDir, 'perms.txt'), '600 .aws/credentials\n');
        return { seededPaths: ['/home/dev/.aws/credentials'] }; // what run/seed.mjs returns (7.6, fs.existing_file_changed)
      },
      evidence: ({ runId, onEvent, onAlert }) => {
        let attached = null;
        let seq = 0;
        const events = [];
        const push = (e) => {
          const ev = { run_id: runId, seq: ++seq, ts_ms: Date.now(), t_rel_ms: seq * 10, ...e };
          events.push(ev);
          onEvent(ev);
          if (ev.kind === 'canary.hit') onAlert(ev);
        };
        return {
          startSinkhole: () => seen.evidence.push('startSinkhole'),
          attachSandbox: (cid) => {
            attached = cid;
            seen.evidence.push(`attach:${cid}`);
            push({ source: 'gvisor', kind: 'proc.exec', pid: 7, ppid: 1, exe: '/usr/bin/echo', argv: ['echo', 'hello'] });
            push({ source: 'orchestrator', kind: 'canary.hit', decoy_id: 'aws_secret', category: 'cloud_credentials', form: 'raw', where: 'body', event_seq: 1 });
          },
          t0Seen: () => t0 && attached !== null,
          scanOutput: (bytes, where) => seen.evidence.push(`scan:${where}:${bytes.length}`),
          stop: async ({ graceMs }) => {
            seen.evidence.push(`stop:${graceMs}`);
            return { events, coverage: { pre_t0: 3, gvisor_dropped: 0, oom_killed: false, notes: ['from evidence'] } };
          },
        };
      },
      rules: (args) => {
        seen.rules = args;
        return {
          findings: [{ id: 'exfil.canary_outbound:1', rule_id: 'exfil.canary_outbound', severity: 'critical', classification: 'forbidden', title: 'leak', event_seqs: [1, 2] }],
          verdict: { level: 'MALICIOUS', rule_ids: ['exfil.canary_outbound'], coverage_notes: ['note'] },
          classifications: { 1: 'forbidden' },
        };
      },
      report: (args) => {
        seen.report = args;
        return { schema_version: 1, run_id: args.run.run_id, created_at: args.run.created_at, verdict: args.verdict, timing: { ...args.timing }, events: args.events, output: args.output };
      },
      explainInput: (a) => ({ claim: a.input.claim, verdict: a.verdict }),
      explainTemplate: (input) => ({ verdict_echo: input.verdict.level, headline: 'tpl', paragraphs: ['p'], finding_notes: [], next_step: 'n' }),
      explainWriter: null,
      llmClient: null,
      contract,
      decoder: (text) => ({
        layers: needsHarness ? [{ index: 1, parent: 0, method: 'base64', bytes_len: 10, text: 'eval x', truncated: false, markers: {}, llm_assisted: false, status: 'ok' }] : [],
        finalText: needsHarness ? 'eval x' : text,
        finalIndex: needsHarness ? 1 : 0,
        needsHarness,
        stopped: needsHarness ? 'needs_harness' : 'clean',
      }),
      harness: async ({ runHarness, onLayer, firstIndex }) => {
        seen.harnessRuns += 1;
        const r = await runHarness({ language: 'bash', code: 'eval() { printf "%s" "$*"; }\neval x' });
        seen.harnessResult = r;
        const layer = { index: firstIndex, parent: firstIndex - 1, method: 'harness', bytes_len: r.stdout.length, text: r.stdout, truncated: false, markers: {}, llm_assisted: true, status: 'ok' };
        onLayer(layer);
        return { layers: [layer], stoppedReason: 'clean', attempts: 1, llmCalls: 1 };
      },
    },
  };
}

async function setup({ env = {}, docker: dockerOpts = {}, modules: moduleOpts = {}, limits = {}, llm = null } = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'firstrun-lc-'));
  const config = loadConfig({
    FIRSTRUN_RUNS_DIR: path.join(dir, 'runs'),
    FIRSTRUN_TRACE_DIR: path.join(dir, 'trace'),
    FIRSTRUN_SPOOL_DIR: path.join(dir, 'spool'),
    FIRSTRUN_SINK_SOCKET: path.join(dir, 'sink.sock'),
    FIRSTRUN_SAMPLES_DIR: path.join(dir, 'samples'),
    FIRSTRUN_RUNSC_LOG_DIR: path.join(dir, 'runsc'),
    ...env,
  });
  mkdirSync(config.traceDir, { recursive: true });
  mkdirSync(config.runscLogDir, { recursive: true });
  const logs = [];
  const log = (r) => logs.push(r);
  const storage = await createStorage({ config, log });
  const docker = fakeDocker(config, dockerOpts);
  const fakes = fakeModules(config, moduleOpts);
  const lifecycle = createLifecycle({
    config,
    llm,
    storage,
    docker,
    modules: fakes.modules,
    log,
    limits: { sinkholeReadyMs: 2000, cidfileWaitMs: 2000, watchdogMs: 5000, evidenceGraceMs: 10, ...limits },
  });
  return { dir, config, storage, docker, fakes, lifecycle, logs, close: () => rmSync(dir, { recursive: true, force: true }) };
}

describe('lifecycle with fake docker and fake modules', () => {
  test('happy path: event order, files during the run, teardown, report stored, run dir removed', async () => {
    const t = await setup({ docker: { exit: { code: 0, stdout: 'hello\n', stderr: 'warn\n' } } });
    try {
      const run = makeRun();
      const runDir = path.join(t.config.runsDir, run.run_id);
      writeFileSync(path.join(t.config.traceDir, `${CID}.jsonl`), '{}\n'); // the sidecar's file for that container
      for (const cmd of ['boot', 'create', 'gofer']) writeFileSync(path.join(t.config.runscLogDir, `${CID}.${cmd}.log`), 'x\n'); // runsc --debug-log (7.6)
      const shared = [];
      try {
        writeFileSync(path.join(t.config.runscLogDir, '<unknown>.delete.log'), 'x\n');
        shared.push('<unknown>.delete.log');
      } catch {
        // "<" is not a legal file name character on Windows
      }
      let seenSeed = null;
      t.docker.runAttached = ((orig) => (argv) => {
        if (!argv.includes('FIRSTRUN_PHASE=unwrap')) {
          seenSeed = readFileSync(path.join(runDir, 'seed', 'home', '.aws', 'credentials'), 'utf8');
          assert.equal(readFileSync(path.join(runDir, 'work', 'cmd.sh'), 'utf8'), 'echo hello\n');
          assert.equal(readFileSync(path.join(runDir, 'resolv.conf'), 'utf8'), 'nameserver 10.213.0.3\noptions timeout:1 attempts:1 ndots:1\n');
          assert.ok(existsSync(path.join(runDir, 'sinkhole', 'bodies')));
        }
        return orig(argv);
      })(t.docker.runAttached);
      const c = makeCtx();
      await t.lifecycle(run, c.ctx);

      assert.match(seenSeed, /FRTESTTOKEN/);
      assert.deepEqual(
        c.events.map((e) => e.name),
        ['run.started', 'contract.ready', 'exec.started', 'evidence', 'evidence', 'alert', 'exec.finished', 'verdict', 'explanation'],
      );
      assert.deepEqual(c.phases, ['setup', 'exec', 'rules', 'explain', 'upload']);
      const by = Object.fromEntries(c.events.map((e) => [e.name, e]));
      assert.equal(by['exec.started'].container_id, CID);
      assert.equal(by['exec.started'].timeout_s, 60);
      assert.equal(by['contract.ready'].contract_meta.source, 'fallback');
      assert.equal(by['contract.ready'].contract.summary, 'prints hello');
      assert.deepEqual(
        { exit_code: by['exec.finished'].exit_code, timed_out: by['exec.finished'].timed_out, killed_by: by['exec.finished'].killed_by, stdout_bytes: by['exec.finished'].stdout_bytes, stderr_bytes: by['exec.finished'].stderr_bytes },
        { exit_code: 0, timed_out: false, killed_by: null, stdout_bytes: 6, stderr_bytes: 5 },
      );
      assert.equal(by['exec.finished'].coverage.pre_t0, 3);
      assert.equal(by.verdict.verdict.level, 'MALICIOUS');
      assert.equal(by.explanation.explanation_meta.source, 'template');
      assert.equal(by.alert.event.kind, 'canary.hit');

      // What rules and report received.
      const r = t.fakes.seen.rules;
      assert.equal(r.sinkIp, '10.213.0.3');
      assert.equal(r.contractMeta.source, 'fallback');
      assert.equal(r.events.length, 2);
      assert.equal(r.exec.stdout_preview, 'hello\n');
      assert.deepEqual(r.unwrap, { stopped: 'clean', harness: null });
      assert.ok(r.coverage.notes.includes('from evidence'));
      assert.deepEqual(t.fakes.seen.report.classifications, { 1: 'forbidden' });
      assert.deepEqual(t.fakes.seen.report.output, { stdout_preview: 'hello\n', stderr_preview: 'warn\n', stdout_bytes: 6, stderr_bytes: 5, truncated: false });
      assert.deepEqual(t.fakes.seen.evidence, ['startSinkhole', `attach:${CID}`, 'scan:stdout:6', 'scan:stderr:5', 'stop:10']);

      // Report stored and handed to the caller, with the final timing.
      assert.equal(c.report.run_id, run.run_id);
      assert.ok(Number.isInteger(c.report.timing.total_ms) && c.report.timing.total_ms >= 0);
      assert.deepEqual(await t.storage.getReport(run.run_id), c.report);

      // Teardown: containers, network, run dir, trace file.
      const calls = t.docker.calls;
      assert.ok(calls.includes(`rm -f fr-${run.run_id}-sb fr-${run.run_id}-sink`), calls.join('\n'));
      assert.ok(calls.includes(`network rm fr-${run.run_id}`));
      assert.ok(calls.some((x) => x.startsWith('network create --internal')));
      assert.ok(calls.some((x) => x.includes('--runtime=runsc') && x.includes(`--network fr-${run.run_id}`) && x.includes('FIRSTRUN_PHASE=execute')));
      assert.equal(existsSync(runDir), false, 'run dir removed after a stored report');
      assert.equal(existsSync(path.join(t.config.traceDir, `${CID}.jsonl`)), false, 'trace file removed');
      assert.deepEqual(readdirSync(t.config.runscLogDir), shared, 'runsc logs of the container removed, the shared one left to the janitor');
      assert.ok(r.seededPaths.includes('/home/dev/.aws/credentials'), 'writeSeed paths reach the rules');
      assert.equal(JSON.stringify(t.logs).includes('echo hello'), false, 'command text never logged');
    } finally {
      t.close();
    }
  });

  test('sinkhole never ready -> RunError sinkhole_not_ready, teardown ran, sinkhole/ kept', async () => {
    const t = await setup({ docker: { sinkholeReady: false }, limits: { sinkholeReadyMs: 60 } });
    try {
      const run = makeRun();
      const c = makeCtx();
      await assert.rejects(t.lifecycle(run, c.ctx), (err) => err instanceof RunError && err.code === 'sinkhole_not_ready' && err.stage === 'setup');
      assert.ok(t.docker.calls.includes(`rm -f fr-${run.run_id}-sink`));
      assert.ok(t.docker.calls.includes(`network rm fr-${run.run_id}`));
      const runDir = path.join(t.config.runsDir, run.run_id);
      assert.equal(existsSync(path.join(runDir, 'seed')), false);
      assert.equal(existsSync(path.join(runDir, 'work')), false);
      assert.equal(existsSync(path.join(runDir, 'sinkhole')), true, 'kept for debugging');
      assert.equal(c.report, null);
    } finally {
      t.close();
    }
  });

  test('watchdog: a sandbox that never exits is killed and reported killed_by watchdog', async () => {
    const t = await setup({ docker: { hang: true }, limits: { watchdogMs: 80 } });
    try {
      const run = makeRun();
      const c = makeCtx();
      await t.lifecycle(run, c.ctx);
      assert.ok(t.docker.calls.includes(`kill fr-${run.run_id}-sb`));
      const fin = c.events.find((e) => e.name === 'exec.finished');
      assert.equal(fin.killed_by, 'watchdog');
      assert.equal(fin.timed_out, true);
      assert.equal(fin.exit_code, 137);
      assert.equal(fin.coverage.timed_out, true);
    } finally {
      t.close();
    }
  });

  test('timeout inside (exit 124) -> timed_out, killed_by timeout; non-zero exit is kept', async () => {
    const t = await setup({ docker: { exit: { code: 124, stdout: '', stderr: '' } } });
    try {
      const c = makeCtx();
      await t.lifecycle(makeRun(), c.ctx);
      const fin = c.events.find((e) => e.name === 'exec.finished');
      assert.deepEqual({ exit_code: fin.exit_code, timed_out: fin.timed_out, killed_by: fin.killed_by }, { exit_code: 124, timed_out: true, killed_by: 'timeout' });
    } finally {
      t.close();
    }
  });

  test('exit 137 alone is not a timeout (OOM / self-inflicted SIGKILL); 137 at the limit is', async () => {
    // The fake sandbox runs ~30 ms. Default limit (60 s): a quick 137 is just a kill.
    let t = await setup({ docker: { exit: { code: 137, stdout: '', stderr: '' } } });
    try {
      t.docker.oomKilled = async () => true;
      const c = makeCtx();
      await t.lifecycle(makeRun(), c.ctx);
      const fin = c.events.find((e) => e.name === 'exec.finished');
      assert.deepEqual({ exit_code: fin.exit_code, timed_out: fin.timed_out, killed_by: fin.killed_by, oom: fin.coverage.oom_killed }, { exit_code: 137, timed_out: false, killed_by: null, oom: true });
    } finally {
      t.close();
    }
    // Same exit, but the run lasted up to the limit: timeout.
    t = await setup({ docker: { exit: { code: 137, stdout: '', stderr: '' } }, limits: { execTimeoutMs: 20, timeoutSlackMs: 0 } });
    try {
      const c = makeCtx();
      await t.lifecycle(makeRun(), c.ctx);
      const fin = c.events.find((e) => e.name === 'exec.finished');
      assert.deepEqual({ timed_out: fin.timed_out, killed_by: fin.killed_by }, { timed_out: true, killed_by: 'timeout' });
    } finally {
      t.close();
    }
  });

  test('contract: step 11 waits (bounded) for the LLM; only the contract used is announced', async () => {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const llmContract = { summary: 'from llm', expected_hosts: [], expected_write_paths: [], expected_processes: [], allowed_decoy_categories: [], notes: '' };
    // Slow but within the wait: the LLM contract is used, exactly one contract.ready.
    let t = await setup({ llm: {}, modules: { contract: async () => { await sleep(150); return { contract: llmContract, meta: { source: 'llm' } }; } }, limits: { contractWaitMs: 2000 } });
    try {
      const c = makeCtx();
      await t.lifecycle(makeRun(), c.ctx);
      const ready = c.events.filter((e) => e.name === 'contract.ready');
      assert.equal(ready.length, 1);
      assert.equal(ready[0].contract_meta.source, 'llm');
      assert.equal(t.fakes.seen.rules.contract.summary, 'from llm');
      assert.ok(c.events.findIndex((e) => e.name === 'contract.ready') < c.events.findIndex((e) => e.name === 'verdict'));
    } finally {
      t.close();
    }
    // Too slow: fallback once, and the late answer is never emitted.
    t = await setup({ llm: {}, modules: { contract: async () => { await sleep(300); return { contract: llmContract, meta: { source: 'llm' } }; } }, limits: { contractWaitMs: 20 } });
    try {
      const c = makeCtx();
      await t.lifecycle(makeRun(), c.ctx);
      await sleep(400);
      const ready = c.events.filter((e) => e.name === 'contract.ready');
      assert.equal(ready.length, 1);
      assert.equal(ready[0].contract_meta.source, 'fallback');
      assert.equal(t.fakes.seen.rules.contractMeta.source, 'fallback');
      assert.ok(t.fakes.seen.rules.coverage.notes.some((n) => /had not finished/.test(n)));
    } finally {
      t.close();
    }
  });

  test('no T0 marker -> run.error no_t0_marker, nothing stored', async () => {
    const t = await setup({ modules: { t0: false } });
    try {
      const run = makeRun();
      const c = makeCtx();
      await assert.rejects(t.lifecycle(run, c.ctx), (err) => err instanceof RunError && err.code === 'no_t0_marker');
      assert.equal(c.events.some((e) => e.name === 'exec.started'), false);
      assert.equal(await t.storage.getReport(run.run_id), null);
    } finally {
      t.close();
    }
  });

  test('sandbox start failure (no cidfile) -> sandbox_start_failed; trace_unavailable without the sidecar socket', async () => {
    const t = await setup({ limits: { cidfileWaitMs: 100 } });
    try {
      t.docker.runAttached = (argv) => {
        t.docker.calls.push(argv.join(' '));
        return { pid: 1, done: Promise.resolve({ code: 125, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.from('docker: Error response from daemon: boom'), stdoutBytes: 0, stderrBytes: 40, truncated: false }) };
      };
      const c = makeCtx();
      await assert.rejects(t.lifecycle(makeRun(), c.ctx), (err) => err.code === 'trace_unavailable', 'no sidecar socket at all');
      writeFileSync(t.config.sinkSocket, ''); // a plain file is enough for stat() here
      await assert.rejects(t.lifecycle(makeRun(), makeCtx().ctx), (err) => err.code === 'sandbox_start_failed');
    } finally {
      t.close();
    }
  });

  test('harness path: runs alongside execution, unwrap container with --network none, layers emitted', async () => {
    const llm = { modelsUsed: () => [{ role: 'harness', model: 'm', calls: 1, ms: 5, fallback: false }] };
    const t = await setup({ modules: { needsHarness: true }, llm });
    try {
      // A slow harness loop must not delay the sandbox: hold it until exec.started is out.
      const run = makeRun('echo ZXZhbCB4 | base64 -d | bash\n');
      const c = makeCtx();
      const origHarness = t.fakes.modules.harness;
      t.fakes.modules.harness = async (args) => {
        const giveUp = Date.now() + 10_000; // never hang the suite; the order assert below still fails
        while (!c.events.some((e) => e.name === 'exec.started') && Date.now() < giveUp) await new Promise((r) => setTimeout(r, 5));
        return origHarness(args);
      };
      await t.lifecycle(run, c.ctx);
      assert.equal(t.fakes.seen.harnessRuns, 1);
      assert.deepEqual(t.fakes.seen.harnessResult, { stdout: 'echo decoded-layer\n', stderr: '', exit_code: 0, timed_out: false });
      const uw = t.docker.calls.find((x) => x.includes('FIRSTRUN_PHASE=unwrap'));
      assert.ok(uw.includes('--network none') && uw.includes(`--name fr-${run.run_id}-uw0`) && uw.includes('INTERP=bash') && uw.includes('EXT=sh'));
      assert.ok(!uw.includes('dst=/seed'));
      assert.ok(uw.includes(`src=${path.join(t.config.runsDir, run.run_id, 'unwrap')}`.replaceAll('\\', '/')) || uw.includes('/unwrap,dst=/work'), 'harness from unwrap/');
      assert.ok(c.events.findIndex((e) => e.name === 'exec.started') < c.events.findIndex((e) => e.name === 'unwrap.layer' && e.layer.method === 'harness'), 'exec did not wait for the harness');
      assert.ok(c.events.findIndex((e) => e.name === 'unwrap.layer' && e.layer.method === 'harness') < c.events.findIndex((e) => e.name === 'verdict'), 'rules waited for the harness');
      assert.equal(c.report.timing.setup_ms >= 0 && Number.isInteger(c.report.timing.setup_ms), true);
      assert.ok(t.docker.calls.includes(`rm -f fr-${run.run_id}-uw0`));
      const layers = c.events.filter((e) => e.name === 'unwrap.layer').map((e) => e.layer);
      assert.deepEqual(layers.map((l) => [l.index, l.method, l.preview]), [[1, 'base64', 'eval x'], [2, 'harness', 'echo decoded-layer\n']]);
      assert.equal(c.phases.includes('unwrap'), true);
      assert.deepEqual(t.fakes.seen.rules.unwrap, { stopped: 'needs_harness', harness: { stoppedReason: 'clean' } });
      assert.equal(t.fakes.seen.rules.layers.length, 2);
      assert.equal(t.fakes.seen.report.modelsUsed[0].role, 'harness');
      assert.ok(c.report.timing.unwrap_ms >= 0);
    } finally {
      t.close();
    }
  });

  test('storage failure (unwritable spool) -> storage_failed', async () => {
    const t = await setup();
    try {
      t.storage.putReport = async () => {
        throw new Error('disk full');
      };
      await assert.rejects(t.lifecycle(makeRun(), makeCtx().ctx), (err) => err.code === 'storage_failed' && err.stage === 'upload');
    } finally {
      t.close();
    }
  });
});

describe('lifecycle with the real peer modules on the captured fixture', () => {
  test('canary, seed, evidence, rules, explain template and report build a full report', async () => {
    const { modules, missing } = await loadModules();
    assert.deepEqual(missing, [], `peer modules missing: ${missing}`);
    const dir = mkdtempSync(path.join(tmpdir(), 'firstrun-lc-real-'));
    try {
      const config = loadConfig({
        FIRSTRUN_RUNS_DIR: path.join(dir, 'runs'),
        FIRSTRUN_TRACE_DIR: path.join(dir, 'trace'),
        FIRSTRUN_SPOOL_DIR: path.join(dir, 'spool'),
        FIRSTRUN_SINK_SOCKET: path.join(dir, 'sink.sock'),
        FIRSTRUN_SAMPLES_DIR: path.join(dir, 'samples'),
      });
      mkdirSync(config.traceDir, { recursive: true });
      const logs = [];
      const storage = await createStorage({ config, log: (r) => logs.push(r) });
      const docker = fakeDocker(config, {
        exit: { code: 0, stdout: readFileSync(path.join(CAPTURE, 'stdout.txt'), 'utf8'), stderr: readFileSync(path.join(CAPTURE, 'stderr.txt'), 'utf8') },
        onSinkhole: (runDir) => {
          for (const f of ['events.jsonl', 'dns.log', 'tcp.jsonl']) copyFileSync(path.join(CAPTURE, f), path.join(runDir, 'sinkhole', f));
        },
      });
      // The captured sandbox: its cid goes to sb.cid and its trace file to the trace dir.
      docker.runAttached = ((orig) => (argv) => {
        const r = orig(argv.map((a) => a));
        return r;
      })(docker.runAttached);
      const sbCidOriginal = CID;
      const traceFile = path.join(config.traceDir, `${CAP_CID}.jsonl`);
      copyFileSync(path.join(CAPTURE, 'trace.jsonl'), traceFile);
      const realDocker = {
        ...docker,
        runAttached(argv) {
          const res = docker.runAttached(argv);
          if (!argv.includes('FIRSTRUN_PHASE=unwrap')) {
            const cidfile = argv[argv.indexOf('--cidfile') + 1];
            return { pid: 1, done: res.done.then((r) => { writeFileSync(cidfile, CAP_CID); return r; }) };
          }
          return res;
        },
      };
      // sb.cid must carry the capture's container id before the trace is attached: write it
      // ourselves as soon as the sandbox "starts" (fakeDocker writes CID after 5 ms; override).
      realDocker.runAttached = (argv) => {
        const cidfile = argv[argv.indexOf('--cidfile') + 1];
        const unwrap = argv.includes('FIRSTRUN_PHASE=unwrap');
        if (!unwrap) writeFileSync(cidfile, CAP_CID);
        const res = docker.runAttached(argv);
        return { pid: 1, done: res.done.then((r) => { if (!unwrap) writeFileSync(cidfile, CAP_CID); return r; }) };
      };
      void sbCidOriginal;
      const lifecycle = createLifecycle({
        config,
        llm: null,
        storage,
        docker: realDocker,
        modules,
        log: (r) => logs.push(r),
        limits: { sinkholeReadyMs: 2000, cidfileWaitMs: 2000, watchdogMs: 5000, evidenceGraceMs: 300 },
      });
      const run = makeRun('curl -s https://example.test/hello; /opt/firstrun/shims/crontab -l\n', 'fetches a greeting');
      const c = makeCtx();
      await lifecycle(run, c.ctx);
      const names = c.events.map((e) => e.name);
      assert.equal(names[0], 'run.started');
      assert.ok(names.includes('exec.started') && names.includes('exec.finished') && names.includes('verdict') && names.includes('explanation'));
      const evidence = c.events.filter((e) => e.name === 'evidence').map((e) => e.event.kind);
      assert.ok(evidence.includes('proc.exec'), `kinds: ${[...new Set(evidence)]}`);
      assert.ok(evidence.includes('http.request') || evidence.includes('dns.query'), `sinkhole kinds: ${[...new Set(evidence)]}`);
      const report = c.report;
      assert.equal(report.schema_version, 1);
      assert.equal(report.run_id, run.run_id);
      assert.ok(['CLEAN', 'SUSPICIOUS', 'MALICIOUS'].includes(report.verdict.level));
      assert.ok(report.events.length > 0);
      assert.ok(report.decoys.length > 5 && report.decoys.every((d) => 'id' in d && 'category' in d));
      assert.equal(report.explanation.verdict_echo, report.verdict.level);
      assert.equal(report.explanation_meta.source, 'template');
      assert.equal(report.contract_meta.source, 'fallback');
      assert.equal(report.coverage.mode, 'trace');
      assert.equal(typeof report.coverage.pre_t0, 'number');
      assert.deepEqual(await storage.getReport(run.run_id), report);
      assert.equal(existsSync(traceFile), false, 'trace file removed at teardown');
      assert.equal(existsSync(path.join(config.runsDir, run.run_id)), false);
      const text = JSON.stringify(logs);
      for (const d of report.decoys) if (d.value) assert.equal(text.includes(d.value), false, 'canary value never logged');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('AI review and second try', () => {
  const CLEAN = { findings: [], verdict: { level: 'CLEAN', rule_ids: [], coverage_notes: ['CLEAN means nothing suspicious was observed in this run (Linux sandbox, 60 s, no internet), not proof that the command is safe.'] }, classifications: {} };
  const reason = { what: 'Deletes files', why: 'Not in the claim', quote: 'rm -rf x' };

  async function reviewed(review) {
    const t = await setup({ llm: {} });
    t.fakes.modules.rules = (args) => {
      t.fakes.seen.rulesCalls = (t.fakes.seen.rulesCalls ?? 0) + 1;
      t.fakes.seen.rules = args;
      return structuredClone(CLEAN);
    };
    t.fakes.modules.review = review;
    t.fakes.modules.applyReview = applyReview;
    return t;
  }

  test('a verified risk raises CLEAN to SUSPICIOUS, marked as not observed', async () => {
    const t = await reviewed(async () => ({ review: { risk: 'high', summary: 'Deletes your files', real_machine_effects: [], reasons: [reason] }, retry: null, meta: { source: 'llm', ms: 5 } }));
    try {
      const run = makeRun();
      const c = makeCtx();
      await t.lifecycle(run, c.ctx);
      assert.equal(c.report.verdict.level, 'SUSPICIOUS');
      assert.deepEqual(c.report.verdict.rule_ids, ['ai.review']);
      assert.ok(!c.report.verdict.coverage_notes.some((n) => n.startsWith('CLEAN means')));
      const verdicts = c.events.filter((e) => e.name === 'verdict');
      assert.equal(verdicts.length, 1, 'the verdict is announced once, after the review');
      assert.equal(verdicts[0].verdict.level, 'SUSPICIOUS');
      assert.equal(t.fakes.seen.report.review.risk, 'high');
      assert.equal(t.fakes.seen.report.reviewMeta.source, 'llm');
      assert.equal(t.fakes.seen.report.findings[0].observed, false);
      assert.equal(t.fakes.seen.rulesCalls, 1, 'no second run, so the rules ran once');
    } finally {
      t.close();
    }
  });

  test('a failed review leaves the rules verdict and says so', async () => {
    const t = await reviewed(async () => ({ review: null, retry: null, meta: { source: 'failed', reason: 'timeout', ms: 5 } }));
    try {
      const c = makeCtx();
      await t.lifecycle(makeRun(), c.ctx);
      assert.equal(c.report.verdict.level, 'CLEAN');
      assert.ok(c.report.verdict.coverage_notes.some((n) => n.includes('did not run')));
    } finally {
      t.close();
    }
  });

  test('proof already in hand: no review call at all', async () => {
    const t = await setup({ llm: {} });
    try {
      let called = 0;
      t.fakes.modules.review = async () => void (called += 1);
      const c = makeCtx();
      await t.lifecycle(makeRun(), c.ctx);
      assert.equal(called, 0);
      assert.equal(c.report.verdict.level, 'MALICIOUS');
    } finally {
      t.close();
    }
  });

  const knobs = { env: [['CI', 'true']], hostname: 'ci-runner-7', answerYes: true, skipSleep: true, timeoutS: 30 };
  const retry = { why: 'It checks CI.', quote: '[ -n "$CI" ]', knobs };

  test('second try: fresh sandbox with the settings, events appended, one retry only', async () => {
    let reviews = 0;
    const t = await reviewed(async () => {
      reviews += 1;
      return { review: { risk: 'none', summary: 's', real_machine_effects: [], reasons: [] }, retry, meta: { source: 'llm', ms: 5 } };
    });
    try {
      const run = makeRun();
      const c = makeCtx();
      await t.lifecycle(run, c.ctx);
      assert.equal(reviews, 1);
      const runs = t.docker.calls.filter((x) => x.startsWith('run --name') && x.includes('FIRSTRUN_PHASE=execute'));
      assert.equal(runs.length, 2);
      assert.ok(runs[0].includes('--hostname devbox') && !runs[0].includes('CI=true'));
      assert.ok(runs[1].includes('--hostname ci-runner-7') && runs[1].includes('CI=true') && runs[1].includes('FIRSTRUN_STDIN=answers') && runs[1].includes('FIRSTRUN_TIMEOUT=30'));
      assert.equal(t.docker.calls.filter((x) => x.startsWith('network create')).length, 2, 'a fresh fake internet');

      const started = c.events.find((e) => e.name === 'retry.started');
      assert.deepEqual(started.settings, { set_env: ['CI'], hostname: 'ci-runner-7', answer_yes: true, skip_sleep: true });
      assert.deepEqual(c.events.filter((e) => e.name === 'exec.started').map((e) => e.attempt), [1, 2]);

      const seqs = t.fakes.seen.rules.events.map((e) => e.seq);
      assert.deepEqual(seqs, [1, 2, 3, 4], 'no seq collides across the two runs');
      const hit = t.fakes.seen.rules.events[3];
      assert.equal(hit.attempt, 2);
      assert.equal(hit.event_seq, 3, 'a hit still points at its own event');
      assert.equal(t.fakes.seen.report.attempts.length, 2);
      assert.equal(t.fakes.seen.report.attempts[1].settings.hostname, 'ci-runner-7');
      assert.ok(!JSON.stringify(t.fakes.seen.report.attempts).includes('"true"'), 'values stay out of the report');
      assert.ok(c.report.verdict.coverage_notes.some((n) => n.includes('second time')));
      assert.equal(existsSync(path.join(t.config.runsDir, run.run_id)), false, 'run dir removed');
    } finally {
      t.close();
    }
  });

  test('a second try that cannot run costs nothing: the first run stands', async () => {
    const t = await reviewed(async () => ({ review: null, retry, meta: { source: 'llm', ms: 5 } }));
    try {
      const orig = t.docker.run;
      let creates = 0;
      t.docker.run = async (argv) => {
        if (argv[0] === 'network' && argv[1] === 'create' && ++creates === 2) throw new Error('no network');
        return orig(argv);
      };
      const c = makeCtx();
      await t.lifecycle(makeRun(), c.ctx);
      assert.equal(c.error, undefined);
      assert.equal(c.report.verdict.level, 'CLEAN');
      assert.equal(t.fakes.seen.report.attempts[1].failed, true);
      assert.ok(!c.report.verdict.coverage_notes.some((n) => n.includes('second time')));
    } finally {
      t.close();
    }
  });
});
