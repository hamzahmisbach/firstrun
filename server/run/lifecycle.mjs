// One run, docs/ARCHITECTURE.md section 4 steps 3-13:
//   3  run dir <runsDir>/<id>/{seed,work,sinkhole}; the command goes to work/cmd.sh via fs.writeFile
//   4  canaries + seed HOME (5.3)                    5  deterministic decoder (8.2) -> unwrap.layer
//   6  in parallel: network + sinkhole (6.1, 6.2), claim-to-contract (8.1), harness loop (8.3)
//   7  attached `docker run` sandbox (5.1), stdout/stderr capped at 1 MiB, 32 KiB preview
//   8  evidence from the sidecar trace file and the sinkhole tails -> evidence / alert
//   9  `timeout -s KILL 60` inside, `docker kill` watchdog at 75 s outside -> exec.finished
//   10 teardown in finally (rm -f containers, network rm, seed/ work/ trace files)
//   11 rules -> verdict   12 explanation (LLM or template)   13 report -> storage -> run.done
// Contract with the caller (http/routes.mjs): call ctx.done(report) once, or throw (a RunError for
// a known failure code); the caller turns anything else into run.error {code: "internal"}.
// Peer modules (evidence, rules, llm, unwrap, explain, canary, seed, report) are injected; a
// missing one is logged at startup and replaced by a deterministic fallback with a coverage note,
// so the engine can be exercised end to end before every module exists.
import { chmod, mkdir, readFile, readdir, rm, stat, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { LIMITS } from '../config.mjs';
import { ANSWERS_FILE_TEXT, describeKnobs } from '../review/knobs.mjs';
import { INTERPRETERS, names, sandboxRunArgs, sinkholeRunArgs, networkCreateArgs, inspectSinkIpArgs } from './docker.mjs';

/** A failure with a run.error code from section 10.2 (sandbox_start_failed, internal, ...). */
export class RunError extends Error {
  constructor(code, message, { stage = null, retryable = false } = {}) {
    super(message);
    this.code = code;
    this.stage = stage;
    this.retryable = retryable;
  }
}

/** Fallback contract (8.1) when the LLM is unavailable or not finished when rules run. */
export const FALLBACK_CONTRACT = Object.freeze({
  summary: '',
  expected_hosts: [],
  expected_write_paths: [],
  expected_processes: [],
  allowed_decoy_categories: [],
  notes: 'Contract could not be generated; only the sandbox baseline (tmp and cache) is treated as expected.',
});

const NEXT_STEP = {
  CLEAN: "Consistent with the claim within this run's limits",
  SUSPICIOUS: 'Read the unexplained items before deciding',
  MALICIOUS: 'Do not run this on your machine',
};

// ---------------------------------------------------------------------------------------------
// Peer modules

const SERVER_DIR = fileURLToPath(new URL('..', import.meta.url));

/** module key -> [relative path, export name] */
export const MODULE_SPECS = Object.freeze({
  canary: ['run/canary.mjs', 'createCanaries'],
  seed: ['run/seed.mjs', 'writeSeed'],
  evidence: ['evidence/index.mjs', 'createEvidence'],
  rules: ['rules/engine.mjs', 'evaluate'],
  report: ['run/report.mjs', 'buildReport'],
  explainInput: ['explain/input.mjs', 'buildExplanationInput'],
  explainTemplate: ['explain/template.mjs', 'renderTemplateExplanation'],
  explainWriter: ['explain/writer.mjs', 'writeExplanation'],
  llmClient: ['llm/client.mjs', 'createLlm'],
  contract: ['llm/contract.mjs', 'deriveContract'],
  decoder: ['unwrap/decoder-thread.mjs', 'decodeInWorker'],
  harness: ['unwrap/harness.mjs', 'runHarnessLoop'],
  review: ['review/review.mjs', 'reviewRun'],
  applyReview: ['review/apply.mjs', 'applyReview'],
});

/**
 * Import every peer module that exists. `devDir` (FIRSTRUN_DEV_MODULES_DIR) shadows server/ for
 * stand-ins kept outside the repo. Returns {modules: {key: fn | null}, missing: [key]}.
 */
export async function loadModules({ devDir = null, serverDir = SERVER_DIR, log = () => {} } = {}) {
  const modules = {};
  const missing = [];
  for (const [key, [rel, exportName]] of Object.entries(MODULE_SPECS)) {
    modules[key] = null;
    const candidates = devDir ? [path.join(devDir, rel), path.join(serverDir, rel)] : [path.join(serverDir, rel)];
    for (const file of candidates) {
      try {
        await stat(file);
      } catch {
        continue;
      }
      try {
        const mod = await import(new URL(`file:///${file.replaceAll('\\', '/')}`).href);
        if (typeof mod[exportName] !== 'function') throw new Error(`does not export ${exportName}`);
        modules[key] = mod[exportName];
        break;
      } catch (err) {
        log({ level: 'error', msg: 'module.load_failed', module: key, file: rel, err: err?.message ?? String(err) });
      }
    }
    if (!modules[key]) missing.push(key);
  }
  return { modules, missing };
}

// ---------------------------------------------------------------------------------------------
// Small helpers

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const CID_RE = /^[0-9a-f]{64}$/;

async function ensureDir(dir, mode) {
  await mkdir(dir, { recursive: true });
  await chmod(dir, mode); // mkdir's mode is masked by the service UMask (0027)
}

/** The sandbox runs as uid 1000 and the service as another uid: seed files must be world-readable. */
async function makeWorldReadable(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  await chmod(dir, 0o755);
  for (const entry of entries) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) await makeWorldReadable(p);
    else await chmod(p, 0o644);
  }
}

/** Remove runsc's `<cid>.<command>.log` files (7.6) for one container; the dir may not exist. */
export async function removeRunscLogs(logDir, cid) {
  if (!logDir || !CID_RE.test(cid)) return;
  let names;
  try {
    names = await readdir(logDir);
  } catch {
    return;
  }
  for (const name of names) {
    if (name.startsWith(`${cid}.`) && name.endsWith('.log')) await unlink(path.join(logDir, name)).catch(() => {});
  }
}

/** Poll `file` every 20 ms until it exists, `stop` resolves, or timeoutMs passes. */
async function waitForFile(file, timeoutMs, stop = null, now = Date.now) {
  const deadline = now() + timeoutMs;
  let stopped = false;
  stop?.then(() => (stopped = true), () => (stopped = true));
  while (now() < deadline) {
    try {
      const text = await readFile(file, 'utf8');
      if (text.length > 0) return text;
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
    if (stopped) return null;
    await sleep(20);
  }
  return null;
}

/** t0Seen() may be a boolean getter or a promise; track it either way. */
function trackT0(evidence) {
  let seen = false;
  const probe = () => {
    if (seen || !evidence) return seen;
    const v = evidence.t0Seen();
    if (v === true) seen = true;
    else if (v && typeof v.then === 'function') v.then(() => (seen = true), () => {});
    return seen;
  };
  probe();
  return {
    seen: () => probe(),
    async wait(until) {
      let done = false;
      until.then(() => (done = true), () => (done = true));
      while (!done) {
        if (probe()) return true;
        await sleep(25);
      }
      return probe();
    },
  };
}

const previewOf = (buf, max) => buf.subarray(0, max).toString('utf8');

function sseLayer(layer) {
  if (!layer || typeof layer !== 'object') return layer;
  const { text, ...rest } = layer;
  const preview = typeof text === 'string' ? text.slice(0, 4096) : (layer.preview ?? '');
  return { ...rest, preview };
}

function templateExplanation(verdict, findings, claim) {
  const level = verdict.level;
  const top = findings.slice(0, 3).map((f) => f.title).filter(Boolean);
  const headline =
    level === 'CLEAN'
      ? 'Nothing beyond the claim was observed in this run'
      : level === 'SUSPICIOUS'
        ? `${findings.length} thing${findings.length === 1 ? '' : 's'} the claim does not explain`
        : (findings.find((f) => f.severity === 'critical')?.title ?? top[0] ?? 'Harmful behaviour was observed');
  const paragraphs = [`You were told: ${claim}`];
  if (top.length) paragraphs.push(`Observed: ${top.join('; ')}.`);
  if (verdict.coverage_notes?.length) paragraphs.push(verdict.coverage_notes.join(' '));
  return {
    verdict_echo: level,
    headline,
    paragraphs: paragraphs.slice(0, 3),
    finding_notes: [],
    next_step: NEXT_STEP[level] ?? NEXT_STEP.SUSPICIOUS,
  };
}

const NOTE_REVIEW_NOT_RUN = 'The AI reading of the code did not run for this report, so this rests only on what was recorded in the sandbox.';
const NOTE_SECOND_TRY = 'FirstRun ran the command a second time with changed conditions, because the code looked like it was waiting for them. Both runs are included here.';

const CLEAN_NOTE =
  'CLEAN means nothing suspicious was observed in this run (Linux sandbox, 60 s, no internet), not proof that the command is safe.';

/** Minimal 10.3 report, used only until run/report.mjs exists. */
function fallbackReport(a) {
  return {
    schema_version: 1,
    run_id: a.run.run_id,
    created_at: a.run.created_at,
    input: a.run.input,
    layers: a.layers,
    contract: a.contract,
    contract_meta: a.contractMeta,
    events: a.events,
    findings: a.findings,
    verdict: a.verdict,
    explanation: a.explanation,
    explanation_meta: a.explanationMeta,
    decoys: a.decoys,
    coverage: a.coverage,
    output: a.output,
    timing: a.timing,
    models_used: a.modelsUsed,
  };
}

// ---------------------------------------------------------------------------------------------

/**
 * @param {object} opts
 * @param {ReturnType<import('../config.mjs').loadConfig>} opts.config
 * @param {object | null} [opts.llm]  llm/client.mjs instance, or null (fallbacks only)
 * @param {object} opts.storage  storage/index.mjs instance
 * @param {object} opts.docker  run/docker.mjs createDocker() instance
 * @param {object} opts.modules  from loadModules(); missing entries are null
 * @param {Function} [opts.log]
 * @param {() => number} [opts.now]
 * @param {object} [opts.limits]  overrides for timing-sensitive limits (tests)
 * @returns {(run: object, ctx: object) => Promise<void>}
 */
export function createLifecycle({ config, llm: sharedLlm = null, storage, docker, modules = {}, log = () => {}, now = Date.now, limits = {} }) {
  const m = modules;
  const L = {
    sinkholeReadyMs: LIMITS.sandbox.sinkholeReadyMs,
    cidfileWaitMs: LIMITS.sandbox.cidfileWaitMs,
    watchdogMs: LIMITS.sandbox.watchdogS * 1000,
    unwrapWatchdogMs: LIMITS.sandbox.unwrapWatchdogS * 1000,
    evidenceGraceMs: LIMITS.sandbox.evidenceGraceMs,
    unwrapBudgetMs: LIMITS.unwrap.budgetMs,
    execTimeoutMs: LIMITS.sandbox.execTimeoutS * 1000,
    timeoutSlackMs: LIMITS.sandbox.timeoutSlackMs,
    contractWaitMs: LIMITS.llm.contractWaitMs,
    ...limits,
  };

  async function readSampleContract(sampleId) {
    if (!sampleId) return null;
    try {
      const text = await readFile(path.join(config.samplesDir, sampleId, 'contract.json'), 'utf8');
      return JSON.parse(text);
    } catch {
      return null;
    }
  }

  return async function lifecycle(run, ctx) {
    const id = run.run_id;
    // Usage is counted per run, so models_used in a report covers this run and no other (10.3).
    const llm = sharedLlm?.forRun ? sharedLlm.forRun() : sharedLlm;
    const runDir = path.join(config.runsDir, id);
    const dirs = {
      seed: path.join(runDir, 'seed'),
      work: path.join(runDir, 'work'),
      unwrap: path.join(runDir, 'unwrap'),
      sinkhole: path.join(runDir, 'sinkhole'),
    };
    const timing = { queued_ms: now() - run.created_ms };
    const notes = []; // run-level coverage notes (section 10.3 coverage.notes)
    const state = { network: false, sinkhole: false, sandbox: false, cids: new Set(), watchdog: null, stored: false, unwrapCount: 0, sinkIp: null, networkMs: 0 };
    const harnessAbort = new AbortController();
    const stageLog = (stage, extra = {}) => log({ msg: 'run.stage', run_id: id, stage, ...extra });
    let mark = now();
    const lap = (key) => {
      const t = now();
      timing[key] = t - mark;
      mark = t;
      return timing[key];
    };

    // ---- teardown (step 10), idempotent, always run from finally
    /** Containers, network and their records. The seed and command stay for a possible second try. */
    async function teardownContainers() {
      clearTimeout(state.watchdog);
      const containers = [];
      if (state.sandbox) containers.push(names.sandbox(id));
      if (state.sinkhole) containers.push(names.sinkhole(id));
      if (containers.length) await docker.rmForce(containers);
      if (state.network) await docker.networkRm(id);
      state.sandbox = state.sinkhole = state.network = false;
      await Promise.all([unlink(path.join(runDir, 'resolv.conf')).catch(() => {}), unlink(path.join(runDir, 'sb.cid')).catch(() => {})]);
      for (const cid of state.cids) {
        await unlink(path.join(config.traceDir, `${cid}.jsonl`)).catch(() => {});
        await removeRunscLogs(config.runscLogDir, cid);
      }
      state.cids.clear();
    }

    async function teardownSandbox() {
      await teardownContainers();
      await Promise.all([
        rm(dirs.seed, { recursive: true, force: true }),
        rm(dirs.work, { recursive: true, force: true }),
        rm(dirs.unwrap, { recursive: true, force: true }),
      ]);
      for (let i = 0; i < state.unwrapCount; i++) await unlink(path.join(runDir, `unwrap-${i}.cid`)).catch(() => {});
    }

    async function readCid(file) {
      try {
        const cid = (await readFile(file, 'utf8')).trim();
        if (CID_RE.test(cid)) state.cids.add(cid);
        return cid;
      } catch {
        return null;
      }
    }

    // ---- step 6(a): network, sinkhole, resolv.conf, readiness
    async function setupNetwork() {
      const t = now();
      try {
        await docker.run(networkCreateArgs(id));
        state.network = true;
        await docker.run(sinkholeRunArgs({ id, runDir, sampleId: run.sample_id }));
        state.sinkhole = true;
        const ip = (await docker.run(inspectSinkIpArgs(id))).stdout.trim();
        if (!IPV4_RE.test(ip)) throw new Error('sinkhole has no IPv4 address');
        state.sinkIp = ip;
        await writeFile(path.join(runDir, 'resolv.conf'), `nameserver ${ip}\noptions timeout:1 attempts:1 ndots:1\n`, { mode: 0o644 });
        await chmod(path.join(runDir, 'resolv.conf'), 0o644);
        const ready = await waitForFile(path.join(dirs.sinkhole, 'ready'), L.sinkholeReadyMs, null, now);
        if (ready === null) throw new Error(`sinkhole not ready after ${L.sinkholeReadyMs} ms`);
        state.networkMs = now() - t;
        stageLog('network', { ms: state.networkMs });
      } catch (err) {
        log({ level: 'warn', msg: 'run.sinkhole_failed', run_id: id, err: err?.message ?? String(err) });
        throw new RunError('sinkhole_not_ready', 'The fake internet for this run did not start.', { stage: 'setup', retryable: true });
      }
    }

    // ---- step 6(b): claim-to-contract, consumed at step 11
    async function deriveContract() {
      const sampleContract = await readSampleContract(run.sample_id);
      if (llm && m.contract) {
        try {
          const t = now();
          // Claim only: the command never reaches the contract call (8.1), so hidden or visible
          // parts of the command cannot shape the expectations they are judged against.
          const r = await m.contract(llm, run.input.claim, { sampleContract, sampleId: run.sample_id });
          stageLog('contract', { ms: now() - t, source: r?.meta?.source ?? null });
          if (r?.contract) return { contract: r.contract, meta: r.meta ?? { source: 'llm', prompt_version: 'unknown' } };
        } catch (err) {
          log({ level: 'warn', msg: 'run.contract_failed', run_id: id, err: err?.message ?? String(err) });
        }
      }
      if (sampleContract) return { contract: { ...FALLBACK_CONTRACT, ...sampleContract }, meta: { source: 'fallback', prompt_version: 'none' } };
      return { contract: { ...FALLBACK_CONTRACT, summary: run.input.claim }, meta: { source: 'fallback', prompt_version: 'none' } };
    }

    // ---- step 6(c): one harness container (5.1 unwrap variant); injected into the harness loop
    async function runHarness({ language, code }) {
      const interp = INTERPRETERS[language];
      if (!interp || typeof code !== 'string') return { stdout: '', stderr: 'unsupported harness language', exit_code: 64, timed_out: false };
      const n = state.unwrapCount++;
      const name = names.unwrap(id, n);
      const file = path.join(dirs.unwrap, `harness.${interp.ext}`);
      await writeFile(file, code, { mode: 0o644 });
      await chmod(file, 0o644);
      let watchdog = null;
      try {
        const proc = docker.runAttached(sandboxRunArgs({ id, runDir, phase: 'unwrap', language, unwrapIndex: n }), {
          maxBytes: LIMITS.unwrap.harnessStdoutMaxBytes,
          maxStderrBytes: LIMITS.unwrap.harnessStderrMaxBytes,
        });
        watchdog = setTimeout(() => docker.kill(name), L.unwrapWatchdogMs);
        const r = await proc.done;
        return {
          stdout: r.stdout.toString('utf8'),
          stderr: r.stderr.toString('utf8'),
          exit_code: r.code ?? -1,
          timed_out: r.code === 124 || r.code === 137,
        };
      } finally {
        clearTimeout(watchdog);
        await docker.rmForce([name]);
        const cid = await readCid(path.join(runDir, `unwrap-${n}.cid`));
        if (cid) {
          await unlink(path.join(config.traceDir, `${cid}.jsonl`)).catch(() => {});
          await removeRunscLogs(config.runscLogDir, cid);
        }
        await unlink(path.join(runDir, `unwrap-${n}.cid`)).catch(() => {});
        await unlink(file).catch(() => {});
      }
    }

    async function harnessLoop(text, onLayer, { priorTexts = [], firstIndex = 1, parent = 0 } = {}) {
      const t = now();
      try {
        const r = await m.harness({
          llm,
          text,
          runHarness,
          budgetMs: L.unwrapBudgetMs,
          onLayer,
          signal: AbortSignal.any([harnessAbort.signal, AbortSignal.timeout(L.unwrapBudgetMs + 5000)]),
          priorTexts,
          firstIndex,
          parent,
          log,
        });
        stageLog('harness', { ms: now() - t, layers: r?.layers?.length ?? 0, stopped: r?.stoppedReason ?? null });
        return { ...(r ?? { layers: [], stoppedReason: 'none' }), ms: now() - t };
      } catch (err) {
        log({ level: 'warn', msg: 'run.harness_failed', run_id: id, err: err?.message ?? String(err) });
        notes.push('Inner layers could not be decoded; the verdict rests on runtime evidence only.');
        return { layers: [], stoppedReason: 'error', ms: now() - t };
      }
    }

    // ---- steps 7-9. A second try (8.7) passes knobs and shifts its events after the first run's.
    async function execute(decoys, { attempt = 1, knobs = null, seqOffset = 0, tOffset = 0 } = {}) {
      const name = names.sandbox(id);
      const limitMs = knobs ? knobs.timeoutS * 1000 : L.execTimeoutMs;
      const shift =
        attempt === 1
          ? (event) => event
          : (event) => ({
              ...event,
              attempt,
              seq: event.seq + seqOffset,
              t_rel_ms: (event.t_rel_ms ?? 0) + tOffset,
              ...(Number.isInteger(event.event_seq) ? { event_seq: event.event_seq + seqOffset } : {}),
            });
      // SSE order (10.2): exec.started precedes every evidence/alert. The tails can deliver the
      // first events before the T0 poll notices, so they are held until exec.started is out.
      let started = false;
      const held = [];
      const emitEvidence = (sse, event) => (started ? ctx.emit(sse, { event: shift(event) }) : held.push([sse, event]));
      const markStarted = (cid) => {
        started = true;
        ctx.emit('exec.started', { container_id: cid, timeout_s: limitMs / 1000, attempt });
        for (const [sse, event] of held.splice(0)) ctx.emit(sse, { event: shift(event) });
      };
      const evidence = m.evidence
        ? m.evidence({
            runId: id,
            sinkholeDir: dirs.sinkhole,
            traceDir: config.traceDir,
            runscLogDir: config.runscLogDir ?? null,
            decoys,
            onEvent: (event) => emitEvidence('evidence', event),
            onAlert: (event) => emitEvidence('alert', event),
            log,
          })
        : null;
      evidence?.startSinkhole();
      const t0 = trackT0(evidence);
      const startedMs = now();
      const proc = docker.runAttached(sandboxRunArgs({ id, runDir, knobs }), { maxBytes: LIMITS.output.streamMaxBytes });
      state.sandbox = true;
      let killedBy = null;
      state.watchdog = setTimeout(() => {
        killedBy = 'watchdog';
        log({ level: 'warn', msg: 'run.watchdog', run_id: id });
        docker.kill(name);
      }, knobs ? Math.min(L.watchdogMs, limitMs + 15_000) : L.watchdogMs);

      const cidText = await waitForFile(path.join(runDir, 'sb.cid'), L.cidfileWaitMs, proc.done, now);
      const cid = cidText ? cidText.trim() : null;
      if (cid && CID_RE.test(cid)) {
        state.cids.add(cid);
        evidence?.attachSandbox(cid);
        const seen = evidence ? await t0.wait(proc.done) : true;
        if (seen) markStarted(cid);
      }

      const r = await proc.done;
      clearTimeout(state.watchdog);
      const durationMs = now() - startedMs;
      const oomKilled = cid ? await docker.oomKilled(name) : false;
      let ev = { events: [], coverage: {} };
      if (evidence) {
        try {
          // A canary printed to stdout/stderr is still a leak (event_seq: null in the hit).
          if (typeof evidence.scanOutput === 'function') {
            if (r.stdout.length) evidence.scanOutput(r.stdout, 'stdout');
            if (r.stderr.length) evidence.scanOutput(r.stderr, 'stderr');
          }
          ev = await evidence.stop({ graceMs: L.evidenceGraceMs });
        } catch (err) {
          log({ level: 'error', msg: 'run.evidence_stop_failed', run_id: id, err: err?.stack ?? String(err) });
          throw new RunError('internal', 'Evidence collection failed.', { stage: 'exec', retryable: true });
        }
      } else {
        notes.push('Evidence module unavailable: no trace or network events were collected for this run.');
      }

      if (!cid || !CID_RE.test(cid)) {
        const stderr = r.stderr.toString('utf8').slice(0, 500);
        log({ level: 'error', msg: 'run.sandbox_start_failed', run_id: id, code: r.code, stderr });
        let sidecarUp = true;
        try {
          await stat(config.sinkSocket);
        } catch {
          sidecarUp = false;
        }
        if (!sidecarUp || /sink|pod-init|seccheck/i.test(stderr)) {
          throw new RunError('trace_unavailable', 'The evidence channel (gVisor trace sidecar) is unavailable.', { stage: 'exec', retryable: true });
        }
        throw new RunError('sandbox_start_failed', 'The sandbox did not start.', { stage: 'exec', retryable: true });
      }
      if (evidence && !t0.seen()) {
        throw new RunError('no_t0_marker', 'The sandbox never reached the command (no T0 marker), so there is no verdict.', {
          stage: 'exec',
          retryable: true,
        });
      }

      // 124 is `timeout`'s own code; 137 is any SIGKILL (timeout, watchdog, OOM, the command itself),
      // so it only counts as a timeout when the run actually reached the limit.
      const reachedLimit = durationMs >= limitMs - L.timeoutSlackMs;
      const timedOut = killedBy === 'watchdog' || r.code === 124 || (r.code === 137 && reachedLimit && !oomKilled);
      if (timedOut && !killedBy) killedBy = 'timeout';
      const exitCode = r.code ?? (r.signal ? 128 : -1);
      const coverage = {
        timed_out: timedOut,
        tls_unreadable: [],
        notes: [],
        mode: evidence ? config.evidence : 'none',
        gvisor_dropped: 0,
        decode_errors: 0,
        pre_t0: 0,
        dedup: 0,
        capped: {},
        scan_truncated: false,
        oom_killed: oomKilled,
        ...(ev.coverage ?? {}),
      };
      coverage.timed_out = timedOut;
      coverage.oom_killed = oomKilled || Boolean(ev.coverage?.oom_killed);
      const exec = {
        exit_code: exitCode,
        timed_out: timedOut,
        killed_by: killedBy,
        duration_ms: durationMs,
        stdout_bytes: r.stdoutBytes,
        stderr_bytes: r.stderrBytes,
      };
      const output = {
        stdout_preview: previewOf(r.stdout, LIMITS.output.previewMaxBytes),
        stderr_preview: previewOf(r.stderr, LIMITS.output.previewMaxBytes),
        stdout_bytes: r.stdoutBytes,
        stderr_bytes: r.stderrBytes,
        truncated: r.truncated || r.stdoutBytes > LIMITS.output.previewMaxBytes || r.stderrBytes > LIMITS.output.previewMaxBytes,
      };
      ctx.emit('exec.finished', { ...exec, coverage, attempt });
      stageLog('exec', { attempt, ms: durationMs, exit_code: exitCode, timed_out: timedOut, killed_by: killedBy, events: ev.events?.length ?? 0 });
      return { exec, output, events: (ev.events ?? []).map(shift), coverage };
    }

    /**
     * One more run with settings from the fixed menu (review/knobs.mjs), in a fresh sandbox and a
     * fresh fake internet. A failure here costs nothing: the first run's evidence stands.
     * @returns {Promise<object|null>} execute()'s result, or null if it could not run
     */
    async function secondTry(decoys, retry, { seqOffset, tOffset }) {
      ctx.emit('retry.started', { why: retry.why, quote: retry.quote, settings: describeKnobs(retry.knobs) });
      try {
        await rm(dirs.sinkhole, { recursive: true, force: true });
        await ensureDir(dirs.sinkhole, 0o777);
        await ensureDir(path.join(dirs.sinkhole, 'bodies'), 0o777);
        await setupNetwork();
        if (retry.knobs.answerYes) {
          await writeFile(path.join(dirs.work, 'answers.txt'), ANSWERS_FILE_TEXT, { mode: 0o644 });
          await chmod(path.join(dirs.work, 'answers.txt'), 0o644);
        }
        return await execute(decoys, { attempt: 2, knobs: retry.knobs, seqOffset, tOffset });
      } catch (err) {
        log({ level: 'warn', msg: 'run.retry_failed', run_id: id, code: err?.code ?? null, err: err?.message ?? String(err) });
        return null;
      } finally {
        await teardownContainers();
      }
    }

    // =========================================================================================
    ctx.emit('run.started', { sample_id: run.sample_id, command_sha256: run.command_sha256, claim: run.input.claim });
    let report = null;
    let harnessPending = null;
    try {
      ctx.phase('setup');
      // step 3
      await ensureDir(runDir, 0o755);
      await Promise.all([ensureDir(dirs.seed, 0o755), ensureDir(dirs.work, 0o755), ensureDir(dirs.unwrap, 0o755), ensureDir(dirs.sinkhole, 0o777)]);
      // The sinkhole writes as a non-root user: pre-create bodies/ so its files stay deletable by us.
      await ensureDir(path.join(dirs.sinkhole, 'bodies'), 0o777);
      const command = run.input.command.endsWith('\n') ? run.input.command : `${run.input.command}\n`;
      // The service runs with UMask=0027 and the sandbox reads as uid 1000: chmod after every write.
      await writeFile(path.join(dirs.work, 'cmd.sh'), command, { mode: 0o644 });
      await chmod(path.join(dirs.work, 'cmd.sh'), 0o644);

      // step 4
      let decoys = [];
      let seededPaths = [];
      if (m.canary) {
        const c = m.canary();
        decoys = Array.isArray(c?.decoys) ? c.decoys : [];
        if (m.seed) {
          const s = await m.seed(dirs.seed, decoys);
          seededPaths = Array.isArray(s?.seededPaths) ? s.seededPaths : [];
        } else notes.push('Seed module unavailable: the decoy home directory was empty.');
      } else {
        notes.push('Canary module unavailable: no decoy credentials were planted.');
      }
      await makeWorldReadable(dirs.seed);

      // step 5
      let layers = [];
      let decoded = { layers: [], finalText: run.input.command, needsHarness: false };
      if (m.decoder) {
        try {
          decoded = (await m.decoder(run.input.command)) ?? decoded;
          layers = Array.isArray(decoded.layers) ? [...decoded.layers] : [];
          for (const layer of layers) ctx.emit('unwrap.layer', { layer: sseLayer(layer) });
        } catch (err) {
          log({ level: 'warn', msg: 'run.decoder_failed', run_id: id, err: err?.message ?? String(err) });
        }
      }

      // step 6. Only the contract the rules actually use is announced: a late LLM answer after
      // the fallback was chosen is dropped.
      let contractResult = null;
      let contractDecided = false;
      const contractP = deriveContract().then((r) => {
        if (contractDecided) return;
        contractResult = r;
        contractDecided = true;
        ctx.emit('contract.ready', { contract: r.contract, contract_meta: r.meta });
      });
      contractP.catch(() => {});
      const networkP = setupNetwork();
      const wantHarness = Boolean(decoded.needsHarness && m.harness && llm);
      const harnessP = wantHarness
        ? harnessLoop(
            decoded.finalText ?? run.input.command,
            (layer) => {
              // The loop also reports notices (status gave_up / too_large ...) through onLayer;
              // only real layers (with text) join the report's layers[].
              if (typeof layer?.text === 'string') layers.push(layer);
              ctx.emit('unwrap.layer', { layer: sseLayer(layer) });
            },
            {
              priorTexts: [run.input.command, ...layers.map((l) => l.text).filter((x) => typeof x === 'string')],
              firstIndex: (decoded.finalIndex ?? layers.length) + 1,
              parent: decoded.finalIndex ?? layers.length,
            },
          )
        : Promise.resolve(null);
      harnessPending = harnessP;
      // The harness only adds visibility (8.3): it runs alongside the execution and is awaited
      // at step 11, so a slow LLM never delays what actually gets executed.
      harnessP.catch(() => {});
      await networkP;
      timing.setup_ms = state.networkMs;
      mark = now();

      // steps 7-9
      ctx.phase('exec');
      const { exec, output, events: firstEvents, coverage } = await execute(decoys);
      lap('exec_ms');
      // step 10, right away (the finally block repeats it harmlessly); the seed stays for a retry
      await teardownContainers();

      // step 11: wait (bounded) for the harness loop and the contract
      if (wantHarness) ctx.phase('unwrap');
      const harnessResult = await harnessP;
      timing.unwrap_ms = harnessResult?.ms ?? 0;
      ctx.phase('rules');
      if (!contractDecided) {
        let timer;
        await Promise.race([contractP, new Promise((resolve) => (timer = setTimeout(resolve, L.contractWaitMs)))]);
        clearTimeout(timer);
      }
      if (!contractDecided) {
        contractDecided = true;
        contractResult = {
          contract: { ...FALLBACK_CONTRACT, summary: run.input.claim },
          meta: { source: 'fallback', prompt_version: 'none' },
        };
        notes.push('The claim-to-contract step had not finished when the rules ran; the fallback contract was used.');
        ctx.emit('contract.ready', { contract: contractResult.contract, contract_meta: contractResult.meta });
      }
      mark = now();
      coverage.notes = [...(coverage.notes ?? []), ...notes];
      const { contract, meta: contractMeta } = contractResult;
      let events = firstEvents;
      const runRules = () =>
        m.rules({
          events,
          contract,
          contractMeta,
          decoys,
          seededPaths,
          layers,
          coverage,
          exec: { ...exec, ...output },
          sinkIp: state.sinkIp,
          unwrap: { stopped: decoded.stopped ?? null, harness: harnessResult ? { stoppedReason: harnessResult.stoppedReason } : null },
        });
      let ruled = m.rules ? runRules() : null;

      // AI review (8.7): a reading of the code that can only raise the verdict, and one more run
      // when the code shows it stopped because of something in this sandbox. Proof needs neither.
      let review = null;
      let reviewMeta = { source: 'skipped' };
      const attempts = [{ attempt: 1, exit_code: exec.exit_code, timed_out: exec.timed_out, duration_ms: exec.duration_ms, event_count: firstEvents.length }];
      if (llm && m.review && ruled && ruled.verdict.level !== 'MALICIOUS') {
        ctx.phase('review');
        const r = await m.review(llm, { input: run.input, layers, events, exec, decoys, sinkIp: state.sinkIp });
        review = r?.review ?? null;
        reviewMeta = r?.meta ?? { source: 'failed', reason: 'internal' };
        timing.review_ms = reviewMeta.ms ?? 0;
        stageLog('review', { source: reviewMeta.source, risk: review?.risk ?? null, retry: Boolean(r?.retry), ms: timing.review_ms });
        if (r?.retry) {
          const seqOffset = firstEvents.reduce((max, e) => Math.max(max, e.seq ?? 0), 0);
          const t = now();
          const second = await secondTry(decoys, r.retry, { seqOffset, tOffset: exec.duration_ms });
          timing.retry_ms = now() - t;
          attempts.push({
            attempt: 2,
            why: r.retry.why,
            quote: r.retry.quote,
            settings: describeKnobs(r.retry.knobs),
            ...(second
              ? {
                  exit_code: second.exec.exit_code,
                  timed_out: second.exec.timed_out,
                  duration_ms: second.exec.duration_ms,
                  event_count: second.events.length,
                  stdout_preview: previewOf(Buffer.from(second.output.stdout_preview), 4096),
                  stderr_preview: previewOf(Buffer.from(second.output.stderr_preview), 4096),
                }
              : { failed: true }),
          });
          if (second) {
            events = [...firstEvents, ...second.events];
            ruled = runRules();
          }
        }
      } else if (ruled && ruled.verdict.level !== 'MALICIOUS') {
        reviewMeta = { source: 'skipped', reason: llm ? 'module_missing' : 'llm_disabled' };
      }

      let verdict;
      let findings;
      let classifications = {};
      if (ruled) {
        verdict = ruled.verdict;
        findings = Array.isArray(ruled.findings) ? ruled.findings : [];
        classifications = ruled.classifications ?? {};
      } else {
        verdict = { level: 'SUSPICIOUS', rule_ids: [], coverage_notes: ['Rules engine unavailable: no verdict was computed for this run.', CLEAN_NOTE] };
        findings = [];
      }
      if (m.applyReview && review) ({ verdict, findings } = m.applyReview({ verdict, findings, review }));
      const extraNotes = [];
      if (reviewMeta.source !== 'llm' && verdict.level !== 'MALICIOUS') extraNotes.push(NOTE_REVIEW_NOT_RUN);
      if (attempts.length > 1 && !attempts[1].failed) extraNotes.push(NOTE_SECOND_TRY);
      if (extraNotes.length) verdict = { ...verdict, coverage_notes: [...(verdict.coverage_notes ?? []), ...extraNotes] };
      ctx.emit('verdict', { verdict, findings });
      lap('rules_ms');

      // step 12
      ctx.phase('explain');
      let explanation = null;
      let explanationMeta = { source: 'template' };
      const explanationInput = m.explainInput
        ? m.explainInput({ input: run.input, verdict, findings, layers, contract, coverage, events, decoys, review, attempts })
        : null;
      if (llm && m.explainWriter && explanationInput) {
        try {
          const r = await m.explainWriter(llm, explanationInput, { decoys });
          explanation = r?.explanation ?? null;
          explanationMeta = r?.meta ?? explanationMeta;
        } catch (err) {
          log({ level: 'warn', msg: 'run.explanation_failed', run_id: id, err: err?.message ?? String(err) });
        }
      }
      if (!explanation && m.explainTemplate && explanationInput) {
        try {
          explanation = m.explainTemplate(explanationInput);
          explanationMeta = { source: 'template' };
        } catch (err) {
          log({ level: 'warn', msg: 'run.template_failed', run_id: id, err: err?.message ?? String(err) });
        }
      }
      if (!explanation) {
        explanation = templateExplanation(verdict, findings, run.input.claim);
        explanationMeta = { source: 'template' };
      }
      ctx.emit('explanation', { explanation, explanation_meta: explanationMeta });
      lap('explain_ms');

      // step 13
      ctx.phase('upload');
      timing.upload_ms = 0;
      timing.total_ms = now() - run.created_ms;
      const modelsUsed = typeof llm?.modelsUsed === 'function' ? llm.modelsUsed() : [];
      const args = {
        run,
        layers,
        contract,
        contractMeta,
        events,
        findings,
        verdict,
        explanation,
        explanationMeta,
        decoys,
        coverage,
        output,
        timing,
        modelsUsed,
        classifications,
        review,
        reviewMeta,
        attempts,
      };
      report = m.report ? m.report(args) : fallbackReport(args);
      let where;
      try {
        ({ where } = await storage.putReport(id, report));
      } catch (err) {
        log({ level: 'error', msg: 'run.storage_failed', run_id: id, err: err?.message ?? String(err) });
        throw new RunError('storage_failed', 'The report could not be stored.', { stage: 'upload', retryable: true });
      }
      lap('upload_ms');
      if (report.timing && typeof report.timing === 'object') {
        report.timing.upload_ms = timing.upload_ms;
        report.timing.total_ms = now() - run.created_ms;
        storage.cache.set(id, report);
      }
      state.stored = true;
      stageLog('upload', { ms: timing.upload_ms, where });
      ctx.done(report);
    } finally {
      // A harness loop still running after a failure is told to stop; its container finishes on
      // its own 20 s timeout before the run dir goes away.
      harnessAbort.abort();
      if (harnessPending) await harnessPending.catch(() => {});
      await teardownSandbox().catch((err) => log({ level: 'error', msg: 'run.teardown_failed', run_id: id, err: err?.message ?? String(err) }));
      if (state.stored) {
        await rm(runDir, { recursive: true, force: true }).catch((err) =>
          log({ level: 'warn', msg: 'run.dir_rm_failed', run_id: id, err: err?.message ?? String(err) }),
        );
      } else {
        // Failed run: keep sinkhole/ (0700) for a day of debugging; the janitor removes it later.
        await chmod(dirs.sinkhole, 0o700).catch(() => {});
      }
    }
  };
}
