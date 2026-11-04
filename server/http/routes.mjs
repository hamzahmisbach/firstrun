// HTTP API (section 10.1): POST /api/runs, GET /api/runs/:id, GET /api/runs/:id/events,
// GET /api/samples, GET /healthz, GET /r/:id and the static files. createApp() wires router, rate
// limits, queue, SSE, storage and the lifecycle.
// Logging rule (section 11): never log command text, claim, or access code; only sizes and sha256.
import { createHash, timingSafeEqual } from 'node:crypto';
import { access, readdir, readFile, stat, statfs } from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';
import { LIMITS, SAMPLE_ID_RE, VERSION } from '../config.mjs';
import { RUN_ID_RE, newRunId } from '../run/ids.mjs';
import { RunError } from '../run/lifecycle.mjs';
import { RunQueue } from '../run/queue.mjs';
import { RunRegistry } from '../run/registry.mjs';
import { RateLimiter } from './ratelimit.mjs';
import { HttpError, createRouter, sendJson } from './router.mjs';
import { SseHubs } from './sse.mjs';

// ---------------------------------------------------------------------------------------------
// Input validation (section 10.1 notes)

const normalize = (s) => s.replaceAll('\0', '').replaceAll('\r\n', '\n');
const codePoints = (s) => [...s].length;

const CommandSchema = z
  .string()
  .refine((s) => s.isWellFormed(), 'must be valid UTF-8')
  .transform(normalize)
  .refine((s) => s.trim() !== '', 'must not be empty')
  .refine(
    (s) => Buffer.byteLength(s, 'utf8') <= LIMITS.input.commandMaxBytes,
    `must be at most ${LIMITS.input.commandMaxBytes} bytes`,
  );

const ClaimSchema = z
  .string()
  .refine((s) => s.isWellFormed(), 'must be valid UTF-8')
  .transform((s) => normalize(s).trim())
  .refine((s) => s !== '', 'must not be empty')
  .refine((s) => codePoints(s) <= LIMITS.input.claimMaxChars, `must be at most ${LIMITS.input.claimMaxChars} characters`);

const FreeformBody = z.strictObject({ command: CommandSchema, claim: ClaimSchema });
const SampleBody = z.strictObject({
  sample_id: z.string().regex(SAMPLE_ID_RE, `must match ${SAMPLE_ID_RE.source}`),
});

function zodMessage(error) {
  const text = error.issues.map((i) => (i.path.length ? `${i.path.join('.')}: ` : '') + i.message).join('; ');
  return text.length > 500 ? `${text.slice(0, 497)}...` : text;
}

const invalid = (message) => new HttpError(400, 'invalid_input', message);

/** "sample" when the body has sample_id, else "freeform". Throws 400 unless it is a JSON object. */
export function requestKind(body) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) throw invalid('Body must be a JSON object.');
  return Object.hasOwn(body, 'sample_id') ? 'sample' : 'freeform';
}

/** Curated run: exactly {sample_id}; command and claim come from the fixture, never the body. */
export function parseSampleRequest(body, samples) {
  if (Object.hasOwn(body, 'command') || Object.hasOwn(body, 'claim')) {
    throw invalid('Send either sample_id or command and claim, not both.');
  }
  const parsed = SampleBody.safeParse(body);
  if (!parsed.success) throw invalid(zodMessage(parsed.error));
  const sample = samples.get(parsed.data.sample_id);
  if (!sample) throw invalid('sample_id: unknown sample');
  return { command: sample.command, claim: sample.claim, sample_id: sample.id };
}

/** Free-form run: exactly {command, claim}; NUL removed, CRLF -> LF, claim trimmed. */
export function parseFreeformRequest(body) {
  const parsed = FreeformBody.safeParse(body);
  if (!parsed.success) throw invalid(zodMessage(parsed.error));
  return { command: parsed.data.command, claim: parsed.data.claim, sample_id: null };
}

/** sha256(header) vs sha256(FIRSTRUN_ACCESS_CODE) with timingSafeEqual: "ok" | "missing" | "invalid". */
export function checkAccessCode(header, expectedSha256) {
  if (typeof header !== 'string' || header === '') return 'missing';
  if (!expectedSha256) return 'invalid';
  // Node decodes header bytes as latin1; hash the original bytes.
  const got = createHash('sha256').update(Buffer.from(header, 'latin1')).digest();
  return timingSafeEqual(got, expectedSha256) ? 'ok' : 'invalid';
}

// ---------------------------------------------------------------------------------------------
// Curated samples: fixtures/samples/<id>/, read once at startup (section 10.4)

const utf8 = new TextDecoder('utf-8', { fatal: true });
const VERDICTS = new Set(['CLEAN', 'SUSPICIOUS', 'MALICIOUS']);

async function readSmallFile(file) {
  let info;
  try {
    info = await stat(file);
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
  if (!info.isFile()) return null;
  if (info.size > LIMITS.input.sampleFileMaxBytes) throw new Error(`${path.basename(file)} is too large`);
  return utf8.decode(await readFile(file));
}

async function readOptionalJson(file) {
  const text = await readSmallFile(file);
  if (text === null) return null;
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${path.basename(file)} is not valid JSON`);
  }
}

const shortText = (v, max) => (typeof v === 'string' && v.trim() !== '' ? v.trim().slice(0, max) : null);

function expectedVerdict(expected) {
  const candidates = [expected?.expected_verdict, expected?.verdict?.level, expected?.verdict, expected?.level];
  return candidates.find((v) => VERDICTS.has(v)) ?? null;
}

/**
 * command.txt and claim.txt are required and pass the same validation as free-form input.
 * Optional: meta.json {title, description}, expected.json {level | verdict | expected_verdict}.
 * A missing or empty folder means no samples.
 */
export async function loadSamples(dir, log = () => {}) {
  const samples = new Map();
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (err) {
    if (err.code !== 'ENOENT') log({ level: 'warn', msg: 'samples.unreadable', code: err.code });
    return samples;
  }
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const entry of entries) {
    if (!entry.isDirectory() || !SAMPLE_ID_RE.test(entry.name)) continue;
    const id = entry.name;
    const base = path.join(dir, id);
    try {
      const [command, claim] = await Promise.all([
        readSmallFile(path.join(base, 'command.txt')),
        readSmallFile(path.join(base, 'claim.txt')),
      ]);
      if (command === null || claim === null) {
        log({ level: 'warn', msg: 'sample.skipped', sample_id: id, reason: 'command.txt and claim.txt are required' });
        continue;
      }
      const parsed = FreeformBody.safeParse({ command, claim });
      if (!parsed.success) {
        log({ level: 'warn', msg: 'sample.skipped', sample_id: id, reason: zodMessage(parsed.error) });
        continue;
      }
      const meta = await readOptionalJson(path.join(base, 'meta.json'));
      const expected = await readOptionalJson(path.join(base, 'expected.json'));
      samples.set(id, {
        id,
        title: shortText(meta?.title, 100) ?? id,
        description: shortText(meta?.description, 500) ?? '',
        command: parsed.data.command,
        claim: parsed.data.claim,
        expected_verdict: expectedVerdict(expected),
      });
    } catch (err) {
      log({ level: 'warn', msg: 'sample.skipped', sample_id: id, reason: err.message });
    }
  }
  return samples;
}

// ---------------------------------------------------------------------------------------------
// Health probes (section 10.1 /healthz, 11 "Monitoring dasar")

const UNCHECKED = Object.freeze({
  docker: async () => 'unchecked',
  sidecar: async () => 'unchecked',
  selftest: () => 'unchecked',
  storage: async () => 'unchecked',
  diskFreeMb: async () => null,
});

/**
 * Real probes for main.mjs: `docker version` cached 30 s, sidecar socket + heartbeat file younger
 * than 60 s, the startup self-test result, storage check (HeadBucket cached 5 min, or "local"),
 * and free space under the runs dir cached 10 s.
 */
export function createHealthProbes({ config, docker, storage, now = Date.now }) {
  let dockerCache = { at: 0, value: null };
  let diskCache = { at: 0, value: null };
  const selfTest = { status: 'pending', detail: null };
  return {
    selfTest,
    async docker() {
      if (now() - dockerCache.at < LIMITS.health.dockerCacheMs && dockerCache.value) return dockerCache.value;
      let value = 'ok';
      try {
        await docker.version();
      } catch {
        value = 'failed';
      }
      dockerCache = { at: now(), value };
      return value;
    },
    async sidecar() {
      try {
        const s = await stat(config.sinkSocket);
        if (!s.isSocket()) return 'missing';
      } catch {
        return 'missing';
      }
      try {
        const h = await stat(`${config.sinkSocket}.heartbeat`);
        return now() - h.mtimeMs <= LIMITS.health.sidecarHeartbeatMaxAgeMs ? 'ok' : 'stale';
      } catch {
        return 'stale';
      }
    },
    selftest: () => selfTest.status,
    storage: () => storage.check(),
    async diskFreeMb() {
      if (now() - diskCache.at < LIMITS.health.diskCacheMs && diskCache.value !== null) return diskCache.value;
      try {
        const fs = await statfs(config.runsDir);
        diskCache = { at: now(), value: Math.floor((Number(fs.bavail) * Number(fs.bsize)) / (1024 * 1024)) };
      } catch {
        diskCache = { at: now(), value: null };
      }
      return diskCache.value;
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Application

const sha256hex = (text) => createHash('sha256').update(text, 'utf8').digest('hex');
const REPORT_PATH_RE = /^\/r\/([^/]+)$/;

/**
 * @param {ReturnType<typeof import('../config.mjs').loadConfig>} config
 * @param {object} opts
 * @param {(run: object, ctx: object) => Promise<void>} opts.lifecycle  run/lifecycle.mjs (tests inject fakes)
 * @param {(record: object) => void} [opts.log]  one JSON line per record (main.mjs)
 * @param {object} [opts.storage]  storage/index.mjs; GET /api/runs/:id falls back to it
 * @param {object} [opts.health]  createHealthProbes(); default: everything "unchecked"
 * @param {(req, res, pathname: string) => boolean} [opts.staticHandler]  http/static.mjs
 * @param {object} [opts.sse]  overrides for LIMITS.sse (tests)
 * @param {object} [opts.runs]  overrides for LIMITS.runs (tests)
 * @param {() => number} [opts.now]
 */
export async function createApp(config, opts = {}) {
  if (typeof opts.lifecycle !== 'function') throw new TypeError('createApp: opts.lifecycle is required');
  const log = opts.log ?? (() => {});
  const now = opts.now ?? Date.now;
  const startedMs = now();
  const samples = await loadSamples(config.samplesDir, log);
  const sampleList = [...samples.values()];
  const freeformEnabled = config.freeform && config.accessCodeSha256 !== null;
  const limiter = new RateLimiter({ now });
  const registry = new RunRegistry({ now, ...opts.runs });
  const hubs = new SseHubs(opts.sse);
  const lifecycle = opts.lifecycle;
  const storage = opts.storage ?? null;
  const health = { ...UNCHECKED, ...opts.health };
  const staticHandler = opts.staticHandler ?? null;
  const counters = { runs_total: 0, runs_failed: 0, rate_limited: 0, queue_rejections: 0 };
  let accepting = true;
  let acceptingReason = null; // why accepting is false (self-test failure, shutdown)

  const reportUrl = (id) => (config.publicUrl ? `${config.publicUrl}/r/${id}` : `/r/${id}`);

  function publish(run, event, fields) {
    const hub = hubs.get(run.run_id);
    if (hub) run.last_n = hub.publish(event, fields);
  }

  function completeRun(run, report) {
    if (run.ended_ms !== null) return;
    Object.assign(run, { status: 'done', phase: null, report, ended_ms: now() });
    const totalMs = run.ended_ms - run.created_ms;
    publish(run, 'run.done', {
      report_url: reportUrl(run.run_id),
      verdict_level: report?.verdict?.level ?? null,
      total_ms: totalMs,
    });
    log({ msg: 'run.done', run_id: run.run_id, verdict: report?.verdict?.level ?? null, ms: totalMs });
  }

  function failRun(run, err) {
    if (run.ended_ms !== null) return;
    const known = err instanceof RunError;
    const error = {
      code: known ? err.code : 'internal',
      message: known ? err.message : 'Internal error.',
      stage: (known && err.stage) || run.phase || 'queue',
      retryable: known ? err.retryable : true,
    };
    Object.assign(run, { status: 'error', phase: null, error, ended_ms: now() });
    counters.runs_failed += 1;
    publish(run, 'run.error', error);
    log({ level: 'warn', msg: 'run.error', run_id: run.run_id, code: error.code, stage: error.stage, ms: run.ended_ms - run.created_ms });
  }

  async function execute(run) {
    run.status = 'running';
    run.phase = 'setup';
    const live = () => run.ended_ms === null;
    const ctx = {
      reportUrl: reportUrl(run.run_id),
      emit: (event, fields) => live() && publish(run, event, fields),
      phase: (name) => live() && (run.phase = name),
      done: (report) => completeRun(run, report),
    };
    try {
      await lifecycle(run, ctx);
      if (live()) failRun(run, new RunError('internal', 'Run ended without a result.', { retryable: true }));
    } catch (err) {
      if (!(err instanceof RunError)) {
        log({ level: 'error', msg: 'run.crash', run_id: run.run_id, stage: run.phase, err: err?.stack ?? String(err) });
      }
      failRun(run, err);
    }
  }

  const queue = new RunQueue({
    execute,
    emit: publish,
    onCrash: (run, err) => failRun(run, err),
  });

  function createRun(input, ip) {
    let runId = newRunId();
    while (registry.has(runId)) runId = newRunId(); // 128 random bits: never loops in practice
    const created = now();
    const run = {
      run_id: runId,
      created_at: new Date(created).toISOString(),
      created_ms: created,
      ip,
      sample_id: input.sample_id,
      input: input.sample_id
        ? { command: input.command, claim: input.claim, sample_id: input.sample_id }
        : { command: input.command, claim: input.claim },
      command_sha256: sha256hex(input.command),
      command_bytes: Buffer.byteLength(input.command, 'utf8'),
      claim_chars: codePoints(input.claim),
      status: 'queued',
      phase: null,
      last_n: 0,
      report: null,
      error: null,
      ended_ms: null,
    };
    registry.add(run);
    hubs.create(runId);
    counters.runs_total += 1;
    log({
      msg: 'run.accepted',
      run_id: runId,
      ip,
      sample_id: input.sample_id,
      command_sha256: run.command_sha256,
      command_bytes: run.command_bytes,
      claim_chars: run.claim_chars,
    });
    return run;
  }

  /** Env flag, or the kill-switch file (checked on every POST, no restart needed). */
  async function killSwitchOn() {
    if (config.killSwitch) return true;
    try {
      await access(config.killSwitchFile);
      return true;
    } catch (err) {
      if (err.code === 'ENOENT' || err.code === 'ENOTDIR') return false;
      log({ level: 'warn', msg: 'kill_switch.unreadable', code: err.code });
      return true; // fail closed
    }
  }

  function tooMany(code, message, retryAfterS) {
    counters.rate_limited += 1;
    return new HttpError(429, code, message, { retryAfterS });
  }

  function limit(policy, ip) {
    const r = limiter.take(policy, ip);
    if (!r.ok) throw tooMany('rate_limited', 'Too many requests; slow down.', r.retryAfterS);
  }

  const notFound = () => new HttpError(404, 'not_found', 'Not found.');

  /** Disk guard (10.4): below 2 GB free under the runs dir, new runs are refused. */
  async function diskLow() {
    const freeMb = await health.diskFreeMb();
    return freeMb !== null && freeMb * 1024 * 1024 < LIMITS.disk.minFreeBytes;
  }

  // POST /api/runs ------------------------------------------------------------------------------
  async function postRun(ctx) {
    const { ip } = ctx;
    const killed = await killSwitchOn();
    const low = await diskLow();
    // No await below this line: the checks and the enqueue happen atomically.
    if (killed || !accepting || low) {
      throw new HttpError(503, 'runs_disabled', 'New runs are disabled right now; try again later.', {
        retryAfterS: LIMITS.retryAfterS.runsDisabled,
      });
    }
    const blockedS = limiter.blockedFor(ip);
    if (blockedS > 0) throw tooMany('rate_limited', 'Too many wrong access codes; try again later.', blockedS);
    const rl = limiter.take('postRun', ip);
    if (!rl.ok) throw tooMany('rate_limited', 'Too many runs from this address; try again later.', rl.retryAfterS);

    let input;
    if (requestKind(ctx.body) === 'sample') {
      input = parseSampleRequest(ctx.body, samples);
    } else {
      if (!freeformEnabled) {
        throw new HttpError(403, 'freeform_disabled', 'Free-form commands are disabled on this instance; pick a sample.');
      }
      const code = checkAccessCode(ctx.req.headers['x-firstrun-access-code'], config.accessCodeSha256);
      if (code === 'missing') {
        throw new HttpError(401, 'access_code_required', 'Free-form commands need the x-firstrun-access-code header.');
      }
      if (code === 'invalid') {
        const { blocked } = limiter.wrongCode(ip);
        log({ level: 'warn', msg: 'access_code.invalid', ip, blocked });
        throw new HttpError(403, 'access_code_invalid', 'The access code is not valid.');
      }
      input = parseFreeformRequest(ctx.body);
    }

    if (queue.isFull()) {
      counters.queue_rejections += 1;
      throw new HttpError(503, 'queue_full', 'The queue is full; try again shortly.', {
        retryAfterS: LIMITS.retryAfterS.queueFull,
      });
    }
    const global = limiter.takeGlobalRun();
    if (!global.ok) throw tooMany('rate_limited', 'This instance reached its hourly run limit.', global.retryAfterS);

    const run = createRun(input, ip);
    const position = queue.enqueue(run);
    ctx.json(202, {
      run_id: run.run_id,
      status: 'queued',
      position,
      events_url: `/api/runs/${run.run_id}/events`,
      report_url: reportUrl(run.run_id),
    });
  }

  // GET /api/runs/:id ---------------------------------------------------------------------------
  const IMMUTABLE = { 'Cache-Control': 'public, max-age=86400, immutable' };

  async function getRun(ctx) {
    limit('getRun', ctx.ip);
    const run = registry.get(ctx.params.id);
    if (!run) {
      // Not in memory any more (or never ran here): cache -> spool -> Object Storage (10.4).
      if (!storage) throw notFound();
      let report;
      try {
        report = await storage.getReport(ctx.params.id);
      } catch (err) {
        log({ level: 'warn', msg: 'storage.get_failed', run_id: ctx.params.id, err: err?.message ?? String(err) });
        throw new HttpError(503, 'storage_unavailable', 'The report store is unavailable; try again shortly.', {
          retryAfterS: LIMITS.retryAfterS.storageUnavailable,
        });
      }
      if (!report) throw notFound();
      ctx.json(200, { status: 'done', run_id: ctx.params.id, created_at: report.created_at ?? null, report }, IMMUTABLE);
      return;
    }
    const body = { status: run.status, run_id: run.run_id, created_at: run.created_at };
    if (run.status === 'queued') body.position = queue.position(run.run_id);
    if (run.status === 'running') body.phase = run.phase;
    body.last_n = run.last_n;
    if (run.status === 'done') body.report = run.report;
    if (run.status === 'error') body.error = run.error;
    ctx.json(200, body, run.status === 'done' ? IMMUTABLE : {});
  }

  // GET /api/runs/:id/events --------------------------------------------------------------------
  function lastSeenId(ctx) {
    const header = ctx.req.headers['last-event-id'];
    if (typeof header === 'string' && /^\d{1,15}$/.test(header.trim())) return Number(header.trim());
    const after = ctx.query.get('after');
    if (after === null) return 0;
    if (!/^\d{1,15}$/.test(after)) throw invalid('after must be a non-negative integer.');
    return Number(after);
  }

  function getEvents(ctx) {
    limit('sseOpen', ctx.ip);
    const run = registry.get(ctx.params.id);
    if (!run) throw notFound();
    const after = lastSeenId(ctx); // Last-Event-ID wins over ?after= (browser reconnects send both)
    const hub = hubs.get(run.run_id);
    // Finished and nothing left to send (buffer dropped, or client already has the last message):
    // 204 makes EventSource stop reconnecting.
    if (!hub || (hub.ended && after >= hub.lastId)) {
      ctx.res.writeHead(204, { 'Cache-Control': 'no-store' });
      ctx.res.end();
      return;
    }
    const lease = limiter.openStream(ctx.ip);
    if (!lease.ok) {
      const scope = lease.reason === 'ip' ? 'from this address' : 'on this instance';
      throw tooMany('too_many_streams', `Too many open event streams ${scope}.`, LIMITS.rate.tooManyStreamsRetryAfterS);
    }
    hub.attach(ctx.res, after, lease.release);
  }

  // GET /api/samples, GET /healthz ----------------------------------------------------------------
  function getSamples(ctx) {
    limit('getOther', ctx.ip);
    ctx.json(200, { samples: sampleList }, { 'Cache-Control': 'public, max-age=300' });
  }

  /** 503 when docker, the sidecar, or the startup self-test failed (fail closed, section 11). */
  async function healthz(ctx) {
    limit('getOther', ctx.ip);
    const [killed, dockerStatus, sidecar, storageStatus, diskFreeMb] = await Promise.all([
      killSwitchOn(),
      health.docker(),
      health.sidecar(),
      health.storage(),
      health.diskFreeMb(),
    ]);
    const selftest = health.selftest();
    const broken = (v) => !['ok', 'unchecked', 'local', 'pending'].includes(v);
    const ok = !broken(dockerStatus) && !broken(sidecar) && !broken(selftest);
    const low = diskFreeMb !== null && diskFreeMb * 1024 * 1024 < LIMITS.disk.minFreeBytes;
    const body = {
      ok,
      version: VERSION,
      uptime_s: Math.floor((now() - startedMs) / 1000),
      accepting_runs: ok && accepting && !killed && !low && selftest !== 'pending',
      active_runs: queue.active,
      queued: queue.waiting,
      checks: {
        docker: dockerStatus,
        sidecar,
        sinkhole_selftest: selftest,
        storage: low ? 'degraded' : storageStatus,
        disk_free_mb: diskFreeMb,
      },
      counters: { ...counters },
    };
    if (acceptingReason) body.reason = acceptingReason;
    ctx.json(ok ? 200 : 503, body);
  }

  // GET /r/:id and static files ----------------------------------------------------------------
  function serveReportShell(req, res, id) {
    res.setHeader('X-Robots-Tag', 'noindex');
    if (staticHandler && staticHandler(req, res, `/r/${id}`)) return;
    // Placeholder until web/report.html exists: the API link still works.
    const html = `<!doctype html><meta charset="utf-8"><title>FirstRun report</title><p>Report <code>${id}</code>: <a href="/api/runs/${id}">/api/runs/${id}</a></p>`;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff' });
    res.end(html);
  }

  const router = createRouter({ log });
  router.param('id', RUN_ID_RE);
  router.route('POST', '/api/runs', postRun, { json: true });
  router.route('GET', '/api/runs/:id', getRun);
  router.route('GET', '/api/runs/:id/events', getEvents);
  router.route('GET', '/api/samples', getSamples);
  router.route('GET', '/healthz', healthz);

  /** Static files and /r/:id go first (GET/HEAD, outside /api); everything else is the router. */
  function handle(req, res) {
    const url = req.url ?? '/';
    const q = url.indexOf('?');
    const pathname = q === -1 ? url : url.slice(0, q);
    if ((req.method === 'GET' || req.method === 'HEAD') && !pathname.startsWith('/api/') && pathname !== '/healthz') {
      const m = REPORT_PATH_RE.exec(pathname);
      if (m) {
        if (!RUN_ID_RE.test(m[1])) {
          sendJson(res, 404, { error: 'not_found', message: 'Not found.' });
          return;
        }
        serveReportShell(req, res, m[1]);
        return;
      }
      if (staticHandler && staticHandler(req, res, pathname)) return;
    }
    return router.handle(req, res);
  }

  /** Startup self-test outcome (main.mjs): a failure keeps accepting_runs false, fail closed. */
  function setAccepting(value, reason = null) {
    accepting = Boolean(value);
    acceptingReason = accepting ? null : reason;
  }

  /** Stop accepting runs, fail the waiting ones, give active ones graceMs, then end all streams. */
  async function shutdown({ graceMs = LIMITS.shutdownGraceMs } = {}) {
    accepting = false;
    acceptingReason = 'shutting down';
    for (const run of queue.close()) {
      failRun(run, new RunError('internal', 'The server is restarting; please retry.', { stage: 'queue', retryable: true }));
    }
    let timer;
    await Promise.race([queue.idle(), new Promise((resolve) => (timer = setTimeout(resolve, graceMs)))]);
    clearTimeout(timer);
    hubs.closeAll();
    limiter.close();
    registry.close();
  }

  return {
    handle,
    shutdown,
    setAccepting,
    queue,
    registry,
    hubs,
    limiter,
    samples,
    counters,
    freeformEnabled,
    /** For the janitor: a run that is queued or running must not be swept. */
    isActive: (runId) => {
      const run = registry.get(runId);
      return Boolean(run && run.ended_ms === null);
    },
    get accepting() {
      return accepting;
    },
  };
}
