// HTTP API (section 10.1): POST /api/runs, GET /api/runs/:id, GET /api/runs/:id/events,
// GET /api/samples, GET /healthz. createApp() wires router, rate limits, queue, SSE and lifecycle.
// Logging rule (section 11): never log command text, claim, or access code; only sizes and sha256.
import { createHash, timingSafeEqual } from 'node:crypto';
import { access, readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';
import { LIMITS, SAMPLE_ID_RE, VERSION } from '../config.mjs';
import { RUN_ID_RE, newRunId } from '../run/ids.mjs';
import { RunError, createStubLifecycle } from '../run/lifecycle.mjs';
import { RunQueue } from '../run/queue.mjs';
import { RunRegistry } from '../run/registry.mjs';
import { RateLimiter } from './ratelimit.mjs';
import { HttpError, createRouter } from './router.mjs';
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
// Application

const sha256hex = (text) => createHash('sha256').update(text, 'utf8').digest('hex');

/**
 * @param {ReturnType<typeof import('../config.mjs').loadConfig>} config
 * @param {object} [opts]
 * @param {(record: object) => void} [opts.log]  one JSON line per record (main.mjs)
 * @param {(run: object, ctx: object) => Promise<void>} [opts.lifecycle]  default: day-1 stub
 * @param {{stepMs?: number}} [opts.stub]
 * @param {object} [opts.sse]  overrides for LIMITS.sse (tests)
 * @param {object} [opts.runs]  overrides for LIMITS.runs (tests)
 * @param {() => number} [opts.now]
 */
export async function createApp(config, opts = {}) {
  const log = opts.log ?? (() => {});
  const now = opts.now ?? Date.now;
  const startedMs = now();
  const samples = await loadSamples(config.samplesDir, log);
  const sampleList = [...samples.values()];
  const freeformEnabled = config.freeform && config.accessCodeSha256 !== null;
  const limiter = new RateLimiter({ now });
  const registry = new RunRegistry({ now, ...opts.runs });
  const hubs = new SseHubs(opts.sse);
  const lifecycle = opts.lifecycle ?? createStubLifecycle(opts.stub);
  const counters = { runs_total: 0, runs_failed: 0, rate_limited: 0, queue_rejections: 0 };
  let accepting = true;

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

  // POST /api/runs ------------------------------------------------------------------------------
  async function postRun(ctx) {
    const { ip } = ctx;
    const killed = await killSwitchOn();
    // No await below this line: the checks and the enqueue happen atomically.
    if (killed || !accepting) {
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
  function getRun(ctx) {
    limit('getRun', ctx.ip);
    const run = registry.get(ctx.params.id);
    if (!run) throw notFound();
    const body = { status: run.status, run_id: run.run_id, created_at: run.created_at };
    if (run.status === 'queued') body.position = queue.position(run.run_id);
    if (run.status === 'running') body.phase = run.phase;
    body.last_n = run.last_n;
    if (run.status === 'done') body.report = run.report;
    if (run.status === 'error') body.error = run.error;
    const cache = run.status === 'done' ? { 'Cache-Control': 'public, max-age=86400, immutable' } : {};
    ctx.json(200, body, cache);
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

  async function healthz(ctx) {
    limit('getOther', ctx.ip);
    const killed = await killSwitchOn();
    ctx.json(200, {
      ok: true,
      version: VERSION,
      uptime_s: Math.floor((now() - startedMs) / 1000),
      accepting_runs: accepting && !killed,
      active_runs: queue.active,
      queued: queue.waiting,
      // TODO(day 2+): real checks (docker version cached 30 s, sidecar socket + heartbeat,
      // sinkhole self-test at start, HeadBucket cached 5 min, statfs on /srv); 503 when one fails.
      checks: {
        docker: 'unchecked',
        sidecar: 'unchecked',
        sinkhole_selftest: 'unchecked',
        storage: 'unchecked',
        disk_free_mb: null,
      },
      counters: { ...counters },
    });
  }

  const router = createRouter({ log });
  router.param('id', RUN_ID_RE);
  router.route('POST', '/api/runs', postRun, { json: true });
  router.route('GET', '/api/runs/:id', getRun);
  router.route('GET', '/api/runs/:id/events', getEvents);
  router.route('GET', '/api/samples', getSamples);
  router.route('GET', '/healthz', healthz);

  /** Stop accepting runs, fail the waiting ones, give active ones graceMs, then end all streams. */
  async function shutdown({ graceMs = LIMITS.shutdownGraceMs } = {}) {
    accepting = false;
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
    handle: router.handle,
    shutdown,
    queue,
    registry,
    hubs,
    limiter,
    samples,
    counters,
    freeformEnabled,
    get accepting() {
      return accepting;
    },
  };
}
