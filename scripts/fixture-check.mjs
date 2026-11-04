#!/usr/bin/env node
// Demo regression (docs/ARCHITECTURE.md 14.2 day 3, 15.2): submit every curated sample to a running
// FirstRun instance, follow its SSE stream to run.done, fetch the report and compare it with the
// sample's expected.json. Any difference, run.error or timeout makes the exit code 1.
//
//   node scripts/fixture-check.mjs [BASE_URL] [--base URL] [--repeat N] [--only a,b] [--timeout S]
//                                  [--samples DIR] [--verbose]
//
// expected.json: { verdict, rule_ids: {require[], forbid[], exact[]?}, events: {require[], forbid[]},
//                  alerts_min, layers_min, exit_code }. An event pattern matches when every listed
//                  field equals the event's field; a string "re:<regex>" tests the field as text.
// No access code is needed: samples are open. 429/503 answers are retried after Retry-After.
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const USAGE = 'usage: node scripts/fixture-check.mjs [BASE_URL] [--base URL] [--repeat N] [--only a,b] [--timeout S] [--samples DIR] [--verbose]';
const DEFAULT_SAMPLES = fileURLToPath(new URL('../fixtures/samples/', import.meta.url));
const END_EVENTS = new Set(['run.done', 'run.error']);

function parseArgs(argv) {
  const opts = { base: 'http://127.0.0.1:3000', repeat: 1, only: null, samples: DEFAULT_SAMPLES, timeoutS: 240, verbose: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const value = () => {
      if (i + 1 >= argv.length) throw new Error(`${arg} needs a value`);
      i += 1;
      return argv[i];
    };
    if (arg === '--base') opts.base = value();
    else if (arg === '--repeat') opts.repeat = Number(value());
    else if (arg === '--only') opts.only = new Set(value().split(',').map((s) => s.trim()).filter(Boolean));
    else if (arg === '--samples') opts.samples = path.resolve(value());
    else if (arg === '--timeout') opts.timeoutS = Number(value());
    else if (arg === '--verbose' || arg === '-v') opts.verbose = true;
    else if (arg === '--help' || arg === '-h') {
      console.log(USAGE);
      process.exit(0);
    } else if (/^https?:\/\//.test(arg)) opts.base = arg;
    else throw new Error(`unknown argument ${arg}\n${USAGE}`);
  }
  opts.base = opts.base.replace(/\/+$/, '');
  if (!Number.isInteger(opts.repeat) || opts.repeat < 1) throw new Error('--repeat must be a positive integer');
  if (!(opts.timeoutS > 0)) throw new Error('--timeout must be a positive number of seconds');
  return opts;
}

async function loadSamples(dir, only) {
  const samples = [];
  for (const entry of (await readdir(dir, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    if (!entry.isDirectory()) continue;
    if (only && !only.has(entry.name)) continue;
    let expected;
    try {
      expected = JSON.parse(await readFile(path.join(dir, entry.name, 'expected.json'), 'utf8'));
    } catch (err) {
      if (err.code === 'ENOENT') {
        console.log(`skip ${entry.name}: no expected.json`);
        continue;
      }
      throw new Error(`${entry.name}/expected.json: ${err.message}`);
    }
    samples.push({ id: entry.name, expected });
  }
  if (only) for (const id of only) if (!samples.some((s) => s.id === id)) throw new Error(`unknown sample ${id}`);
  return samples;
}

// ---------------------------------------------------------------------------------------------
// HTTP

async function submit(base, sampleId, log) {
  const deadline = Date.now() + 20 * 60 * 1000;
  for (;;) {
    const res = await fetch(`${base}/api/runs`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sample_id: sampleId }),
    });
    const body = await res.json().catch(() => ({}));
    if (res.status === 202) return body;
    const retryable = res.status === 429 || (res.status === 503 && body.error === 'queue_full');
    if (retryable && Date.now() < deadline) {
      const waitS = Math.min(Math.max(Number(res.headers.get('retry-after')) || 30, 1), 600);
      log(`  ${res.status} ${body.error ?? ''}: waiting ${waitS} s before retrying`);
      await sleep(waitS * 1000);
      continue;
    }
    throw new Error(`POST /api/runs -> ${res.status} ${body.error ?? ''} ${body.message ?? ''}`.trim());
  }
}

function parseSseBlock(block) {
  let event = 'message';
  const data = [];
  for (const line of block.split('\n')) {
    if (line.startsWith(':') || line === '') continue;
    const sep = line.indexOf(':');
    const field = sep < 0 ? line : line.slice(0, sep);
    let value = sep < 0 ? '' : line.slice(sep + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (field === 'event') event = value;
    else if (field === 'data') data.push(value);
  }
  if (data.length === 0) return null;
  let parsed = null;
  try {
    parsed = JSON.parse(data.join('\n'));
  } catch {
    parsed = null;
  }
  return { event, data: parsed };
}

/** Follow the SSE stream until run.done / run.error; returns per-event counts and the end event. */
async function follow(base, runId, timeoutMs) {
  const counts = {};
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${base}/api/runs/${runId}/events`, {
      headers: { accept: 'text/event-stream' },
      signal: controller.signal,
    });
    if (res.status === 204) return { counts, end: null };
    if (!res.ok) throw new Error(`GET /api/runs/${runId}/events -> ${res.status}`);
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let idx;
      while ((idx = buffer.indexOf('\n\n')) >= 0) {
        const msg = parseSseBlock(buffer.slice(0, idx));
        buffer = buffer.slice(idx + 2);
        if (!msg) continue;
        counts[msg.event] = (counts[msg.event] ?? 0) + 1;
        if (END_EVENTS.has(msg.event)) {
          controller.abort();
          return { counts, end: msg };
        }
      }
    }
    return { counts, end: null };
  } catch (err) {
    if (err.name === 'AbortError' || err.cause?.name === 'AbortError') return { counts, end: null, timedOut: true };
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

/** GET /api/runs/:id until status is done or error (also the fallback when the stream was gone). */
async function fetchFinal(base, runId, deadlineMs) {
  for (;;) {
    const res = await fetch(`${base}/api/runs/${runId}`);
    if (res.status === 429) {
      await sleep(2000);
      continue;
    }
    if (!res.ok) throw new Error(`GET /api/runs/${runId} -> ${res.status}`);
    const body = await res.json();
    if (body.status === 'done' || body.status === 'error') return body;
    if (Date.now() > deadlineMs) throw new Error(`run ${runId} still ${body.status} (${body.phase ?? ''}) after the timeout`);
    await sleep(2000);
  }
}

// ---------------------------------------------------------------------------------------------
// Comparison

function matchValue(pattern, actual) {
  if (typeof pattern === 'string' && pattern.startsWith('re:')) {
    return new RegExp(pattern.slice(3)).test(actual === undefined || actual === null ? '' : String(actual));
  }
  return pattern === actual;
}

const matchEvent = (pattern, event) => Object.entries(pattern).every(([key, value]) => matchValue(value, event?.[key]));
const show = (obj) => JSON.stringify(obj);

/** Returns a list of problems; empty means the report matches expected.json. */
function compare(expected, report, sse) {
  const problems = [];
  if (!report || typeof report !== 'object') return ['no report in GET /api/runs/:id'];
  if (report.stub === true) problems.push('report is from the day-1 stub lifecycle: nothing was executed');

  const level = report.verdict?.level;
  if (expected.verdict && level !== expected.verdict) problems.push(`verdict: expected ${expected.verdict}, got ${level}`);

  const ruleIds = Array.isArray(report.verdict?.rule_ids) ? report.verdict.rule_ids : [];
  const findingRules = new Set((report.findings ?? []).map((f) => f.rule_id));
  const rules = expected.rule_ids ?? {};
  for (const id of rules.require ?? []) if (!ruleIds.includes(id)) problems.push(`rule_ids: missing ${id} (got ${show(ruleIds)})`);
  for (const id of rules.forbid ?? []) if (ruleIds.includes(id) || findingRules.has(id)) problems.push(`rule_ids: forbidden ${id} is present`);
  if (rules.exact && show([...rules.exact].sort()) !== show([...ruleIds].sort())) {
    problems.push(`rule_ids: expected exactly ${show(rules.exact)}, got ${show(ruleIds)}`);
  }

  const events = Array.isArray(report.events) ? report.events : [];
  for (const pattern of expected.events?.require ?? []) {
    if (!events.some((e) => matchEvent(pattern, e))) problems.push(`events: no event matches ${show(pattern)}`);
  }
  for (const pattern of expected.events?.forbid ?? []) {
    const hit = events.find((e) => matchEvent(pattern, e));
    if (hit) problems.push(`events: forbidden ${show(pattern)} matched seq ${hit.seq}`);
  }

  if (expected.alerts_min !== undefined) {
    const hits = events.filter((e) => e.kind === 'canary.hit').length;
    const alerts = Math.max(sse.alert ?? 0, hits);
    if (alerts < expected.alerts_min) problems.push(`alerts: expected >= ${expected.alerts_min}, got ${alerts}`);
  }
  if (expected.layers_min !== undefined) {
    const layers = Array.isArray(report.layers) ? report.layers.length : 0;
    if (layers < expected.layers_min) problems.push(`layers: expected >= ${expected.layers_min}, got ${layers}`);
  }
  if (expected.exit_code !== undefined) {
    const finished = events.find((e) => e.kind === 'exec.finished');
    const exitCode = finished?.exit_code ?? report.exit_code;
    if (exitCode !== undefined && exitCode !== expected.exit_code) problems.push(`exit_code: expected ${expected.exit_code}, got ${exitCode}`);
    if (finished?.timed_out === true || report.coverage?.timed_out === true) problems.push('the command timed out');
  }
  return problems;
}

// ---------------------------------------------------------------------------------------------

async function checkOnce(opts, sample, log) {
  const started = Date.now();
  const accepted = await submit(opts.base, sample.id, log);
  const runId = accepted.run_id;
  if (typeof runId !== 'string') throw new Error(`202 without run_id: ${show(accepted)}`);
  log(`  run ${runId} queued at position ${accepted.position}`);
  const timeoutMs = opts.timeoutS * 1000;
  const { counts, end, timedOut } = await follow(opts.base, runId, timeoutMs);
  if (timedOut) throw new Error(`run ${runId}: no run.done within ${opts.timeoutS} s`);
  const final = await fetchFinal(opts.base, runId, started + timeoutMs);
  const seconds = ((Date.now() - started) / 1000).toFixed(1);
  if (final.status === 'error') {
    const e = final.error ?? end?.data ?? {};
    return { runId, seconds, problems: [`run.error ${e.code ?? '?'} at ${e.stage ?? '?'}: ${e.message ?? ''}`] };
  }
  const problems = compare(sample.expected, final.report, counts);
  log(`  sse: ${show(counts)}`);
  return { runId, seconds, problems, level: final.report?.verdict?.level };
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const log = opts.verbose ? (line) => console.log(line) : () => {};
  const samples = await loadSamples(opts.samples, opts.only);
  if (samples.length === 0) throw new Error(`no samples with expected.json under ${opts.samples}`);
  console.log(`fixture-check: ${samples.length} sample(s) x ${opts.repeat} against ${opts.base}`);

  const tally = Object.fromEntries(samples.map((s) => [s.id, { ok: 0, fail: 0 }]));
  let failures = 0;
  for (let round = 1; round <= opts.repeat; round += 1) {
    for (const sample of samples) {
      const label = opts.repeat > 1 ? `${sample.id} #${round}` : sample.id;
      let result;
      try {
        result = await checkOnce(opts, sample, log);
      } catch (err) {
        result = { runId: '-', seconds: '-', problems: [err.message] };
      }
      if (result.problems.length === 0) {
        tally[sample.id].ok += 1;
        console.log(`ok   ${label} ${result.level} ${result.runId} ${result.seconds}s`);
      } else {
        tally[sample.id].fail += 1;
        failures += 1;
        console.log(`FAIL ${label} ${result.level ?? ''} ${result.runId} ${result.seconds}s`);
        for (const p of result.problems) console.log(`     - ${p}`);
      }
    }
  }
  const summary = samples.map((s) => `${s.id} ${tally[s.id].ok}/${tally[s.id].ok + tally[s.id].fail}`).join(', ');
  console.log(`${failures === 0 ? 'PASS' : 'FAIL'}: ${summary}`);
  process.exitCode = failures === 0 ? 0 : 1;
}

main().catch((err) => {
  console.error(`fixture-check: ${err.message}`);
  process.exitCode = 1;
});
