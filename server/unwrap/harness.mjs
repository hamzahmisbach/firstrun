// Harness loop, Pattern A (docs/ARCHITECTURE.md 8.3). When the decoder stops at a layer that still
// decodes and executes something at runtime, the LLM writes a harness that turns the execution
// sink into print; the engine runs it in a network-less unwrap container (injected `runHarness`)
// and the stdout becomes the next layer, which goes back through the deterministic decoder.
// The harness output is untrusted text. Nothing here influences the verdict: the execute phase
// always runs the original command, so this loop is for visibility only.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { LIMITS } from '../config.mjs';
import { LlmError, UNTRUSTED_PREAMBLE, createDelimiter } from '../llm/client.mjs';
import { Harness } from '../llm/schemas.mjs';
import { DECODER_LIMITS, decodeLayers, guessLanguage, scanMarkers } from './decoder.mjs';

const SYSTEM_PROMPT = readFileSync(new URL('../llm/prompts/harness.md', import.meta.url), 'utf8');

export const LAYER_TEXT_MAX_BYTES = 24 * 1024;
export const HARNESS_MAX_BYTES = 32 * 1024;
const STDERR_MAX = 2 * 1024;
const STDOUT_MAX = 1 * 1024;
const VIOLATIONS_MAX = 5;
const MIN_LLM_MS = 2000; // budget left below which no further LLM call is started
const MIN_CONTAINER_MS = 3000; // same for an unwrap container (<= 20 s inside, about 1 s overhead)

/** Fixed map language -> [interpreter, extension]; the only route from an LLM string to `launch` (5.2). */
export const INTERPRETERS = Object.freeze({
  bash: ['bash', 'sh'],
  pwsh: ['pwsh', 'ps1'],
  python3: ['python3', 'py'],
  node: ['node', 'js'],
});

/** Languages the sandbox image can run: it was built without pwsh (brief, 2026-11-04). */
export const DEFAULT_LANGUAGES = Object.freeze(['bash', 'python3', 'node']);

/** Helpers a harness may exec besides its own interpreter (8.3 dynamic check 1). */
export const HARNESS_HELPERS = new Set([
  'base64', 'gzip', 'gunzip', 'zcat', 'xz', 'bzip2', 'xxd', 'openssl', 'printf', 'echo', 'cat', 'tr', 'cut',
  'head', 'tail', 'sed', 'awk', 'iconv', 'od', 'rev', 'sort', 'uniq', 'wc', 'tee',
]);
const INTERPRETER_BINARIES = { bash: ['bash', 'sh', 'dash'], pwsh: ['pwsh'], python3: ['python3', 'python3.12', 'python3.13', 'python'], node: ['node', 'nodejs'] };
const LAUNCH_BINARIES = new Set(['launch', 'entry.sh', 'timeout']);
const WRITE_OK_PREFIXES = ['/tmp/', '/var/tmp/', '/home/dev/', '/dev/null', '/dev/std'];

const DENY = [
  ['curl', /\bcurl\b/i],
  ['wget', /\bwget\b/i],
  ['nc', /(?:^|[\s;|&(])nc\s/m],
  ['/dev/tcp', /\/dev\/tcp/],
  ['/dev/udp', /\/dev\/udp/],
  ['ssh', /\bssh\b/],
  ['socket', /\bsocket\b/i],
  ['http.', /\bhttp\./i],
  ['fetch(', /\bfetch\s*\(/],
  ['Invoke-WebRequest', /Invoke-WebRequest/i],
  ['iwr', /\biwr\b/i],
  ['irm', /\birm\b/i],
  ['WebClient', /WebClient/i],
  ['urllib', /\burllib\b/],
  ['requests', /\brequests\b/],
  ['Net.Sockets', /Net\.Sockets/i],
  ['/seed', /\/seed\b/],
  ['/opt/firstrun', /\/opt\/firstrun/],
  ['/proc/1', /\/proc\/1\b/],
];

function sha256(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function clip(text, maxBytes) {
  const buf = Buffer.from(String(text ?? ''), 'utf8');
  return buf.length <= maxBytes ? String(text ?? '') : buf.subarray(0, maxBytes).toString('utf8').replace(/�+$/, '');
}

/**
 * Static checks before anything runs (8.3). The layer text itself is removed from the harness
 * before the deny-list scan, since the harness must embed it unchanged.
 * @returns {string[]} violations; empty = accepted
 */
export function staticCheck(harness, { languageGuess, languages = DEFAULT_LANGUAGES, layerText = '' } = {}) {
  const violations = [];
  if (!languages.includes(harness.language)) violations.push(`language_unavailable:${harness.language}`);
  else if (languages.includes(languageGuess) && harness.language !== languageGuess && harness.notes.trim().length < 10) {
    violations.push(`language_mismatch:${harness.language}`);
  }
  if (Buffer.byteLength(harness.harness) > HARNESS_MAX_BYTES) violations.push('too_large');
  const own = layerText ? harness.harness.split(layerText).join('') : harness.harness;
  for (const [name, re] of DENY) if (re.test(own)) violations.push(`deny:${name}`);
  return violations;
}

/**
 * Dynamic checks over the normalized trace events (7.4) of the unwrap container, for the engine
 * to pass back as `violations` in the runHarness result. One hit of any kind discards the stdout.
 * @returns {string[]} subset of ["exec", "network", "write"]
 */
export function harnessViolations(events, { language = 'bash' } = {}) {
  const allowed = new Set([...HARNESS_HELPERS, ...LAUNCH_BINARIES, ...(INTERPRETER_BINARIES[language] ?? [])]);
  const found = new Set();
  for (const ev of events ?? []) {
    switch (ev?.kind) {
      case 'proc.exec': {
        const exe = String(ev.exe ?? '');
        const name = exe.split('/').pop();
        if (exe.startsWith('/opt/firstrun/shims/') || !allowed.has(name)) found.add('exec');
        break;
      }
      case 'shim.call':
        found.add('exec');
        break;
      case 'net.connect':
      case 'dns.query':
      case 'udp.datagram':
      case 'tcp.connect':
      case 'http.request':
      case 'tls.clienthello':
      case 'tls.failed':
        found.add('network');
        break;
      case 'file.open': {
        if (ev.access !== 'write' && ev.access !== 'create') break;
        const p = String(ev.path ?? '');
        if (!WRITE_OK_PREFIXES.some((prefix) => p.startsWith(prefix))) found.add('write');
        break;
      }
      default:
        break;
    }
  }
  return ['exec', 'network', 'write'].filter((v) => found.has(v));
}

function buildUser({ layerText, languageGuess, markers, previousError }) {
  const d = createDelimiter();
  const parts = [
    UNTRUSTED_PREAMBLE,
    `LANGUAGE_GUESS: ${languageGuess}`,
    `MARKERS: ${JSON.stringify({ exec: markers.exec, decode: markers.decode, remote: markers.remote })}`,
    d.field('LAYER_TEXT', layerText),
  ];
  if (previousError) parts.push(d.field('PREVIOUS_ERROR', JSON.stringify(previousError)));
  return parts.join('\n\n');
}

/**
 * @param {object} args
 * @param {ReturnType<import('../llm/client.mjs').createLlm>} args.llm
 * @param {string} args.text the layer text the decoder stopped at (decodeLayers().finalText)
 * @param {(h: {language: string, code: string, interpreter: string, ext: string}) => Promise<{stdout: string, stderr: string, exit_code: number, timed_out: boolean, violations?: string[]}>} args.runHarness
 *   injected by the engine: writes work/harness.<ext>, runs the unwrap container, and may add
 *   `violations` from harnessViolations() over the container's trace
 * @param {number} [args.budgetMs] wall clock for LLM + containers (LIMITS.unwrap.budgetMs)
 * @param {(layer: object) => void} [args.onLayer] each new layer (harness or decoder) and the final gave_up notice, in SSE shape minus preview
 * @param {AbortSignal} [args.signal]
 * @param {number} [args.parent=0] index of the layer holding `text` (decodeLayers().finalIndex)
 * @param {number} [args.firstIndex=1] next free layer index (decoder layers + 1)
 * @param {string[]} [args.priorTexts] texts of the command and every decoder layer (no_progress check)
 * @param {string[]} [args.languages] interpreters the image can run
 * @returns {Promise<{layers: object[], stoppedReason: string, attempts: number, llmCalls: number}>}
 *   stoppedReason: clean | remote | gave_up | too_large | budget | max_layers | llm_disabled | aborted
 */
export async function runHarnessLoop({
  llm,
  text,
  runHarness,
  budgetMs = LIMITS.unwrap.budgetMs,
  onLayer = () => {},
  signal,
  parent = 0,
  firstIndex = 1,
  priorTexts = [],
  languages = llm?.config?.harness_languages ?? DEFAULT_LANGUAGES,
  maxLayers = LIMITS.unwrap.maxLayers,
  retriesPerLayer = LIMITS.unwrap.retriesPerLayer,
  log = () => {},
}) {
  const started = performance.now();
  const deadline = started + budgetMs;
  const seen = new Set([text, ...priorTexts].map(sha256));
  const layers = [];
  let nextIndex = firstIndex;
  let parentIndex = parent;
  let layerText = String(text ?? '');
  let attempts = 0;
  let llmCalls = 0;
  let harnessLayers = 0;

  const notice = (status, reason, extra = {}) => {
    const n = { method: 'harness', status, reason, attempts, parent: parentIndex, llm_assisted: true, ...extra };
    onLayer(n);
    return n;
  };
  const result = (stoppedReason) => ({ layers, stoppedReason, attempts, llmCalls, ms: Math.round(performance.now() - started) });
  const left = () => deadline - performance.now();

  while (harnessLayers < maxLayers) {
    if (signal?.aborted) return result('aborted');
    if (Buffer.byteLength(layerText) > LAYER_TEXT_MAX_BYTES) {
      notice('too_large', 'layer text over 24 KiB');
      return result('too_large');
    }
    const languageGuess = guessLanguage(layerText);
    const markers = scanMarkers(layerText);
    const requested = languages.includes(languageGuess) ? languageGuess : 'python3';
    const system = SYSTEM_PROMPT.replaceAll('{{LANGUAGE}}', requested).replaceAll('{{LANGUAGES}}', languages.join(', '));
    let previousError = null;
    let lastSignature = null;
    let stuck = false; // another retry will not help
    let repeated = false; // the same failure twice in a row
    let accepted = null;
    const fail = (err, { terminal = false } = {}) => {
      const signature = JSON.stringify(err);
      repeated = signature === lastSignature;
      if (terminal || repeated) stuck = true;
      lastSignature = signature;
      previousError = err;
    };

    for (let attempt = 1; attempt <= retriesPerLayer && !accepted && !stuck; attempt += 1) {
      if (signal?.aborted) return result('aborted');
      if (left() < MIN_LLM_MS) {
        notice('gave_up', 'budget');
        return result('budget');
      }
      attempts += 1;
      let answer;
      try {
        llmCalls += 1;
        answer = await llm.callJson('harness', { system, user: buildUser({ layerText, languageGuess, markers, previousError }) }, Harness, { signal, deadline });
      } catch (err) {
        const code = err instanceof LlmError ? err.code : 'internal';
        log({ level: 'warn', msg: 'harness_llm_failed', code, attempt });
        if (code === 'disabled') return result('llm_disabled');
        if (code === 'aborted') return result('aborted');
        // The client already retried and tried the fallback model; asking again is pointless.
        fail({ kind: 'llm_error', detail: code }, { terminal: true });
        continue;
      }
      const harness = answer.data;
      const violations = staticCheck(harness, { languageGuess, languages, layerText });
      if (violations.length) {
        log({ msg: 'harness_static_reject', attempt, violations: violations.slice(0, VIOLATIONS_MAX) });
        fail({ kind: 'static_reject', violations: violations.slice(0, VIOLATIONS_MAX) });
        continue;
      }
      if (left() < MIN_CONTAINER_MS) {
        notice('gave_up', 'budget');
        return result('budget');
      }
      const [interpreter, ext] = INTERPRETERS[harness.language];
      let run;
      try {
        run = await runHarness({ language: harness.language, code: harness.harness, interpreter, ext, signal });
      } catch (err) {
        log({ level: 'warn', msg: 'harness_run_failed', attempt, err: String(err?.message ?? err).slice(0, 200) });
        fail({ kind: 'runtime_error', stderr: clip(err?.message, STDERR_MAX) });
        continue;
      }
      const stdout = String(run?.stdout ?? '');
      const stderr = clip(run?.stderr, STDERR_MAX);
      const traceViolations = Array.isArray(run?.violations) ? run.violations.slice(0, VIOLATIONS_MAX) : [];
      let kind = null;
      if (traceViolations.length) kind = 'violation';
      else if (run?.timed_out) kind = 'timeout';
      else if (stdout.trim() === '') kind = run?.exit_code === 0 ? 'empty_output' : 'runtime_error';
      else if (seen.has(sha256(stdout))) kind = 'no_progress';
      if (kind) {
        log({ msg: 'harness_rejected', attempt, kind, exit_code: run?.exit_code ?? null });
        fail({ kind, stderr, stdout: clip(stdout, STDOUT_MAX), violations: traceViolations });
        continue;
      }
      accepted = stdout;
    }

    if (accepted === null) {
      const reason = previousError ? `${previousError.kind}${repeated ? '_repeated' : ''}` : 'retries_exhausted';
      notice('gave_up', reason);
      return result('gave_up');
    }

    seen.add(sha256(accepted));
    harnessLayers += 1;
    const clipped = clip(accepted, DECODER_LIMITS.textMaxBytes);
    const layer = {
      index: nextIndex,
      parent: parentIndex,
      method: 'harness',
      bytes_len: Buffer.byteLength(accepted),
      text: clipped,
      truncated: clipped.length !== accepted.length,
      markers: scanMarkers(accepted),
      llm_assisted: true,
      status: clipped.length !== accepted.length ? 'truncated' : 'ok',
    };
    nextIndex += 1;
    layers.push(layer);
    onLayer(layer);

    // Cheap pass first (8.3 step 5): literal layers inside the harness output are opened on the host.
    const decoded = decodeLayers(accepted, { firstIndex: nextIndex, parent: layer.index, seen });
    for (const l of decoded.layers) {
      layers.push(l);
      onLayer(l);
    }
    nextIndex += decoded.layers.length;
    if (!decoded.needsHarness) return result(decoded.stopped === 'remote' ? 'remote' : 'clean');
    layerText = decoded.finalText;
    parentIndex = decoded.finalIndex;
  }
  notice('gave_up', 'max_layers');
  return result('max_layers');
}
