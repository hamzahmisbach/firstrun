// The 10.3 report object, trimmed to LIMITS.output.reportMaxBytes. Pure: no I/O.
import { LIMITS } from '../config.mjs';

const KiB = 1024;
export const REPORT_LIMITS = Object.freeze({
  layerTextMaxBytes: 64 * KiB,
  previewMaxBytes: LIMITS.output.previewMaxBytes,
  explanationMaxBytes: 4 * KiB,
  reportMaxBytes: LIMITS.output.reportMaxBytes,
});

const EMPTY_CONTRACT = Object.freeze({
  summary: '',
  expected_hosts: [],
  expected_write_paths: [],
  expected_processes: [],
  allowed_decoy_categories: [],
  notes: '',
});

export function utf8Bytes(value) {
  return Buffer.byteLength(typeof value === 'string' ? value : JSON.stringify(value), 'utf8');
}

/** Cut a string to at most `maxBytes` of UTF-8 without splitting a character. */
export function truncateUtf8(text, maxBytes) {
  if (typeof text !== 'string') return '';
  if (Buffer.byteLength(text, 'utf8') <= maxBytes) return text;
  const buf = Buffer.from(text, 'utf8');
  let end = Math.max(0, maxBytes);
  while (end > 0 && (buf[end] & 0xc0) === 0x80) end--;
  return buf.subarray(0, end).toString('utf8');
}

function trimLayer(layer) {
  const out = { ...layer };
  const text = typeof out.text === 'string' ? out.text : '';
  if (Buffer.byteLength(text, 'utf8') > REPORT_LIMITS.layerTextMaxBytes) {
    out.text = truncateUtf8(text, REPORT_LIMITS.layerTextMaxBytes);
    out.truncated = true;
  } else {
    out.text = text;
    out.truncated = out.truncated === true;
  }
  return out;
}

function trimExplanation(explanation, level) {
  const e = explanation && typeof explanation === 'object' ? explanation : {};
  let out = {
    verdict_echo: typeof e.verdict_echo === 'string' ? e.verdict_echo : level,
    headline: typeof e.headline === 'string' ? e.headline : '',
    paragraphs: Array.isArray(e.paragraphs) ? e.paragraphs.filter((p) => typeof p === 'string') : [],
    finding_notes: Array.isArray(e.finding_notes) ? e.finding_notes : [],
    next_step: typeof e.next_step === 'string' ? e.next_step : '',
  };
  // Shrink in order of least value: finding notes, then paragraphs from the end, then lengths.
  while (utf8Bytes(out) > REPORT_LIMITS.explanationMaxBytes) {
    if (out.finding_notes.length > 0) out.finding_notes = out.finding_notes.slice(0, -1);
    else if (out.paragraphs.length > 1) out.paragraphs = out.paragraphs.slice(0, -1);
    else if (out.paragraphs.length === 1 && Buffer.byteLength(out.paragraphs[0], 'utf8') > 256) {
      out.paragraphs = [truncateUtf8(out.paragraphs[0], Math.floor(Buffer.byteLength(out.paragraphs[0], 'utf8') / 2))];
    } else if (Buffer.byteLength(out.headline, 'utf8') > 120) out.headline = truncateUtf8(out.headline, 120);
    else if (Buffer.byteLength(out.next_step, 'utf8') > 200) out.next_step = truncateUtf8(out.next_step, 200);
    else break;
  }
  return out;
}

function trimOutput(output) {
  if (!output || typeof output !== 'object') return undefined;
  const stdout = typeof output.stdout_preview === 'string' ? output.stdout_preview : '';
  const stderr = typeof output.stderr_preview === 'string' ? output.stderr_preview : '';
  const stdoutCut = Buffer.byteLength(stdout, 'utf8') > REPORT_LIMITS.previewMaxBytes;
  const stderrCut = Buffer.byteLength(stderr, 'utf8') > REPORT_LIMITS.previewMaxBytes;
  return {
    stdout_preview: stdoutCut ? truncateUtf8(stdout, REPORT_LIMITS.previewMaxBytes) : stdout,
    stderr_preview: stderrCut ? truncateUtf8(stderr, REPORT_LIMITS.previewMaxBytes) : stderr,
    stdout_bytes: Number.isFinite(output.stdout_bytes) ? output.stdout_bytes : Buffer.byteLength(stdout, 'utf8'),
    stderr_bytes: Number.isFinite(output.stderr_bytes) ? output.stderr_bytes : Buffer.byteLength(stderr, 'utf8'),
    truncated: output.truncated === true || stdoutCut || stderrCut,
  };
}

function toIso(run) {
  if (typeof run?.created_at === 'string') return run.created_at;
  if (Number.isFinite(run?.created_ms)) return new Date(run.created_ms).toISOString();
  return new Date(0).toISOString();
}

/**
 * Build the immutable 10.3 report. `classifications` (seq -> classification, from
 * `evaluate`) is written onto the events; events that already carry one keep it.
 * Trimming order when the whole report exceeds `reportMaxBytes`: events that no finding
 * references (from the end), then layer texts, then output previews. What was trimmed is
 * recorded in `coverage.report_trimmed` and as a `coverage.notes` line.
 */
export function buildReport({
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
  review,
  reviewMeta,
  attempts,
  classifications,
}) {
  const level = verdict?.level ?? 'CLEAN';
  const cls = classifications && typeof classifications === 'object' ? classifications : {};
  const allEvents = (Array.isArray(events) ? events : [])
    .filter((e) => e && typeof e === 'object')
    .map((e) => {
      const c = e.classification ?? cls[String(e.seq)];
      return c ? { ...e, classification: c } : { ...e };
    })
    .sort((a, b) => (a.t_rel_ms ?? 0) - (b.t_rel_ms ?? 0) || (a.seq ?? 0) - (b.seq ?? 0));
  const allFindings = Array.isArray(findings) ? findings : [];
  const referenced = new Set();
  for (const f of allFindings) for (const s of f.event_seqs ?? []) referenced.add(s);

  const cov = coverage && typeof coverage === 'object' ? { ...coverage } : {};
  const report = {
    schema_version: 1,
    run_id: run?.run_id ?? '',
    created_at: toIso(run),
    input: {
      command: typeof run?.input?.command === 'string' ? run.input.command : '',
      claim: typeof run?.input?.claim === 'string' ? run.input.claim : '',
      ...(run?.input?.sample_id ? { sample_id: run.input.sample_id } : {}),
    },
    layers: (Array.isArray(layers) ? layers : []).map(trimLayer),
    contract: { ...EMPTY_CONTRACT, ...(contract && typeof contract === 'object' ? contract : {}) },
    contract_meta: contractMeta && typeof contractMeta === 'object' ? contractMeta : { source: 'fallback', prompt_version: 'none' },
    events: allEvents,
    findings: allFindings,
    verdict: {
      level,
      rule_ids: Array.isArray(verdict?.rule_ids) ? verdict.rule_ids : [],
      coverage_notes: Array.isArray(verdict?.coverage_notes) ? verdict.coverage_notes : [],
    },
    explanation: trimExplanation(explanation, level),
    explanation_meta: explanationMeta && typeof explanationMeta === 'object' ? explanationMeta : { source: 'template' },
    decoys: Array.isArray(decoys) ? decoys : [],
    coverage: {
      timed_out: cov.timed_out === true,
      tls_unreadable: Array.isArray(cov.tls_unreadable) ? cov.tls_unreadable : [],
      notes: Array.isArray(cov.notes) ? [...cov.notes] : [],
      mode: typeof cov.mode === 'string' ? cov.mode : 'trace',
      gvisor_dropped: cov.gvisor_dropped ?? 0,
      decode_errors: cov.decode_errors ?? 0,
      pre_t0: cov.pre_t0 ?? 0,
      dedup: cov.dedup ?? 0,
      capped: cov.capped && typeof cov.capped === 'object' ? cov.capped : {},
      scan_truncated: cov.scan_truncated === true,
      oom_killed: cov.oom_killed === true,
      ...Object.fromEntries(
        Object.entries(cov).filter(
          ([k]) =>
            !['timed_out', 'tls_unreadable', 'notes', 'mode', 'gvisor_dropped', 'decode_errors', 'pre_t0', 'dedup', 'capped', 'scan_truncated', 'oom_killed'].includes(k),
        ),
      ),
    },
    timing: timing && typeof timing === 'object' ? timing : {},
    models_used: Array.isArray(modelsUsed) ? modelsUsed : [],
    review: review && typeof review === 'object' ? review : null,
    review_meta: reviewMeta && typeof reviewMeta === 'object' ? reviewMeta : { source: 'skipped' },
    attempts: Array.isArray(attempts) ? attempts : [],
  };
  if (output !== undefined) {
    const trimmed = trimOutput(output);
    if (trimmed) report.output = trimmed;
  }

  const max = REPORT_LIMITS.reportMaxBytes;
  if (utf8Bytes(report) <= max) return report;

  const trimmed = { events_dropped: 0, layers_text_dropped: 0, previews_dropped: false };
  // The trim record and its coverage note are added after trimming, so trim against a budget
  // that leaves room for them.
  const budget = max - 1024;
  // 1. Drop unreferenced events from the end until it fits (binary search on the keep count).
  const unreferenced = report.events.filter((e) => !referenced.has(e.seq));
  const referencedEvents = report.events.filter((e) => referenced.has(e.seq));
  if (unreferenced.length > 0) {
    let lo = 0;
    let hi = unreferenced.length;
    const build = (n) =>
      [...referencedEvents, ...unreferenced.slice(0, n)].sort(
        (a, b) => (a.t_rel_ms ?? 0) - (b.t_rel_ms ?? 0) || (a.seq ?? 0) - (b.seq ?? 0),
      );
    while (lo < hi) {
      const mid = Math.ceil((lo + hi) / 2);
      report.events = build(mid);
      if (utf8Bytes(report) <= budget) lo = mid;
      else hi = mid - 1;
    }
    report.events = build(lo);
    trimmed.events_dropped = unreferenced.length - lo;
  }
  // 2. Layer texts.
  if (utf8Bytes(report) > budget) {
    for (let i = report.layers.length - 1; i >= 0 && utf8Bytes(report) > budget; i--) {
      if (report.layers[i].text === '') continue;
      report.layers[i] = { ...report.layers[i], text: '', truncated: true };
      trimmed.layers_text_dropped++;
    }
  }
  // 3. Output previews.
  if (utf8Bytes(report) > budget && report.output) {
    report.output = { ...report.output, stdout_preview: '', stderr_preview: '', truncated: true };
    trimmed.previews_dropped = true;
  }
  report.coverage.report_trimmed = trimmed;
  report.coverage.notes.push(
    `Report was trimmed to fit ${Math.floor(max / (1024 * 1024))} MiB: ${trimmed.events_dropped} unreferenced events, ${trimmed.layers_text_dropped} layer texts${trimmed.previews_dropped ? ' and the output previews' : ''} were removed.`,
  );
  return report;
}
