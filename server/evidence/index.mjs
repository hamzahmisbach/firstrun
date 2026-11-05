// Evidence pipeline for one run: sinkhole tail + sidecar trace tail -> normalizer -> matcher.
// Contract (BUILD-BRIEF): createEvidence({ runId, sinkholeDir, traceDir, decoys, onEvent, onAlert,
// log }) -> { startSinkhole(), attachSandbox(containerId), t0Seen(), stop({ graceMs }) }.
import { setTimeout as sleep } from 'node:timers/promises';
import { createFileopsReader } from './fileops-reader.mjs';
import { createMatcher } from './matcher.mjs';
import { createNormalizer } from './normalizer.mjs';
import { EVIDENCE_LIMITS } from './schema.mjs';
import { createSinkReader } from './sink-reader.mjs';
import { createSinkholeTail } from './sinkhole-tail.mjs';

export { EVIDENCE_LIMITS } from './schema.mjs';

/**
 * @param {object} opts
 * @param {string} opts.runId
 * @param {string} opts.sinkholeDir run's sinkhole/ (events.jsonl, dns.log, tcp.jsonl, bodies/)
 * @param {string} opts.traceDir sidecar output dir (/srv/firstrun/trace)
 * @param {string|null} [opts.runscLogDir] runsc --debug-log dir with <cid>.boot.log (7.6); null
 *   means file changes are not recorded and coverage.fileops says so
 * @param {Array} opts.decoys manifest from run/canary.mjs
 * @param {(event) => void} opts.onEvent every normalized event, arrival order
 * @param {(event) => void} [opts.onAlert] every canary.hit (also delivered through onEvent)
 * @param {(record) => void} [opts.log] structured log; never gets values or command text
 */
export function createEvidence({ runId, sinkholeDir, traceDir, runscLogDir = null, decoys = [], onEvent, onAlert = () => {}, log = () => {}, limits = EVIDENCE_LIMITS }) {
  if (typeof onEvent !== 'function') throw new Error('onEvent is required');
  const normalizer = createNormalizer({ runId, decoys, onEvent, log, limits });
  const matcher = createMatcher({ decoys, sinkholeDir, limits: limits.matcher });
  const tailErrors = [];
  let sinkholeTail = null;
  let sinkReader = null;
  let fileopsReader = null;
  let fileopsError = null;
  let fileopsExists = null;
  let stopped = false;
  // Sinkhole records are processed strictly in order: the body scan is async (bodies/<id>.bin).
  let chain = Promise.resolve();

  const onTailError = (err) => {
    tailErrors.push(err?.code ?? err?.message ?? 'error');
    log({ stage: 'evidence', warn: 'tail_error', code: err?.code ?? null, message: err?.message ?? null });
  };

  function alert(hit) {
    const event = normalizer.orchestrator({ kind: 'canary.hit', ...hit });
    if (!event) return;
    try {
      onAlert(event);
    } catch (err) {
      log({ stage: 'evidence', warn: 'onAlert_threw', message: err?.message });
    }
  }

  function handleSinkholeRecord(record) {
    chain = chain
      .then(async () => {
        const event = await normalizer.sinkhole(record);
        if (!event) return;
        const hits = await matcher.scan(record, event.seq);
        for (const hit of hits) alert(hit);
      })
      .catch((err) => log({ stage: 'evidence', warn: 'sinkhole_record_failed', message: err?.message }));
  }

  return {
    startSinkhole() {
      if (sinkholeTail) return;
      sinkholeTail = createSinkholeTail({ sinkholeDir, onRecord: handleSinkholeRecord, onError: onTailError, pollMs: limits.tail.sinkholePollMs });
      sinkholeTail.start();
    },

    attachSandbox(containerId) {
      if (sinkReader) throw new Error('attachSandbox called twice');
      sinkReader = createSinkReader({
        traceDir,
        containerId,
        pollMs: limits.tail.tracePollMs,
        onRecord: (record) => normalizer.gvisor(record),
        onClosed: (record) => normalizer.gvisor(record),
        onError: onTailError,
      });
      sinkReader.start();
      if (runscLogDir) {
        fileopsReader = createFileopsReader({
          logDir: runscLogDir,
          containerId,
          pollMs: limits.tail.tracePollMs,
          onRecord: (record) => normalizer.fileop(record),
          onError: (err) => {
            if (err?.code === 'ENOTREGULAR' || err?.code === 'ELOOP' || err?.code === 'EACCES') fileopsError = err.code;
            onTailError(err);
          },
        });
        fileopsReader.start();
      }
    },

    t0Seen: () => normalizer.t0() !== null,
    pidRoot: () => normalizer.pidRoot(),
    coverage: () => normalizer.coverage(),

    /** Scan captured stdout/stderr for canary values; emits canary.hit {where} like sinkhole hits. */
    scanOutput(bytes, where) {
      const hits = matcher.scanBytes(bytes, where);
      for (const hit of hits) alert(hit);
      return hits;
    },

    /**
     * Wait up to graceMs for the sidecar's sink.closed line (written when the container exits),
     * drain both tails, then resolve { events, coverage }.
     */
    async stop({ graceMs = 2000 } = {}) {
      if (stopped) return { events: normalizer.events(), coverage: finalCoverage() };
      stopped = true;
      const deadline = Date.now() + graceMs;
      if (sinkReader) {
        while (!sinkReader.closed() && Date.now() < deadline) {
          await sinkReader.drain();
          if (sinkReader.closed()) break;
          await sleep(Math.min(limits.tail.tracePollMs, Math.max(1, deadline - Date.now())));
        }
        await sinkReader.stop();
      }
      if (fileopsReader) {
        await fileopsReader.stop();
        try {
          fileopsExists = await fileopsReader.exists();
        } catch (err) {
          fileopsError = fileopsError ?? err?.code ?? 'error';
        }
      }
      if (sinkholeTail) await sinkholeTail.stop();
      // Records still waiting for a T0 that never came are released here, or the chain never ends.
      normalizer.finish();
      await chain;
      return { events: normalizer.events(), coverage: finalCoverage() };
    },
  };

  /**
   * `coverage.fileops` (7.6): `recorded` is true only when the runsc log was read and its launch
   * marker seen; otherwise `reason` says why (no log dir configured, log missing, unreadable, no
   * T0 marker in the log) and the rules add the note that file changes were not recorded.
   */
  function fileopsCoverage() {
    if (!runscLogDir) return { recorded: false, reason: 'disabled' };
    if (!fileopsReader) return { recorded: false, reason: 'not_attached' };
    const stats = fileopsReader.stats();
    const out = { recorded: false, ...stats, decode_errors: fileopsReader.decodeErrors() };
    if (fileopsError) out.reason = fileopsError === 'ENOTREGULAR' || fileopsError === 'ELOOP' ? 'not_regular' : 'unreadable';
    else if (fileopsExists === false) out.reason = 'missing';
    else if (!normalizer.fileopsT0()) out.reason = 'no_t0';
    else out.recorded = true;
    return out;
  }

  function finalCoverage() {
    const coverage = normalizer.coverage();
    coverage.scan_truncated = matcher.truncated();
    coverage.scanned_bytes = matcher.scannedBytes();
    coverage.decode_errors += (sinkReader?.decodeErrors() ?? 0) + (sinkholeTail?.decodeErrors() ?? 0) + matcher.decodeErrors();
    if (tailErrors.length) coverage.tail_errors = tailErrors.length;
    coverage.fileops = fileopsCoverage();
    return coverage;
  }
}
