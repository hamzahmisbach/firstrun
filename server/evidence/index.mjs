// Evidence pipeline for one run: sinkhole tail + sidecar trace tail -> normalizer -> matcher.
// Contract (BUILD-BRIEF): createEvidence({ runId, sinkholeDir, traceDir, decoys, onEvent, onAlert,
// log }) -> { startSinkhole(), attachSandbox(containerId), t0Seen(), stop({ graceMs }) }.
import { setTimeout as sleep } from 'node:timers/promises';
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
 * @param {Array} opts.decoys manifest from run/canary.mjs
 * @param {(event) => void} opts.onEvent every normalized event, arrival order
 * @param {(event) => void} [opts.onAlert] every canary.hit (also delivered through onEvent)
 * @param {(record) => void} [opts.log] structured log; never gets values or command text
 */
export function createEvidence({ runId, sinkholeDir, traceDir, decoys = [], onEvent, onAlert = () => {}, log = () => {}, limits = EVIDENCE_LIMITS }) {
  if (typeof onEvent !== 'function') throw new Error('onEvent is required');
  const normalizer = createNormalizer({ runId, decoys, onEvent, log, limits });
  const matcher = createMatcher({ decoys, sinkholeDir, limits: limits.matcher });
  const tailErrors = [];
  let sinkholeTail = null;
  let sinkReader = null;
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
      if (sinkholeTail) await sinkholeTail.stop();
      // Records still waiting for a T0 that never came are released here, or the chain never ends.
      normalizer.finish();
      await chain;
      return { events: normalizer.events(), coverage: finalCoverage() };
    },
  };

  function finalCoverage() {
    const coverage = normalizer.coverage();
    coverage.scan_truncated = matcher.truncated();
    coverage.scanned_bytes = matcher.scannedBytes();
    coverage.decode_errors += (sinkReader?.decodeErrors() ?? 0) + (sinkholeTail?.decodeErrors() ?? 0);
    if (tailErrors.length) coverage.tail_errors = tailErrors.length;
    return coverage;
  }
}
