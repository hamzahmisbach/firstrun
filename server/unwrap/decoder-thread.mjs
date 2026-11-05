// Runs decodeLayers on a worker thread. A worst-case 16 KiB input costs seconds of pure CPU on the
// production VM, and on the main thread that would stall every SSE stream and health check.
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { decodeLayers } from './decoder.mjs';

const HARD_LIMIT_MS = 6000;

if (!isMainThread && workerData?.firstrunDecoder === true) {
  parentPort.postMessage(decodeLayers(workerData.text));
}

/** What the lifecycle gets when the decoder could not answer: the harness loop may still try. */
function unanswered(text) {
  return { layers: [], finalText: text, finalIndex: 0, needsHarness: true, stopped: 'time' };
}

/**
 * Same result shape as decodeLayers, off the main thread. Never rejects: a crash or a hard timeout
 * comes back as "not decoded", which only costs visibility, not the run.
 * @param {string} text
 * @param {{limitMs?: number}} [opts]
 */
export function decodeInWorker(text, { limitMs = HARD_LIMIT_MS } = {}) {
  return new Promise((resolve) => {
    let settled = false;
    let worker;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      worker?.terminate();
      resolve(value);
    };
    const timer = setTimeout(() => finish(unanswered(text)), limitMs);
    try {
      worker = new Worker(new URL(import.meta.url), { workerData: { firstrunDecoder: true, text } });
      worker.once('message', finish);
      worker.once('error', () => finish(unanswered(text)));
      worker.once('exit', () => finish(unanswered(text)));
    } catch {
      finish(unanswered(text));
    }
  });
}
