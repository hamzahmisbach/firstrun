// Tail of the sidecar's per-container trace file, /srv/firstrun/trace/<cid>.jsonl (7.2). The file
// may not exist yet when the tail starts (the sidecar creates it on the first message) and the
// tail always starts from byte 0, so nothing written before attach is lost. The generic
// createFileTail is shared with sinkhole-tail.mjs.
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import path from 'node:path';
import { EVIDENCE_LIMITS } from './schema.mjs';

// The sinkhole container parses hostile traffic and writes into a directory we read. A compromised
// container could replace a record file with a symlink to a host file, so every open here refuses
// to follow links (O_NOFOLLOW is undefined on Windows; the lstat check still applies there).
const OPEN_FLAGS = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);

export class NotRegularFileError extends Error {
  constructor(filePath) {
    super('not a regular file');
    this.code = 'ENOTREGULAR';
    this.path = filePath;
  }
}

/**
 * lstat + open without following symlinks. Resolves `{ fh, size }`; rejects with ENOENT when the
 * file does not exist and ENOTREGULAR when it is a symlink or anything but a regular file.
 */
export async function openRegular(filePath) {
  const info = await lstat(filePath);
  if (!info.isFile()) throw new NotRegularFileError(filePath);
  const fh = await open(filePath, OPEN_FLAGS);
  try {
    const after = await fh.stat();
    if (!after.isFile()) throw new NotRegularFileError(filePath);
    return { fh, size: after.size };
  } catch (err) {
    await fh.close();
    throw err;
  }
}

/**
 * Poll a file for appended lines. `onLine(text)` gets each complete line (without the newline);
 * a truncated/replaced file restarts from 0. `stop()` drains what is on disk first. Overlong
 * lines and a file that is not a regular file are counted in `decodeErrors()`.
 */
export function createFileTail(filePath, { pollMs, onLine, onError = () => {}, maxLineBytes = EVIDENCE_LIMITS.tail.maxLineBytes } = {}) {
  const chunkBytes = EVIDENCE_LIMITS.tail.readChunkBytes;
  let offset = 0;
  let pending = Buffer.alloc(0);
  let overlong = false;
  let timer = null;
  let running = false;
  let reading = null;
  let stopped = false;
  let decodeErrors = 0;
  let rejected = false;

  function emitLines() {
    let start = 0;
    let nl;
    while ((nl = pending.indexOf(10, start)) !== -1) {
      if (overlong) {
        overlong = false;
      } else {
        let line = pending.subarray(start, nl);
        if (line.length && line[line.length - 1] === 13) line = line.subarray(0, -1);
        if (line.length) onLine(line.toString('utf8'));
      }
      start = nl + 1;
    }
    pending = start ? Buffer.from(pending.subarray(start)) : pending;
    if (pending.length > maxLineBytes) {
      pending = Buffer.alloc(0);
      overlong = true;
      decodeErrors += 1;
      onError(new Error('line exceeds maxLineBytes'));
    }
  }

  async function readOnce() {
    let opened;
    try {
      opened = await openRegular(filePath);
    } catch (err) {
      if (err.code === 'ENOENT') return false;
      if (err.code === 'ENOTREGULAR' || err.code === 'ELOOP') {
        // Counted once per occurrence, not once per poll; the file is never followed.
        if (!rejected) {
          rejected = true;
          decodeErrors += 1;
          onError(new NotRegularFileError(filePath));
        }
        return false;
      }
      throw err;
    }
    rejected = false;
    const { fh, size } = opened;
    try {
      if (size < offset) {
        offset = 0;
        pending = Buffer.alloc(0);
      }
      while (offset < size) {
        const want = Math.min(chunkBytes, size - offset);
        const buf = Buffer.allocUnsafe(want);
        const { bytesRead } = await fh.read(buf, 0, want, offset);
        if (bytesRead === 0) break;
        offset += bytesRead;
        pending = pending.length ? Buffer.concat([pending, buf.subarray(0, bytesRead)]) : Buffer.from(buf.subarray(0, bytesRead));
        emitLines();
      }
    } finally {
      await fh.close();
    }
    return true;
  }

  /** One read pass; serialized so a slow read never overlaps the next tick. */
  function drain() {
    if (reading) return reading;
    reading = readOnce()
      .catch((err) => {
        onError(err);
        return false;
      })
      .finally(() => {
        reading = null;
      });
    return reading;
  }

  async function tick() {
    if (stopped) return;
    await drain();
    if (!stopped) timer = setTimeout(tick, pollMs);
  }

  return {
    path: filePath,
    start() {
      if (running) return;
      running = true;
      stopped = false;
      timer = setTimeout(tick, 0);
    },
    drain,
    async stop() {
      stopped = true;
      if (timer) clearTimeout(timer);
      timer = null;
      await drain();
      running = false;
    },
    offset: () => offset,
    decodeErrors: () => decodeErrors,
  };
}

/**
 * Tail `<traceDir>/<containerId>.jsonl`. `onRecord(record)` gets each parsed JSON line;
 * `onClosed(record)` the final `sink.closed` line (the tail keeps running until stop()).
 */
export function createSinkReader({ traceDir, containerId, onRecord, onClosed = () => {}, onError = () => {}, pollMs = EVIDENCE_LIMITS.tail.tracePollMs }) {
  if (!/^[0-9a-f]{64}$/.test(containerId)) throw new Error('containerId must be 64 hex characters');
  let closed = false;
  let decodeErrors = 0;
  const tail = createFileTail(path.join(traceDir, `${containerId}.jsonl`), {
    pollMs,
    onError,
    onLine(line) {
      let record;
      try {
        record = JSON.parse(line);
      } catch {
        decodeErrors += 1;
        return;
      }
      if (!record || typeof record !== 'object') {
        decodeErrors += 1;
        return;
      }
      if (record.kind === 'sink.closed') {
        closed = true;
        onClosed(record);
        return;
      }
      onRecord(record);
    },
  });
  return {
    start: tail.start,
    stop: tail.stop,
    drain: tail.drain,
    closed: () => closed,
    decodeErrors: () => decodeErrors + tail.decodeErrors(),
  };
}
