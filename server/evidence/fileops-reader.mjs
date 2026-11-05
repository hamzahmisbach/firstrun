// Tail of runsc's boot log, <logDir>/<cid>.boot.log (docs/ARCHITECTURE.md 7.6): the strace lines
// for the file-changing syscalls that the trace points do not cover (unlink, rename, chmod, link,
// mkdir, ...), plus chdir/clone for cwd tracking and execve for the T0 gate. Exit lines only.
//
// Format, verified on the VM (runsc release-20261102.0):
//   I1105 05:54:53.219431       1 strace.go:606] [  52:  52] rm X unlinkat(AT_FDCWD /tmp, 0x55bacbdd02e0 a, 0x0) = 0 (0x0) (14.8µs)
// File names are printed raw: no quoting, so a name may contain ", 0x..." (an argument separator),
// ") = 0 (0x0)" (a result) or a line break (the record continues on the next physical line). The
// process name (comm) is raw too. The parser therefore (1) joins continuation lines, (2) anchors
// the result at the end of the record, (3) tries every split of the variable-length arguments and
// reports all readings, and (4) keeps the readable head of a record it cannot finish as a partial
// path. A hostile name can add readings or a partial record; it cannot remove the real one from
// the readings of its own record, and nothing here throws on input.
import { lstat } from 'node:fs/promises';
import path from 'node:path';
import { EVIDENCE_LIMITS } from './schema.mjs';
import { createFileTail } from './sink-reader.mjs';

const AT_FDCWD = 0xffffff9c;

// Any gVisor log line: level+date, time, pid, file:line]. Only strace.go lines are parsed.
const LOG_LINE_RE = /^[IWDEF](\d{2})(\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d{6})\s+\d+ ([a-z_0-9]+\.go):\d+\] (.*)$/s;
// "[ tgid: tid] <comm> <E|X> <name>(<rest>"; comm is at most 16 bytes and may itself contain " X ".
const TASK_RE = /^\[\s*(\d+):\s*(\d+)\] (.*)$/s;
// "= 0 (0x0) (28.6µs)" on success, "= -1 errno=18 (cross-device link) (22µs)" on failure.
const RESULT_RE = /\) = (-?\d+)(?: \((0x[0-9a-f]+)\)| errno=(\d+) \(([^)]*)\)) \(\d+(?:\.\d+)?(?:ns|µs|ms|s)\)$/;

/** Argument types gVisor prints for the syscalls we trace (pkg/sentry/strace/linux64_amd64.go). */
const SPECS = Object.freeze({
  execve: ['path', 'vec', 'vec'],
  unlink: ['path'],
  rmdir: ['path'],
  chdir: ['path'],
  mkdir: ['path', 'mode'],
  chmod: ['path', 'mode'],
  truncate: ['path', 'hex'],
  fchmod: ['fd', 'mode'],
  ftruncate: ['fd', 'hex'],
  fchdir: ['fd'],
  rename: ['path', 'path'],
  link: ['path', 'path'],
  symlink: ['path', 'path'],
  unlinkat: ['fd', 'path', 'hex'],
  mkdirat: ['fd', 'path', 'mode'],
  fchmodat: ['fd', 'path', 'mode'],
  renameat: ['fd', 'path', 'fd', 'path'],
  renameat2: ['fd', 'path', 'hex', 'path', 'hex'],
  linkat: ['fd', 'path', 'hex', 'path', 'hex'],
  symlinkat: ['path', 'fd', 'path'],
  clone: ['flags', 'hex', 'hex', 'hex', 'hex'],
  clone3: ['hex', 'hex'],
  fork: [],
  vfork: [],
});

export const TRACED_SYSCALLS = Object.freeze(Object.keys(SPECS));

/** "I1105 05:54:53.219431" -> epoch ms in the host's local time; the year is the current one. */
export function logTimeToMs(month, day, h, m, s, micro, now = Date.now()) {
  const year = new Date(now).getFullYear();
  let ms = new Date(year, Number(month) - 1, Number(day), Number(h), Number(m), Number(s), Math.floor(Number(micro) / 1000)).getTime();
  if (ms - now > 24 * 3600 * 1000) ms = new Date(year - 1, Number(month) - 1, Number(day), Number(h), Number(m), Number(s), Math.floor(Number(micro) / 1000)).getTime();
  return Number.isFinite(ms) ? ms : now;
}

// --- argument grammar ------------------------------------------------------------------------

/** Fixed-width heads: everything but the variable-length text that follows a path or fd pointer. */
const HEADS = {
  hex: /^0x[0-9a-f]+/,
  // mkdir/chmod print "0o755", fchmod "S_IFREG|0o600", mkdirat a plain hex "0x1ed".
  mode: /^(?:[A-Z_]+\|)*(?:0o[0-7]+|0x[0-9a-f]+)/,
  flags: /^[A-Z0-9_|x]+/,
  path: /^(?:(<null>)|(0x[0-9a-f]+) (\(error decoding path: [^)]*\))|(0x[0-9a-f]+) )/,
  fd: /^(?:(AT_FDCWD) |(0x[0-9a-f]+) (\(bad FD\))|(0x[0-9a-f]+) )/,
  vec: /^0x[0-9a-f]+ \[/,
};

/**
 * Every way `text` reads as `spec` (a list of argument types). Returns the readings (arrays of
 * {type, ...}) in left-to-right order of the splits, so readings[0] is the one with the shortest
 * names, which is the only reading an ordinary name produces. `state.splits` bounds the search.
 */
function readArgs(text, spec, state, i = 0) {
  if (i === spec.length) return text === '' ? [[]] : [];
  const type = spec[i];
  const sep = i === spec.length - 1 ? '' : ', ';
  // The text after a fixed-width argument: nothing (last argument) or the separator and the rest.
  const restOf = (rest) => (rest === '' ? [''] : rest.startsWith(', ') ? [rest.slice(2)] : null);
  const out = [];
  if (type === 'hex' || type === 'mode' || type === 'flags') {
    const m = HEADS[type].exec(text);
    if (!m) return [];
    const octal = m[0].lastIndexOf('0o');
    const value = type === 'flags' ? m[0] : type === 'hex' || octal === -1 ? Number(m[0].slice(m[0].lastIndexOf('0x'))) : parseInt(m[0].slice(octal + 2), 8);
    const rests = restOf(text.slice(m[0].length));
    if (!rests) return [];
    for (const rest of rests) for (const tail of readArgs(rest, spec, state, i + 1)) out.push([{ type, value }, ...tail]);
    return out;
  }
  if (type === 'vec') {
    // %q-quoted strings in a Go slice: the closing `]` of the real vector is followed by the
    // separator or the end; a quoted `]` cannot end the slice, so the first such position is right.
    const m = HEADS.vec.exec(text);
    if (!m) return [];
    let depth = 0;
    let quoted = false;
    for (let k = m[0].length - 1; k < text.length; k++) {
      const c = text[k];
      if (quoted) {
        if (c === '\\') k++;
        else if (c === '"') quoted = false;
        continue;
      }
      if (c === '"') quoted = true;
      else if (c === '[') depth++;
      else if (c === ']') {
        depth--;
        if (depth === 0) {
          const rests = restOf(text.slice(k + 1));
          if (!rests) return [];
          for (const rest of rests) for (const tail of readArgs(rest, spec, state, i + 1)) out.push([{ type }, ...tail]);
          return out;
        }
      }
    }
    return [];
  }
  // path | fd: a pointer head, then free text up to a separator that lets the rest parse.
  const m = HEADS[type].exec(text);
  if (!m) return [];
  if (m[1] === '<null>' || m[3]) {
    const rests = restOf(text.slice(m[0].length));
    if (!rests) return [];
    const arg = type === 'fd' ? { type, fd: Number(m[2]), path: null } : { type, path: null };
    for (const rest of rests) for (const tail of readArgs(rest, spec, state, i + 1)) out.push([arg, ...tail]);
    return out;
  }
  const fd = type === 'fd' ? (m[1] === 'AT_FDCWD' ? AT_FDCWD : Number(m[4])) : null;
  const body = text.slice(m[0].length);
  if (sep === '') {
    return [[type === 'fd' ? { type, fd, path: body } : { type, path: body }]];
  }
  // Every separator is a possible end of the name. The honest split is the first one for an
  // ordinary name and the last one for a name made of separators, so the search takes the first
  // maxSplits positions from each end and gives up on the middle (state.capped).
  const positions = [];
  for (let at = body.indexOf(sep); at !== -1; at = body.indexOf(sep, at + 1)) positions.push(at);
  let tried = positions;
  if (positions.length > 2 * state.maxSplits) {
    state.capped = true;
    tried = [...positions.slice(0, state.maxSplits), ...positions.slice(-state.maxSplits)];
  }
  for (const at of tried) {
    const name = body.slice(0, at);
    const arg = type === 'fd' ? { type, fd, path: name } : { type, path: name };
    for (const tail of readArgs(body.slice(at + sep.length), spec, state, i + 1)) {
      out.push([arg, ...tail]);
      if (out.length > state.maxSplits) {
        state.capped = true;
        return out;
      }
    }
  }
  return out;
}

/** The text after the last pointer head in `text`: the start of the name a broken record was printing. */
function partialHead(text) {
  const re = /(?:AT_FDCWD |0x[0-9a-f]+ )/g;
  let last = null;
  let m;
  while ((m = re.exec(text)) !== null) last = m;
  if (!last) return { dir: null, path: null };
  const head = text.slice(last.index + last[0].length);
  // For an *at syscall the first argument is the directory the name is relative to.
  const fd = /^AT_FDCWD ([^\n]*?), 0x[0-9a-f]+ /.exec(text);
  return { dir: fd ? fd[1] : null, path: head };
}

/**
 * Parse one assembled record (a strace.go log line plus its continuation lines). Returns null for
 * a line that is not a syscall exit of a traced syscall, else
 * `{syscall, pid, tid, comm, ts_ms, ok, ret, errno?, readings}` or, for a record whose result could
 * not be read, `{..., malformed: true, partial: {dir, path}}`.
 */
export function parseRecord(line, { maxSplits = EVIDENCE_LIMITS.fileops.maxSplits, now = Date.now() } = {}) {
  const lm = LOG_LINE_RE.exec(line);
  if (!lm || lm[7] !== 'strace.go') return null;
  const tm = TASK_RE.exec(lm[8]);
  if (!tm) return null;
  const pid = Number(tm[1]);
  const tid = Number(tm[2]);
  const rest = tm[3];
  const ts_ms = logTimeToMs(lm[1], lm[2], lm[3], lm[4], lm[5], lm[6], now);
  // comm is raw and may contain " X ": try each " X " within its 16-byte reach, left to right.
  const re = / X ([a-z0-9_]+)\(/g;
  let m;
  let headless = null;
  while ((m = re.exec(rest)) !== null && m.index <= 16) {
    const comm = rest.slice(0, m.index);
    const syscall = m[1];
    const spec = SPECS[syscall];
    if (!spec) continue;
    const body = rest.slice(m.index + m[0].length);
    const base = { syscall, pid, tid, comm, ts_ms };
    const rm = RESULT_RE.exec(body);
    if (!rm) {
      headless = headless ?? { ...base, malformed: true, partial: partialHead(body) };
      continue;
    }
    const args = body.slice(0, rm.index);
    const state = { maxSplits, capped: false };
    const readings = readArgs(args, spec, state);
    if (readings.length === 0) {
      headless = headless ?? { ...base, malformed: true, partial: partialHead(args) };
      continue;
    }
    const ret = Number(rm[1]);
    const out = { ...base, ok: rm[3] === undefined && ret >= 0, ret, readings };
    if (rm[3] !== undefined) out.errno = Number(rm[3]);
    if (state.capped) out.splits_capped = true;
    return out;
  }
  return headless;
}

/**
 * Tail `<logDir>/<containerId>.boot.log`. `onRecord(record)` gets every parsed exit record of a
 * traced syscall (malformed ones included), in file order. The tail refuses symlinks (sink-reader).
 */
export function createFileopsReader({ logDir, containerId, onRecord, onError = () => {}, pollMs = EVIDENCE_LIMITS.tail.tracePollMs, limits = EVIDENCE_LIMITS, now = Date.now }) {
  if (!/^[0-9a-f]{64}$/.test(containerId)) throw new Error('containerId must be 64 hex characters');
  const L = limits.fileops;
  const file = path.join(logDir, `${containerId}.boot.log`);
  const stats = { lines: 0, records: 0, malformed: 0, ambiguous: 0, capped: 0, stray: 0, overlong: 0 };
  let current = null; // the strace line of the record being assembled
  let following = []; // unprefixed lines after it: a name's line breaks, or gVisor's own tables
  let currentBytes = 0;
  let dropping = false; // the record outgrew maxRecordBytes/maxContinuationLines

  const parse = (text) => parseRecord(text, { maxSplits: L.maxSplits, now: now() });

  /**
   * A record is its strace line plus as many following lines as make it parse. The line alone
   * is the honest reading when it parses; the joined readings are still added, so a name that
   * ends like a result before its line break cannot hide what came after the break. Following
   * lines that make nothing parse are gVisor's own output (timing tables), not a name.
   */
  function flush() {
    if (current === null) return;
    const head = current;
    const rest = following;
    current = null;
    following = [];
    currentBytes = 0;
    dropping = false;
    let record;
    try {
      record = parse(head);
      const joins = [];
      for (let k = 1; k <= rest.length; k++) {
        const r = parse(`${head}\n${rest.slice(0, k).join('\n')}`);
        if (r && !r.malformed) joins.push(r);
      }
      if (record && record.malformed && joins.length) record = joins.shift();
      if (record && !record.malformed) {
        for (const j of joins) {
          if (j.syscall !== record.syscall) continue;
          record.readings.push(...j.readings);
          if (j.splits_capped) record.splits_capped = true;
        }
      }
    } catch (err) {
      stats.malformed += 1;
      onError(err);
      return;
    }
    if (!record) return;
    stats.records += 1;
    if (record.malformed) stats.malformed += 1;
    else if (record.readings.length > 1 || record.splits_capped) stats.ambiguous += 1;
    try {
      onRecord(record);
    } catch (err) {
      onError(err);
    }
  }

  const tail = createFileTail(file, {
    pollMs,
    onError,
    maxLineBytes: L.maxRecordBytes,
    onLine(line) {
      if (LOG_LINE_RE.test(line)) {
        flush();
        if (!line.includes(' strace.go:')) return;
        stats.lines += 1;
        if (stats.lines > L.maxLines) {
          stats.capped += 1;
          return;
        }
        current = line;
        currentBytes = Buffer.byteLength(line);
        return;
      }
      if (current === null) {
        // gVisor's boot timing table precedes the first strace line; only later strays are odd.
        if (stats.lines > 0) stats.stray += 1;
        return;
      }
      if (dropping) return;
      currentBytes += line.length + 1;
      if (following.length >= L.maxContinuationLines || currentBytes > L.maxRecordBytes) {
        dropping = true;
        stats.overlong += 1;
        return;
      }
      following.push(line);
    },
  });

  return {
    path: file,
    start: tail.start,
    drain: tail.drain,
    async stop() {
      await tail.stop();
      flush();
    },
    /** true once the log file exists (null until checked). */
    async exists() {
      try {
        await lstat(file);
        return true;
      } catch (err) {
        if (err.code === 'ENOENT') return false;
        throw err;
      }
    },
    stats: () => ({ ...stats }),
    decodeErrors: () => tail.decodeErrors(),
  };
}
