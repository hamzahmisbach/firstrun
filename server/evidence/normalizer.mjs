// Raw sidecar and sinkhole records -> normalized events (docs/ARCHITECTURE.md 7.3, 7.4): T0 gating,
// framework filtering, shim.call, decoy_id mapping, loader-noise filter, dedup, caps. Pure state
// machine, no I/O; evidence/index.mjs feeds it from the tails.
import path from 'node:path';
import { EVIDENCE_LIMITS, FILEOP_KINDS, SINKHOLE_KINDS, emptyCoverage, safeValidateEvent } from './schema.mjs';

const O_ACCMODE = 0o3;
const O_CREAT = 0o100;
const AT_FDCWD = -100;
const AT_FDCWD_U32 = 0xffffff9c; // how strace prints AT_FDCWD in a plain hex argument
const AT_REMOVEDIR = 0x200;
const MAX_SYMLINKS = 500;
const AF_UNIX = 1;
const AF_INET = 2;
const AF_INET6 = 10;
const HOME = '/home/dev';
const SEED_HOME = '/seed/home';
const SHIM_CANARIES = '/seed/shim-canaries.json';
const CMD_SH = '/work/cmd.sh';
const MAX_FORK_LINKS = 64; // per event, so a long fork chain cannot make one event huge
const ANSWERS_FILE = '/work/answers.txt'; // stdin of a second try, opened by launch itself (8.7)

/** Successful reads under these prefixes are loader/runtime noise (7.3). */
export const NOISE_READ_PREFIXES = Object.freeze([
  '/lib/', '/lib64/', '/usr/lib/', '/usr/local/lib/', '/usr/share/', '/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/',
  '/etc/ld.so.cache', '/etc/ld.so.preload', '/etc/alternatives/', '/etc/localtime', '/etc/nsswitch.conf',
  '/etc/host.conf', '/etc/hosts', '/etc/resolv.conf', '/etc/gai.conf', '/etc/services', '/etc/protocols',
  '/etc/ssl/', '/etc/passwd', '/etc/group', '/proc/', '/sys/', '/dev/null', '/dev/zero', '/dev/urandom',
  '/dev/random', '/dev/tty', '/opt/firstrun/',
]);

/** Any successful access (`>/dev/null` is an O_CREAT open). /dev/tty is dropped earlier, any result. */
export const NOISE_ANY_ACCESS = Object.freeze(['/dev/null']);

export function isNoiseRead(abs) {
  return NOISE_READ_PREFIXES.some((p) => abs.startsWith(p));
}

export function isNoiseAnyAccess(abs) {
  return NOISE_ANY_ACCESS.includes(abs);
}

/** `time_ns` is a decimal string above 2^53: BigInt first, then to ms. */
export function nsToMs(timeNs) {
  if (timeNs === undefined || timeNs === null) return null;
  try {
    return Number(BigInt(timeNs) / 1000000n);
  } catch {
    return null;
  }
}

function absolutize(p, cwd) {
  if (typeof p !== 'string' || p === '') return null;
  const joined = path.posix.isAbsolute(p) ? p : path.posix.join(cwd || '/', p);
  return path.posix.normalize(joined);
}

function ipv4(buf, off) {
  return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`;
}

function ipv6(buf, off) {
  const groups = [];
  for (let i = 0; i < 8; i++) groups.push(buf.readUInt16BE(off + i * 2));
  // IPv4-mapped (::ffff:a.b.c.d): show the dotted form, which is what the user would recognize.
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) return `::ffff:${ipv4(buf, off + 12)}`;
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLen < 2) return hex.join(':');
  const head = hex.slice(0, bestStart).join(':');
  const tail = hex.slice(bestStart + bestLen).join(':');
  return `${head}::${tail}`;
}

/**
 * Decode the fixed-size sockaddr buffer of a connect record (7.4). Returns
 * `{family, dst_ip, dst_port, path?}` or `{family: null}` for families we do not report.
 */
export function parseSockaddr(addressB64) {
  let buf;
  try {
    buf = Buffer.from(addressB64 ?? '', 'base64');
  } catch {
    return { family: null };
  }
  if (buf.length < 2) return { family: null };
  const family = buf.readUInt16LE(0);
  if (family === AF_INET && buf.length >= 8) {
    return { family: 'inet', dst_ip: ipv4(buf, 4), dst_port: buf.readUInt16BE(2) };
  }
  if (family === AF_INET6 && buf.length >= 24) {
    return { family: 'inet6', dst_ip: ipv6(buf, 8), dst_port: buf.readUInt16BE(2) };
  }
  if (family === AF_UNIX) {
    const abstract = buf.length > 2 && buf[2] === 0;
    const start = abstract ? 3 : 2;
    let end = buf.indexOf(0, start);
    if (end === -1) end = buf.length;
    const name = buf.subarray(start, end).toString('latin1');
    return { family: 'unix', dst_ip: null, dst_port: null, path: abstract ? `@${name}` : name };
  }
  return { family: null };
}

function buildDecoyByPath(decoys) {
  const map = new Map();
  for (const d of decoys ?? []) {
    if (typeof d.path !== 'string' || !d.path.startsWith('~/')) continue;
    const rel = d.path.slice(2);
    map.set(path.posix.normalize(`${HOME}/${rel}`), d.id);
    map.set(path.posix.normalize(`${SEED_HOME}/${rel}`), d.id);
  }
  return map;
}

/**
 * @param {object} opts
 * @param {string} opts.runId
 * @param {Array} opts.decoys manifest (5.3); only id and path are used here
 * @param {(event: object) => void} opts.onEvent called with each validated event, in arrival order
 * @param {(record: object) => void} [opts.log] never receives command text or canary values
 */
export function createNormalizer({ runId, decoys = [], onEvent, log = () => {}, limits = EVIDENCE_LIMITS }) {
  const caps = limits.caps;
  const decoyByPath = buildDecoyByPath(decoys);
  const coverage = emptyCoverage();
  const events = [];
  const counts = new Map();
  const seenOpen = new Set();
  const seenConnect = new Set();
  const seenFileop = new Set();
  const shimPids = new Set();
  const forkParent = new Map(); // child pid -> pid that forked it, from sentry/clone
  const execed = new Set(); // every pid that ran a program
  const forkLinked = new Set(); // forks whose parent has already gone out on an event
  const pendingSinkhole = [];
  // 7.6: cwd per thread group (from execve context, AT_FDCWD arguments, chdir/fchdir and clone
  // inheritance) and the symlinks the run created, so a path through one of them still names the
  // real file.
  const cwdByPid = new Map();
  const symlinks = new Map();
  let seq = 0;
  let t0Ns = null;
  let t0Ms = null;
  let pidT0 = null;
  let pidRoot = null;
  let lastDropped = 0;
  let fileopsT0 = false;

  function capFor(kind) {
    if (kind === 'canary.hit' || kind === 'exec.finished') return Infinity;
    return SINKHOLE_KINDS.includes(kind) ? caps.sinkhole : (caps[kind] ?? Infinity);
  }

  function capped(kind) {
    const n = counts.get(kind) ?? 0;
    if (n >= capFor(kind)) {
      coverage.capped[kind] = (coverage.capped[kind] ?? 0) + 1;
      return true;
    }
    if (capFor(kind) !== Infinity && !FILEOP_KINDS.includes(kind) && seq >= caps.total) {
      coverage.capped.total = (coverage.capped.total ?? 0) + 1;
      return true;
    }
    return false;
  }

  /**
   * Parent links for processes that never ran a program, which no proc.exec can name (7.3). Each goes
   * out once, on the first event that needs it.
   */
  function forkLinks(pid) {
    const links = [];
    for (let p = pid; links.length < MAX_FORK_LINKS && forkParent.has(p) && !execed.has(p) && !forkLinked.has(p); p = forkParent.get(p)) {
      forkLinked.add(p);
      links.push([p, forkParent.get(p)]);
    }
    return links;
  }

  /** Assign the envelope, validate, store and deliver. Returns the event or null. */
  function emit(partial, tsMs) {
    if (capped(partial.kind)) return null;
    const ts = tsMs ?? Date.now();
    const forks = forkLinks(partial.kind === 'proc.exec' || partial.kind === 'shim.call' ? partial.ppid : partial.pid);
    const event = {
      run_id: runId,
      seq: seq + 1,
      ts_ms: ts,
      t_rel_ms: ts - (t0Ms ?? ts),
      ...partial,
      ...(forks.length ? { forks } : {}),
    };
    const parsed = safeValidateEvent(event);
    if (!parsed.success) {
      coverage.invalid += 1;
      log({ stage: 'evidence', warn: 'invalid_event', kind: partial.kind, issues: parsed.error.issues.map((i) => i.path.join('.')) });
      return null;
    }
    seq += 1;
    counts.set(event.kind, (counts.get(event.kind) ?? 0) + 1);
    events.push(parsed.data);
    try {
      onEvent(parsed.data);
    } catch (err) {
      log({ stage: 'evidence', warn: 'onEvent_threw', message: err?.message });
    }
    return parsed.data;
  }

  function flushPendingSinkhole() {
    const list = pendingSinkhole.splice(0);
    const out = [];
    for (const { record, resolve } of list) {
      const ev = sinkholeNow(record);
      resolve(ev);
      if (ev) out.push(ev);
    }
    return out;
  }

  function setT0(ns, ms, pid) {
    t0Ns = ns;
    t0Ms = ms;
    pidT0 = pid;
    coverage.t0_ms = ms;
    flushPendingSinkhole();
  }

  function execve(msg, ctx, tsMs, timeNs) {
    const argv = Array.isArray(msg.argv) ? msg.argv.map(String) : [];
    const cwd = ctx.cwd || '/';
    const execfn = typeof msg.execfn === 'string' ? absolutize(msg.execfn, cwd) : null;
    const binaryPath = typeof msg.binary_path === 'string' ? msg.binary_path : null;
    const pid = Number(ctx.thread_group_id ?? 0);
    const ppid = Number(ctx.parent_thread_group_id ?? 0);
    if (typeof ctx.cwd === 'string' && ctx.cwd.startsWith('/')) cwdByPid.set(pid, ctx.cwd);
    execed.add(pid);

    if (t0Ns === null) {
      if (execfn === limits.t0Marker || argv[0] === limits.t0Marker) {
        setT0(timeNs, tsMs, pid);
        coverage.framework += 1;
      } else {
        coverage.pre_t0 += 1;
      }
      return null;
    }
    if (pid === pidT0 && (binaryPath?.endsWith('/timeout') || execfn?.endsWith('/timeout'))) {
      coverage.framework += 1;
      return null;
    }
    if (pidRoot === null && ppid === pidT0 && argv.includes(CMD_SH)) {
      pidRoot = pid;
      coverage.framework += 1;
      return null;
    }

    const argv0Abs = argv.length ? absolutize(argv[0], cwd) : null;
    const prefix = limits.shimPrefix;
    if ([execfn, binaryPath, argv0Abs].some((p) => p && p.startsWith(prefix))) {
      shimPids.add(pid);
      const name = execfn ?? argv[0] ?? binaryPath;
      return emit({ source: 'gvisor', kind: 'shim.call', tool: path.posix.basename(name), args: argv.slice(1), pid, ppid }, tsMs);
    }

    const exe = execfn ?? binaryPath ?? argv0Abs;
    if (!exe) {
      coverage.ignored += 1;
      return null;
    }
    const event = { source: 'gvisor', kind: 'proc.exec', pid, ppid, exe, argv, cwd };
    if (binaryPath && binaryPath !== exe) event.interp = binaryPath;
    return emit(event, tsMs);
  }

  /** Who forked whom, nothing else: no event of its own. A new thread stays in its thread group. */
  function clone(msg, ctx) {
    if (t0Ns === null) {
      coverage.pre_t0 += 1;
      return null;
    }
    const parent = Number(ctx.thread_group_id ?? 0);
    const child = Number(msg.created_thread_group_id ?? 0);
    if (parent > 0 && child > 0 && child !== parent) forkParent.set(child, parent);
    return null;
  }

  function openat(msg, ctx, tsMs) {
    if (t0Ns === null) {
      coverage.pre_t0 += 1;
      return null;
    }
    const pid = Number(ctx.thread_group_id ?? 0);
    const fd = Number(msg.fd ?? 0);
    const cwd = ctx.cwd || '/';
    const base = fd === AT_FDCWD ? cwd : (msg.fd_path || cwd);
    const abs = throughSymlinks(absolutize(msg.pathname, base));
    if (!abs) {
      coverage.ignored += 1;
      return null;
    }
    const flags = Number(msg.flags ?? 0);
    const access = flags & O_CREAT ? 'create' : (flags & O_ACCMODE) !== 0 ? 'write' : 'read';
    const errno = msg.exit?.errorno !== undefined ? Number(msg.exit.errorno) : null;
    const ok = errno === null && Number(msg.exit?.result ?? 0) >= 0;

    // Every bash (ours and any the command starts) opens /dev/tty O_RDWR at startup and fails
    // with ENXIO: never the user's doing, whatever the pid or result.
    if (abs === '/dev/tty') {
      coverage.noise += 1;
      return null;
    }
    if (pid === pidRoot && (abs === CMD_SH || abs === '/dev/null')) {
      coverage.framework += 1;
      return null;
    }
    if (pid === pidT0 && abs === ANSWERS_FILE) {
      coverage.framework += 1;
      return null;
    }
    if (abs === SHIM_CANARIES && shimPids.has(pid)) {
      coverage.framework += 1;
      return null;
    }
    if (access === 'read' && !ok) {
      coverage.noise += 1;
      return null;
    }
    if (ok && (access === 'read' ? isNoiseRead(abs) : isNoiseAnyAccess(abs))) {
      coverage.noise += 1;
      return null;
    }
    const key = `${pid}\0${abs}\0${access}`;
    if (seenOpen.has(key)) {
      coverage.dedup += 1;
      return null;
    }
    seenOpen.add(key);

    const event = { source: 'gvisor', kind: 'file.open', pid, path: abs, access };
    const decoyId = decoyByPath.get(abs);
    if (decoyId) event.decoy_id = decoyId;
    if (!ok) {
      event.ok = false;
      event.errno = errno ?? -Number(msg.exit?.result ?? 0);
    }
    return emit(event, tsMs);
  }

  function connect(msg, ctx, tsMs) {
    if (t0Ns === null) {
      coverage.pre_t0 += 1;
      return null;
    }
    const pid = Number(ctx.thread_group_id ?? 0);
    const addr = parseSockaddr(msg.address);
    if (!addr.family) {
      coverage.ignored += 1;
      return null;
    }
    const key = `${pid}\0${addr.family}\0${addr.dst_ip ?? addr.path}\0${addr.dst_port}`;
    if (seenConnect.has(key)) {
      coverage.dedup += 1;
      return null;
    }
    seenConnect.add(key);
    const event = { source: 'gvisor', kind: 'net.connect', pid, family: addr.family, dst_ip: addr.dst_ip, dst_port: addr.dst_port };
    if (addr.family === 'unix') event.path = addr.path;
    return emit(event, tsMs);
  }

  /** Rewrite the prefix of `abs` that is a symlink this run created, so the target is named. */
  function throughSymlinks(abs) {
    if (!abs || symlinks.size === 0) return abs;
    let out = abs;
    for (let hop = 0; hop < 8; hop++) {
      let hit = null;
      for (const [link, target] of symlinks) {
        if (out === link || out.startsWith(`${link}/`)) {
          if (!hit || link.length > hit.length) hit = link;
        }
      }
      if (!hit) break;
      out = path.posix.normalize(symlinks.get(hit) + out.slice(hit.length));
    }
    return out;
  }

  /**
   * Absolute form of a strace path argument. `dir` is the fd argument it is relative to (null for
   * the plain syscalls, whose line shows no cwd); then the pid's known cwd; then HOME, the
   * directory every sandbox process starts in, flagged in `flags.cwd_assumed`.
   */
  function resolveFileopPath(pid, dir, p, flags) {
    if (typeof p !== 'string') return null;
    if (p.startsWith('/')) return throughSymlinks(path.posix.normalize(p));
    let base = null;
    if (dir && typeof dir.path === 'string' && dir.path.startsWith('/')) {
      base = dir.path;
      if (dir.fd === AT_FDCWD_U32) cwdByPid.set(pid, dir.path);
    } else if (dir && dir.path === null) {
      return null; // a bad fd: the call failed and names nothing
    } else if (cwdByPid.has(pid)) {
      base = cwdByPid.get(pid);
    } else {
      base = HOME;
      flags.cwd_assumed = true;
    }
    return throughSymlinks(absolutize(p, base));
  }

  /** A hex argument that stands for a dirfd (renameat2/linkat second dirfd): only AT_FDCWD is resolvable. */
  function hexDir(pid, arg) {
    if (arg?.value === AT_FDCWD_U32) return { fd: AT_FDCWD_U32, path: cwdByPid.get(pid) ?? null };
    return { fd: arg?.value ?? null, path: null };
  }

  /**
   * One parsed record from the runsc strace log (fileops-reader). The T0 gate is this stream's
   * own launch execve, so entry.sh's cp/chmod setup never appears. Returns the event or null.
   */
  function fileop(record) {
    if (!record || typeof record !== 'object') return null;
    const pid = Number(record.pid ?? 0);
    const tsMs = Number(record.ts_ms ?? Date.now());
    const first = record.readings?.[0] ?? [];
    if (record.syscall === 'execve') {
      if (!fileopsT0 && first[0]?.path === limits.t0Marker && record.ok) fileopsT0 = true;
      coverage[fileopsT0 ? 'framework' : 'pre_t0'] += 1;
      return null;
    }
    if (!fileopsT0) {
      coverage.pre_t0 += 1;
      return null;
    }
    const sc = record.syscall;
    if (sc === 'clone' || sc === 'clone3' || sc === 'fork' || sc === 'vfork') {
      if (record.ok && record.ret > 0 && cwdByPid.has(pid)) cwdByPid.set(record.ret, cwdByPid.get(pid));
      return null;
    }
    if (record.malformed) {
      // A name with a line break cut the record; what was readable still says where it pointed.
      const flags = {};
      const dir = record.partial?.dir ? { fd: AT_FDCWD_U32, path: record.partial.dir } : null;
      // An empty head (the break came right after the pointer) still names the directory.
      const abs = resolveFileopPath(pid, dir, record.partial?.path || '.', flags);
      if (!abs) {
        coverage.ignored += 1;
        return null;
      }
      const kind = sc === 'rmdir' ? 'dir.remove' : sc === 'mkdir' || sc === 'mkdirat' ? 'dir.create' : sc === 'chmod' || sc === 'fchmodat' || sc === 'fchmod' ? 'file.chmod' : sc === 'truncate' || sc === 'ftruncate' ? 'file.truncate' : sc === 'unlink' || sc === 'unlinkat' ? 'file.delete' : sc.startsWith('rename') ? 'file.rename' : sc === 'chdir' || sc === 'fchdir' ? null : 'file.link';
      if (!kind) return null;
      const event = { source: 'gvisor', kind, pid, ok: true, partial: true, ...flags };
      if (kind === 'file.rename' || kind === 'file.link') event.from = abs;
      else event.path = abs;
      if (kind === 'file.link') event.link = sc.startsWith('sym') ? 'symlink' : 'hard';
      return emit(withDecoys(event), tsMs);
    }
    if (sc === 'chdir') {
      const abs = resolveFileopPath(pid, null, first[0]?.path, {});
      if (record.ok && abs) cwdByPid.set(pid, abs);
      return null;
    }
    if (sc === 'fchdir') {
      if (record.ok && first[0]?.path) cwdByPid.set(pid, first[0].path);
      return null;
    }

    // Every reading of the record is resolved; the first is the event, the others are alt_paths.
    const flags = {};
    const resolved = record.readings.map((args) => resolveReading(pid, sc, args, flags));
    const main = resolved.find(Boolean);
    if (!main) {
      coverage.ignored += 1;
      return null;
    }
    if (!record.ok && main.kind === 'dir.create') {
      coverage.noise += 1; // mkdir -p probes every parent and gets EEXIST
      return null;
    }
    const event = { source: 'gvisor', kind: main.kind, pid, ok: Boolean(record.ok), ...main.fields, ...flags };
    if (!record.ok && record.errno !== undefined) event.errno = record.errno;
    const alt = new Set();
    for (const r of resolved) {
      if (!r || r === main) continue;
      for (const p of [r.fields.path, r.fields.from, r.fields.to]) if (p && p !== main.fields.path && p !== main.fields.from && p !== main.fields.to) alt.add(p);
    }
    if (alt.size) event.alt_paths = [...alt].slice(0, 16);
    if (main.kind === 'file.chmod' || main.kind === 'dir.create') {
      const key = `${main.kind}\0${pid}\0${event.path}\0${event.mode}\0${event.ok}`;
      if (seenFileop.has(key)) {
        coverage.dedup += 1;
        return null;
      }
      seenFileop.add(key);
    }
    if (event.ok && main.kind === 'file.link' && event.link === 'symlink' && event.to && event.from && symlinks.size < MAX_SYMLINKS) {
      symlinks.set(event.to, event.from);
    }
    return emit(withDecoys(event), tsMs);
  }

  function withDecoys(event) {
    const from = event.path ?? event.from;
    const id = decoyByPath.get(from);
    if (id) event.decoy_id = id;
    const toId = event.to ? decoyByPath.get(event.to) : null;
    if (toId) event.to_decoy_id = toId;
    return event;
  }

  /** Map one reading (typed args) of a syscall to `{kind, fields}` with absolute paths, or null. */
  function resolveReading(pid, sc, args, flags) {
    const a = (i) => args[i] ?? {};
    switch (sc) {
      case 'unlink':
      case 'rmdir': {
        const p = resolveFileopPath(pid, null, a(0).path, flags);
        return p ? { kind: sc === 'rmdir' ? 'dir.remove' : 'file.delete', fields: { path: p } } : null;
      }
      case 'unlinkat': {
        const p = resolveFileopPath(pid, a(0), a(1).path, flags);
        return p ? { kind: a(2).value & AT_REMOVEDIR ? 'dir.remove' : 'file.delete', fields: { path: p } } : null;
      }
      case 'mkdir':
      case 'chmod':
      case 'truncate': {
        const p = resolveFileopPath(pid, null, a(0).path, flags);
        if (!p) return null;
        if (sc === 'truncate') return { kind: 'file.truncate', fields: { path: p } };
        return { kind: sc === 'mkdir' ? 'dir.create' : 'file.chmod', fields: { path: p, mode: a(1).value } };
      }
      case 'mkdirat':
      case 'fchmodat': {
        const p = resolveFileopPath(pid, a(0), a(1).path, flags);
        return p ? { kind: sc === 'mkdirat' ? 'dir.create' : 'file.chmod', fields: { path: p, mode: a(2).value } } : null;
      }
      case 'fchmod':
      case 'ftruncate': {
        const p = a(0).path;
        if (typeof p !== 'string' || !p.startsWith('/')) return null;
        return sc === 'fchmod' ? { kind: 'file.chmod', fields: { path: throughSymlinks(p), mode: a(1).value } } : { kind: 'file.truncate', fields: { path: throughSymlinks(p) } };
      }
      case 'rename':
      case 'link': {
        const from = resolveFileopPath(pid, null, a(0).path, flags);
        const to = resolveFileopPath(pid, null, a(1).path, flags);
        if (!from) return null;
        const fields = { from };
        if (to) fields.to = to;
        if (sc === 'link') fields.link = 'hard';
        return { kind: sc === 'rename' ? 'file.rename' : 'file.link', fields };
      }
      case 'renameat':
      case 'renameat2':
      case 'linkat': {
        const from = resolveFileopPath(pid, a(0), a(1).path, flags);
        const toDir = sc === 'renameat' ? a(2) : hexDir(pid, a(2));
        const to = resolveFileopPath(pid, toDir, a(3).path, flags);
        if (!from) return null;
        const fields = { from };
        if (to) fields.to = to;
        if (sc === 'linkat') fields.link = 'hard';
        return { kind: sc === 'linkat' ? 'file.link' : 'file.rename', fields };
      }
      case 'symlink':
      case 'symlinkat': {
        // The target is stored verbatim and resolved relative to the link's own directory.
        const to = sc === 'symlink' ? resolveFileopPath(pid, null, a(1).path, flags) : resolveFileopPath(pid, a(1), a(2).path, flags);
        const target = a(0).path;
        if (typeof target !== 'string') return null;
        const from = target.startsWith('/') ? throughSymlinks(path.posix.normalize(target)) : to ? throughSymlinks(absolutize(target, path.posix.dirname(to))) : null;
        if (!from) return null;
        const fields = { from, link: 'symlink' };
        if (to) fields.to = to;
        return { kind: 'file.link', fields };
      }
      default:
        return null;
    }
  }

  /** One raw line from the sidecar file. Returns the emitted event or null. */
  function gvisor(record) {
    if (!record || typeof record !== 'object') return null;
    if (record.kind === 'sink.closed') {
      coverage.sink_closed = true;
      coverage.decode_errors += Number(record.decode_errors ?? 0);
      coverage.gvisor_dropped = Math.max(coverage.gvisor_dropped, lastDropped, Number(record.dropped ?? 0));
      if (record.capped) coverage.sidecar_capped = Number(record.capped);
      return null;
    }
    if (typeof record.dropped === 'number' && record.dropped > lastDropped) lastDropped = record.dropped;
    coverage.gvisor_dropped = Math.max(coverage.gvisor_dropped, lastDropped);
    const msg = record.msg;
    const ctx = msg?.context_data;
    if (!msg || !ctx) {
      coverage.ignored += 1;
      return null;
    }
    const timeNs = typeof ctx.time_ns === 'string' || typeof ctx.time_ns === 'number' ? BigInt(ctx.time_ns) : null;
    const tsMs = timeNs === null ? Number(record.recv_ms ?? Date.now()) : Number(timeNs / 1000000n);
    if (t0Ns !== null && timeNs !== null && timeNs < t0Ns) {
      coverage.pre_t0 += 1;
      return null;
    }
    switch (record.type) {
      case 2:
        return clone(msg, ctx);
      case 3:
        return execve(msg, ctx, tsMs, timeNs);
      case 7:
        return openat(msg, ctx, tsMs);
      case 10:
        return connect(msg, ctx, tsMs);
      default:
        if (t0Ns === null) coverage.pre_t0 += 1;
        else coverage.ignored += 1;
        return null;
    }
  }

  function sinkholeNow(record) {
    const tsMs = Number(record.ts_ms ?? Date.now());
    const base = { source: 'sinkhole', kind: record.kind };
    switch (record.kind) {
      case 'dns.query':
        return emit({ ...base, name: String(record.name ?? ''), qtype: String(record.qtype ?? ''), ts_src: record.ts_src ?? 'arrival', client: record.client }, tsMs);
      case 'http.request': {
        const ev = {
          ...base,
          id: record.id,
          method: String(record.method ?? ''),
          host: String(record.host ?? ''),
          port: record.port ?? null,
          path: String(record.path ?? ''),
          body_len: record.body_len ?? null,
          scheme: record.scheme,
          status: record.response?.status,
          canned: record.response?.canned,
        };
        if (record.body_ref) ev.body_ref = record.body_ref;
        if (record.body_sha256) ev.body_sha256 = record.body_sha256;
        return emit(ev, tsMs);
      }
      case 'tls.clienthello':
        return emit({ ...base, sni: String(record.sni ?? ''), port: record.port ?? null, alpn: Array.isArray(record.alpn) ? record.alpn.map(String) : [] }, tsMs);
      case 'tls.failed':
        return emit({ ...base, sni: String(record.sni ?? ''), port: record.port ?? null, error: String(record.error ?? '') }, tsMs);
      case 'tcp.connect': {
        const ev = {
          ...base,
          orig_dst_port: record.orig_dst_port ?? null,
          orig_dst_ip: record.orig_dst_ip ?? null,
          src_port: record.src_port,
          bytes_in: Number(record.bytes_in ?? 0),
          looks_like_tls: Boolean(record.looks_like_tls),
        };
        if (record.sni !== undefined) ev.sni = record.sni;
        return emit(ev, tsMs);
      }
      case 'udp.datagram': {
        const ev = { ...base, src_port: record.src_port, len: Number(record.len ?? 0) };
        // The listener port means "unknown": REDIRECT rewrote it (see tcpsink.py).
        if (typeof record.orig_dst_port === 'number' && record.orig_dst_port !== limits.sinkPort) ev.orig_dst_port = record.orig_dst_port;
        return emit(ev, tsMs);
      }
      default:
        coverage.ignored += 1;
        return null;
    }
  }

  /**
   * One sinkhole record. Not T0-gated, but t_rel_ms needs T0, so records that arrive before the
   * marker wait for it; the promise resolves to the event (or null) once it is emitted.
   */
  function sinkhole(record) {
    if (!record || typeof record !== 'object') return Promise.resolve(null);
    if (t0Ms !== null) return Promise.resolve(sinkholeNow(record));
    return new Promise((resolve) => pendingSinkhole.push({ record, resolve }));
  }

  /** Orchestrator events (canary.hit, exec.finished). */
  function orchestrator(partial, tsMs) {
    return emit({ source: 'orchestrator', ...partial }, tsMs);
  }

  /** End of run: without T0 the pending sinkhole records are emitted relative to their first ts. */
  function finish() {
    if (t0Ms === null && pendingSinkhole.length) {
      t0Ms = Math.min(...pendingSinkhole.map((p) => Number(p.record.ts_ms ?? Date.now())));
      flushPendingSinkhole();
      t0Ms = null;
    }
  }

  return {
    gvisor,
    fileop,
    sinkhole,
    orchestrator,
    finish,
    t0: () => t0Ms,
    fileopsT0: () => fileopsT0,
    pidRoot: () => pidRoot,
    pidT0: () => pidT0,
    events: () => events,
    coverage: () => ({ ...coverage, capped: { ...coverage.capped } }),
    seq: () => seq,
  };
}
