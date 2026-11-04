// Path and host constants plus the matchers the rules rely on (docs/ARCHITECTURE.md section 9).
// Pure functions only: no I/O, no clock, no randomness.

export const HOME = '/home/dev';
/** Read-only copy of the seeded HOME, also visible from inside the sandbox (7.3). */
export const SEED_HOME = '/seed/home';

/** Writes here never produce a finding, whatever the contract says. */
export const BASELINE_WRITE_OK = Object.freeze([
  '/tmp/**',
  '/var/tmp/**',
  '/dev/null',
  '/dev/stdout',
  '/dev/stderr',
  '/dev/tty',
  '~/.cache/**',
]);

/** Files a shell or terminal reads at startup: writing one is a persistence signal. */
export const SHELL_STARTUP = Object.freeze([
  '/etc/profile',
  '/etc/profile.d/**',
  '/etc/bash.bashrc',
  '/etc/zshenv',
  '/etc/zprofile',
  '/etc/zshrc',
  '/etc/zlogin',
  '/etc/zlogout',
  '/etc/zsh/**',
  '~/.bash_profile',
  '~/.bash_login',
  '~/.profile',
  '~/.bashrc',
  '~/.bash_logout',
  '~/.bash_aliases',
  '~/.zshenv',
  '~/.zprofile',
  '~/.zshrc',
  '~/.zlogin',
  '~/.zlogout',
  '~/.config/fish/**',
  '~/.config/powershell/*.ps1',
]);

/** Scheduler and autostart locations (systemd user units, cron, XDG autostart, launchd). */
export const SCHEDULER = Object.freeze([
  '~/.config/systemd/user/**',
  '~/.local/share/systemd/user/**',
  '/etc/systemd/**',
  '~/.config/autostart/**',
  '/etc/xdg/autostart/**',
  '/etc/cron*/**',
  '/etc/crontab',
  '/var/spool/cron/**',
  '~/Library/LaunchAgents/**',
  '/Library/LaunchDaemons/**',
]);

const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;

/** `~/x` -> `/home/dev/x`; absolute paths unchanged. */
export function expandHome(p) {
  if (p === '~') return HOME;
  if (p.startsWith('~/')) return HOME + p.slice(1);
  return p;
}

/** `/home/dev/x` -> `~/x` for titles; everything else unchanged. */
export function displayPath(p) {
  if (typeof p !== 'string') return '';
  if (p === HOME) return '~';
  if (p.startsWith(HOME + '/')) return '~' + p.slice(HOME.length);
  return p;
}

/** Paths referring to the same seeded file: `/seed/home/x` is the read-only twin of `/home/dev/x`. */
export function canonicalHomePath(p) {
  if (p === SEED_HOME) return HOME;
  if (p.startsWith(SEED_HOME + '/')) return HOME + p.slice(SEED_HOME.length);
  return p;
}

function globSource(glob) {
  let re = '^';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        re += '.*';
        i++;
      } else {
        re += '[^/]*';
      }
    } else if ('\\^$.|?+()[]{}'.includes(c)) {
      re += '\\' + c;
    } else {
      re += c;
    }
  }
  return re + '$';
}

const globCache = new Map();
const listCache = new WeakMap(); // glob array -> one alternation RegExp

/** Anchored glob: `**` matches anything including `/`, `*` one path segment, the rest literal. */
export function matchGlob(glob, p) {
  if (typeof glob !== 'string' || typeof p !== 'string') return false;
  const expanded = expandHome(glob);
  let re = globCache.get(expanded);
  if (!re) {
    re = new RegExp(globSource(expanded));
    globCache.set(expanded, re);
  }
  return re.test(p);
}

/** Same as `globs.some(g => matchGlob(g, p))`, but one compiled regexp per list. */
export function matchesAnyGlob(globs, p) {
  if (!Array.isArray(globs) || globs.length === 0 || typeof p !== 'string') return false;
  let re = listCache.get(globs);
  if (!re) {
    const parts = globs.filter((g) => typeof g === 'string' && g !== '').map((g) => `(?:${globSource(expandHome(g))})`);
    re = parts.length > 0 ? new RegExp(parts.join('|')) : /(?!)/;
    listCache.set(globs, re);
  }
  return re.test(p);
}

/** Normalize a host for comparison: lowercase, no trailing dot, no port, no brackets. */
export function normalizeHost(host) {
  if (typeof host !== 'string') return '';
  let h = host.trim().toLowerCase();
  if (h.startsWith('[')) h = h.slice(1, h.indexOf(']') === -1 ? undefined : h.indexOf(']'));
  else if (/^[^:]+:\d{1,5}$/.test(h)) h = h.slice(0, h.lastIndexOf(':'));
  return h.replace(/\.+$/, '');
}

/**
 * `expected_hosts` match exact (case-insensitive) or `*.x` for any subdomain of `x` (not `x`
 * itself); IP literals match exact. Unknown or empty hosts never match.
 */
export function hostMatches(expectedHosts, host) {
  const h = normalizeHost(host);
  if (!h || !Array.isArray(expectedHosts)) return false;
  for (const raw of expectedHosts) {
    const e = normalizeHost(raw);
    if (!e) continue;
    if (e.startsWith('*.')) {
      const suffix = e.slice(1); // ".x"
      if (h.length > suffix.length && h.endsWith(suffix)) return true;
    } else if (e === h) {
      return true;
    }
  }
  return false;
}

export function isIpv4(s) {
  return typeof s === 'string' && IPV4_RE.test(s);
}

export function isLoopback(ip) {
  if (typeof ip !== 'string') return false;
  const v = ip.toLowerCase();
  if (v.startsWith('::ffff:')) return isLoopback(v.slice(7));
  if (v === '::1' || v === '0.0.0.0' || v === '::') return true;
  return v.startsWith('127.');
}

/** RFC 1918 and link-local ranges, where a per-run sinkhole lives when its IP is not known. */
export function isPrivateIp(ip) {
  if (typeof ip !== 'string') return false;
  const v = ip.toLowerCase();
  if (v.startsWith('::ffff:')) return isPrivateIp(v.slice(7));
  if (isIpv4(v)) {
    const [a, b] = v.split('.').map(Number);
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  return v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80:');
}

export function isPtrName(name) {
  const n = normalizeHost(name);
  return n.endsWith('.in-addr.arpa') || n.endsWith('.ip6.arpa');
}

/** Group key for `fs.unexpected_write`: `~/<dir>` inside HOME, otherwise the top-level directory. */
export function writeGroup(p) {
  const abs = canonicalHomePath(p);
  if (abs === HOME) return '~';
  if (abs.startsWith(HOME + '/')) {
    const rest = abs.slice(HOME.length + 1);
    const first = rest.split('/')[0];
    return '~/' + first;
  }
  const parts = abs.split('/').filter(Boolean);
  if (parts.length <= 1) return '/';
  return '/' + parts[0];
}

export function basename(p) {
  if (typeof p !== 'string' || p === '') return '';
  const trimmed = p.replace(/\/+$/, '');
  const i = trimmed.lastIndexOf('/');
  return i === -1 ? trimmed : trimmed.slice(i + 1);
}

export function dirname(p) {
  if (typeof p !== 'string') return '';
  const i = p.lastIndexOf('/');
  if (i <= 0) return '/';
  return p.slice(0, i);
}

/**
 * Parent directory of every decoy (both the HOME and the /seed/home twin), excluding HOME and
 * `/` themselves so a read in the home directory is not "listing a credential directory".
 */
export function decoyDirs(decoys) {
  const out = new Map(); // dir -> Set<category>
  for (const d of decoys ?? []) {
    if (!d || typeof d.path !== 'string') continue;
    const abs = expandHome(d.path);
    if (!abs.startsWith('/')) continue;
    const dir = dirname(abs);
    if (dir === HOME || dir === '/' || dir === SEED_HOME) continue;
    const twins = dir.startsWith(HOME + '/') ? [dir, SEED_HOME + dir.slice(HOME.length)] : [dir];
    for (const t of twins) {
      if (!out.has(t)) out.set(t, new Set());
      out.get(t).add(d.category);
    }
  }
  return out;
}

/** The longest decoy dir that contains `p` (or equals it), or null. */
export function matchDecoyDir(dirs, p) {
  if (typeof p !== 'string') return null;
  let best = null;
  for (const dir of dirs.keys()) {
    if ((p === dir || p.startsWith(dir + '/')) && (best === null || dir.length > best.length)) best = dir;
  }
  return best;
}
