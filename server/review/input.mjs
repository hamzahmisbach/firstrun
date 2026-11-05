// Allowlisted projection for the AI reviewer (docs/ARCHITECTURE.md 8.7, 8.6 item 3). The model
// gets the claim, the command as pasted, the decoded layer texts and a compact summary of what
// was recorded (programs with arguments, writes outside the baseline including failed ones,
// hosts contacted, credential files read, exit code). Never: stdout/stderr, request bodies, the
// decoy manifest, canary values in any form. Every string is scrubbed against the manifest's
// values anyway (an argument can echo a file the command just read). Pure: no I/O.
import { LIMITS } from '../config.mjs';
import { canaryPatterns } from '../explain/writer.mjs';
import { BASELINE_WRITE_OK, displayPath, isLoopback, matchesAnyGlob, normalizeHost } from '../rules/paths.mjs';

export const REVIEW_LIMITS = LIMITS.llm.review;
const REDACTED = '[redacted]';

function cutChars(text, max) {
  const chars = [...String(text ?? '')];
  return chars.length > max ? { text: chars.slice(0, max).join(''), cut: chars.length - max } : { text: chars.join(''), cut: 0 };
}

/** Case-insensitive replacement of every canary form (6.6) in `text`. */
export function makeScrubber(decoys) {
  const patterns = canaryPatterns(decoys);
  const raw = (Array.isArray(decoys) ? decoys : []).map((d) => (typeof d?.value === 'string' ? d.value : '')).filter((v) => v.length >= 8);
  const needles = [...new Set([...raw, ...patterns])].sort((a, b) => b.length - a.length);
  const escaped = needles.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const re = escaped.length ? new RegExp(escaped.join('|'), 'gi') : null;
  return (text) => (re ? String(text ?? '').replace(re, REDACTED) : String(text ?? ''));
}

function pushCapped(list, item, max, dropped) {
  if (!item || list.includes(item)) return;
  if (list.length >= max) dropped.count += 1;
  else list.push(item);
}

/**
 * @param {object} args
 * @param {{command?: string, claim?: string}} args.input
 * @param {object[]} [args.layers] 8.2 layer objects (only index, method, text are read)
 * @param {object[]} [args.events] normalized events (7.4)
 * @param {{exit_code?: number, timed_out?: boolean}} [args.exec]
 * @param {object[]} [args.decoys] manifest; only `value` (for scrubbing) and `path` (for display) are read
 * @param {string|null} [args.sinkIp]
 * @param {object} [args.limits] overrides of LIMITS.llm.review (tests)
 */
export function buildReviewInput({ input, layers, events, exec, decoys, sinkIp = null, limits = REVIEW_LIMITS }) {
  const L = { ...REVIEW_LIMITS, ...(limits ?? {}) };
  const scrub = makeScrubber(decoys);
  const truncation = [];

  const claim = scrub(cutChars(typeof input?.claim === 'string' ? input.claim : '', 300).text);
  const cmd = cutChars(typeof input?.command === 'string' ? input.command : '', L.commandMaxChars);
  if (cmd.cut) truncation.push(`COMMAND was cut after ${L.commandMaxChars} characters (${cmd.cut} more not shown)`);

  const allLayers = (Array.isArray(layers) ? layers : []).filter((l) => l && typeof l === 'object' && typeof l.text === 'string' && l.text.length > 0);
  if (allLayers.length > L.layersMax) truncation.push(`only the first ${L.layersMax} of ${allLayers.length} decoded layers are shown`);
  const projectedLayers = allLayers.slice(0, L.layersMax).map((l) => {
    const c = cutChars(l.text, L.layerMaxChars);
    const index = Number.isInteger(l.index) ? l.index : 0;
    if (c.cut) truncation.push(`LAYER_${index} was cut after ${L.layerMaxChars} characters (${c.cut} more not shown)`);
    return { index, method: typeof l.method === 'string' ? l.method : 'unknown', text: scrub(c.text), truncated: c.cut > 0 };
  });

  const programs = [];
  const writes = [];
  const hosts = [];
  const credentialReads = [];
  const dropped = { programs: { count: 0 }, writes: { count: 0 }, hosts: { count: 0 }, reads: { count: 0 } };
  for (const ev of Array.isArray(events) ? events : []) {
    if (!ev || typeof ev !== 'object') continue;
    switch (ev.kind) {
      case 'proc.exec': {
        const argv = Array.isArray(ev.argv) ? ev.argv.map((a) => String(a ?? '')) : [];
        const line = argv.length ? argv.join(' ') : String(ev.exe ?? '');
        pushCapped(programs, scrub(cutChars(line, L.programMaxChars).text), L.programsMax, dropped.programs);
        break;
      }
      case 'shim.call': {
        const args = Array.isArray(ev.args) ? ev.args.map((a) => String(a ?? '')).join(' ') : '';
        const line = `${String(ev.tool ?? 'tool')}${args ? ' ' + args : ''} (macOS/Windows tool: recorded, not executed)`;
        pushCapped(programs, scrub(cutChars(line, L.programMaxChars).text), L.programsMax, dropped.programs);
        break;
      }
      case 'file.open': {
        const p = typeof ev.path === 'string' ? ev.path : '';
        if (!p) break;
        if (ev.access === 'read') {
          if (typeof ev.decoy_id === 'string' && ev.decoy_id) pushCapped(credentialReads, scrub(displayPath(p)), L.credentialReadsMax, dropped.reads);
          break;
        }
        if (ev.access !== 'write' && ev.access !== 'create') break;
        if (matchesAnyGlob(BASELINE_WRITE_OK, p)) break;
        pushCapped(writes, scrub(displayPath(p)) + (ev.ok === false ? ' (failed)' : ''), L.writesMax, dropped.writes);
        break;
      }
      case 'file.delete':
      case 'file.rename':
      case 'file.chmod':
      case 'file.truncate':
      case 'file.link':
      case 'dir.remove': {
        // 7.6 file changes, phrased like the writes above; the run's own tmp files are baseline.
        const p = typeof ev.path === 'string' ? ev.path : typeof ev.from === 'string' ? ev.from : '';
        if (!p || ev.ok === false || matchesAnyGlob(BASELINE_WRITE_OK, p)) break;
        const verb = { 'file.delete': 'deleted', 'file.rename': 'moved', 'file.chmod': 'chmod', 'file.truncate': 'truncated', 'file.link': 'linked', 'dir.remove': 'removed dir' }[ev.kind];
        pushCapped(writes, `${verb} ${scrub(displayPath(p))}${typeof ev.to === 'string' ? ` -> ${scrub(displayPath(ev.to))}` : ''}`, L.writesMax, dropped.writes);
        break;
      }
      case 'dns.query':
        pushCapped(hosts, `looked up ${scrub(normalizeHost(ev.name) || '?')}`, L.hostsMax, dropped.hosts);
        break;
      case 'http.request': {
        const method = String(ev.method ?? '').toUpperCase() || 'request';
        const bytes = ev.body_len > 0 ? ` sending ${ev.body_len} bytes` : '';
        pushCapped(hosts, `${method} ${scrub(normalizeHost(ev.host) || '?')}${bytes}`, L.hostsMax, dropped.hosts);
        break;
      }
      case 'tls.clienthello':
      case 'tls.failed':
        pushCapped(hosts, `TLS to ${scrub(normalizeHost(ev.sni) || '?')}`, L.hostsMax, dropped.hosts);
        break;
      case 'tcp.connect':
        pushCapped(hosts, `raw tcp to port ${ev.orig_dst_port ?? '?'}${ev.bytes_in > 0 ? ` sending ${ev.bytes_in} bytes` : ''}`, L.hostsMax, dropped.hosts);
        break;
      case 'udp.datagram':
        pushCapped(hosts, `udp to port ${ev.orig_dst_port ?? '?'}`, L.hostsMax, dropped.hosts);
        break;
      case 'net.connect': {
        if (ev.family === 'unix' || typeof ev.dst_ip !== 'string') break;
        if (ev.dst_ip === sinkIp || isLoopback(ev.dst_ip)) break;
        pushCapped(hosts, `connected to ${scrub(ev.dst_ip)}:${ev.dst_port ?? '?'}`, L.hostsMax, dropped.hosts);
        break;
      }
      default:
        break;
    }
  }
  for (const [name, d] of Object.entries(dropped)) if (d.count > 0) truncation.push(`${d.count} more recorded ${name} not shown`);

  return {
    claim,
    command: scrub(cmd.text),
    command_truncated: cmd.cut > 0,
    layers: projectedLayers,
    recorded: {
      programs,
      writes_outside_baseline: writes,
      credential_files_read: credentialReads,
      hosts,
      exit_code: Number.isInteger(exec?.exit_code) ? exec.exit_code : null,
      timed_out: exec?.timed_out === true,
    },
    truncation,
  };
}
