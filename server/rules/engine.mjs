// Deterministic verdict rules (docs/ARCHITECTURE.md section 9). Pure: no I/O, no clock, no
// randomness, no LLM. Events are sorted by seq, rules run in the 9.2 table order, and findings
// are sorted stably, so the same input always gives the same bytes. Only post-T0 execute-phase
// events are expected; unwrap events never reach this module.
import { z } from 'zod';
import {
  BASELINE_WRITE_OK,
  SCHEDULER,
  SHELL_STARTUP,
  basename,
  canonicalHomePath,
  decoyDirs,
  displayPath,
  expandHome,
  hostMatches,
  isLoopback,
  isPrivateIp,
  isPtrName,
  matchDecoyDir,
  matchesAnyGlob,
  normalizeHost,
  writeGroup,
} from './paths.mjs';
import {
  AI_CLI,
  CATEGORY_OWNER,
  CRED_PROMPT,
  INTERPRETERS,
  NET_TOOLS,
  NEVER_ALLOWED,
  OPENER,
  OS_EXEC,
  PERSIST,
  PREFS,
  PRIV,
  SHELLS,
  categoryLabel,
  hasInlineFlag,
  isDecodeHelper,
  isSensitive,
} from './tools.mjs';

export const SEVERITIES = Object.freeze(['info', 'low', 'medium', 'high', 'critical']);
/** Findings carry one of these three. */
export const FINDING_CLASSIFICATIONS = Object.freeze(['explained', 'unexplained', 'forbidden']);
/** Events carry one of these: `baseline` = allowed for any command (9.1), not matched by the claim. */
export const CLASSIFICATIONS = Object.freeze([...FINDING_CLASSIFICATIONS, 'baseline']);
export const LEVELS = Object.freeze(['CLEAN', 'SUSPICIOUS', 'MALICIOUS']);

/** Every rule of the 9.2 table, in table order. */
export const RULE_IDS = Object.freeze([
  'exfil.canary_outbound',
  'exfil.read_then_send',
  'exfil.canary_stdout',
  'decoy.credential_read',
  'decoy.write',
  'decoy.history_read',
  'decoy.meta_read',
  'decoy.dir_enum',
  'shim.credential_prompt',
  'shim.persistence',
  'shim.privilege',
  'shim.os_exec',
  'shim.prefs',
  'shim.ai_cli',
  'shim.opener',
  'net.unexpected_upload',
  'net.unexpected_host',
  'net.ip_literal',
  'net.raw_socket',
  'net.dns_only',
  'net.tls_opaque',
  'proc.exec_written_file',
  'proc.interpreter_inline',
  'proc.interpreter',
  'proc.net_tool',
  'proc.decode_helper',
  'fs.shell_startup_write',
  'fs.scheduler_write',
  'fs.unexpected_write',
  'unwrap.hidden_code',
  'run.timeout',
  'run.oom',
  'run.no_activity',
]);

export const MAX_FINDINGS = 200;
export const MAX_SEQS_PER_FINDING = 50;
const ARGS_PREVIEW_CHARS = 80;

export const FindingSchema = z.strictObject({
  id: z.string().min(1).max(80),
  rule_id: z.enum(RULE_IDS),
  severity: z.enum(SEVERITIES),
  classification: z.enum(FINDING_CLASSIFICATIONS),
  title: z.string().min(1).max(300),
  event_seqs: z.array(z.number().int().nonnegative()).max(MAX_SEQS_PER_FINDING),
});

export const VerdictSchema = z.strictObject({
  level: z.enum(LEVELS),
  rule_ids: z.array(z.enum(RULE_IDS)),
  coverage_notes: z.array(z.string().min(1)),
});

export const NOTE_CLEAN_MEANS =
  'CLEAN means nothing suspicious was observed in this run (Linux sandbox, 60 s, no internet), not proof that the command is safe.';
export const NOTE_LIMITS = 'This shows what happened in a Linux sandbox for up to 60 seconds with no real internet.';
export const NOTE_SINKHOLED =
  "The internet in this sandbox is fake: every site it tried to reach was answered by FirstRun's own server with an empty reply, and nothing was forwarded.";
export const NOTE_DOWNLOAD =
  'Because the internet here is fake, anything this command would have downloaded and run was not observed.';

const SEV_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));
const UPLOAD_METHODS = new Set(['POST', 'PUT', 'PATCH']);

// --- small helpers ---------------------------------------------------------------------------

function str(v) {
  return typeof v === 'string' ? v : '';
}

function num(v) {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string' && /^-?\d+$/.test(v)) return Number(v);
  return 0;
}

function sortedUnique(values) {
  return [...new Set(values)].sort();
}

function listHosts(hosts, max = 5) {
  const all = sortedUnique(hosts.filter(Boolean));
  if (all.length <= max) return all.join(', ');
  return `${all.slice(0, max).join(', ')} and ${all.length - max} more`;
}

function previewArgs(args) {
  const text = (Array.isArray(args) ? args : []).map(String).join(' ');
  return text.length > ARGS_PREVIEW_CHARS ? text.slice(0, ARGS_PREVIEW_CHARS - 1) + '…' : text;
}

function isWrite(ev) {
  return ev.access !== 'read';
}

/** Titles say what was observed: a failed write (`ok: false`) is an attempt, not a change. */
function writeVerb(ev) {
  return ev.ok === false ? 'Tried to write to' : 'Wrote to';
}

function isOutboundHit(where) {
  const w = str(where);
  return !(w === 'stdout' || w === 'stderr' || w.startsWith('stdout.') || w.startsWith('stderr.'));
}

/** Where a sinkhole/network event was aimed, for titles. */
function destinationOf(ev) {
  if (!ev) return '';
  switch (ev.kind) {
    case 'http.request':
      return normalizeHost(ev.host) || 'an unknown host';
    case 'tls.clienthello':
    case 'tls.failed':
      return normalizeHost(ev.sni) || 'an unknown host';
    case 'dns.query':
      return normalizeHost(ev.name) || 'an unknown name';
    case 'tcp.connect':
    case 'udp.datagram': {
      const sni = normalizeHost(ev.sni);
      if (sni) return sni;
      const proto = ev.kind === 'tcp.connect' ? 'tcp' : 'udp';
      return ev.orig_dst_port == null ? `a ${proto} port` : `${proto} port ${num(ev.orig_dst_port)}`;
    }
    case 'net.connect':
      return ev.dst_ip ? `${ev.dst_ip}:${num(ev.dst_port)}` : 'a socket';
    default:
      return '';
  }
}

/**
 * Replace every decoy value (raw, base64 at the three alignments, hex, base32-ish = raw) in a
 * title. Titles only ever carry paths, hosts, tool names and short argument previews, but an
 * argument can echo a file the command just read, so this is the last line of defence.
 */
function makeScrubber(decoys) {
  const needles = [];
  for (const d of decoys ?? []) {
    const v = str(d?.value);
    if (v.length < 8) continue;
    needles.push(v);
    needles.push(Buffer.from(v).toString('base64').replace(/=+$/, ''));
    needles.push(Buffer.from('x' + v).toString('base64').slice(4).replace(/=+$/, ''));
    needles.push(Buffer.from('xx' + v).toString('base64').slice(4).replace(/=+$/, ''));
    needles.push(Buffer.from(v).toString('hex'));
    needles.push(Buffer.from(v).toString('hex').toUpperCase());
  }
  const unique = sortedUnique(needles.filter((n) => n.length >= 8));
  return (text) => {
    let out = text;
    for (const n of unique) {
      if (out.includes(n)) out = out.split(n).join('[token]');
      const lower = n.toLowerCase();
      if (out.toLowerCase().includes(lower)) {
        const re = new RegExp(lower.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
        out = out.replace(re, '[token]');
      }
    }
    return out;
  };
}

// --- contract view ---------------------------------------------------------------------------

function contractView(contract) {
  const c = contract && typeof contract === 'object' ? contract : {};
  const hosts = Array.isArray(c.expected_hosts) ? c.expected_hosts.map(str).filter(Boolean) : [];
  const paths = Array.isArray(c.expected_write_paths) ? c.expected_write_paths.map(str).filter(Boolean) : [];
  const procs = new Set(Array.isArray(c.expected_processes) ? c.expected_processes.map(str).filter(Boolean) : []);
  // NEVER_ALLOWED is removed here too, so a contract that slipped past salvage still cannot
  // explain a wallet or browser profile read.
  const cats = new Set(
    (Array.isArray(c.allowed_decoy_categories) ? c.allowed_decoy_categories.map(str) : []).filter(
      (cat) => cat && !NEVER_ALLOWED.has(cat),
    ),
  );
  return {
    hostOk: (h) => hostMatches(hosts, h),
    writeOk: (p) => matchesAnyGlob(paths, p) || matchesAnyGlob(paths, canonicalHomePath(p)),
    procOk: (name) => procs.has(name),
    catOk: (cat) => cats.has(cat),
    ownerOk: (cat) => (CATEGORY_OWNER[cat] ?? []).some((tool) => procs.has(tool)),
  };
}

// --- findings accumulator --------------------------------------------------------------------

class Findings {
  constructor(scrub) {
    this.map = new Map();
    this.scrub = scrub;
  }

  /** One finding per rule_id + group key; later events only add seqs. */
  add(ruleId, key, { severity, classification, title, seqs }) {
    const k = `${ruleId}\u0000${key}`;
    let f = this.map.get(k);
    if (!f) {
      f = { rule_id: ruleId, severity, classification, title: this.scrub(title), seqs: new Set(), extra: {} };
      this.map.set(k, f);
    } else if (SEV_RANK[severity] > SEV_RANK[f.severity]) {
      // Keep the group at its worst severity (e.g. one explained and one forbidden open).
      f.severity = severity;
      f.classification = classification;
      f.title = this.scrub(title);
    }
    for (const s of seqs) if (Number.isInteger(s)) f.seqs.add(s);
    return f;
  }

  has(ruleId, key) {
    return this.map.has(`${ruleId}\u0000${key}`);
  }

  delete(ruleId, key) {
    this.map.delete(`${ruleId}\u0000${key}`);
  }

  values() {
    return [...this.map.values()];
  }
}

// --- evaluate --------------------------------------------------------------------------------

/**
 * @param {object} args
 * @param {object[]} args.events normalized 7.4 events (any order; sorted by seq here)
 * @param {object} args.contract 8.1 contract (fallback contract when the LLM failed)
 * @param {object[]} args.decoys 5.3 manifest
 * @param {object[]} [args.layers] 8.2 layers (index >= 1)
 * @param {object} [args.coverage] exec.finished coverage plus run notes (10.3 `coverage`)
 * @param {object} [args.exec] `{exit_code, timed_out}` when not present as an exec.finished event
 * @param {string} [args.sinkIp] the run's sinkhole IP; without it private-range connects are
 *   attributed to the sinkhole (see README of the lead)
 * @param {object} [args.contractMeta] `{source}`; `"fallback"` adds the 9.3 note
 * @param {object} [args.unwrap] `{stopped, harness: {stoppedReason}}` from the decoder/harness loop
 * @returns {{findings: object[], verdict: object, classifications: Record<string, string>}}
 */
export function evaluate({ events, contract, decoys, layers, coverage, exec, sinkIp, sink_ip, contractMeta, unwrap }) {
  const evs = (Array.isArray(events) ? events : [])
    .filter((e) => e && typeof e === 'object' && Number.isInteger(e.seq))
    .slice()
    .sort((a, b) => a.seq - b.seq);
  const manifest = Array.isArray(decoys) ? decoys : [];
  const byId = new Map(manifest.map((d) => [d?.id, d]));
  const dirs = decoyDirs(manifest);
  const c = contractView(contract);
  const scrub = makeScrubber(manifest);
  const findings = new Findings(scrub);
  const classifications = {};
  const bySeq = new Map(evs.map((e) => [e.seq, e]));
  const sink = str(sinkIp ?? sink_ip);
  const cov = coverage && typeof coverage === 'object' ? coverage : {};

  const classify = (ev, cls) => {
    classifications[String(ev.seq)] = cls;
  };

  const writtenPaths = new Set(); // absolute paths written so far (seq order)
  const sensitiveOpens = []; // forbidden opens of SENSITIVE decoys: {seq}
  const outboundSends = []; // unexplained sends: {seq, dest}
  let outboundCanary = false;
  const unexpectedHosts = new Set();
  const dnsOnly = new Map(); // name -> {seqs}
  const shimTools = new Set();
  let downloadAttempt = false; // a GET/HEAD the fake server answered empty
  const tlsFailedHosts = new Set();
  let execFinished = null;
  let activity = false;

  const decoyExplained = (decoy, category, ev) => {
    if (NEVER_ALLOWED.has(category)) return false;
    if (c.catOk(category)) return true;
    if (c.ownerOk(category)) return true;
    if (isWrite(ev) && c.writeOk(ev.path)) return true;
    return false;
  };

  for (const ev of evs) {
    switch (ev.kind) {
      case 'canary.hit': {
        activity = true;
        const decoy = byId.get(ev.decoy_id);
        const category = str(ev.category) || str(decoy?.category);
        const path = decoy ? displayPath(expandHome(str(decoy.path))) : str(ev.decoy_id) || 'a fake credential file';
        const ref = bySeq.get(ev.event_seq);
        if (isOutboundHit(ev.where)) {
          outboundCanary = true;
          classify(ev, 'forbidden');
          const dest = destinationOf(ref) || str(ev.where).split('.')[0] || 'the network';
          const what = category === 'phished_input' ? 'Fake password typed into a prompt' : `Fake credential from ${path}`;
          findings.add('exfil.canary_outbound', `${str(ev.decoy_id)}|${dest}`, {
            severity: 'critical',
            classification: 'forbidden',
            title: `${what} was sent to ${dest}`,
            seqs: [ev.seq, ...(ref ? [ref.seq] : [])],
          });
        } else {
          const explained = category && !NEVER_ALLOWED.has(category) && (c.catOk(category) || c.ownerOk(category));
          classify(ev, explained ? 'explained' : 'unexplained');
          findings.add('exfil.canary_stdout', str(ev.decoy_id), {
            severity: explained ? 'info' : 'medium',
            classification: explained ? 'explained' : 'unexplained',
            title: `A fake credential from ${path} appeared in the program output`,
            seqs: [ev.seq, ...(ref ? [ref.seq] : [])],
          });
        }
        break;
      }

      case 'file.open': {
        activity = true;
        const path = str(ev.path);
        if (isWrite(ev)) writtenPaths.add(path);
        if (ev.decoy_id != null && ev.decoy_id !== '') {
          const decoy = byId.get(ev.decoy_id);
          // Unknown decoy ids are treated as sensitive credentials (fail safe).
          const category = str(decoy?.category) || 'unknown';
          const shown = displayPath(canonicalHomePath(path)) || str(ev.decoy_id);
          const explained = decoyExplained(decoy, category, ev);
          if (isWrite(ev)) {
            classify(ev, explained ? 'explained' : 'forbidden');
            findings.add('decoy.write', str(ev.decoy_id), {
              severity: explained ? 'low' : 'high',
              classification: explained ? 'explained' : 'forbidden',
              title: `${ev.ok === false ? 'Tried to open' : 'Opened'} ${shown} for writing (fake ${categoryLabel(category)})`,
              seqs: [ev.seq],
            });
            if (!explained && isSensitive(category)) sensitiveOpens.push({ seq: ev.seq });
          } else if (category === 'history') {
            classify(ev, explained ? 'explained' : 'forbidden');
            findings.add('decoy.history_read', str(ev.decoy_id), {
              severity: explained ? 'low' : 'medium',
              classification: explained ? 'explained' : 'forbidden',
              title: `Read shell history ${shown}`,
              seqs: [ev.seq],
            });
          } else if (category === 'ssh_meta') {
            classify(ev, explained ? 'explained' : 'forbidden');
            findings.add('decoy.meta_read', str(ev.decoy_id), {
              severity: explained ? 'info' : 'low',
              classification: explained ? 'explained' : 'forbidden',
              title: `Read SSH metadata ${shown}`,
              seqs: [ev.seq],
            });
          } else {
            classify(ev, explained ? 'explained' : 'forbidden');
            findings.add('decoy.credential_read', str(ev.decoy_id), {
              severity: explained ? 'low' : 'high',
              classification: explained ? 'explained' : 'forbidden',
              title: `Opened ${shown} (fake ${categoryLabel(category)})`,
              seqs: [ev.seq],
            });
            if (!explained) sensitiveOpens.push({ seq: ev.seq });
          }
          break;
        }
        if (isWrite(ev)) {
          if (matchesAnyGlob(BASELINE_WRITE_OK, path)) {
            classify(ev, 'baseline');
            break;
          }
          const inContract = c.writeOk(path);
          const shown = displayPath(path);
          if (matchesAnyGlob(SHELL_STARTUP, path)) {
            classify(ev, inContract ? 'explained' : 'unexplained');
            findings.add('fs.shell_startup_write', path, {
              severity: inContract ? 'low' : 'high',
              classification: inContract ? 'explained' : 'unexplained',
              title: `${writeVerb(ev)} shell startup file ${shown}`,
              seqs: [ev.seq],
            });
          } else if (matchesAnyGlob(SCHEDULER, path)) {
            classify(ev, inContract ? 'explained' : 'unexplained');
            findings.add('fs.scheduler_write', path, {
              severity: inContract ? 'low' : 'high',
              classification: inContract ? 'explained' : 'unexplained',
              title: `${writeVerb(ev)} autostart/scheduler location ${shown}`,
              seqs: [ev.seq],
            });
          } else if (inContract) {
            classify(ev, 'explained');
          } else {
            classify(ev, 'unexplained');
            const group = writeGroup(path);
            const f = findings.add('fs.unexpected_write', group, {
              severity: 'low',
              classification: 'unexplained',
              title: '',
              seqs: [ev.seq],
            });
            f.extra.paths = f.extra.paths ?? new Set();
            f.extra.paths.add(path);
            f.title = `Wrote ${f.extra.paths.size} file${f.extra.paths.size === 1 ? '' : 's'} under ${group} not covered by the claim`;
          }
          break;
        }
        // Read of a non-decoy path: only credential-directory listing is interesting.
        const dir = matchDecoyDir(dirs, path);
        if (dir) {
          const cats = [...dirs.get(dir)];
          const explained = cats.some((cat) => !NEVER_ALLOWED.has(cat) && (c.catOk(cat) || c.ownerOk(cat)));
          classify(ev, explained ? 'explained' : 'unexplained');
          findings.add('decoy.dir_enum', dir, {
            severity: explained ? 'info' : 'low',
            classification: explained ? 'explained' : 'unexplained',
            title: `Opened credential directory ${displayPath(canonicalHomePath(dir))}`,
            seqs: [ev.seq],
          });
        }
        break;
      }

      case 'dns.query': {
        activity = true;
        const name = normalizeHost(ev.name);
        if (c.hostOk(name)) {
          classify(ev, 'explained');
        } else if (isPtrName(name)) {
          classify(ev, 'baseline');
        } else {
          classify(ev, 'unexplained');
          const entry = dnsOnly.get(name) ?? { seqs: [] };
          entry.seqs.push(ev.seq);
          dnsOnly.set(name, entry);
        }
        break;
      }

      case 'http.request':
      case 'tls.clienthello':
      case 'tls.failed': {
        activity = true;
        const host = normalizeHost(ev.kind === 'http.request' ? ev.host : ev.sni);
        const hostKey = host || '(unknown host)';
        const explained = c.hostOk(host);
        if (ev.kind === 'http.request' && ev.canned !== true && !UPLOAD_METHODS.has(str(ev.method).toUpperCase())) downloadAttempt = true;
        if (ev.kind === 'tls.failed') {
          tlsFailedHosts.add(hostKey);
          findings.add('net.tls_opaque', hostKey, {
            severity: 'info',
            classification: explained ? 'explained' : 'unexplained',
            title: `TLS to ${hostKey} could not be inspected (client rejected the test CA)`,
            seqs: [ev.seq],
          });
        }
        if (explained) {
          classify(ev, 'explained');
          break;
        }
        classify(ev, 'unexplained');
        unexpectedHosts.add(hostKey);
        findings.add('net.unexpected_host', hostKey, {
          severity: 'medium',
          classification: 'unexplained',
          title: `Contacted ${hostKey}, which the claim does not mention`,
          seqs: [ev.seq],
        });
        if (ev.kind === 'http.request' && UPLOAD_METHODS.has(str(ev.method).toUpperCase()) && num(ev.body_len) > 0) {
          const f = findings.add('net.unexpected_upload', hostKey, {
            severity: 'high',
            classification: 'unexplained',
            title: '',
            seqs: [ev.seq],
          });
          f.extra.bytes = (f.extra.bytes ?? 0) + num(ev.body_len);
          f.title = `Uploaded ${f.extra.bytes} bytes to ${hostKey}`;
          outboundSends.push({ seq: ev.seq, dest: hostKey });
        }
        break;
      }

      case 'net.connect': {
        activity = true;
        if (ev.family === 'unix') {
          classify(ev, 'baseline'); // local IPC, never leaves the sandbox
          break;
        }
        const ip = str(ev.dst_ip);
        const port = num(ev.dst_port);
        const toSink = sink ? ip === sink : isPrivateIp(ip);
        if (toSink || isLoopback(ip)) {
          classify(ev, 'baseline'); // the sinkhole answers every name, so this is any command's path
          break;
        }
        const explained = c.hostOk(ip);
        classify(ev, explained ? 'explained' : 'unexplained');
        findings.add('net.ip_literal', `${ip}:${port}`, {
          severity: explained ? 'info' : 'medium',
          classification: explained ? 'explained' : 'unexplained',
          title: `Attempted a direct connection to ${ip || '(unknown ip)'}:${port}, skipping name lookup`,
          seqs: [ev.seq],
        });
        break;
      }

      case 'tcp.connect':
      case 'udp.datagram': {
        activity = true;
        const proto = ev.kind === 'tcp.connect' ? 'tcp' : 'udp';
        const sni = normalizeHost(ev.sni);
        const explained = !!sni && c.hostOk(sni);
        const port = ev.orig_dst_port == null ? 'unknown' : String(num(ev.orig_dst_port));
        classify(ev, explained ? 'explained' : 'unexplained');
        findings.add('net.raw_socket', `${proto}:${port}`, {
          severity: explained ? 'info' : 'medium',
          classification: explained ? 'explained' : 'unexplained',
          title: `Raw ${proto} connection to port ${port}`,
          seqs: [ev.seq],
        });
        if (!explained && (proto === 'udp' || num(ev.bytes_in) > 0)) {
          outboundSends.push({ seq: ev.seq, dest: destinationOf(ev) });
        }
        break;
      }

      case 'shim.call': {
        activity = true;
        const tool = str(ev.tool);
        shimTools.add(tool);
        const inContract = c.procOk(tool);
        let rule;
        let sev;
        let title;
        let key = tool;
        // The shim only records the call; the title says what the tool is, never what the call
        // "wanted" (crontab -l lists, it does not register anything).
        const shownArgs = previewArgs(ev.args);
        const called = (what) => `Called ${tool}, ${what} (${shownArgs ? `${tool} ${shownArgs}` : tool})`;
        if (CRED_PROMPT.has(tool)) {
          rule = 'shim.credential_prompt';
          sev = 'high';
          title = called('a tool that can show password prompts or read the keychain');
        } else if (PERSIST.has(tool)) {
          rule = 'shim.persistence';
          sev = inContract ? 'low' : 'high';
          title = called('a tool that manages scheduled tasks and services');
        } else if (PRIV.has(tool)) {
          rule = 'shim.privilege';
          sev = inContract ? 'medium' : 'high';
          title = called('a tool that runs commands with elevated privileges');
        } else if (PREFS.has(tool)) {
          rule = 'shim.prefs';
          sev = inContract ? 'low' : 'medium';
          title = called('the tool that changes macOS preferences');
        } else if (AI_CLI.has(tool)) {
          rule = 'shim.ai_cli';
          sev = inContract ? 'low' : 'medium';
          title = called('an AI assistant command-line tool');
        } else if (OPENER.has(tool)) {
          rule = 'shim.opener';
          sev = inContract ? 'info' : 'low';
          const arg = previewArgs((Array.isArray(ev.args) ? ev.args : []).slice(0, 1));
          key = `${tool}|${arg}`;
          title = `Called ${tool}, which opens files and links with desktop applications (${arg ? `${tool} ${arg}` : tool})`;
        } else {
          // OS_EXEC, and any shim name the table does not list (fail safe: same weight).
          rule = 'shim.os_exec';
          sev = inContract ? 'medium' : 'high';
          title = called(OS_EXEC.has(tool) ? 'a Windows tool that can run or download code' : 'an OS-specific tool');
        }
        const explained = inContract && rule !== 'shim.credential_prompt';
        classify(ev, explained ? 'explained' : 'unexplained');
        findings.add(rule, key, {
          severity: sev,
          classification: explained ? 'explained' : 'unexplained',
          title,
          seqs: [ev.seq],
        });
        break;
      }

      case 'proc.exec': {
        const argv = Array.isArray(ev.argv) ? ev.argv.map(String) : [];
        const exe = str(ev.exe) || argv[0] || '';
        const name = basename(exe) || basename(argv[0] ?? '');
        if (!SHELLS.has(name)) activity = true;
        const inContract = c.procOk(name);

        // "Write then execute": the binary, argv[0], or (for shells and interpreters) a script
        // argument is a path this run wrote earlier.
        const cwd = str(ev.cwd);
        const candidates = [exe, str(ev.interp), argv[0] ?? ''];
        if (SHELLS.has(name) || INTERPRETERS.has(name)) candidates.push(...argv.slice(1));
        const written = candidates
          .map((p) => (p.startsWith('/') ? p : cwd && p && !p.startsWith('-') ? `${cwd.replace(/\/+$/, '')}/${p}` : ''))
          .find((p) => p && writtenPaths.has(p));
        if (written) {
          classify(ev, inContract ? 'explained' : 'unexplained');
          findings.add('proc.exec_written_file', written, {
            severity: inContract ? 'low' : 'high',
            classification: inContract ? 'explained' : 'unexplained',
            title: `Executed a file it had just written: ${displayPath(written)}`,
            seqs: [ev.seq],
          });
          break;
        }
        if (SHELLS.has(name)) break;
        if (INTERPRETERS.has(name)) {
          classify(ev, inContract ? 'explained' : 'unexplained');
          if (hasInlineFlag(argv)) {
            // Low, not medium: using an interpreter is not harm by itself; what the inline code
            // does is still caught by the other rules.
            findings.add('proc.interpreter_inline', name, {
              severity: inContract ? 'info' : 'low',
              classification: inContract ? 'explained' : 'unexplained',
              title: `Ran ${name} with inline code`,
              seqs: [ev.seq],
            });
          } else {
            const script = argv.slice(1).find((a) => !a.startsWith('-')) ?? '';
            const shown = displayPath(script).slice(0, ARGS_PREVIEW_CHARS);
            findings.add('proc.interpreter', `${name}|${shown}`, {
              severity: inContract ? 'info' : 'low',
              classification: inContract ? 'explained' : 'unexplained',
              title: `Ran ${name} ${shown}`.trimEnd(),
              seqs: [ev.seq],
            });
          }
          break;
        }
        if (NET_TOOLS.has(name)) {
          classify(ev, inContract ? 'explained' : 'unexplained');
          findings.add('proc.net_tool', name, {
            severity: inContract ? 'low' : 'medium',
            classification: inContract ? 'explained' : 'unexplained',
            title: `Used raw network tool ${name}`,
            seqs: [ev.seq],
          });
          break;
        }
        if (isDecodeHelper(name, argv)) {
          classify(ev, inContract ? 'explained' : 'unexplained');
          findings.add('proc.decode_helper', name, {
            severity: inContract ? 'info' : 'low',
            classification: inContract ? 'explained' : 'unexplained',
            title: `Ran a decoding tool (${name})`,
            seqs: [ev.seq],
          });
          break;
        }
        if (inContract) classify(ev, 'explained');
        break;
      }

      case 'exec.finished':
        execFinished = ev;
        break;

      default:
        break;
    }
  }

  // exfil.read_then_send: a forbidden SENSITIVE open, then an unexplained send, no outbound hit.
  if (!outboundCanary && sensitiveOpens.length > 0) {
    const firstOpen = sensitiveOpens[0].seq;
    for (const send of outboundSends) {
      if (send.seq <= firstOpen) continue;
      const openSeq = sensitiveOpens.filter((o) => o.seq < send.seq).map((o) => o.seq);
      findings.add('exfil.read_then_send', send.dest, {
        severity: 'critical',
        classification: 'forbidden',
        title: `Read a credential file, then sent data to ${send.dest}`,
        seqs: [...openSeq, send.seq],
      });
    }
  }

  // net.dns_only: lookups of names that never produced a net.unexpected_host finding.
  for (const [name, entry] of dnsOnly) {
    if (unexpectedHosts.has(name)) continue;
    findings.add('net.dns_only', name, {
      severity: 'low',
      classification: 'unexplained',
      title: `Looked up ${name || '(empty name)'}`,
      seqs: entry.seqs,
    });
  }

  // unwrap.hidden_code: deterministic decoder layers with an exec marker.
  const detLayers = (Array.isArray(layers) ? layers : []).filter(
    (l) => l && l.llm_assisted !== true && l.method !== 'harness' && (l.status === 'ok' || l.status === 'truncated'),
  );
  if (detLayers.some((l) => Array.isArray(l.markers?.exec) && l.markers.exec.length > 0)) {
    findings.add('unwrap.hidden_code', 'layers', {
      severity: 'low',
      classification: 'unexplained',
      title: `The command contains ${detLayers.length} layer${detLayers.length === 1 ? '' : 's'} of encoded code`,
      seqs: [],
    });
  }

  // run.timeout / run.no_activity / exit code.
  const execInfo = {
    timed_out: exec?.timed_out === true || execFinished?.timed_out === true || cov.timed_out === true,
    exit_code: exec?.exit_code ?? execFinished?.exit_code ?? null,
  };
  if (execInfo.timed_out) {
    if (execFinished) classify(execFinished, 'unexplained');
    findings.add('run.timeout', 'run', {
      severity: 'medium',
      classification: 'unexplained',
      title: 'Did not finish within 60 s',
      seqs: execFinished ? [execFinished.seq] : [],
    });
  } else if (execFinished) {
    classify(execFinished, 'baseline');
  }
  const oomKilled = cov.oom_killed === true;
  if (oomKilled) {
    if (execFinished) classify(execFinished, 'unexplained');
    findings.add('run.oom', 'run', {
      severity: 'medium',
      classification: 'unexplained',
      title: 'Used more memory than the sandbox allows and was stopped',
      seqs: execFinished ? [execFinished.seq] : [],
    });
  }
  const noActivity = !activity;
  const printedOutput =
    num(exec?.stdout_bytes ?? execFinished?.stdout_bytes) + num(exec?.stderr_bytes ?? execFinished?.stderr_bytes) > 0;
  if (noActivity) {
    findings.add('run.no_activity', 'run', {
      severity: 'info',
      classification: 'unexplained',
      title: printedOutput
        ? 'Only printed text; no file, network or program activity was observed'
        : 'No activity observed in the sandbox',
      seqs: execFinished ? [execFinished.seq] : [],
    });
  }

  // --- assemble findings -------------------------------------------------------------------
  const all = findings.values().map((f) => {
    const seqs = [...f.seqs].sort((a, b) => a - b);
    const first = seqs.length > 0 ? seqs[0] : 0;
    return {
      id: `${f.rule_id}:${first}`,
      rule_id: f.rule_id,
      severity: f.severity,
      classification: f.classification,
      title: f.title,
      event_seqs: seqs.slice(0, MAX_SEQS_PER_FINDING),
      _first: first,
    };
  });
  all.sort(
    (a, b) =>
      SEV_RANK[b.severity] - SEV_RANK[a.severity] ||
      a._first - b._first ||
      (a.rule_id < b.rule_id ? -1 : a.rule_id > b.rule_id ? 1 : 0) ||
      (a.title < b.title ? -1 : a.title > b.title ? 1 : 0),
  );
  // Two groups of the same rule can share a first seq (e.g. one event feeding two hosts is
  // impossible, but a scrubbed title collision is not), so ids are made unique by suffix.
  const seenIds = new Map();
  for (const f of all) {
    const n = seenIds.get(f.id) ?? 0;
    seenIds.set(f.id, n + 1);
    if (n > 0) f.id = `${f.id}#${n}`;
  }

  // Verdict is computed over all findings, before the 200 cap, so trimming never lowers it.
  let maxSev = -1;
  const deciding = new Set();
  for (const f of all) {
    maxSev = Math.max(maxSev, SEV_RANK[f.severity]);
    if (SEV_RANK[f.severity] >= SEV_RANK.medium) deciding.add(f.rule_id);
  }
  const level = maxSev >= SEV_RANK.critical ? 'MALICIOUS' : maxSev >= SEV_RANK.medium ? 'SUSPICIOUS' : 'CLEAN';

  let kept = all;
  if (all.length > MAX_FINDINGS) {
    kept = all.slice(0, MAX_FINDINGS);
    const dropped = all.slice(MAX_FINDINGS);
    const sinkIdx = findLastIndex(kept, (f) => f.rule_id === 'fs.unexpected_write' || f.rule_id === 'net.unexpected_host');
    if (sinkIdx !== -1) {
      const target = kept[sinkIdx];
      const merged = new Set(target.event_seqs);
      for (const d of dropped) for (const s of d.event_seqs) merged.add(s);
      target.event_seqs = [...merged].sort((a, b) => a - b).slice(0, MAX_SEQS_PER_FINDING);
      target.title += ` (and ${dropped.length} more findings merged here)`;
    }
  }
  const finalFindings = kept.map(({ _first, ...f }) => f);

  const remoteMarker =
    downloadAttempt ||
    unwrap?.stopped === 'remote' ||
    unwrap?.harness?.stoppedReason === 'remote' ||
    (Array.isArray(layers) ? layers : []).some((l) => Array.isArray(l?.markers?.remote) && l.markers.remote.length > 0);
  const coverageNotes = buildCoverageNotes({
    level,
    tlsFailedHosts: [...tlsFailedHosts, ...(Array.isArray(cov.tls_unreadable) ? cov.tls_unreadable.map((t) => normalizeHost(t?.sni)) : [])],
    timedOut: execInfo.timed_out,
    noActivity,
    printedOutput,
    contractFallback: contractMeta?.source === 'fallback' || contractMeta?.source === undefined && contract?.source === 'fallback',
    shimTools: [...shimTools],
    harnessGaveUp: harnessUnclean(layers, unwrap),
    remoteMarker,
    evidenceMode: str(cov.mode),
    exitCode: execInfo.exit_code,
    coverage: cov,
  });

  return {
    findings: finalFindings,
    verdict: { level, rule_ids: [...deciding].sort(), coverage_notes: coverageNotes },
    classifications,
  };
}

/**
 * The harness loop (8.3) stops with `clean | remote | gave_up | too_large | budget | max_layers |
 * llm_disabled | aborted`. Only `clean` means every inner layer was decoded; anything else,
 * including a value this code does not know, must be said out loud (fail safe). No harness at
 * all (`unwrap.harness` null/absent and no harness layer) is not a failure.
 */
function harnessUnclean(layers, unwrap) {
  const layerList = Array.isArray(layers) ? layers : [];
  if (layerList.some((l) => l?.method === 'harness' && l.status !== 'ok')) return true;
  const harness = unwrap?.harness;
  if (harness && typeof harness === 'object') return harness.stoppedReason !== 'clean';
  const legacy = unwrap?.stoppedReason;
  if (legacy !== undefined && legacy !== null) return legacy !== 'clean';
  return false;
}

function findLastIndex(arr, pred) {
  for (let i = arr.length - 1; i >= 0; i--) if (pred(arr[i])) return i;
  return -1;
}

/** 9.3 coverage notes, always in table order, plus partial-evidence notes (7.2, 7.3). */
export function buildCoverageNotes({
  level = 'SUSPICIOUS',
  tlsFailedHosts = [],
  timedOut = false,
  noActivity = false,
  printedOutput = false,
  contractFallback = false,
  shimTools = [],
  harnessGaveUp = false,
  remoteMarker = false,
  evidenceMode = '',
  exitCode = null,
  coverage = {},
}) {
  // "CLEAN means ..." only makes sense under a CLEAN banner; the others get the neutral limit.
  const notes = [level === 'CLEAN' ? NOTE_CLEAN_MEANS : NOTE_LIMITS, NOTE_SINKHOLED];
  if (remoteMarker) notes.push(NOTE_DOWNLOAD);
  const tls = sortedUnique(tlsFailedHosts.filter(Boolean));
  if (tls.length > 0) {
    notes.push(
      `TLS to ${listHosts(tls)} could not be inspected (client rejected the test CA); the destination is proven, the content is not.`,
    );
  }
  if (timedOut) notes.push('The command did not finish within 60 s; later behaviour was not observed.');
  if (coverage.oom_killed === true) {
    notes.push('The command used more memory than the sandbox allows and was stopped, so the rest of the command did not run.');
  }
  if (noActivity) {
    notes.push(
      printedOutput
        ? 'The command only printed text; no file, network or program activity was observed.'
        : 'No activity observed; the command may require an interactive terminal or an OS feature this sandbox does not provide.',
    );
  }
  if (contractFallback) {
    notes.push('The claim could not be turned into a contract; every host and path is treated as unexplained.');
  }
  const shims = sortedUnique(shimTools.filter(Boolean));
  if (shims.length > 0) {
    notes.push(
      `OS-specific tools (${shims.join(', ')}) were recorded, not executed; behaviour on a real macOS/Windows machine may differ.`,
    );
  }
  if (harnessGaveUp) {
    notes.push('Inner layers of the command could not be fully decoded; the verdict rests on runtime evidence only.');
  }
  if (evidenceMode === 'strace') {
    notes.push('Evidence came from the fallback tracer; some paths or arguments may be truncated.');
  }
  // A timeout or OOM already has its own note; a plain non-zero exit gets this one.
  if (exitCode !== null && exitCode !== undefined && num(exitCode) !== 0 && !timedOut && coverage.oom_killed !== true) {
    notes.push(
      `The command ended with an error (exit code ${num(exitCode)}), so part of it may not have run; what it would have done after that point was not observed. This can also happen when a command hits the sandbox's process limit.`,
    );
  }
  // Partial evidence (7.2 / 7.3): a CLEAN with gaps must say so.
  const dropped = num(coverage.gvisor_dropped) + num(coverage.decode_errors);
  const capped = coverage.capped && typeof coverage.capped === 'object' ? Object.values(coverage.capped).reduce((a, b) => a + num(b), 0) : 0;
  if (dropped > 0 || capped > 0) {
    const parts = [];
    if (dropped > 0) parts.push(`${dropped} trace record${dropped === 1 ? ' was' : 's were'} lost`);
    if (capped > 0) parts.push(`${capped} event${capped === 1 ? ' was' : 's were'} cut by the per-run cap`);
    notes.push(`Evidence is incomplete: ${parts.join(' and ')}; some file, process or network activity may be missing from this report.`);
  }
  if (coverage.t0_seen === false || coverage.no_t0 === true) {
    notes.push('The sandbox start marker was never seen, so file and process activity inside the sandbox was not observed.');
  }
  if (coverage.scan_truncated === true) {
    notes.push('Not all network traffic could be scanned for the fake credentials; a leak may have gone unnoticed.');
  }
  return notes;
}
