// Allowlisted projection for the explanation writer (docs/ARCHITECTURE.md 8.4, 8.6 item 3).
// Only named fields are copied; stdout/stderr, request bodies, the decoy manifest, shim/argv
// text and canary values in any form never reach this object. Pure: no I/O.
import { displayPath, normalizeHost } from '../rules/paths.mjs';

export const EVIDENCE_SUMMARY_MAX = 200;
export const LAYER_PREVIEW_MAX = 300;
export const MAX_FINDINGS_IN_INPUT = 50;

const FORM_WORDS = Object.freeze({
  raw: 'in plain text',
  b64x3: 'base64-encoded',
  b64b64x3: 'double base64-encoded',
  url: 'percent-encoded',
  hex: 'hex-encoded',
  base32: 'base32-encoded',
});

const WHERE_WORDS = Object.freeze({
  url: 'in the request URL',
  header: 'in a request header',
  body: 'in the request body',
  dns: 'in a DNS name',
  tcp_bytes: 'in raw bytes sent',
  stdout: 'in the program output',
  stderr: 'in the program output',
});

function cut(text, max) {
  if (typeof text !== 'string') return '';
  const chars = [...text];
  return chars.length > max ? chars.slice(0, max - 1).join('') + '…' : text;
}

function whereWords(where) {
  const w = typeof where === 'string' ? where : '';
  if (WHERE_WORDS[w]) return WHERE_WORDS[w];
  const prefix = w.split('.')[0];
  if (w.startsWith('http.')) return `in the ${w.slice(5)} of an HTTP request`;
  if (prefix === 'dns' || prefix === 'tls') return 'in a DNS or TLS name';
  if (prefix === 'tcp' || prefix === 'udp') return 'in raw bytes sent';
  if (prefix === 'stdout' || prefix === 'stderr') return 'in the program output';
  return 'in network traffic';
}

/** One plain sentence per event, built only from the fields listed here. */
export function summarizeEvent(ev, { decoyPathById = new Map(), bySeq = new Map() } = {}) {
  if (!ev || typeof ev !== 'object') return '';
  switch (ev.kind) {
    case 'canary.hit': {
      const path = decoyPathById.get(ev.decoy_id) ?? 'a fake credential file';
      const form = FORM_WORDS[ev.form] ?? 'encoded';
      const ref = bySeq.get(ev.event_seq);
      let dest = '';
      if (ref?.kind === 'http.request') dest = ` to host ${normalizeHost(ref.host) || 'unknown'} (${String(ref.method ?? '').toUpperCase() || 'request'})`;
      else if (ref?.kind === 'dns.query' || ref?.kind === 'tls.clienthello' || ref?.kind === 'tls.failed') dest = ` to ${normalizeHost(ref.name ?? ref.sni) || 'an unknown name'}`;
      else if (ref?.kind === 'tcp.connect' || ref?.kind === 'udp.datagram') dest = ` to port ${ref.orig_dst_port ?? 'unknown'}`;
      return `canary from ${path} seen ${form} ${whereWords(ev.where)}${dest}`;
    }
    case 'file.open': {
      const verb = ev.access === 'read' ? 'read' : ev.access === 'create' ? 'created' : 'wrote';
      return `${verb} ${displayPath(ev.path)}${ev.ok === false ? ' (failed)' : ''}`;
    }
    case 'file.delete':
      return `deleted ${displayPath(ev.path)}${ev.ok === false ? ' (failed)' : ''}`;
    case 'file.rename':
      return `moved ${displayPath(ev.from)}${typeof ev.to === 'string' ? ` to ${displayPath(ev.to)}` : ' away'}${ev.ok === false ? ' (failed)' : ''}`;
    case 'file.chmod':
      return `changed permissions of ${displayPath(ev.path)}${ev.ok === false ? ' (failed)' : ''}`;
    case 'file.truncate':
      return `emptied ${displayPath(ev.path)}${ev.ok === false ? ' (failed)' : ''}`;
    case 'file.link':
      return `made a ${ev.link === 'symlink' ? 'symbolic link' : 'hard link'} to ${displayPath(ev.from)}${ev.ok === false ? ' (failed)' : ''}`;
    case 'dir.remove':
      return `removed folder ${displayPath(ev.path)}${ev.ok === false ? ' (failed)' : ''}`;
    case 'dir.create':
      return `created folder ${displayPath(ev.path)}`;
    case 'http.request':
      return `${String(ev.method ?? '').toUpperCase() || 'request'} to ${normalizeHost(ev.host) || 'unknown host'}${ev.body_len > 0 ? ` with ${ev.body_len} bytes` : ''}`;
    case 'tls.clienthello':
      return `TLS connection to ${normalizeHost(ev.sni) || 'unknown host'} port ${ev.port ?? '?'}`;
    case 'tls.failed':
      return `TLS to ${normalizeHost(ev.sni) || 'unknown host'} rejected the test certificate`;
    case 'dns.query':
      return `looked up ${normalizeHost(ev.name) || 'an unknown name'}`;
    case 'net.connect':
      return ev.family === 'unix' ? 'local socket connection' : `connection to ${ev.dst_ip ?? '?'} port ${ev.dst_port ?? '?'}`;
    case 'tcp.connect':
      return `raw tcp connection to port ${ev.orig_dst_port ?? 'unknown'}${ev.bytes_in > 0 ? ` sending ${ev.bytes_in} bytes` : ''}`;
    case 'udp.datagram':
      return `udp packet of ${ev.len ?? '?'} bytes${ev.orig_dst_port != null ? ` to port ${ev.orig_dst_port}` : ''}`;
    case 'shim.call':
      return `called ${ev.tool ?? 'an OS tool'}`;
    case 'proc.exec': {
      const argv = Array.isArray(ev.argv) ? ev.argv : [];
      const name = displayPath(String(ev.exe ?? argv[0] ?? '')).split('/').pop();
      return `ran ${name || 'a program'}`;
    }
    case 'exec.finished':
      return ev.timed_out ? 'the command was stopped at the time limit' : `the command exited with code ${ev.exit_code ?? 0}`;
    default:
      return '';
  }
}

/**
 * @param {object} args
 * @param {{claim?: string}} args.input the run input; only `claim` is used
 * @param {object} args.verdict `{level, rule_ids, coverage_notes}`
 * @param {object[]} args.findings
 * @param {object[]} [args.layers]
 * @param {object} args.contract
 * @param {object} [args.coverage] unused beyond `notes` fallback; verdict.coverage_notes wins
 * @param {object[]} [args.events] lets `evidence_summary` name hosts/paths/bytes; optional
 * @param {object[]} [args.decoys] only `id` and `path` are read (for "canary from ~/x")
 */
export function buildExplanationInput({ input, verdict, findings, layers, contract, coverage, events, decoys, review, attempts }) {
  const bySeq = new Map((Array.isArray(events) ? events : []).filter((e) => e && Number.isInteger(e.seq)).map((e) => [e.seq, e]));
  const decoyPathById = new Map(
    (Array.isArray(decoys) ? decoys : [])
      .filter((d) => d && typeof d.id === 'string' && typeof d.path === 'string')
      .map((d) => [d.id, displayPath(d.path.startsWith('~/') ? '/home/dev' + d.path.slice(1) : d.path)]),
  );
  const level = verdict?.level ?? 'CLEAN';
  const coverageNotes = Array.isArray(verdict?.coverage_notes)
    ? verdict.coverage_notes
    : Array.isArray(coverage?.notes)
      ? coverage.notes
      : [];
  const c = contract && typeof contract === 'object' ? contract : {};
  const strList = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string').map((x) => cut(x, 256)) : []);

  const projectedFindings = (Array.isArray(findings) ? findings : []).slice(0, MAX_FINDINGS_IN_INPUT).map((f) => {
    const parts = [];
    // The canary sentence leads ("canary from ~/x seen ... to host Y"), then the rest by seq.
    const isHit = (s) => (bySeq.get(s)?.kind === 'canary.hit' ? 1 : 0);
    const seqs = (Array.isArray(f.event_seqs) ? f.event_seqs : []).slice().sort((a, b) => isHit(b) - isHit(a) || a - b);
    for (const seq of seqs) {
      const s = summarizeEvent(bySeq.get(seq), { decoyPathById, bySeq });
      if (s && !parts.includes(s)) parts.push(s);
      if (parts.join('; ').length > EVIDENCE_SUMMARY_MAX) break;
    }
    return {
      id: String(f.id ?? ''),
      rule_id: String(f.rule_id ?? ''),
      severity: String(f.severity ?? ''),
      classification: String(f.classification ?? ''),
      title: cut(String(f.title ?? ''), 300),
      evidence_summary: cut(parts.join('; '), EVIDENCE_SUMMARY_MAX),
    };
  });

  const projectedLayers = (Array.isArray(layers) ? layers : [])
    .filter((l) => l && typeof l === 'object')
    .map((l) => ({
      index: Number.isInteger(l.index) ? l.index : 0,
      method: typeof l.method === 'string' ? l.method : 'unknown',
      llm_assisted: l.llm_assisted === true,
      preview: cut(typeof l.preview === 'string' ? l.preview : typeof l.text === 'string' ? l.text : '', LAYER_PREVIEW_MAX),
    }));

  return {
    verdict: { level, rule_ids: strList(verdict?.rule_ids), coverage_notes: coverageNotes.map((n) => cut(n, 400)) },
    claim: cut(typeof input?.claim === 'string' ? input.claim : '', 300),
    contract: {
      summary: cut(typeof c.summary === 'string' ? c.summary : '', 300),
      expected_hosts: strList(c.expected_hosts),
      expected_write_paths: strList(c.expected_write_paths),
      expected_processes: strList(c.expected_processes),
      allowed_decoy_categories: strList(c.allowed_decoy_categories),
      notes: cut(typeof c.notes === 'string' ? c.notes : '', 500),
    },
    findings: projectedFindings,
    layers: projectedLayers,
    coverage_notes: coverageNotes.map((n) => cut(n, 400)),
    ai_review:
      review && typeof review === 'object'
        ? {
            risk: String(review.risk ?? 'none'),
            summary: cut(String(review.summary ?? ''), 300),
            real_machine_effects: strList(review.real_machine_effects).map((s) => cut(s, 200)).slice(0, 6),
          }
        : null,
    ran_twice: Array.isArray(attempts) && attempts.length > 1 && attempts[1]?.failed !== true,
  };
}
