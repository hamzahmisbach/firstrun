// Canary matcher (docs/ARCHITECTURE.md 6.6). Runs only in the orchestrator process: the manifest
// never enters a container. Patterns are prepared once per run; every sinkhole record is scanned
// byte-wise in five places (url, header, body, dns names, first TCP/UDP bytes) and the first form
// that matches yields one canary.hit per (decoy_id, event_seq).
import path from 'node:path';
import { EVIDENCE_LIMITS } from './schema.mjs';
import { openRegular } from './sink-reader.mjs';

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32(bytes) {
  let out = '';
  let acc = 0;
  let bits = 0;
  for (const b of bytes) {
    acc = ((acc << 8) | b) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32[(acc >>> bits) & 31];
    }
  }
  if (bits > 0) out += BASE32[(acc << (5 - bits)) & 31];
  return out;
}

/**
 * The characters of encode(prefix + value + suffix) that do not depend on the neighbouring bytes,
 * for one alignment `k` (number of unknown bytes before the value): encode with two different
 * fillings and keep the common middle. Works for any block encoding (base64: 3, base32: 5).
 */
export function stableEncoding(value, k, encode, blockSize) {
  const pad = blockSize + 1;
  const a = encode(Buffer.concat([Buffer.alloc(k, 0x00), value, Buffer.alloc(pad, 0x00)]));
  const b = encode(Buffer.concat([Buffer.alloc(k, 0xff), value, Buffer.alloc(pad, 0xff)]));
  // Chars that encode any filling bit differ between a and b (0x00 vs 0xff), so the longest run
  // of equal chars is exactly the part determined by `value` alone.
  let bestStart = 0;
  let bestLen = 0;
  let runStart = 0;
  for (let i = 0; i <= a.length; i++) {
    if (i === a.length || a[i] !== b[i]) {
      if (i - runStart > bestLen) {
        bestLen = i - runStart;
        bestStart = runStart;
      }
      runStart = i + 1;
    }
  }
  return a.slice(bestStart, bestStart + bestLen);
}

const b64 = (buf) => buf.toString('base64');
const b32 = (buf) => base32(buf);

/** All byte patterns for one value, in the manifest's form order; duplicates keep the first form. */
export function patternsFor(value, forms, minBytes = EVIDENCE_LIMITS.matcher.minPatternBytes) {
  const raw = Buffer.from(value, 'utf8');
  const out = [];
  const seen = new Set();
  const add = (form, text) => {
    const buf = Buffer.isBuffer(text) ? text : Buffer.from(text, 'latin1');
    if (buf.length < minBytes) return;
    const key = buf.toString('latin1');
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ form, bytes: buf, lower: Buffer.from(key.toLowerCase(), 'latin1') });
  };
  for (const form of forms) {
    switch (form) {
      case 'raw':
        add('raw', raw);
        break;
      case 'b64x3':
        for (let k = 0; k < 3; k++) add('b64x3', stableEncoding(raw, k, b64, 3));
        break;
      case 'b64b64x3':
        for (let k = 0; k < 3; k++) {
          const inner = Buffer.from(stableEncoding(raw, k, b64, 3), 'latin1');
          for (let j = 0; j < 3; j++) add('b64b64x3', stableEncoding(inner, j, b64, 3));
        }
        break;
      case 'url':
        add('url', encodeURIComponent(value));
        break;
      case 'hex':
        add('hex', raw.toString('hex'));
        add('hex', raw.toString('hex').toUpperCase());
        break;
      case 'base32':
        for (let k = 0; k < 5; k++) add('base32', stableEncoding(raw, k, b32, 5));
        break;
      default:
        break;
    }
  }
  return out;
}

/** DNS names: lower-case, labels joined without dots so a token split across labels still matches. */
function dnsBytes(name) {
  return Buffer.from(String(name).toLowerCase().replace(/\./g, ''), 'latin1');
}

/** First `maxBytes` of bodies/<id>.bin; `null` when missing, `false` when it is not a regular file. */
async function readBodyFile(filePath, maxBytes) {
  let fh;
  try {
    ({ fh } = await openRegular(filePath));
  } catch (err) {
    return err.code === 'ENOTREGULAR' || err.code === 'ELOOP' ? false : null;
  }
  try {
    const buf = Buffer.allocUnsafe(maxBytes);
    const { bytesRead } = await fh.read(buf, 0, maxBytes, 0);
    return buf.subarray(0, bytesRead);
  } finally {
    await fh.close();
  }
}

/**
 * @param {object} opts
 * @param {Array} opts.decoys manifest (5.3)
 * @param {string} [opts.sinkholeDir] where `bodies/<id>.bin` live (body_ref)
 */
export function createMatcher({ decoys = [], sinkholeDir = null, limits = EVIDENCE_LIMITS.matcher } = {}) {
  const targets = [];
  for (const d of decoys) {
    if (typeof d.value !== 'string' || !d.value || !Array.isArray(d.forms) || !d.forms.length) continue;
    const patterns = patternsFor(d.value, d.forms, limits.minPatternBytes);
    if (patterns.length) targets.push({ decoy_id: d.id, category: d.category, patterns });
  }
  let scanned = 0;
  let truncated = 0;
  let decodeErrors = 0;

  function budget(bytes) {
    if (scanned + bytes > limits.scanBudgetBytes) {
      truncated += 1;
      return false;
    }
    scanned += bytes;
    return true;
  }

  /**
   * Scan `locations` = [{where, bytes, lower?}] and return at most one hit per decoy:
   * the first location, then the first form, that matches.
   */
  function scanLocations(locations, candidates = targets) {
    const hits = [];
    const live = locations.filter((l) => l.bytes && l.bytes.length >= limits.minPatternBytes && budget(l.bytes.length));
    if (!live.length) return hits;
    for (const target of candidates) {
      let hit = null;
      for (const loc of live) {
        for (const p of target.patterns) {
          const needle = loc.lower ? p.lower : p.bytes;
          if (loc.bytes.indexOf(needle) !== -1) {
            hit = { decoy_id: target.decoy_id, category: target.category, form: p.form, where: loc.where };
            break;
          }
        }
        if (hit) break;
      }
      if (hit) hits.push(hit);
    }
    return hits;
  }

  /** Locations of one raw sinkhole record (events.jsonl, tcp.jsonl, dns.query). */
  async function locationsOf(record) {
    const out = [];
    switch (record.kind) {
      case 'http.request': {
        const url = `${record.host ?? ''}${record.path ?? ''}${record.query ? `?${record.query}` : ''}`;
        out.push({ where: 'url', bytes: Buffer.from(url, 'utf8') });
        const headers = record.headers && typeof record.headers === 'object' ? Object.entries(record.headers) : [];
        if (headers.length) {
          out.push({ where: 'header', bytes: Buffer.from(headers.map(([k, v]) => `${k}: ${v}`).join('\n'), 'utf8') });
        }
        if (typeof record.body_b64 === 'string' && record.body_b64) {
          out.push({ where: 'body', bytes: Buffer.from(record.body_b64, 'base64') });
        } else if (typeof record.body_ref === 'string' && sinkholeDir && /^bodies\/[A-Za-z0-9_.-]+$/.test(record.body_ref)) {
          const body = await readBodyFile(path.join(sinkholeDir, record.body_ref), limits.bodyMaxBytes);
          if (body === false) decodeErrors += 1;
          else if (body) out.push({ where: 'body', bytes: body });
        }
        out.push({ where: 'dns', bytes: dnsBytes(record.host ?? ''), lower: true });
        break;
      }
      case 'dns.query':
        out.push({ where: 'dns', bytes: dnsBytes(record.name ?? ''), lower: true });
        break;
      case 'tls.clienthello':
      case 'tls.failed':
        out.push({ where: 'dns', bytes: dnsBytes(record.sni ?? ''), lower: true });
        break;
      case 'tcp.connect':
      case 'udp.datagram':
        if (typeof record.first_bytes_hex === 'string' && record.first_bytes_hex) {
          out.push({ where: 'tcp_bytes', bytes: Buffer.from(record.first_bytes_hex, 'hex') });
        }
        if (typeof record.sni === 'string' && record.sni) out.push({ where: 'dns', bytes: dnsBytes(record.sni), lower: true });
        break;
      default:
        break;
    }
    return out;
  }

  return {
    patternCount: () => targets.reduce((n, t) => n + t.patterns.length, 0),
    /** Hits for one sinkhole record; `eventSeq` is the seq of its normalized event. */
    async scan(record, eventSeq) {
      if (!targets.length || !record) return [];
      const locations = await locationsOf(record);
      return scanLocations(locations).map((h) => ({ ...h, event_seq: eventSeq }));
    },
    /**
     * Hits in the command's stdout/stderr; `where` is reported as given. The `pw` canary is
     * skipped here: every shim prints it by design (5.4), so on stdout it proves nothing. Only
     * file-based tokens count, and `pw` still matches outbound through scan().
     */
    scanBytes(bytes, where) {
      if (!targets.length || !bytes?.length) return [];
      const fileTargets = targets.filter((t) => t.category !== 'phished_input');
      return scanLocations([{ where, bytes }], fileTargets).map((h) => ({ ...h, event_seq: null }));
    },
    scannedBytes: () => scanned,
    truncated: () => truncated > 0,
    /** body_ref files that were symlinks or otherwise not regular files (never followed). */
    decodeErrors: () => decodeErrors,
  };
}
