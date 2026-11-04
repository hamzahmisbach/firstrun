// Deterministic decoder (docs/ARCHITECTURE.md 8.2): a pure string function that peels literal
// encoding layers off a command. No I/O, no eval, no child_process. Every pattern is a character
// class with a minimum length, so nothing backtracks quadratically; the input is already capped at
// 16 KiB by the API and each layer scan at 256 KiB here. It never judges: it only produces layers.
import { createHash } from 'node:crypto';
import zlib from 'node:zlib';

export const DECODER_LIMITS = Object.freeze({
  maxDepth: 8,
  maxChildren: 8,
  maxLayers: 32,
  scanMaxBytes: 256 * 1024,
  textMaxBytes: 64 * 1024, // layer.text kept in the report
  inflateMaxBytes: 1024 * 1024,
  timeMs: 2000,
  maxSubstitutions: 200,
});

// Marker vocabulary (8.2): what the UI, the harness prompt and rule unwrap.hidden_code look at.
const EXEC_MARKERS = [
  ['eval', /(?<![\w.$])eval\b(?!\s*\()/],
  ['| bash', /\|\s*(?:sudo\s+)?bash\b/],
  ['| sh', /\|\s*(?:sudo\s+)?(?:sh|dash|zsh)\b/],
  ['bash -c', /\bbash\s+-c\b/],
  ['sh -c', /\b(?:sh|dash|zsh)\s+-c\b/],
  ['source <(', /\bsource\s+<\(/],
  ['. <(', /(?:^|[\s;])\.\s+<\(/],
  ['exec', /(?:^|[\s;&|])exec\s+[^\s>&]/],
  ['bash <(', /\b(?:bash|sh)\s+<\(/],
  ['iex', /\biex\b/i],
  ['Invoke-Expression', /\bInvoke-Expression\b/i],
  ['-EncodedCommand', /\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*\s-(?:EncodedCommand|enc|ec|e)\b/i],
  ['[ScriptBlock]::Create', /\[ScriptBlock\]::Create/i],
  ['Invoke-Command', /\bInvoke-Command\b/i],
  ['& (', /(?<!&)&\s*\(/],
  ['.(', /(?:^|\s)\.\s*\((?!\))/],
  ['exec(', /\bexec\s*\(/],
  ['eval(', /\beval\s*\(/],
  ['compile(', /\bcompile\s*\(/],
  ['os.system', /\bos\.(?:system|popen)\b/],
  ['subprocess', /\bsubprocess\b/],
  ['new Function(', /\bnew\s+Function\s*\(/],
  ['child_process', /\bchild_process\b/],
  ['vm.run', /\bvm\.run[A-Za-z]*\s*\(/],
];
const DECODE_MARKERS = [
  ['base64 -d', /\bbase64\s+(?:-d|-D|--decode)\b/],
  ['FromBase64String', /FromBase64String/i],
  ['openssl enc -d', /\bopenssl\s+(?:enc|base64)\b[^\n]*\s-d\b/],
  ['xxd -r', /\bxxd\s+-r\b/],
  ['gunzip', /\b(?:gunzip|zcat|gzip\s+-d[c]?)\b/],
  ['b64decode', /\bb64decode\b/],
  ["Buffer.from(..., 'base64')", /Buffer\.from\([^)\n]*['"](?:base64|hex)['"]/],
  ['IO.Compression', /IO\.Compression/i],
  ['fromhex', /\b(?:fromhex|unhexlify)\b/],
  ['[char]', /\[char\]\s*\d/i],
  ['-join', /-join\b/i],
];
const REMOTE_MARKERS = [
  ['curl', /\bcurl\b/],
  ['wget', /\bwget\b/],
  ['Invoke-WebRequest', /\b(?:Invoke-WebRequest|iwr)\b/i],
  ['Invoke-RestMethod', /\b(?:Invoke-RestMethod|irm)\b/i],
  ['Net.WebClient', /Net\.WebClient/i],
  ['DownloadString', /\bDownload(?:String|File|Data)\b/i],
  ['fetch(', /\bfetch\s*\(/],
  ['urllib', /\burllib\b/],
  ['requests.get', /\brequests\.(?:get|post)\b/],
  ['http.get', /\bhttps?\.(?:get|request)\b/],
];

/** Marker scan of one text: `{exec[], remote[], decode[], opaque}`; opaque is filled by the layer scan. */
export function scanMarkers(text) {
  const hits = (table) => table.filter(([, re]) => re.test(text)).map(([name]) => name);
  return { exec: hits(EXEC_MARKERS), remote: hits(REMOTE_MARKERS), decode: hits(DECODE_MARKERS), opaque: 0 };
}

const LANGUAGE_HINTS = {
  pwsh: [
    /\b(?:Invoke-Expression|iex|Invoke-WebRequest|Invoke-RestMethod|New-Object|Write-Host|Write-Output|Start-Process|Set-ExecutionPolicy)\b/i,
    /\$env:|\[System\.|\[Convert\]::|\[Text\.Encoding\]|\[IO\.|\[char\]|-join\b|-EncodedCommand\b|\bpowershell(?:\.exe)?\b/i,
  ],
  python3: [/^\s*(?:import|from)\s+[A-Za-z_]/m, /\b(?:b64decode|__import__|os\.system|subprocess\.|print\s*\()/, /\bexec\s*\(/],
  node: [/\brequire\s*\(/, /\bBuffer\.from\b/, /\bprocess\.(?:env|argv|stdout)\b/, /\bchild_process\b|\bnew\s+Function\s*\(/],
};

/** Deterministic interpreter guess for the harness prompt (8.3): shebang first, then marker counts. */
export function guessLanguage(text) {
  const head = String(text).slice(0, 200);
  const shebang = /^#!\s*\S*?(python|node|bash|sh|zsh|dash|pwsh)\b/.exec(head);
  if (shebang) {
    const name = shebang[1];
    if (name === 'python') return 'python3';
    if (name === 'node') return 'node';
    if (name === 'pwsh') return 'pwsh';
    return 'bash';
  }
  let best = 'bash';
  let bestScore = 0;
  for (const [lang, patterns] of Object.entries(LANGUAGE_HINTS)) {
    const score = patterns.filter((re) => re.test(text)).length;
    if (score > bestScore) {
      best = lang;
      bestScore = score;
    }
  }
  return best;
}

function sha256(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function controlRatioOk(text) {
  if (text.length === 0) return false;
  let bad = 0;
  for (let i = 0; i < text.length; i += 1) {
    const c = text.charCodeAt(i);
    if ((c < 0x20 && c !== 9 && c !== 10 && c !== 13) || c === 0x7f || c === 0xfffd) bad += 1;
  }
  return bad / text.length < 0.02;
}

const utf8 = new TextDecoder('utf-8', { fatal: true });

/** Accept decoded bytes as text (8.2 step 3 a-b). Returns `{text, utf16}` or null. */
function bytesToText(buf) {
  if (buf.length === 0) return null;
  if (buf.length >= 4 && buf.length % 2 === 0) {
    let zeros = 0;
    for (let i = 1; i < buf.length; i += 2) if (buf[i] === 0) zeros += 1;
    if (zeros / (buf.length / 2) >= 0.9) {
      const text = buf.toString('utf16le').replace(/\0+$/, '');
      return controlRatioOk(text) ? { text, utf16: true } : null;
    }
  }
  let text;
  try {
    text = utf8.decode(buf);
  } catch {
    return null;
  }
  return controlRatioOk(text) ? { text, utf16: false } : null;
}

/** gzip / zlib / raw deflate with the 1 MiB output cap. Returns `{bytes}`, `{overflow: true}` or null. */
function inflate(buf, method) {
  const fn = method === 'gzip' ? zlib.gunzipSync : method === 'deflate' ? zlib.inflateSync : zlib.inflateRawSync;
  try {
    return { bytes: fn(buf, { maxOutputLength: DECODER_LIMITS.inflateMaxBytes }) };
  } catch (err) {
    return err?.code === 'ERR_BUFFER_TOO_LARGE' ? { overflow: true } : null;
  }
}

const RAW_DEFLATE_HINT = /DeflateStream|inflateRaw|zlib\.decompress\([^)\n]*-15\)/;

/**
 * Turn decoded bytes into a child candidate (text or compressed text). `method` is the outer
 * method (base64 / hex / hex_escape); compression replaces it.
 */
function bytesToChild(bytes, method, span, context) {
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) return inflated(bytes, 'gzip', span);
  if (bytes.length >= 2 && bytes[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(bytes[1])) {
    return inflated(bytes, 'deflate', span);
  }
  const text = bytesToText(bytes);
  if (text) return { method: text.utf16 && method === 'base64' ? 'base64_utf16le' : method, span, text: text.text, bytes_len: bytes.length };
  if (RAW_DEFLATE_HINT.test(context)) return inflated(bytes, 'deflate_raw', span);
  return null;
}

function inflated(bytes, method, span) {
  const result = inflate(bytes, method);
  if (!result) return null;
  if (result.overflow) return { method, span, text: '', bytes_len: DECODER_LIMITS.inflateMaxBytes, overflow: true };
  const text = bytesToText(result.bytes);
  return text ? { method, span, text: text.text, bytes_len: result.bytes.length } : null;
}

// --- step 1: vars / concat (text -> text) -----------------------------------------------------

// Assignments may be followed by `;` and more on the same line (`X=foo; eval "$X"`).
const SHELL_ASSIGN_RE = /(?:^|;)[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"$`\\\n]*)"|'([^'\n]*)'|([A-Za-z0-9_./:+=@%,-]*))(?=[ \t]*(?:;|$))/gm;
const PS_ASSIGN_RE = /(?:^|;)[ \t]*\$([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(?:'([^'\n]*)'|"([^"$`\n]*)")(?=[ \t]*(?:;|$))/gm;
const VAR_REF_RE = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)\b(?![ \t]*=[^=])/g;
const SQ_CONCAT_RE = /'([^'\\\n]*)'[ \t]*\+[ \t]*'([^'\\\n]*)'/;
const DQ_CONCAT_RE = /"([^"\\\n$`]*)"[ \t]*\+[ \t]*"([^"\\\n$`]*)"/;
const SQ_ADJACENT_RE = /'([^'\\\n]*)''([^'\\\n]*)'/;
const DQ_ADJACENT_RE = /"([^"\\\n$`]*)""([^"\\\n$`]*)"/;
const PY_SPACED_SQ_RE = /'([^'\\\n]*)'[ \t]+'([^'\\\n]*)'/;
// ('a','b' -join '') and (('a','b') -join ''): the list may sit in its own parentheses.
const PS_JOIN_RE = /\(?\s*\(?\s*((?:'[^'\n]*'\s*,\s*){1,64}'[^'\n]*')\s*\)?\s*-join\s*(?:''|"")\s*\)?/i;
const PS_CHAR_RE = /\[char\]\s*(\d{2,3})\b/gi;
// Text just before a `$VAR` reference: command position (start of a command, argument of an
// execution sink) or inside a URL.
const CMD_POS_RE = /(?:^|[\n;|&(`{]|\$\(|\b(?:then|do|else|eval|exec|source|iex|sudo|time|nohup|xargs|env|exec)\b|\bInvoke-Expression\b|\b(?:bash|sh|zsh|dash)\s+-c|-Command|-c)\s*["']?$/;
const URL_POS_RE = /[a-z][a-z0-9+.-]*:\/\/[^\s"'`]*$/i;

/** Shell / PowerShell literal variable substitution plus literal string concatenation. */
export function substituteLiterals(text, language = 'bash') {
  let budget = DECODER_LIMITS.maxSubstitutions;
  let out = text;
  let method = null;

  const vars = new Map();
  for (const m of text.matchAll(SHELL_ASSIGN_RE)) vars.set(m[1], m[2] ?? m[3] ?? m[4] ?? '');
  for (const m of text.matchAll(PS_ASSIGN_RE)) vars.set(m[1], m[2] ?? m[3] ?? '');
  if (vars.size) {
    // A vars layer is only worth showing when substitution reveals something: a variable in
    // command position or inside a URL, or a text that gains a marker or a decodable token.
    // Plain counters (`n=0; ...; echo started $n`) stay out.
    let revealing = false;
    const substituted = out.replace(VAR_REF_RE, (whole, braced, bare, offset, str) => {
      const name = braced ?? bare;
      if (!vars.has(name) || budget <= 0) return whole;
      budget -= 1;
      const before = str.slice(Math.max(0, offset - 60), offset);
      if (CMD_POS_RE.test(before) || URL_POS_RE.test(before)) revealing = true;
      return vars.get(name);
    });
    if (substituted !== out) {
      if (!revealing) {
        const mb = scanMarkers(out);
        const ma = scanMarkers(substituted);
        revealing =
          ['exec', 'decode', 'remote'].some((k) => ma[k].some((n) => !mb[k].includes(n))) ||
          base64Candidates(substituted).length > base64Candidates(out).length ||
          hexCandidates(substituted).length > hexCandidates(out).length;
      }
      if (revealing) {
        out = substituted;
        method = 'vars';
      } else {
        budget = DECODER_LIMITS.maxSubstitutions;
      }
    }
  }

  const concat = (re, build) => {
    for (;;) {
      if (budget <= 0) return;
      const m = re.exec(out);
      if (!m) return;
      budget -= 1;
      method ??= 'concat';
      out = out.slice(0, m.index) + build(m) + out.slice(m.index + m[0].length);
    }
  };
  // PowerShell [char]NN only for printable ASCII; a lone one becomes a quoted char for the concat pass.
  out = out.replace(PS_CHAR_RE, (whole, code) => {
    const n = Number(code);
    if (n < 32 || n > 126 || n === 39 || budget <= 0) return whole;
    budget -= 1;
    method ??= 'concat';
    return `'${String.fromCharCode(n)}'`;
  });
  concat(PS_JOIN_RE, (m) => `'${[...m[1].matchAll(/'([^'\n]*)'/g)].map((x) => x[1]).join('')}'`);
  concat(SQ_CONCAT_RE, (m) => `'${m[1]}${m[2]}'`);
  concat(DQ_CONCAT_RE, (m) => `"${m[1]}${m[2]}"`);
  concat(SQ_ADJACENT_RE, (m) => `'${m[1]}${m[2]}'`);
  concat(DQ_ADJACENT_RE, (m) => `"${m[1]}${m[2]}"`);
  if (language === 'python3') concat(PY_SPACED_SQ_RE, (m) => `'${m[1]}${m[2]}'`);

  return out !== text && method ? { method, text: out } : null;
}

// --- steps 2-4: url, base64, hex -------------------------------------------------------------

const URL_RUN_RE = /(?:%[0-9A-Fa-f]{2}){4,}/g;
const B64_TOKEN_RE = /[A-Za-z0-9+/=_-]{40,}/g;
const B64_QUOTED_RE = /["']([A-Za-z0-9+/=_\s-]{40,})["']/g;
const HEX_ESCAPE_RE = /(?:\\x[0-9A-Fa-f]{2}){6,}/g;
const HEX_BARE_RE = /(?<![0-9A-Za-z])[0-9A-Fa-f]{40,}(?![0-9A-Za-z])/g;
const PURE_HEX_RE = /^[0-9A-Fa-f]+$/;

function urlDecode(text) {
  let changed = false;
  const out = text.replace(URL_RUN_RE, (run) => {
    try {
      const decoded = decodeURIComponent(run);
      changed = true;
      return decoded;
    } catch {
      return run;
    }
  });
  return changed ? out : null;
}

/** Base64 looks like base64: mixed case and a couple of digits, and not a hex string. */
function plausibleBase64(token) {
  if (PURE_HEX_RE.test(token)) return false;
  return /[A-Z]/.test(token) && /[a-z]/.test(token) && (token.match(/\d/g) ?? []).length >= 2;
}

// Short tokens are only opened in a decoding context: piped straight into a decoder
// (`echo TOKEN | base64 -d`), passed to a decode function, or forming the whole layer text
// (a chained pipeline whose first decode yields more base64).
const B64_PIPED_RE = /(["']?)([A-Za-z0-9+/=_-]{12,})\1\s*\|\s*(?:base64|openssl|xxd|gunzip|zcat|gzip|python3?|perl|rev|tr)\b/g;
const B64_ARG_RE = /(?:FromBase64String|b64decode|atob|a2b_base64|decodebytes)\s*\(\s*b?["']([A-Za-z0-9+/=_-]{8,})["']/g;
const B64_WHOLE_RE = /^\s*["']?([A-Za-z0-9+/=_-]{8,})["']?\s*$/;

function base64Candidates(text) {
  const out = [];
  const whole = B64_WHOLE_RE.exec(text);
  if (whole && /[A-Z]/.test(whole[1]) && /[a-z]/.test(whole[1]) && !PURE_HEX_RE.test(whole[1])) {
    const start = text.indexOf(whole[1]);
    return [{ start, end: start + whole[1].length, token: whole[1] }];
  }
  for (const re of [B64_PIPED_RE, B64_ARG_RE]) {
    for (const m of text.matchAll(re)) {
      const token = m[2] ?? m[1];
      if (PURE_HEX_RE.test(token) || !/[A-Z]/.test(token) || !/[a-z]/.test(token)) continue;
      const start = m.index + m[0].indexOf(token);
      const end = start + token.length;
      if (!out.some((c) => start < c.end && end > c.start)) out.push({ start, end, token });
    }
  }
  for (const m of text.matchAll(B64_QUOTED_RE)) {
    const inner = m[1];
    if (!/\s/.test(inner)) continue;
    const token = inner.replace(/\s+/g, '');
    if (token.length >= 40 && plausibleBase64(token)) {
      out.push({ start: m.index + 1, end: m.index + 1 + inner.length, token });
    }
  }
  for (const m of text.matchAll(B64_TOKEN_RE)) {
    const start = m.index;
    const end = start + m[0].length;
    if (out.some((c) => start < c.end && end > c.start)) continue;
    if (plausibleBase64(m[0])) out.push({ start, end, token: m[0] });
  }
  return out.sort((a, b) => a.start - b.start);
}

function hexCandidates(text) {
  const out = [];
  for (const m of text.matchAll(HEX_ESCAPE_RE)) {
    out.push({ start: m.index, end: m.index + m[0].length, hex: m[0].replace(/\\x/g, ''), method: 'hex_escape' });
  }
  for (const m of text.matchAll(HEX_BARE_RE)) {
    if (m[0].length % 2 !== 0) continue;
    out.push({ start: m.index, end: m.index + m[0].length, hex: m[0], method: 'hex' });
  }
  return out.sort((a, b) => a.start - b.start);
}

// --- the tree walk ---------------------------------------------------------------------------

function clipText(text) {
  const buf = Buffer.from(text, 'utf8');
  if (buf.length <= DECODER_LIMITS.textMaxBytes) return { text, truncated: false };
  return { text: buf.subarray(0, DECODER_LIMITS.textMaxBytes).toString('utf8').replace(/�+$/, ''), truncated: true };
}

/**
 * @param {string} commandText
 * @param {object} [opts]
 * @param {number} [opts.firstIndex=1] index of the first layer produced (report layers start at 1)
 * @param {number} [opts.parent=0] index of the layer that holds commandText (0 = the command itself)
 * @param {Set<string>} [opts.seen] sha256 of every earlier layer text, for cycle detection across harness rounds
 * @param {number} [opts.deadline] performance.now() value after which the walk stops with `stopped: "time"`
 * @returns {{layers: object[], finalText: string, finalIndex: number, needsHarness: boolean, stopped: string, languageGuess: string, inputMarkers: object}}
 *   stopped: clean | needs_harness | remote | depth | size | time | cycle
 */
export function decodeLayers(commandText, { firstIndex = 1, parent = 0, seen = new Set(), deadline } = {}) {
  const text = String(commandText ?? '');
  const stopAt = deadline ?? performance.now() + DECODER_LIMITS.timeMs;
  const layers = [];
  const leaves = [];
  let nextIndex = firstIndex;
  let limit = null;
  let cycle = false;
  seen.add(sha256(text));
  const inputMarkers = scanMarkers(text);

  const outOfTime = () => {
    if (performance.now() > stopAt) {
      limit ??= 'time';
      return true;
    }
    return false;
  };

  function children(nodeText, markers) {
    const scan = Buffer.byteLength(nodeText) > DECODER_LIMITS.scanMaxBytes ? Buffer.from(nodeText).subarray(0, DECODER_LIMITS.scanMaxBytes).toString('utf8') : nodeText;
    const subst = substituteLiterals(scan, guessLanguage(scan));
    if (subst) return [{ method: subst.method, text: subst.text, bytes_len: Buffer.byteLength(subst.text) }];
    if (outOfTime()) return [];
    const url = urlDecode(scan);
    if (url) return [{ method: 'url', text: url, bytes_len: Buffer.byteLength(url) }];
    const out = [];
    for (const c of base64Candidates(scan)) {
      if (out.length >= DECODER_LIMITS.maxChildren || outOfTime()) break;
      const child = bytesToChild(Buffer.from(c.token, 'base64'), 'base64', [c.start, c.end], scan);
      if (child) out.push(child);
      else markers.opaque += 1;
    }
    for (const c of hexCandidates(scan)) {
      if (out.length >= DECODER_LIMITS.maxChildren || outOfTime()) break;
      const child = bytesToChild(Buffer.from(c.hex, 'hex'), c.method, [c.start, c.end], scan);
      if (child) out.push(child);
      else markers.opaque += 1;
    }
    return out;
  }

  function expand(parentIndex, nodeText, markers, depth) {
    if (limit) return;
    if (depth >= DECODER_LIMITS.maxDepth) {
      limit = 'depth';
      leaves.push({ index: parentIndex, text: nodeText, markers });
      return;
    }
    const kids = children(nodeText, markers);
    if (kids.length === 0) {
      leaves.push({ index: parentIndex, text: nodeText, markers });
      return;
    }
    for (const kid of kids) {
      if (limit) return;
      if (layers.length >= DECODER_LIMITS.maxLayers) {
        limit = 'size';
        return;
      }
      const hash = sha256(kid.text);
      if (seen.has(hash)) {
        cycle = true;
        continue;
      }
      seen.add(hash);
      const clipped = clipText(kid.text);
      const layer = {
        index: nextIndex,
        parent: parentIndex,
        method: kid.method,
        bytes_len: kid.bytes_len,
        text: clipped.text,
        truncated: clipped.truncated || Boolean(kid.overflow),
        markers: scanMarkers(kid.text),
        llm_assisted: false,
        status: clipped.truncated || kid.overflow ? 'truncated' : 'ok',
      };
      if (kid.span) layer.span = kid.span;
      nextIndex += 1;
      layers.push(layer);
      if (kid.overflow) continue;
      expand(layer.index, kid.text, layer.markers, depth + 1);
    }
  }

  expand(parent, text, inputMarkers, 0);
  // No leaf at all means every child was dropped (cycle or cap): the input itself is the final
  // text, but its literals were decodable, so it does not need a harness.
  const noLeaf = leaves.length === 0;
  if (noLeaf) leaves.push({ index: parent, text, markers: inputMarkers });

  const hidden = (m) => m.exec.length > 0 && m.decode.length > 0;
  const harnessLeaf = noLeaf ? undefined : leaves.find((l) => hidden(l.markers));
  const remoteLeaf = leaves.find((l) => l.markers.remote.length > 0);
  const last = harnessLeaf ?? leaves[leaves.length - 1];
  const needsHarness = Boolean(harnessLeaf);
  const stopped = limit ?? (needsHarness ? 'needs_harness' : remoteLeaf ? 'remote' : cycle ? 'cycle' : 'clean');
  return {
    layers,
    finalText: last.text,
    finalIndex: last.index,
    needsHarness,
    stopped,
    languageGuess: guessLanguage(last.text),
    inputMarkers,
  };
}

/** Alias with the 8.2 name. */
export const decode = decodeLayers;

/** Layer as sent on SSE unwrap.layer (10.2): `text` replaced by a `preview` of at most 4 KiB. */
export function layerPreview(layer, maxBytes = 4096) {
  const { text, ...rest } = layer;
  const buf = Buffer.from(text ?? '', 'utf8');
  const preview = buf.length <= maxBytes ? text ?? '' : buf.subarray(0, maxBytes).toString('utf8').replace(/�+$/, '');
  return { ...rest, preview };
}
