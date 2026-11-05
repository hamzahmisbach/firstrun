// Render the decoy HOME for one run (docs/ARCHITECTURE.md 5.3): seed/home/** from the templates
// next to this file plus the per-run canary values, seed/perms.txt applied by entry.sh inside the
// sandbox, and seed/shim-canaries.json read by the shims. Files are written with default modes on
// purpose: the sandbox copies them as uid 1000 through a read-only bind mount, so they must be
// world-readable here; the tight modes are applied by entry.sh after the copy.
import { randomBytes, randomInt } from 'node:crypto';
import { cp, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { crc32 } from 'node:zlib';
import { DECOY_TABLE, deriveAwsKeyId } from './canary.mjs';
import { HOME } from '../rules/paths.mjs';

const TEMPLATES_DIR = fileURLToPath(new URL('./seed-templates/', import.meta.url));

/** Modes entry.sh applies inside the sandbox ("<mode> <path relative to HOME>"). */
export const PERMS = Object.freeze([
  ['700', '.ssh'],
  ['600', '.ssh/id_ed25519'],
  ['644', '.ssh/id_ed25519.pub'],
  ['600', '.ssh/config'],
  ['644', '.ssh/known_hosts'],
  ['700', '.aws'],
  ['600', '.aws/credentials'],
  ['600', '.aws/config'],
  ['700', '.config/gcloud'],
  ['600', '.config/gcloud/application_default_credentials.json'],
  ['700', '.kube'],
  ['600', '.kube/config'],
  ['600', '.vault-token'],
  ['700', '.azure'],
  ['600', '.azure/msal_token_cache.json'],
  ['700', '.aliyun'],
  ['600', '.aliyun/config.json'],
  ['600', '.npmrc'],
  ['700', '.config/gh'],
  ['600', '.config/gh/hosts.yml'],
  ['600', '.git-credentials'],
  ['700', '.docker'],
  ['600', '.docker/config.json'],
  ['700', '.config/google-chrome'],
  ['700', '.mozilla/firefox/k3x9q1z7.default-release'],
  ['700', '.config/Exodus'],
  ['700', '.electrum'],
  ['600', '.electrum/wallets/default_wallet'],
  ['600', 'Documents/wallet-backup/seed-phrase.txt'],
  ['700', '.claude'],
  ['600', '.claude/.credentials.json'],
  ['600', '.claude.json'],
  ['700', '.gemini'],
  ['600', '.gemini/oauth_creds.json'],
  ['700', '.codex'],
  ['600', '.codex/auth.json'],
  ['700', '.cursor'],
  ['600', '.cursor/mcp.json'],
  ['600', 'projects/acme-app/.env'],
  ['600', '.bash_history'],
  ['600', '.zsh_history'],
]);

// Twelve words that look like a BIP-39 phrase but are not one (the real list is not used).
const FAKE_WORDS = ['harbor', 'velvet', 'copper', 'meadow', 'saddle', 'quartz', 'lantern', 'thistle', 'marble', 'ember', 'canyon', 'willow'];

const SQLITE_HEADER = Buffer.from('SQLite format 3\0', 'latin1');

/** A small fake SQLite file: real header, one "page" with the token in a row-like blob. */
function sqliteLike(token, tableName) {
  const page = Buffer.alloc(4096);
  SQLITE_HEADER.copy(page, 0);
  page.writeUInt16BE(4096, 16); // page size
  page[18] = 1; // file format write version
  page[19] = 1; // read version
  page.writeUInt32BE(1, 28); // page count
  const schema = `CREATE TABLE ${tableName} (id INTEGER PRIMARY KEY, origin_url TEXT, value BLOB)`;
  Buffer.from(schema, 'latin1').copy(page, 100);
  randomBytes(64).copy(page, 1024);
  Buffer.from(`https://github.com\0${token}\0`, 'latin1').copy(page, 1100);
  randomBytes(128).copy(page, 2048);
  return page;
}

/** Exodus seed.seco: magic, version bytes, token, random "ciphertext". */
function secoLike(token) {
  return Buffer.concat([Buffer.from('SECO\x00\x00\x00\x01', 'latin1'), randomBytes(32), Buffer.from(token, 'latin1'), randomBytes(160)]);
}

/** OpenSSH key body: base64(token + random), so the first 32 characters are base64(token). */
function sshBody(token) {
  const raw = Buffer.concat([Buffer.from(token, 'latin1'), randomBytes(213)]);
  return raw.toString('base64').replace(/(.{70})/g, '$1\n').replace(/\n$/, '');
}

const BINARY_RENDERERS = {
  chrome_login_data: (t) => sqliteLike(t, 'logins'),
  chrome_cookies: (t) => sqliteLike(t, 'cookies'),
  chrome_web_data: (t) => sqliteLike(t, 'autofill'),
  firefox_key4: (t) => sqliteLike(t, 'nssPrivate'),
  firefox_cookies: (t) => sqliteLike(t, 'moz_cookies'),
  exodus_seed: (t) => secoLike(t),
};

function placeholders(token) {
  return {
    token,
    akia: deriveAwsKeyId(token),
    b64auth: Buffer.from(`dev-pratama:${token}`, 'latin1').toString('base64'),
    sshbody: sshBody(token),
    words: FAKE_WORDS.join(' '),
  };
}

async function renderTemplate(id, token) {
  const text = await readFile(path.join(TEMPLATES_DIR, 'decoys', `${id}.tmpl`), 'utf8');
  const values = placeholders(token);
  return text.replace(/\{\{(\w+)\}\}/g, (m, key) => {
    if (!(key in values)) throw new Error(`seed template ${id}: unknown placeholder ${key}`);
    return values[key];
  });
}

/** Render one file decoy's bytes; exported so tests can check every row without a run. */
export async function renderDecoy(decoy) {
  if (!decoy.value) return null; // tokenless rows live in seed-templates/home verbatim
  const render = BINARY_RENDERERS[decoy.id];
  return render ? render(decoy.value) : Buffer.from(await renderTemplate(decoy.id, decoy.value), 'utf8');
}

// --- random filler (5.3): a home that is not byte-identical on every run -------------------------
// Files of everyday types with no token and no decoy role. Names are drawn per run from these
// pools and the count varies, so a script cannot fingerprint the sandbox by listing ~/Documents.

/** Per directory: how many files to place (inclusive range) and the names to draw from. */
export const FILLER_POOLS = Object.freeze({
  Documents: Object.freeze({
    count: [3, 6],
    names: Object.freeze([
      'invoice_2026_03.pdf',
      'invoice_2026_07.pdf',
      'lease-agreement-signed.pdf',
      'insurance-policy-2026.pdf',
      'warranty-fridge.pdf',
      'tax-return-final.docx',
      'cv_dev_pratama_2026.docx',
      'thesis-draft-v3.docx',
      'team-okrs-h2.docx',
      'budget-2026.xlsx',
      'expenses_q3.xlsx',
      'mortgage-calc.xlsx',
      'reading-list.md',
      'trip-itinerary-bali.md',
      'packing-list.txt',
      'book-notes.txt',
    ]),
  }),
  Pictures: Object.freeze({
    count: [2, 4],
    names: Object.freeze([
      'family-photo-0412.jpg',
      'IMG_20260814_173205.jpg',
      'IMG_20260902_091533.jpg',
      'whiteboard-sprint-42.jpg',
      'beach-sunset-0219.jpg',
      'team-offsite-2026.jpg',
      'screenshot-2026-09-02.jpg',
      'bike-trip-ubud.jpg',
    ]),
  }),
  Downloads: Object.freeze({
    count: [2, 4],
    names: Object.freeze([
      'export-users-2026-10-30.csv',
      'transactions-sept.csv',
      'sales-leads.csv',
      'bank-statement-oct-2026.pdf',
      'ticket-GA-7731.pdf',
      'receipt-amzn-4471.pdf',
      'conference-badge.pdf',
      'release-notes-3.2.txt',
      'payroll-template.xlsx',
      'q3-roadmap.docx',
    ]),
  }),
});

const WORDS = ['budget', 'review', 'draft', 'notes', 'summary', 'planning', 'invoice', 'meeting', 'travel', 'quarterly', 'update', 'checklist'];
const NAMES = ['Dev', 'Sari', 'Marcus', 'Putri', 'Jonas', 'Mei'];

function pick(list) {
  return list[randomInt(list.length)];
}

/** Choose `n` distinct entries of `list` with crypto randomness (partial Fisher-Yates). */
function sample(list, n) {
  const pool = list.slice();
  for (let i = 0; i < n; i++) {
    const j = i + randomInt(pool.length - i);
    [pool[i], pool[j]] = [pool[j], pool[i]];
  }
  return pool.slice(0, n);
}

function title(name) {
  return name.replace(/\.[a-z0-9]+$/i, '').replace(/[-_]+/g, ' ');
}

function lines(n, make) {
  return Array.from({ length: n }, (_, i) => make(i)).join('\n') + '\n';
}

/** Store-only ZIP (no compression) so Office containers open as real archives. */
function zipStore(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, data] of entries) {
    const nameBuf = Buffer.from(name, 'utf8');
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0, 6); // flags
    local.writeUInt16LE(0, 8); // method: stored
    local.writeUInt16LE(0, 10); // time
    local.writeUInt16LE(0x5321, 12); // a fixed DOS date (2021-09-01); mtime is not a signal here
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt16LE(0, 12);
    central.writeUInt16LE(0x5321, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBuf, data);
    centrals.push(central, nameBuf);
    offset += local.length + nameBuf.length + data.length;
  }
  const centralStart = offset;
  const centralBytes = centrals.reduce((n, b) => n + b.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBytes, 12);
  end.writeUInt32LE(centralStart, 16);
  return Buffer.concat([...locals, ...centrals, end]);
}

const XML_HEAD = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n';

function docx(name) {
  const paras = Array.from({ length: 3 + randomInt(5) }, () => `<w:p><w:r><w:t>${pick(WORDS)} ${pick(WORDS)} ${pick(NAMES)} ${2026 - randomInt(3)}</w:t></w:r></w:p>`);
  const document = `${XML_HEAD}<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>${title(name)}</w:t></w:r></w:p>${paras.join('')}</w:body></w:document>`;
  const types = `${XML_HEAD}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`;
  const rels = `${XML_HEAD}<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`;
  return zipStore([
    ['[Content_Types].xml', Buffer.from(types)],
    ['_rels/.rels', Buffer.from(rels)],
    ['word/document.xml', Buffer.from(document)],
  ]);
}

function xlsx(name) {
  const rows = Array.from({ length: 4 + randomInt(8) }, (_, i) => `<row r="${i + 1}"><c r="A${i + 1}" t="inlineStr"><is><t>${pick(WORDS)}</t></is></c><c r="B${i + 1}"><v>${randomInt(100, 90000)}</v></c></row>`);
  const sheet = `${XML_HEAD}<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>${rows.join('')}</sheetData></worksheet>`;
  const workbook = `${XML_HEAD}<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="${title(name).slice(0, 31)}" sheetId="1" r:id="rId1"/></sheets></workbook>`;
  const wbRels = `${XML_HEAD}<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`;
  const types = `${XML_HEAD}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>`;
  const rels = `${XML_HEAD}<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`;
  return zipStore([
    ['[Content_Types].xml', Buffer.from(types)],
    ['_rels/.rels', Buffer.from(rels)],
    ['xl/workbook.xml', Buffer.from(workbook)],
    ['xl/_rels/workbook.xml.rels', Buffer.from(wbRels)],
    ['xl/worksheets/sheet1.xml', Buffer.from(sheet)],
  ]);
}

/** One-page PDF with the title as text; offsets in the xref are computed, so readers accept it. */
function pdf(name) {
  const text = `BT /F1 18 Tf 72 720 Td (${title(name).replace(/[()\\]/g, '')}) Tj ET`;
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
    `<< /Length ${text.length} >>\nstream\n${text}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  let body = '%PDF-1.4\n%\xe2\xe3\xcf\xd3\n';
  const offsets = [];
  objects.forEach((obj, i) => {
    offsets.push(body.length);
    body += `${i + 1} 0 obj\n${obj}\nendobj\n`;
  });
  const xref = body.length;
  body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('')}`;
  body += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  // Padding after %%EOF, as incremental saves leave behind, so sizes differ between runs too.
  return Buffer.concat([Buffer.from(body, 'latin1'), randomBytes(randomInt(256, 2048))]);
}

/** JFIF header, a few random "scan" bytes, EOI marker. Not decodable, but every sniffer agrees. */
function jpg() {
  const soi = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00]);
  return Buffer.concat([soi, randomBytes(randomInt(1024, 3072)), Buffer.from([0xff, 0xd9])]);
}

function csv() {
  const n = 5 + randomInt(20);
  return 'id,name,email,amount,created_at\n' + lines(n, (i) => `${1000 + i},${pick(NAMES)} ${pick(['Wijaya', 'Hartono', 'Lindqvist', 'Okafor', 'Tanaka'])},user${1000 + i}@example.test,${randomInt(5, 900)}.${String(randomInt(100)).padStart(2, '0')},2026-${String(1 + randomInt(10)).padStart(2, '0')}-${String(1 + randomInt(28)).padStart(2, '0')}`);
}

function txt(name) {
  return `${title(name)}\n\n` + lines(3 + randomInt(8), () => `- ${pick(WORDS)} ${pick(WORDS)} (${pick(NAMES)})`);
}

function md(name) {
  return `# ${title(name)}\n\n` + lines(3 + randomInt(8), (i) => `${i + 1}. ${pick(WORDS)} ${pick(WORDS)}, ${pick(NAMES)}`);
}

/** Bytes for one filler file, by extension; text types come back as strings. */
export function renderFiller(name) {
  const ext = name.slice(name.lastIndexOf('.') + 1).toLowerCase();
  switch (ext) {
    case 'pdf':
      return pdf(name);
    case 'docx':
      return docx(name);
    case 'xlsx':
      return xlsx(name);
    case 'jpg':
      return jpg();
    case 'csv':
      return csv();
    case 'md':
      return md(name);
    default:
      return txt(name);
  }
}

/** This run's filler set as sorted HOME-relative paths (`Documents/invoice_2026_03.pdf`, ...), drawn from FILLER_POOLS. */
export function pickFillers() {
  const out = [];
  for (const [dir, { count, names }] of Object.entries(FILLER_POOLS)) {
    const n = randomInt(count[0], count[1] + 1);
    for (const name of sample(names, n)) out.push(`${dir}/${name}`);
  }
  return out.sort();
}

async function walk(dir, rel = '') {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const r = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory()) out.push(...(await walk(path.join(dir, entry.name), r)));
    else out.push(r);
  }
  return out;
}

/** Manifest `~/x` -> path relative to HOME; rejects anything that could escape the tree. */
export function homeRelative(manifestPath) {
  if (typeof manifestPath !== 'string' || !manifestPath.startsWith('~/')) return null;
  const rel = manifestPath.slice(2);
  if (rel === '' || rel.split('/').some((seg) => seg === '' || seg === '.' || seg === '..')) {
    throw new Error('decoy path must be a clean relative path under ~');
  }
  return rel;
}

/**
 * Write seed/home/**, seed/perms.txt and seed/shim-canaries.json under `seedDir`.
 * @param {string} seedDir
 * @param {Array<{id, path, category, value, forms}>} decoys manifest from canary.mjs
 * @returns {Promise<{ seededPaths: string[] }>} sandbox-absolute (`/home/dev/...`) path of every
 *   file placed, decoys and filler alike, sorted; a later write to one of these changes a file
 *   that already existed.
 */
export async function writeSeed(seedDir, decoys) {
  const home = path.join(seedDir, 'home');
  await mkdir(home, { recursive: true });
  await cp(path.join(TEMPLATES_DIR, 'home'), home, { recursive: true });

  const known = new Set(DECOY_TABLE.map((d) => d.id));
  let pw = null;
  for (const decoy of decoys) {
    if (!known.has(decoy.id)) throw new Error(`unknown decoy id in manifest: ${decoy.id}`);
    if (decoy.id === 'pw') {
      pw = decoy.value;
      continue;
    }
    if (decoy.path === null) continue; // not a file: env_secret only exists as an environment value
    const rel = homeRelative(decoy.path);
    const bytes = await renderDecoy(decoy);
    if (bytes === null) continue;
    const target = path.join(home, rel);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, bytes);
  }

  for (const rel of pickFillers()) {
    const target = path.join(home, rel);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, renderFiller(rel));
  }

  await writeFile(path.join(seedDir, 'perms.txt'), PERMS.map(([mode, rel]) => `${mode} ${rel}\n`).join(''));
  // One line, no spaces: _shim extracts the value with a `*'"pw":"'*` glob on the first line.
  await writeFile(path.join(seedDir, 'shim-canaries.json'), `${JSON.stringify({ pw: pw ?? 'ok' })}\n`);

  const seededPaths = (await walk(home)).map((rel) => `${HOME}/${rel}`).sort();
  return { seededPaths };
}
