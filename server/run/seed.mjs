// Render the decoy HOME for one run (docs/ARCHITECTURE.md 5.3): seed/home/** from the templates
// next to this file plus the per-run canary values, seed/perms.txt applied by entry.sh inside the
// sandbox, and seed/shim-canaries.json read by the shims. Files are written with default modes on
// purpose: the sandbox copies them as uid 1000 through a read-only bind mount, so they must be
// world-readable here; the tight modes are applied by entry.sh after the copy.
import { randomBytes } from 'node:crypto';
import { cp, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DECOY_TABLE, deriveAwsKeyId } from './canary.mjs';

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
    const rel = homeRelative(decoy.path);
    const bytes = await renderDecoy(decoy);
    if (bytes === null) continue;
    const target = path.join(home, rel);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, bytes);
  }

  await writeFile(path.join(seedDir, 'perms.txt'), PERMS.map(([mode, rel]) => `${mode} ${rel}\n`).join(''));
  // One line, no spaces: _shim extracts the value with a `*'"pw":"'*` glob on the first line.
  await writeFile(path.join(seedDir, 'shim-canaries.json'), `${JSON.stringify({ pw: pw ?? 'ok' })}\n`);
}
