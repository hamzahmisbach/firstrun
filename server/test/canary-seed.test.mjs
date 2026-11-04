import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { ALL_FORMS, DECOY_TABLE, TOKEN_RE, createCanaries, deriveAwsKeyId, isToken, newToken } from '../run/canary.mjs';
import { DecoysSchema } from '../evidence/schema.mjs';
import { PERMS, homeRelative, writeSeed } from '../run/seed.mjs';

const tmpRoots = [];
after(() => {
  for (const dir of tmpRoots) rmSync(dir, { recursive: true, force: true });
});

function walk(dir, rel = '') {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const r = rel ? `${rel}/${e.name}` : e.name;
    return e.isDirectory() ? walk(path.join(dir, e.name), r) : [r];
  });
}

test('createCanaries: one manifest row per table row, tokens in the FR+22 base32 shape', () => {
  const { runSecret, decoys } = createCanaries();
  assert.match(runSecret, /^[0-9a-f]{64}$/);
  assert.equal(decoys.length, DECOY_TABLE.length);
  assert.ok(DecoysSchema.safeParse(decoys).success);
  const values = decoys.filter((d) => d.value).map((d) => d.value);
  for (const v of values) assert.match(v, TOKEN_RE);
  assert.equal(new Set(values).size, values.length, 'tokens are unique per file');
  for (const d of decoys) {
    const row = DECOY_TABLE.find((r) => r.id === d.id);
    assert.equal(d.category, row.category);
    assert.equal(d.path, row.path === null ? null : `~/${row.path}`);
    if (row.token) assert.deepEqual(d.forms, [...ALL_FORMS]);
    else assert.deepEqual([d.value, d.forms], [null, []]);
  }
  const pw = decoys.find((d) => d.id === 'pw');
  assert.equal(pw.path, null);
  assert.equal(pw.category, 'phished_input');
  assert.ok(isToken(pw.value));
});

test('createCanaries: every 5.3 row is present, including browser, wallet and AI assistant decoys', () => {
  const ids = new Set(DECOY_TABLE.map((d) => d.id));
  const byCategory = (c) => DECOY_TABLE.filter((d) => d.category === c).map((d) => d.path);
  assert.deepEqual(byCategory('browser_profile').sort(), [
    '.config/google-chrome/Default/Cookies',
    '.config/google-chrome/Default/Login Data',
    '.config/google-chrome/Default/Web Data',
    '.config/google-chrome/Local State',
    '.mozilla/firefox/k3x9q1z7.default-release/cookies.sqlite',
    '.mozilla/firefox/k3x9q1z7.default-release/key4.db',
    '.mozilla/firefox/k3x9q1z7.default-release/logins.json',
  ]);
  assert.deepEqual(byCategory('wallet').sort(), [
    '.config/Exodus/exodus.wallet/seed.seco',
    '.electrum/wallets/default_wallet',
    'Documents/wallet-backup/seed-phrase.txt',
  ]);
  assert.deepEqual(byCategory('ai_assistant_config').sort(), ['.claude.json', '.claude/.credentials.json', '.gemini/oauth_creds.json']);
  for (const id of ['ssh_key', 'aws_secret', 'npmrc', 'gh_hosts', 'git_credentials', 'docker_config', 'project_env', 'bash_history', 'pw']) {
    assert.ok(ids.has(id), id);
  }
});

test('createCanaries: deterministic for a secret, different across runs', () => {
  const a = createCanaries();
  const b = createCanaries({ runSecret: a.runSecret });
  assert.deepEqual(a.decoys, b.decoys);
  const c = createCanaries();
  assert.notEqual(a.decoys.find((d) => d.id === 'aws_secret').value, c.decoys.find((d) => d.id === 'aws_secret').value);
  assert.throws(() => createCanaries({ runSecret: 'abc' }));
});

test('newToken / deriveAwsKeyId shapes', () => {
  const t = newToken();
  assert.match(t, TOKEN_RE);
  assert.match(deriveAwsKeyId(t), /^AKIA[A-Z2-7]{16}$/);
  assert.equal(deriveAwsKeyId(t), deriveAwsKeyId(t));
  assert.equal(isToken('FRQ7K2'), false);
  assert.equal(isToken(`${t}X`), false);
});

test('homeRelative rejects escapes', () => {
  assert.equal(homeRelative('~/.aws/credentials'), '.aws/credentials');
  assert.equal(homeRelative(null), null);
  assert.throws(() => homeRelative('~/../etc/passwd'));
  assert.throws(() => homeRelative('~/'));
});

test('writeSeed: every file decoy is rendered with its own token, fillers and perms are present', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'firstrun-seed-'));
  tmpRoots.push(dir);
  const { decoys } = createCanaries();
  await writeSeed(dir, decoys);
  const home = path.join(dir, 'home');

  for (const d of decoys) {
    if (d.path === null) continue;
    const file = path.join(home, d.path.slice(2));
    assert.ok(statSync(file).isFile(), `${d.path} exists`);
    const bytes = readFileSync(file);
    if (!d.value) {
      for (const other of decoys) if (other.value) assert.equal(bytes.includes(other.value), false, `${d.path} must not carry a token`);
      continue;
    }
    const text = bytes.toString('latin1');
    if (d.id === 'ssh_key') {
      const body = text.split('\n').slice(1, -2).join('');
      assert.equal(body.slice(0, 32), Buffer.from(d.value).toString('base64'), 'first 32 chars of the key body = base64(token)');
      assert.match(text, /^-----BEGIN OPENSSH PRIVATE KEY-----\n/);
    } else if (d.id === 'docker_config') {
      assert.ok(text.includes(Buffer.from(`dev-pratama:${d.value}`).toString('base64')), 'auth = base64(user:token)');
      JSON.parse(text);
    } else {
      assert.ok(bytes.includes(d.value), `${d.path} carries its token`);
    }
    for (const other of decoys) {
      if (other.value && other.id !== d.id) assert.equal(bytes.includes(other.value), false, `${d.path} must not carry ${other.id}'s token`);
    }
  }

  const aws = readFileSync(path.join(home, '.aws/credentials'), 'utf8');
  const awsDecoy = decoys.find((d) => d.id === 'aws_secret');
  assert.ok(aws.includes(`aws_access_key_id = ${deriveAwsKeyId(awsDecoy.value)}`));
  assert.ok(aws.includes(`aws_secret_access_key = ${awsDecoy.value}`));
  assert.equal(readFileSync(path.join(home, '.config/google-chrome/Default/Login Data')).subarray(0, 15).toString(), 'SQLite format 3');
  assert.equal(readFileSync(path.join(home, '.config/Exodus/exodus.wallet/seed.seco')).subarray(0, 4).toString(), 'SECO');
  for (const json of ['.config/gcloud/application_default_credentials.json', '.claude/.credentials.json', '.claude.json', '.gemini/oauth_creds.json', '.config/google-chrome/Local State', '.mozilla/firefox/k3x9q1z7.default-release/logins.json', '.electrum/wallets/default_wallet']) {
    JSON.parse(readFileSync(path.join(home, json), 'utf8'));
  }
  assert.match(readFileSync(path.join(home, 'projects/acme-app/.env'), 'utf8'), /^STRIPE_SECRET_KEY=sk_live_FR[A-Z2-7]{22}$/m);

  // Fillers: a developer laptop, with no token anywhere and git not pointed at .git-credentials.
  const files = walk(home);
  for (const f of ['.bashrc', '.profile', '.gitconfig', 'projects/acme-app/package.json', 'projects/acme-app/src/index.js', '.bash_history', '.zsh_history', '.ssh/id_ed25519.pub', '.ssh/config', '.ssh/known_hosts']) {
    assert.ok(files.includes(f), f);
  }
  assert.ok(files.some((f) => f.startsWith('Downloads/')) && files.some((f) => f.startsWith('.cache/')));
  assert.doesNotMatch(readFileSync(path.join(home, '.gitconfig'), 'utf8'), /credential/i);
  const tokens = decoys.filter((d) => d.value).map((d) => d.value);
  const decoyPaths = new Set(decoys.filter((d) => d.path).map((d) => d.path.slice(2)));
  for (const f of files) {
    if (decoyPaths.has(f)) continue;
    const bytes = readFileSync(path.join(home, f));
    for (const t of tokens) assert.equal(bytes.includes(t), false, `filler ${f} carries a token`);
  }

  // perms.txt: "<mode> <path>", every path exists, ssh key and credentials are 600.
  const perms = readFileSync(path.join(dir, 'perms.txt'), 'utf8').trimEnd().split('\n');
  assert.equal(perms.length, PERMS.length);
  for (const line of perms) {
    const m = /^([0-7]{3}) (.+)$/.exec(line);
    assert.ok(m, line);
    assert.ok(statSync(path.join(home, m[2])), m[2]);
  }
  assert.ok(perms.includes('600 .ssh/id_ed25519') && perms.includes('600 .aws/credentials') && perms.includes('700 .ssh'));

  // shim-canaries.json: a single line the shim can parse with its glob.
  const shim = readFileSync(path.join(dir, 'shim-canaries.json'), 'utf8');
  assert.equal(shim, `{"pw":"${decoys.find((d) => d.id === 'pw').value}"}\n`);
  // Host-side modes stay world-readable: uid 1000 copies them through a read-only bind mount.
  if (process.platform !== 'win32') assert.equal(statSync(path.join(home, '.aws/credentials')).mode & 0o044, 0o044);
});

test('writeSeed rejects unknown decoy ids and bad paths', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'firstrun-seed-'));
  tmpRoots.push(dir);
  await assert.rejects(writeSeed(dir, [{ id: 'evil', path: '~/x', category: 'x', value: newToken(), forms: ['raw'] }]), /unknown decoy id/);
  await assert.rejects(writeSeed(dir, [{ id: 'npmrc', path: '~/../x', category: 'x', value: newToken(), forms: ['raw'] }]), /clean relative path/);
});
