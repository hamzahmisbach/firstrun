import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { createMatcher, patternsFor, stableEncoding } from '../evidence/matcher.mjs';
import { ALL_FORMS } from '../run/canary.mjs';

const TOKEN = 'FRCAPTUREFIXTURETOKEN234';
const PW = 'FRCAPTURESHIMTOKEN234567';
const decoys = [
  { id: 'aws_secret', path: '~/.aws/credentials', category: 'cloud_credentials', value: TOKEN, forms: [...ALL_FORMS] },
  { id: 'ssh_pub', path: '~/.ssh/id_ed25519.pub', category: 'ssh_meta', value: null, forms: [] },
  { id: 'pw', path: null, category: 'phished_input', value: PW, forms: [...ALL_FORMS] },
];
const b64 = (s) => Buffer.from(s, 'latin1').toString('base64');
const http = (over) => ({ kind: 'http.request', id: 'r1', method: 'POST', host: 'collector.example.test', port: 443, path: '/upload', query: '', headers: {}, body_len: 0, ...over });

const tmp = [];
after(() => {
  for (const d of tmp) rmSync(d, { recursive: true, force: true });
});

test('stableEncoding keeps only the characters determined by the value', () => {
  const v = Buffer.from(TOKEN);
  assert.equal(stableEncoding(v, 0, (b) => b.toString('base64'), 3), b64(TOKEN));
  for (let k = 0; k < 3; k++) {
    const stable = stableEncoding(v, k, (b) => b.toString('base64'), 3);
    assert.ok(stable.length >= 30, `k=${k}: ${stable.length}`);
    for (const fill of [0x00, 0x5a, 0xff]) {
      const enc = Buffer.concat([Buffer.alloc(k + 3, fill), v, Buffer.alloc(5, fill)]).toString('base64');
      assert.ok(enc.includes(stable), `k=${k} fill=${fill}`);
    }
  }
});

test('patternsFor: every form, duplicates collapsed into the first form, nothing under 24 bytes', () => {
  const ps = patternsFor(TOKEN, [...ALL_FORMS]);
  const byForm = Object.groupBy(ps, (p) => p.form);
  assert.equal(byForm.raw.length, 1);
  assert.equal(byForm.b64x3.length, 3);
  assert.equal(byForm.b64b64x3.length, 9);
  assert.equal(byForm.url, undefined, 'url form of a base32 token equals raw and is collapsed');
  assert.equal(byForm.hex.length, 2);
  assert.equal(byForm.base32.length, 5);
  for (const p of ps) assert.ok(p.bytes.length >= 24);
  assert.deepEqual(patternsFor(TOKEN, ['url']).map((p) => p.form), ['url']);
  assert.equal(patternsFor('short', ['raw']).length, 0);
});

test('scan: body in raw, base64 at every alignment, double base64, hex and base32', async () => {
  const m = createMatcher({ decoys });
  const cases = [
    ['raw', `aws_secret_access_key = ${TOKEN}\n`],
    ['b64x3', b64(`[default]\naws_secret_access_key = ${TOKEN}\n`)],
    ['b64x3', b64(`x${TOKEN}`)],
    ['b64x3', b64(`xy${TOKEN}`)],
    ['b64b64x3', b64(b64(`key=${TOKEN}\n`))],
    ['b64b64x3', b64(`Q${b64(`zz${TOKEN}`)}`)],
    ['hex', Buffer.from(`abc${TOKEN}`).toString('hex')],
    ['hex', Buffer.from(TOKEN).toString('hex').toUpperCase()],
  ];
  for (const [form, body] of cases) {
    const hits = await m.scan(http({ body_b64: b64(body), body_len: body.length }), 7);
    assert.deepEqual(hits, [{ decoy_id: 'aws_secret', category: 'cloud_credentials', form, where: 'body', event_seq: 7 }], body.slice(0, 40));
  }
  const b32 = patternsFor(TOKEN, ['base32'])[0].bytes.toString();
  const hits = await m.scan(http({ body_b64: b64(`data=${b32}`) }), 8);
  assert.equal(hits[0].form, 'base32');
});

test('scan: url, header, dns (split labels, case-insensitive), tcp bytes; one hit per decoy', async () => {
  const m = createMatcher({ decoys });
  assert.deepEqual((await m.scan(http({ method: 'GET', path: '/c', query: `k=${TOKEN}` }), 1)).map((h) => [h.where, h.form]), [['url', 'raw']]);
  assert.deepEqual((await m.scan(http({ headers: { 'x-auth': `Bearer ${b64(TOKEN)}` } }), 2)).map((h) => [h.where, h.form]), [['header', 'b64x3']]);
  assert.deepEqual((await m.scan({ kind: 'dns.query', name: `${TOKEN.slice(0, 10)}.${TOKEN.slice(10).toLowerCase()}.evil.test`, qtype: 'A' }, 3)).map((h) => h.where), ['dns']);
  assert.deepEqual((await m.scan({ kind: 'tls.clienthello', sni: `${Buffer.from(TOKEN).toString('hex')}.x.test`, port: 443 }, 4)).map((h) => h.form), ['hex']);
  assert.deepEqual((await m.scan({ kind: 'tcp.connect', orig_dst_port: 4444, first_bytes_hex: Buffer.from(`hi ${PW}`).toString('hex') }, 5)), [
    { decoy_id: 'pw', category: 'phished_input', form: 'raw', where: 'tcp_bytes', event_seq: 5 },
  ]);
  assert.deepEqual(await m.scan({ kind: 'udp.datagram', len: 4, first_bytes_hex: '70696e67' }, 6), []);
  // Two decoys in one body: one hit each; the same decoy twice: one hit, first form wins (raw before b64).
  const both = await m.scan(http({ body_b64: b64(`${b64(TOKEN)} ${TOKEN} ${PW}`) }), 9);
  assert.deepEqual(both.map((h) => [h.decoy_id, h.form]), [['aws_secret', 'raw'], ['pw', 'raw']]);
  // Tokenless decoys and short values never match.
  assert.equal(m.patternCount(), 2 * 20);
});

test('scan: body_ref read from sinkholeDir/bodies, capped at bodyMaxBytes; scan budget sets truncated', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'firstrun-matcher-'));
  tmp.push(dir);
  mkdirSync(path.join(dir, 'bodies'));
  writeFileSync(path.join(dir, 'bodies/r9.bin'), Buffer.concat([Buffer.alloc(100, 0x41), Buffer.from(TOKEN), Buffer.alloc(100, 0x42)]));
  writeFileSync(path.join(dir, 'bodies/r10.bin'), Buffer.concat([Buffer.alloc(600, 0x41), Buffer.from(TOKEN)]));
  const limits = { bodyMaxBytes: 500, scanBudgetBytes: 2000, minPatternBytes: 24 };
  const m = createMatcher({ decoys, sinkholeDir: dir, limits });
  assert.equal((await m.scan(http({ body_ref: 'bodies/r9.bin', body_len: 224 }), 1)).length, 1);
  assert.equal((await m.scan(http({ body_ref: 'bodies/r10.bin', body_len: 624 }), 2)).length, 0, 'token beyond bodyMaxBytes is not seen');
  assert.equal((await m.scan(http({ body_ref: '../../etc/passwd' }), 3)).length, 0);
  assert.equal(m.truncated(), false);
  const big = await m.scan(http({ body_b64: b64(`${'z'.repeat(1500)}${TOKEN}`) }), 4);
  assert.equal(big.length, 0, 'over budget: not scanned');
  assert.equal(m.truncated(), true);
});

test('scanBytes: file tokens on stdout/stderr are hits with a null event_seq; the shim-printed pw is not', () => {
  const m = createMatcher({ decoys });
  assert.deepEqual(m.scanBytes(Buffer.from(`aws_secret_access_key = ${TOKEN}\n`), 'stdout'), [
    { decoy_id: 'aws_secret', category: 'cloud_credentials', form: 'raw', where: 'stdout', event_seq: null },
  ]);
  assert.deepEqual(m.scanBytes(Buffer.from(`key: ${b64(TOKEN)}`), 'stderr').map((h) => [h.where, h.form]), [['stderr', 'b64x3']]);
  assert.deepEqual(m.scanBytes(Buffer.from(`${PW}\n`), 'stdout'), [], 'crontab -l prints pw by design');
  assert.deepEqual(m.scanBytes(Buffer.from(`${PW} ${TOKEN}`), 'stdout').map((h) => h.decoy_id), ['aws_secret']);
  assert.deepEqual(m.scanBytes(Buffer.from('nothing here'), 'stderr'), []);
  assert.deepEqual(createMatcher({ decoys: [] }).scanBytes(Buffer.from(TOKEN), 'stdout'), []);
});
