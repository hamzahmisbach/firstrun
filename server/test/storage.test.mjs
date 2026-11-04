// storage/: LRU+TTL cache, spool, and the facade in local and s3 modes (fake S3 wrapper).
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { loadConfig } from '../config.mjs';
import { ReportCache, createSpool } from '../storage/cache.mjs';
import { createStorage } from '../storage/index.mjs';
import { StorageUnavailable, createS3 } from '../storage/s3.mjs';

const ID1 = 'ABCDEFGHJKMNPQRSTVWXYZ0001';
const ID2 = 'ABCDEFGHJKMNPQRSTVWXYZ0002';
const ID3 = 'ABCDEFGHJKMNPQRSTVWXYZ0003';

test('ReportCache: LRU eviction and TTL', () => {
  let t = 0;
  const cache = new ReportCache({ max: 2, ttlMs: 100, now: () => t });
  cache.set(ID1, { a: 1 });
  cache.set(ID2, { a: 2 });
  assert.deepEqual(cache.get(ID1), { a: 1 }); // ID1 is now the most recent
  cache.set(ID3, { a: 3 });
  assert.equal(cache.get(ID2), null, 'least recently used was evicted');
  assert.deepEqual(cache.get(ID1), { a: 1 });
  t = 101;
  assert.equal(cache.get(ID1), null, 'expired');
  assert.equal(cache.size, 1);
});

test('spool: atomic write, read, delete, list; ids validated', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'firstrun-spool-'));
  try {
    const spool = createSpool(path.join(dir, 'spool'));
    await spool.init();
    await spool.write(ID1, { x: 1 });
    assert.deepEqual(await spool.read(ID1), { x: 1 });
    assert.equal(await spool.read(ID2), null);
    assert.deepEqual((await spool.list()).map((e) => e.id), [ID1]);
    assert.deepEqual(readdirSync(path.join(dir, 'spool')), [`${ID1}.json`], 'no temp file left');
    await spool.delete(ID1);
    await spool.delete(ID1);
    assert.equal(await spool.read(ID1), null);
    await assert.rejects(spool.write('../etc', {}), TypeError);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function fakeS3({ failPut = false, failGet = false } = {}) {
  const objects = new Map();
  return {
    bucket: 'fake',
    calls: [],
    objects,
    flags: { failPut, failGet },
    async putReport(id, report) {
      this.calls.push(['put', id]);
      if (this.flags.failPut) throw new Error('put failed');
      objects.set(id, { report, at: new Date() });
    },
    async getReport(id) {
      this.calls.push(['get', id]);
      if (this.flags.failGet) throw new StorageUnavailable('down');
      return objects.get(id)?.report ?? null;
    },
    async deleteReport(id) {
      this.calls.push(['delete', id]);
      objects.delete(id);
    },
    async headBucket() {
      if (this.flags.failGet) throw new Error('down');
    },
    async listReports() {
      return [...objects].map(([id, o]) => ({ id, lastModified: o.at }));
    },
  };
}

test('local mode: no credentials, reports live in the spool, check() says local', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'firstrun-storage-'));
  try {
    const config = loadConfig({ FIRSTRUN_SPOOL_DIR: path.join(dir, 'spool') });
    const storage = await createStorage({ config });
    assert.equal(storage.mode, 'local');
    assert.deepEqual(await storage.putReport(ID1, { run_id: ID1 }), { where: 'spool' });
    assert.equal(await storage.check(), 'local');
    const fresh = await createStorage({ config }); // a new process still finds it
    assert.deepEqual(await fresh.getReport(ID1), { run_id: ID1 });
    assert.equal(await fresh.getReport(ID2), null);
    await fresh.deleteReport(ID1);
    assert.equal(await fresh.getReport(ID1), null);
    assert.deepEqual(await storage.retrySpool(), { uploaded: 0, dropped: 0, pending: 0 });
    assert.deepEqual(await storage.retention(), { deleted: 0 });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('s3 mode: PUT goes to the bucket, falls back to the spool, janitor retries; GET order cache -> spool -> s3', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'firstrun-storage-'));
  try {
    const config = loadConfig({ FIRSTRUN_SPOOL_DIR: path.join(dir, 'spool') });
    const s3 = fakeS3();
    let t = 1_000_000;
    const logs = [];
    const storage = await createStorage({ config, s3, log: (r) => logs.push(r), now: () => t });
    assert.equal(storage.mode, 's3');
    assert.deepEqual(await storage.putReport(ID1, { run_id: ID1 }), { where: 's3' });
    assert.equal(await storage.check(), 'ok');

    s3.flags.failPut = true;
    assert.deepEqual(await storage.putReport(ID2, { run_id: ID2 }), { where: 'spool' });
    assert.ok(logs.some((l) => l.msg === 'storage.put_failed'));
    assert.deepEqual(await storage.retrySpool(), { uploaded: 0, dropped: 0, pending: 1 });
    s3.flags.failPut = false;
    assert.deepEqual(await storage.retrySpool(), { uploaded: 1, dropped: 0, pending: 0 });
    assert.ok(s3.objects.has(ID2));
    assert.deepEqual(await storage.spool.list(), []);

    // GET: cache first (no S3 call), then S3 for an unknown id, null when missing.
    s3.calls.length = 0;
    assert.deepEqual(await storage.getReport(ID1), { run_id: ID1 });
    assert.deepEqual(s3.calls, []);
    const other = await createStorage({ config, s3, now: () => t });
    assert.deepEqual(await other.getReport(ID2), { run_id: ID2 });
    assert.deepEqual(s3.calls, [['get', ID2]]);
    assert.equal(await other.getReport(ID3), null);
    s3.flags.failGet = true;
    await assert.rejects(other.getReport(ID3), StorageUnavailable);
    assert.equal(await other.check(), 'degraded');

    // Retention: objects older than ttl days are deleted.
    s3.flags.failGet = false;
    s3.objects.get(ID1).at = new Date(t - 40 * 24 * 3600 * 1000);
    assert.deepEqual(await storage.retention(30), { deleted: 1 });
    assert.ok(!s3.objects.has(ID1) && s3.objects.has(ID2));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('createS3 wraps the SDK client: key layout, metadata, checksum settings', async () => {
  const sent = [];
  const stored = new Map();
  let ctorInput = null;
  class S3Client {
    constructor(input) {
      ctorInput = input;
    }
  }
  const mk = (name) =>
    class {
      constructor(input) {
        this.name = name;
        this.input = input;
      }
    };
  const sdk = {
    S3Client,
    PutObjectCommand: mk('Put'),
    GetObjectCommand: mk('Get'),
    DeleteObjectCommand: mk('Delete'),
    HeadBucketCommand: mk('Head'),
    ListObjectsV2Command: mk('List'),
  };
  const client = {
    async send(cmd) {
      sent.push(cmd);
      if (cmd.name === 'Put') stored.set(cmd.input.Key, cmd.input.Body);
      if (cmd.name === 'Get') {
        if (!stored.has(cmd.input.Key)) throw Object.assign(new Error('nope'), { name: 'NoSuchKey' });
        return { Body: { transformToString: async () => stored.get(cmd.input.Key) } };
      }
      if (cmd.name === 'Delete') stored.delete(cmd.input.Key);
      if (cmd.name === 'List') return { Contents: [...stored.keys()].map((Key) => ({ Key, LastModified: new Date(0) })), IsTruncated: false };
      return {};
    },
  };
  const cfg = { endpoint: 'https://sgp1.vultrobjects.com', bucket: 'b', accessKey: 'a', secretKey: 's' };
  const s3 = await createS3(cfg, { sdk, client });
  await s3.putReport(ID1, { schema_version: 1, run_id: ID1 });
  assert.equal(sent[0].input.Key, `reports/${ID1}.json`);
  assert.equal(sent[0].input.ContentType, 'application/json; charset=utf-8');
  assert.deepEqual(sent[0].input.Metadata, { 'schema-version': '1' });
  assert.deepEqual(await s3.getReport(ID1), { schema_version: 1, run_id: ID1 });
  assert.equal(await s3.getReport(ID2), null);
  assert.deepEqual((await s3.listReports()).map((o) => o.id), [ID1]);
  await s3.deleteReport(ID1);
  assert.equal(stored.size, 0);
  assert.equal(await s3.selftest().then((k) => k.startsWith('selftest/')), true);
  assert.equal(stored.size, 0, 'selftest cleans up');
  // A real client gets the Vultr-safe settings.
  await createS3(cfg, { sdk });
  assert.equal(ctorInput.requestChecksumCalculation, 'WHEN_REQUIRED');
  assert.equal(ctorInput.responseChecksumValidation, 'WHEN_REQUIRED');
  assert.equal(ctorInput.endpoint, cfg.endpoint);
  assert.equal(ctorInput.credentials.secretAccessKey, 's');
});
