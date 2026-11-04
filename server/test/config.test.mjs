import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { test } from 'node:test';
import { LIMITS, loadConfig } from '../config.mjs';

test('loadConfig: defaults', () => {
  const c = loadConfig({});
  assert.deepEqual(c.listen, { host: '127.0.0.1', port: 3000 });
  assert.equal(c.publicUrl, null);
  assert.equal(c.accessCodeSha256, null);
  assert.equal(c.freeform, true);
  assert.equal(c.killSwitch, false);
  assert.equal(c.killSwitchFile, path.resolve('/srv/firstrun/KILL_SWITCH'));
  assert.equal(c.runsDir, path.resolve('/srv/firstrun/runs'));
  assert.ok(c.samplesDir.endsWith(path.join('fixtures', 'samples')), c.samplesDir);
});

test('loadConfig: parses values; empty strings count as unset; other env vars are ignored', () => {
  const c = loadConfig({
    FIRSTRUN_LISTEN: '[::1]:8080',
    FIRSTRUN_PUBLIC_URL: 'https://firstrun.example.org/',
    FIRSTRUN_ACCESS_CODE: 'x'.repeat(24),
    FIRSTRUN_FREEFORM: '0',
    FIRSTRUN_KILL_SWITCH: '1',
    FIRSTRUN_RUNS_DIR: '',
    PATH: 'whatever',
  });
  assert.deepEqual(c.listen, { host: '::1', port: 8080 });
  assert.equal(c.publicUrl, 'https://firstrun.example.org');
  assert.deepEqual(c.accessCodeSha256, createHash('sha256').update('x'.repeat(24)).digest());
  assert.equal(c.freeform, false);
  assert.equal(c.killSwitch, true);
  assert.equal(c.runsDir, path.resolve('/srv/firstrun/runs'));
  assert.deepEqual(loadConfig({ FIRSTRUN_LISTEN: '0.0.0.0:0' }).listen, { host: '0.0.0.0', port: 0 });
});

test('loadConfig: rejects bad values without echoing them', () => {
  const cases = {
    FIRSTRUN_LISTEN: ['localhost', '127.0.0.1:70000', '127.0.0.1:'],
    FIRSTRUN_PUBLIC_URL: ['ftp://example.org', 'not a url'],
    FIRSTRUN_FREEFORM: ['yes', 'true'],
    FIRSTRUN_KILL_SWITCH: ['on'],
    FIRSTRUN_ACCESS_CODE: ['short-secret-value'],
  };
  for (const [name, values] of Object.entries(cases)) {
    for (const value of values) {
      assert.throws(
        () => loadConfig({ [name]: value }),
        (err) => err.message.includes(name) && (name !== 'FIRSTRUN_ACCESS_CODE' || !err.message.includes(value)),
        `${name}=${value}`,
      );
    }
  }
});

test('LIMITS: section 11 numbers live in config.mjs and are frozen', () => {
  assert.ok(Object.isFrozen(LIMITS) && Object.isFrozen(LIMITS.rate.postRun[0]));
  assert.equal(LIMITS.http.bodyMaxBytes, 64 * 1024);
  assert.equal(LIMITS.input.commandMaxBytes, 16384);
  assert.equal(LIMITS.input.claimMaxChars, 300);
  assert.deepEqual(LIMITS.queue, { concurrency: 2, maxWaiting: 8 });
  assert.deepEqual(
    LIMITS.rate.postRun.map((r) => [r.capacity, r.perMs]),
    [
      [5, 600_000],
      [20, 3_600_000],
    ],
  );
  assert.deepEqual(LIMITS.rate.wrongCode, { capacity: 10, perMs: 3_600_000, blockMs: 3_600_000 });
  assert.equal(LIMITS.rate.getRun[0].capacity, 120);
  assert.equal(LIMITS.rate.sseOpen[0].capacity, 30);
  assert.equal(LIMITS.rate.getOther[0].capacity, 300);
  assert.equal(LIMITS.rate.sseConcurrentPerIp, 4);
  assert.equal(LIMITS.rate.sseConcurrentGlobal, 100);
  assert.equal(LIMITS.rate.globalRuns.capacity, 60);
  assert.equal(LIMITS.rate.maxKeys, 10_000);
  assert.equal(LIMITS.sse.maxMessages, 5000);
  assert.equal(LIMITS.sse.maxBytes, 4 * 1024 * 1024);
  assert.equal(LIMITS.sse.retryMs, 2000);
  assert.equal(LIMITS.sse.heartbeatMs, 15_000);
  assert.equal(LIMITS.sse.retainAfterEndMs, 600_000);
  assert.equal(LIMITS.retryAfterS.runsDisabled, 30);
});
