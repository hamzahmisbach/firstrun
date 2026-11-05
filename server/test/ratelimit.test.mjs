// Token buckets, wrong-code block, SSE slots, LRU cap and client IP, with a fake clock.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { LIMITS } from '../config.mjs';
import { RateLimiter, clientIp, rateKey } from '../http/ratelimit.mjs';

function clock(start = 1_000_000) {
  let t = start;
  const now = () => t;
  now.advance = (ms) => (t += ms);
  return now;
}

function limiter(now, rules = {}, maxKeys) {
  const l = new RateLimiter({ now, rules: { ...LIMITS.rate, ...rules }, maxKeys });
  l.close(); // no prune timer in tests
  return l;
}

test('POST /api/runs: 5 per 10 minutes per IP, then 429 with Retry-After until a token refills', () => {
  const now = clock();
  const l = limiter(now);
  for (let i = 0; i < 5; i++) assert.deepEqual(l.take('postRun', '203.0.113.1'), { ok: true });
  assert.deepEqual(l.take('postRun', '203.0.113.1'), { ok: false, retryAfterS: 120 });
  assert.deepEqual(l.take('postRun', '203.0.113.2'), { ok: true }, 'other IPs are unaffected');
  now.advance(60_000);
  assert.deepEqual(l.take('postRun', '203.0.113.1'), { ok: false, retryAfterS: 60 });
  now.advance(60_000);
  assert.deepEqual(l.take('postRun', '203.0.113.1'), { ok: true });
});

test('refund gives the taken token back to every bucket, never above capacity', () => {
  const now = clock();
  const l = limiter(now);
  const ip = '203.0.113.5';
  for (let i = 0; i < 5; i++) {
    assert.deepEqual(l.take('postRun', ip), { ok: true });
    l.refund('postRun', ip);
  }
  assert.deepEqual(l.take('postRun', ip), { ok: true }, 'refunded takes spent nothing');
  l.refund('postRun', ip);
  l.refund('postRun', ip); // one too many: capped at capacity
  for (let i = 0; i < 5; i++) assert.deepEqual(l.take('postRun', ip), { ok: true });
  assert.equal(l.take('postRun', ip).ok, false);
  l.refund('postRun', '203.0.113.6'); // unknown IP: nothing to give back, no entry created
  assert.equal(l.size, 1);
  assert.throws(() => l.refund('nope', ip), /unknown rate-limit policy/);
});

test('multi-bucket policies take a token from every bucket or from none', () => {
  const now = clock();
  const l = limiter(now, {
    postRun: [
      { capacity: 2, perMs: 1e12 }, // A: practically never refills
      { capacity: 1, perMs: 1000 }, // B
    ],
  });
  const ip = '198.51.100.9';
  assert.equal(l.take('postRun', ip).ok, true, 'A 2 -> 1, B 1 -> 0');
  assert.deepEqual(l.take('postRun', ip), { ok: false, retryAfterS: 1 }, 'B empty; A must keep its token');
  now.advance(1000);
  assert.equal(l.take('postRun', ip).ok, true, 'A still had 1 token, so the failed attempt spent nothing');
  now.advance(1000);
  assert.equal(l.take('postRun', ip).ok, false, 'A is empty now');
});

test('the 20/hour bucket binds under sustained load', () => {
  const now = clock();
  const l = limiter(now);
  let accepted = 0;
  for (let minute = 0; minute <= 180; minute += 2) {
    if (l.take('postRun', '192.0.2.1').ok) accepted += 1;
    now.advance(120_000);
  }
  // The 5/10 min bucket alone would accept all 91 attempts; 20/h caps it at 20 + 3 h * 20.
  assert.ok(accepted <= 80 && accepted >= 78, `accepted ${accepted}`);
});

test('wrong access code: 10 per hour, then the IP is blocked for an hour', () => {
  const now = clock();
  const l = limiter(now);
  const ip = '192.0.2.50';
  for (let i = 1; i <= 9; i++) assert.deepEqual(l.wrongCode(ip), { blocked: false }, `attempt ${i}`);
  assert.equal(l.blockedFor(ip), 0);
  assert.deepEqual(l.wrongCode(ip), { blocked: true });
  assert.equal(l.blockedFor(ip), 3600);
  assert.equal(l.blockedFor('192.0.2.51'), 0);
  now.advance(3_599_000);
  assert.equal(l.blockedFor(ip), 1);
  now.advance(1_000);
  assert.equal(l.blockedFor(ip), 0);
});

test('global run budget: 60 per hour, only consumed on success', () => {
  const now = clock();
  const l = limiter(now);
  for (let i = 0; i < 60; i++) assert.equal(l.takeGlobalRun().ok, true);
  assert.deepEqual(l.takeGlobalRun(), { ok: false, retryAfterS: 60 });
  now.advance(60_000);
  assert.equal(l.takeGlobalRun().ok, true);
  assert.equal(l.takeGlobalRun().ok, false);
});

test('GET run 120/min and SSE 30 opens/min per IP', () => {
  const l = limiter(clock());
  for (let i = 0; i < 120; i++) assert.equal(l.take('getRun', '192.0.2.7').ok, true);
  assert.equal(l.take('getRun', '192.0.2.7').ok, false);
  for (let i = 0; i < 30; i++) assert.equal(l.take('sseOpen', '192.0.2.7').ok, true);
  assert.deepEqual(l.take('sseOpen', '192.0.2.7'), { ok: false, retryAfterS: 2 });
  assert.throws(() => l.take('nope', '192.0.2.7'), /unknown rate-limit policy/);
});

test('SSE: 4 concurrent streams per IP, global cap, release is idempotent', () => {
  const l = limiter(clock(), { sseConcurrentGlobal: 6 });
  const leases = Array.from({ length: 4 }, () => l.openStream('192.0.2.8'));
  assert.ok(leases.every((x) => x.ok));
  assert.deepEqual(l.openStream('192.0.2.8'), { ok: false, reason: 'ip' });
  leases[0].release();
  leases[0].release();
  assert.equal(l.streams, 3);
  assert.equal(l.openStream('192.0.2.8').ok, true);
  assert.equal(l.openStream('192.0.2.9').ok, true);
  assert.equal(l.openStream('192.0.2.10').ok, true);
  assert.deepEqual(l.openStream('192.0.2.11'), { ok: false, reason: 'global' });
});

test('LRU cap: the least recently used key is evicted, never one with open streams', () => {
  const now = clock();
  const l = limiter(now, { getRun: [{ capacity: 1, perMs: 60_000 }] }, 3);
  assert.equal(l.openStream('10.0.0.1').ok, true); // pinned by an open stream
  l.take('getRun', '10.0.0.2');
  l.take('getRun', '10.0.0.3');
  l.take('getRun', '10.0.0.4'); // evicts 10.0.0.2 (oldest without streams)
  assert.equal(l.size, 3);
  assert.equal(l.take('getRun', '10.0.0.2').ok, true, 'evicted key starts with a full bucket');
  assert.equal(l.take('getRun', '10.0.0.4').ok, false, 'recent key kept its state');
});

test('prune drops entries whose buckets are full again', () => {
  const now = clock();
  const l = limiter(now);
  l.take('getRun', '10.1.0.1');
  const lease = l.openStream('10.1.0.2');
  l.wrongCode('10.1.0.3');
  now.advance(60_000);
  l.prune();
  assert.equal(l.size, 2, 'getRun bucket refilled after a minute; stream and wrong-code entries stay');
  lease.release();
  now.advance(3_600_000);
  l.prune();
  assert.equal(l.size, 0);
});

test('clientIp: last X-Forwarded-For value only behind a loopback peer', () => {
  const req = (remoteAddress, xff) => ({ socket: { remoteAddress }, headers: xff === undefined ? {} : { 'x-forwarded-for': xff } });
  assert.equal(clientIp(req('127.0.0.1', '1.1.1.1, 203.0.113.9')), '203.0.113.9');
  assert.equal(clientIp(req('::ffff:127.0.0.1', '203.0.113.9')), '203.0.113.9');
  assert.equal(clientIp(req('::1', ' 2001:db8::1 ')), '2001:db8::1');
  assert.equal(clientIp(req('127.0.0.1')), '127.0.0.1');
  assert.equal(clientIp(req('127.0.0.1', 'garbage')), '127.0.0.1', 'invalid value falls back to the peer');
  assert.equal(clientIp(req('198.51.100.4', '203.0.113.9')), '198.51.100.4', 'untrusted peer: header ignored');
  assert.equal(clientIp(req('::ffff:198.51.100.4')), '198.51.100.4');
});

test('rateKey: IPv4 as is, IPv6 by /64', () => {
  assert.equal(rateKey('203.0.113.9'), '203.0.113.9');
  assert.equal(rateKey('2001:db8:1:2:3:4:5:6'), '2001:db8:1:2::/64');
  assert.equal(rateKey('2001:DB8:1:2::ffff'), '2001:db8:1:2::/64');
  assert.equal(rateKey('2001:db8::1'), '2001:db8:0:0::/64');
  assert.equal(rateKey('::1'), '0:0:0:0::/64');
  assert.equal(rateKey('64:ff9b::192.0.2.1'), '64:ff9b:0:0::/64');
  assert.equal(rateKey('fe80::1%eth0'), 'fe80:0:0:0::/64');
  assert.equal(rateKey('unknown'), 'unknown');
});
