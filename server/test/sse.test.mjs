// SSE: ids from 1, Last-Event-ID / ?after= replay without duplicates, 204, heartbeat, ring buffer.
import assert from 'node:assert/strict';
import { setTimeout as sleep } from 'node:timers/promises';
import { describe, test } from 'node:test';
import { api, gatedLifecycle, openSse, postRun, startApp } from './helpers.mjs';

async function finishedRun(t) {
  const { data } = await postRun(t.base, { sample_id: 'hello' });
  const s = openSse(t.base + data.events_url);
  await s.ended;
  assert.equal(s.events().at(-1), 'run.done');
  return data;
}

describe('reconnect', () => {
  test('live stream, drop, reconnect with Last-Event-ID: no duplicates, no gaps', async () => {
    const gate = gatedLifecycle();
    const t = await startApp({ app: { lifecycle: gate.lifecycle } });
    try {
      const { data } = await postRun(t.base, { sample_id: 'hello' });
      const url = t.base + data.events_url;
      const first = openSse(url);
      await first.waitFor((s) => s.messages.length >= 3);
      assert.deepEqual(first.ids(), [1, 2, 3]);
      first.close();

      // The client "lost" message 3: it resumes from 2 and must get 3 again, then live 4..6, once each.
      const second = openSse(url, { 'Last-Event-ID': '2' });
      await second.waitFor((s) => s.messages.length >= 1);
      gate.release();
      await second.ended;
      assert.equal(second.firstLine, 'retry: 2000');
      assert.deepEqual(second.ids(), [3, 4, 5, 6]);
      assert.deepEqual(second.events(), ['exec.started', 'exec.finished', 'verdict', 'run.done']);
      const seen = [...first.ids().slice(0, 2), ...second.ids()];
      assert.deepEqual(seen, [1, 2, 3, 4, 5, 6]);
    } finally {
      await t.close();
    }
  });

  test('finished run: ?after= and Last-Event-ID replay only newer messages (header wins), then close', async () => {
    const t = await startApp();
    try {
      const { events_url: url } = await finishedRun(t);
      let s = openSse(`${t.base}${url}?after=3`);
      await s.ended;
      assert.equal(s.status, 200);
      assert.deepEqual(s.ids(), [4, 5, 6]);

      s = openSse(`${t.base}${url}?after=1`, { 'Last-Event-ID': '4' });
      await s.ended;
      assert.deepEqual(s.ids(), [5, 6]);

      s = openSse(`${t.base}${url}`, { 'Last-Event-ID': 'garbage' });
      await s.ended;
      assert.deepEqual(s.ids(), [1, 2, 3, 4, 5, 6], 'a malformed header is ignored');

      const bad = await api(t.base, 'GET', `${url}?after=-1`);
      assert.equal(bad.status, 400);
      assert.equal(bad.data.error, 'invalid_input');
    } finally {
      await t.close();
    }
  });

  test('finished run with nothing newer for the client: 204 (EventSource stops reconnecting)', async () => {
    const t = await startApp();
    try {
      const { events_url: url } = await finishedRun(t);
      for (const [suffix, headers] of [
        ['?after=6', {}],
        ['', { 'Last-Event-ID': '6' }],
        ['?after=500', {}],
      ]) {
        const s = openSse(`${t.base}${url}${suffix}`, headers);
        await s.ended;
        assert.equal(s.status, 204, `${suffix} ${JSON.stringify(headers)}`);
        assert.equal(s.raw, '');
      }
    } finally {
      await t.close();
    }
  });

  test('buffer dropped after retention: 204, while GET /api/runs/:id still answers', async () => {
    const t = await startApp({ app: { sse: { retainAfterEndMs: 40 } } });
    try {
      const run = await finishedRun(t);
      await sleep(120);
      const s = openSse(t.base + run.events_url);
      await s.ended;
      assert.equal(s.status, 204);
      const g = await api(t.base, 'GET', `/api/runs/${run.run_id}`);
      assert.equal(g.status, 200);
      assert.equal(g.data.status, 'done');
    } finally {
      await t.close();
    }
  });
});

describe('stream mechanics', () => {
  test('heartbeat comment ": hb <ts_ms>" while idle', async () => {
    const gate = gatedLifecycle();
    const t = await startApp({ app: { lifecycle: gate.lifecycle, sse: { heartbeatMs: 25 } } });
    try {
      const { data } = await postRun(t.base, { sample_id: 'hello' });
      const s = openSse(t.base + data.events_url);
      await s.waitFor((x) => x.comments.length >= 2);
      for (const c of s.comments) assert.match(c, /^: hb \d{13}$/);
      gate.release();
      await s.ended;
      assert.equal(s.events().at(-1), 'run.done');
    } finally {
      await t.close();
    }
  });

  test('ring buffer keeps the newest maxMessages; ids keep counting', async () => {
    const lifecycle = async (run, ctx) => {
      for (let i = 0; i < 10; i++) ctx.emit('evidence', { event: { seq: i + 1 } });
      ctx.done({ verdict: { level: 'CLEAN' } });
    };
    const t = await startApp({ app: { lifecycle, sse: { maxMessages: 4 } } });
    try {
      const { data } = await postRun(t.base, { sample_id: 'hello' });
      await sleep(50);
      const s = openSse(t.base + data.events_url);
      await s.ended;
      assert.deepEqual(s.ids(), [9, 10, 11, 12]); // 1 run.queued + 10 evidence + run.done
      assert.equal(s.events().at(-1), 'run.done');
    } finally {
      await t.close();
    }
  });

  test('ring buffer byte cap', async () => {
    const lifecycle = async (run, ctx) => {
      for (let i = 0; i < 20; i++) ctx.emit('evidence', { event: { seq: i + 1, pad: 'x'.repeat(200) } });
      ctx.done({ verdict: { level: 'CLEAN' } });
    };
    const t = await startApp({ app: { lifecycle, sse: { maxBytes: 1500 } } });
    try {
      const { data } = await postRun(t.base, { sample_id: 'hello' });
      await sleep(50);
      const s = openSse(t.base + data.events_url);
      await s.ended;
      const replayed = Buffer.byteLength(s.raw) - Buffer.byteLength('retry: 2000\n\n');
      assert.ok(replayed <= 1500, `replayed ${replayed} bytes`);
      assert.ok(s.messages.length >= 3 && s.messages.length < 22, `kept ${s.messages.length}`);
      assert.equal(s.ids().at(-1), 22);
      assert.deepEqual(s.ids(), Array.from({ length: s.messages.length }, (_, i) => 23 - s.messages.length + i));
    } finally {
      await t.close();
    }
  });

  test('more than 4 concurrent streams from one IP is 429 too_many_streams', async () => {
    const gate = gatedLifecycle();
    const t = await startApp({ app: { lifecycle: gate.lifecycle } });
    try {
      const { data } = await postRun(t.base, { sample_id: 'hello' });
      const url = t.base + data.events_url;
      const ip = { 'x-forwarded-for': '203.0.113.44' };
      const streams = Array.from({ length: 4 }, () => openSse(url, ip));
      await Promise.all(streams.map((s) => s.waitFor((x) => x.messages.length >= 1)));
      const fifth = await api(t.base, 'GET', data.events_url, { ip: '203.0.113.44' });
      assert.equal(fifth.status, 429);
      assert.equal(fifth.data.error, 'too_many_streams');
      assert.ok(Number(fifth.headers.get('retry-after')) > 0);
      const other = openSse(url, { 'x-forwarded-for': '203.0.113.45' });
      await other.waitFor((x) => x.messages.length >= 1);

      streams[0].close();
      let again; // each attempt costs an open (30/min/IP): keep the loop short
      for (let i = 0; i < 20; i++) {
        again = openSse(url, ip);
        await again.waitFor((x) => x.status !== 0);
        if (again.status === 200) break;
        await sleep(20);
      }
      assert.equal(again.status, 200, 'slot released when a stream closes');
      gate.release();
      await Promise.all([again.ended, other.ended, ...streams.slice(1).map((s) => s.ended)]);
      assert.equal(t.app.limiter.streams, 0);
    } finally {
      await t.close();
    }
  });
});
