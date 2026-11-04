// End-to-end over HTTP: POST -> 202 -> SSE -> GET, auth, rate limits, kill switch, queue, samples.
import assert from 'node:assert/strict';
import { rmSync, writeFileSync } from 'node:fs';
import { describe, test } from 'node:test';
import { RunError } from '../run/lifecycle.mjs';
import { RUN_ID_RE } from '../run/ids.mjs';
import { ACCESS_CODE, api, gatedLifecycle, openSse, postRun, startApp } from './helpers.mjs';

const STUB_SEQUENCE = ['run.queued', 'run.started', 'exec.started', 'exec.finished', 'verdict', 'run.done'];

describe('POST /api/runs -> SSE -> GET /api/runs/:id (stub lifecycle)', () => {
  test('curated sample runs through run.done', async () => {
    const t = await startApp({ env: { FIRSTRUN_PUBLIC_URL: 'https://firstrun.example.org/' } });
    try {
      const r = await postRun(t.base, { sample_id: 'hello' }, { ip: '203.0.113.10' });
      assert.equal(r.status, 202);
      assert.equal(r.headers.get('cache-control'), 'no-store');
      const id = r.data.run_id;
      assert.match(id, RUN_ID_RE);
      assert.deepEqual(r.data, {
        run_id: id,
        status: 'queued',
        position: 0,
        events_url: `/api/runs/${id}/events`,
        report_url: `https://firstrun.example.org/r/${id}`,
      });

      const s = openSse(t.base + r.data.events_url, { 'x-forwarded-for': '203.0.113.10' });
      await s.ended;
      assert.equal(s.status, 200);
      assert.equal(s.headers['content-type'], 'text/event-stream; charset=utf-8');
      assert.equal(s.headers['cache-control'], 'no-cache, no-transform');
      assert.equal(s.headers['x-accel-buffering'], 'no');
      assert.equal(s.firstLine, 'retry: 2000');
      assert.deepEqual(s.events(), STUB_SEQUENCE);
      assert.deepEqual(s.ids(), [1, 2, 3, 4, 5, 6]);
      for (const m of s.messages) {
        assert.equal(m.data.run_id, id);
        assert.equal(typeof m.data.ts_ms, 'number');
      }
      const byEvent = Object.fromEntries(s.messages.map((m) => [m.event, m.data]));
      assert.equal(byEvent['run.queued'].position, 0);
      assert.equal(byEvent['run.started'].sample_id, 'hello');
      assert.equal(byEvent['run.started'].claim, 'prints hello');
      assert.match(byEvent['run.started'].command_sha256, /^[0-9a-f]{64}$/);
      assert.equal(byEvent['exec.finished'].exit_code, 0);
      assert.equal(byEvent['exec.finished'].timed_out, false);
      assert.equal(byEvent.verdict.verdict.level, 'CLEAN');
      assert.match(byEvent.verdict.verdict.coverage_notes[0], /^STUB:/);
      assert.equal(byEvent['run.done'].report_url, `https://firstrun.example.org/r/${id}`);
      assert.equal(byEvent['run.done'].verdict_level, 'CLEAN');

      const g = await api(t.base, 'GET', `/api/runs/${id}`, { ip: '203.0.113.10' });
      assert.equal(g.status, 200);
      assert.equal(g.headers.get('cache-control'), 'public, max-age=86400, immutable');
      assert.equal(g.data.status, 'done');
      assert.equal(g.data.last_n, 6);
      assert.equal(g.data.report.stub, true);
      assert.equal(g.data.report.schema_version, 1);
      assert.deepEqual(g.data.report.input, { command: 'echo hello\n', claim: 'prints hello', sample_id: 'hello' });
    } finally {
      await t.close();
    }
  });

  test('GET /api/runs/:id while running reports phase; no-store', async () => {
    const gate = gatedLifecycle();
    const t = await startApp({ app: { lifecycle: gate.lifecycle } });
    try {
      const { data } = await postRun(t.base, { sample_id: 'hello' });
      const s = openSse(`${t.base}${data.events_url}`);
      await s.waitFor((x) => x.messages.length >= 3);
      const g = await api(t.base, 'GET', `/api/runs/${data.run_id}`);
      assert.equal(g.headers.get('cache-control'), 'no-store');
      assert.deepEqual(g.data, { status: 'running', run_id: data.run_id, created_at: g.data.created_at, phase: 'setup', last_n: 3 });
      gate.release();
      await s.ended;
      assert.equal((await api(t.base, 'GET', `/api/runs/${data.run_id}`)).data.status, 'done');
    } finally {
      await t.close();
    }
  });
});

describe('free-form access code', () => {
  test('401 without the header, 403 with a wrong code, 202 with the right one', async () => {
    const t = await startApp();
    try {
      const secretCommand = 'echo UNIQUE-COMMAND-MARKER-41\r\n';
      const body = { command: secretCommand, claim: ' UNIQUE-CLAIM-MARKER-42 ' };
      let r = await postRun(t.base, body, { ip: '198.51.100.20' });
      assert.equal(r.status, 401);
      assert.equal(r.data.error, 'access_code_required');

      r = await postRun(t.base, body, { ip: '198.51.100.20', headers: { 'x-firstrun-access-code': 'WRONG-CODE-MARKER-43' } });
      assert.equal(r.status, 403);
      assert.equal(r.data.error, 'access_code_invalid');

      r = await postRun(t.base, body, { ip: '198.51.100.20', headers: { 'x-firstrun-access-code': ACCESS_CODE } });
      assert.equal(r.status, 202);
      const s = openSse(t.base + r.data.events_url);
      await s.ended;
      const started = s.messages.find((m) => m.event === 'run.started').data;
      assert.equal(started.sample_id, null);
      assert.equal(started.claim, 'UNIQUE-CLAIM-MARKER-42');
      const report = (await api(t.base, 'GET', `/api/runs/${r.data.run_id}`)).data.report;
      assert.equal(report.input.command, 'echo UNIQUE-COMMAND-MARKER-41\n');
      assert.equal('sample_id' in report.input, false);

      // Logging rule: only sizes and sha256, never the text or the code.
      const logText = JSON.stringify(t.logs);
      for (const secret of ['UNIQUE-COMMAND-MARKER-41', 'UNIQUE-CLAIM-MARKER-42', 'WRONG-CODE-MARKER-43', ACCESS_CODE]) {
        assert.equal(logText.includes(secret), false, `log leaked ${secret}`);
      }
      const accepted = t.logs.find((l) => l.msg === 'run.accepted');
      assert.equal(accepted.command_bytes, Buffer.byteLength('echo UNIQUE-COMMAND-MARKER-41\n'));
      assert.match(accepted.command_sha256, /^[0-9a-f]{64}$/);
      assert.ok(t.logs.some((l) => l.msg === 'access_code.invalid' && l.ip === '198.51.100.20'));
    } finally {
      await t.close();
    }
  });

  test('FIRSTRUN_FREEFORM=0 or no FIRSTRUN_ACCESS_CODE: free-form is 403 freeform_disabled, samples still work', async () => {
    for (const env of [{ FIRSTRUN_FREEFORM: '0' }, { FIRSTRUN_ACCESS_CODE: '' }]) {
      const t = await startApp({ env });
      try {
        const r = await postRun(t.base, { command: 'ls', claim: 'lists' }, { headers: { 'x-firstrun-access-code': ACCESS_CODE } });
        assert.equal(r.status, 403, JSON.stringify(env));
        assert.equal(r.data.error, 'freeform_disabled');
        assert.equal((await postRun(t.base, { sample_id: 'hello' })).status, 202);
      } finally {
        await t.close();
      }
    }
  });
});

describe('abuse controls', () => {
  test('sixth POST from one IP within 10 minutes is 429 rate_limited with Retry-After', async () => {
    const t = await startApp();
    try {
      for (let i = 1; i <= 5; i++) {
        const r = await postRun(t.base, { sample_id: 'hello' }, { ip: '192.0.2.77' });
        assert.equal(r.status, 202, `POST ${i}`);
      }
      const r = await postRun(t.base, { sample_id: 'hello' }, { ip: '192.0.2.77' });
      assert.equal(r.status, 429);
      assert.equal(r.data.error, 'rate_limited');
      const retryAfter = Number(r.headers.get('retry-after'));
      assert.ok(retryAfter > 0 && retryAfter <= 120, `Retry-After ${retryAfter}`);
      assert.equal(r.data.retry_after_s, retryAfter);
      assert.equal((await postRun(t.base, { sample_id: 'hello' }, { ip: '192.0.2.78' })).status, 202, 'other IP');
      const h = await api(t.base, 'GET', '/healthz');
      assert.equal(h.data.counters.rate_limited, 1);
      assert.equal(h.data.counters.runs_total, 6);
    } finally {
      await t.close();
    }
  });

  test('kill switch via FIRSTRUN_KILL_SWITCH=1: 503 runs_disabled, Retry-After 30', async () => {
    const t = await startApp({ env: { FIRSTRUN_KILL_SWITCH: '1' } });
    try {
      const r = await postRun(t.base, { sample_id: 'hello' });
      assert.equal(r.status, 503);
      assert.equal(r.data.error, 'runs_disabled');
      assert.equal(r.data.retry_after_s, 30);
      assert.equal(r.headers.get('retry-after'), '30');
      const h = await api(t.base, 'GET', '/healthz');
      assert.equal(h.status, 200);
      assert.equal(h.data.accepting_runs, false);
    } finally {
      await t.close();
    }
  });

  test('kill switch via file: checked on every POST, no restart needed', async () => {
    const t = await startApp();
    try {
      writeFileSync(t.config.killSwitchFile, '');
      let r = await postRun(t.base, { sample_id: 'hello' });
      assert.equal(r.status, 503);
      assert.equal(r.data.error, 'runs_disabled');
      assert.equal(r.headers.get('retry-after'), '30');
      assert.equal((await api(t.base, 'GET', '/healthz')).data.accepting_runs, false);
      rmSync(t.config.killSwitchFile);
      r = await postRun(t.base, { sample_id: 'hello' });
      assert.equal(r.status, 202);
      assert.equal((await api(t.base, 'GET', '/healthz')).data.accepting_runs, true);
    } finally {
      await t.close();
    }
  });

  test('queue: 2 running + 8 waiting, then 503 queue_full; positions move up', async () => {
    const gate = gatedLifecycle();
    const t = await startApp({ app: { lifecycle: gate.lifecycle } });
    try {
      const runs = [];
      for (let i = 0; i < 10; i++) {
        const r = await postRun(t.base, { sample_id: 'hello' }, { ip: `10.9.0.${i + 1}` });
        assert.equal(r.status, 202);
        runs.push(r.data);
      }
      assert.deepEqual(runs.map((r) => r.position), [0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
      const full = await postRun(t.base, { sample_id: 'hello' }, { ip: '10.9.0.99' });
      assert.equal(full.status, 503);
      assert.equal(full.data.error, 'queue_full');
      assert.equal(full.headers.get('retry-after'), '30');

      const queued = await api(t.base, 'GET', `/api/runs/${runs[9].run_id}`);
      assert.equal(queued.data.status, 'queued');
      assert.equal(queued.data.position, 8);
      const h = await api(t.base, 'GET', '/healthz');
      assert.equal(h.data.active_runs, 2);
      assert.equal(h.data.queued, 8);
      assert.equal(h.data.counters.queue_rejections, 1);

      const last = openSse(t.base + runs[9].events_url);
      gate.release();
      await last.ended;
      const positions = last.messages.filter((m) => m.event === 'run.queued').map((m) => m.data.position);
      assert.equal(positions[0], 8);
      assert.equal(positions.at(-1), 1, 'run.queued is re-sent as the line moves');
      assert.equal(last.events().at(-1), 'run.done');
    } finally {
      await t.close();
    }
  });

  test('shutdown fails waiting runs with run.error and refuses new ones', async () => {
    const gate = gatedLifecycle();
    const t = await startApp({ app: { lifecycle: gate.lifecycle } });
    try {
      const ids = [];
      for (let i = 0; i < 3; i++) ids.push((await postRun(t.base, { sample_id: 'hello' }, { ip: `10.8.0.${i}` })).data.run_id);
      const waiting = openSse(`${t.base}/api/runs/${ids[2]}/events`);
      await waiting.waitFor((x) => x.messages.length >= 1);
      const stopping = t.app.shutdown({ graceMs: 2000 });
      gate.release();
      await stopping;
      await waiting.ended;
      const err = waiting.messages.at(-1);
      assert.equal(err.event, 'run.error');
      assert.deepEqual(
        { code: err.data.code, stage: err.data.stage, retryable: err.data.retryable },
        { code: 'internal', stage: 'queue', retryable: true },
      );
      for (const id of ids.slice(0, 2)) assert.equal((await api(t.base, 'GET', `/api/runs/${id}`)).data.status, 'done');
      const r = await postRun(t.base, { sample_id: 'hello' });
      assert.equal(r.status, 503);
      assert.equal(r.data.error, 'runs_disabled');
    } finally {
      await t.close();
    }
  });
});

describe('lifecycle failures become run.error', () => {
  const cases = [
    ['throws an Error', async () => Promise.reject(new Error('boom with details')), { code: 'internal', message: 'Internal error.', stage: 'setup', retryable: true }],
    [
      'throws a RunError',
      async (run, ctx) => {
        ctx.phase('exec');
        throw new RunError('sandbox_start_failed', 'Sandbox did not start.', { stage: 'exec', retryable: true });
      },
      { code: 'sandbox_start_failed', message: 'Sandbox did not start.', stage: 'exec', retryable: true },
    ],
    ['returns without ctx.done()', async () => {}, { code: 'internal', message: 'Run ended without a result.', stage: 'setup', retryable: true }],
  ];
  for (const [name, lifecycle, expected] of cases) {
    test(name, async () => {
      const t = await startApp({ app: { lifecycle } });
      try {
        const { data } = await postRun(t.base, { sample_id: 'hello' });
        const s = openSse(t.base + data.events_url);
        await s.ended;
        const last = s.messages.at(-1);
        assert.equal(last.event, 'run.error');
        const { run_id: _r, ts_ms: _t, ...fields } = last.data;
        assert.deepEqual(fields, expected);
        const g = await api(t.base, 'GET', `/api/runs/${data.run_id}`);
        assert.equal(g.data.status, 'error');
        assert.deepEqual(g.data.error, expected);
        assert.equal(g.headers.get('cache-control'), 'no-store');
        assert.equal(JSON.stringify(t.logs).includes('boom with details'), name === 'throws an Error', 'stack logged only for crashes');
      } finally {
        await t.close();
      }
    });
  }
});

describe('GET /api/samples and /healthz', () => {
  test('samples come from the fixtures folder', async () => {
    const t = await startApp({
      samples: {
        hello: { 'command.txt': 'echo hello\n', 'claim.txt': 'prints hello' },
        broken: { 'command.txt': 'ls' },
      },
    });
    try {
      const r = await api(t.base, 'GET', '/api/samples');
      assert.equal(r.status, 200);
      assert.equal(r.headers.get('cache-control'), 'public, max-age=300');
      assert.deepEqual(r.data, {
        samples: [{ id: 'hello', title: 'hello', description: '', command: 'echo hello\n', claim: 'prints hello', expected_verdict: null }],
      });
      const unknown = await postRun(t.base, { sample_id: 'broken' });
      assert.equal(unknown.status, 400);
    } finally {
      await t.close();
    }
  });

  test('a missing samples folder is an empty list', async () => {
    const t = await startApp({ samples: null });
    try {
      const r = await api(t.base, 'GET', '/api/samples');
      assert.deepEqual(r.data, { samples: [] });
    } finally {
      await t.close();
    }
  });

  test('/healthz shape', async () => {
    const t = await startApp();
    try {
      const r = await api(t.base, 'GET', '/healthz');
      assert.equal(r.status, 200);
      assert.equal(r.headers.get('cache-control'), 'no-store');
      const { version, uptime_s: uptime, ...rest } = r.data;
      assert.match(version, /^\d+\.\d+\.\d+/);
      assert.ok(Number.isInteger(uptime));
      assert.deepEqual(rest, {
        ok: true,
        accepting_runs: true,
        active_runs: 0,
        queued: 0,
        checks: { docker: 'unchecked', sidecar: 'unchecked', sinkhole_selftest: 'unchecked', storage: 'unchecked', disk_free_mb: null },
        counters: { runs_total: 0, runs_failed: 0, rate_limited: 0, queue_rejections: 0 },
      });
    } finally {
      await t.close();
    }
  });
});
