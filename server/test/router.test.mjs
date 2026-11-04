// Router behaviour: 404, 405 + Allow, 415, 413, run-id params validated before any handler.
import assert from 'node:assert/strict';
import http from 'node:http';
import { after, before, describe, test } from 'node:test';
import { createRouter, HttpError } from '../http/router.mjs';
import { newRunId } from '../run/ids.mjs';
import { api, rawRequest, startApp } from './helpers.mjs';

const JSON_TYPE = 'application/json; charset=utf-8';

describe('router over the real app', () => {
  let t;
  before(async () => {
    t = await startApp();
  });
  after(() => t.close());

  test('unknown paths are 404 not_found with a JSON error body', async () => {
    for (const p of ['/', '/nope', '/api', '/api/runs/', '/healthz/', '/api/samples/x', '//healthz']) {
      const r = await api(t.base, 'GET', p);
      assert.equal(r.status, 404, p);
      assert.deepEqual(r.data, { error: 'not_found', message: 'Not found.' }, p);
      assert.equal(r.headers.get('content-type'), JSON_TYPE);
    }
  });

  test('wrong method is 405 method_not_allowed with Allow', async () => {
    const cases = [
      ['GET', '/api/runs', 'POST'],
      ['DELETE', '/api/runs', 'POST'],
      ['OPTIONS', '/api/runs', 'POST'],
      ['POST', '/healthz', 'GET'],
      ['PUT', '/api/samples', 'GET'],
      ['POST', `/api/runs/${newRunId()}`, 'GET'],
      ['DELETE', `/api/runs/${newRunId()}/events`, 'GET'],
    ];
    for (const [method, p, allow] of cases) {
      const r = await api(t.base, method, p);
      assert.equal(r.status, 405, `${method} ${p}`);
      assert.equal(r.data.error, 'method_not_allowed');
      assert.equal(r.headers.get('allow'), allow);
    }
  });

  test('run ids that fail ^[0-9A-Z]{26}$ are 404 for every method, before any handler', async () => {
    const id = newRunId();
    for (const bad of [id.toLowerCase(), id.slice(1), `${id}A`, 'abc', '..%2F..%2Fetc', `${id.slice(1)}%41`]) {
      for (const [method, suffix] of [
        ['GET', ''],
        ['POST', ''],
        ['GET', '/events'],
      ]) {
        const r = await api(t.base, method, `/api/runs/${bad}${suffix}`);
        assert.equal(r.status, 404, `${method} ${bad}${suffix}`);
      }
    }
    assert.equal((await api(t.base, 'GET', `/api/runs/${id}`)).status, 404, 'valid but unknown');
    assert.equal((await api(t.base, 'GET', `/api/runs/${id}/events`)).status, 404, 'valid but unknown');
  });

  test('POST bodies must be application/json (utf-8): 415 otherwise', async () => {
    for (const type of [undefined, 'text/plain', 'application/x-www-form-urlencoded', 'application/json; charset=latin1', 'application/jsonp']) {
      const headers = type ? { 'content-type': type } : {};
      const r = await rawRequest(t.base, { method: 'POST', path: '/api/runs', headers, body: '{"sample_id":"hello"}' });
      assert.equal(r.status, 415, String(type));
      assert.equal(r.data.error, 'unsupported_media_type');
    }
    for (const type of ['application/json; charset=UTF-8', 'Application/JSON', 'application/json;charset="utf-8"']) {
      const r = await rawRequest(t.base, {
        method: 'POST',
        path: '/api/runs',
        headers: { 'content-type': type, 'x-forwarded-for': '203.0.113.200' },
        body: '{"sample_id":"hello"}',
      });
      assert.equal(r.status, 202, type);
    }
  });

  test('bodies over 64 KiB are 413 body_too_large (declared length and chunked)', async () => {
    const big = `{"command":"${'a'.repeat(64 * 1024)}","claim":"x"}`;
    let r = await rawRequest(t.base, {
      method: 'POST',
      path: '/api/runs',
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(big) },
      body: big,
    });
    assert.equal(r.status, 413);
    assert.deepEqual(r.data, { error: 'body_too_large', message: 'Body must be at most 65536 bytes.' });

    r = await rawRequest(t.base, {
      method: 'POST',
      path: '/api/runs',
      headers: { 'content-type': 'application/json', 'transfer-encoding': 'chunked' },
      chunks: Array.from({ length: 20 }, () => 'a'.repeat(4096)),
    });
    assert.equal(r.status, 413);

    // Exactly at the limit passes the size check (then the request fails later, on auth).
    const edge = JSON.stringify({ x: 'a'.repeat(64 * 1024 - 8) });
    assert.equal(Buffer.byteLength(edge), 64 * 1024);
    r = await rawRequest(t.base, { method: 'POST', path: '/api/runs', headers: { 'content-type': 'application/json' }, body: edge });
    assert.equal(r.status, 401, 'past the size check; free-form without a code');
  });

  test('a huge declared body gets 413 right away (even with a wrong type) and the connection is closed', async () => {
    const port = new URL(t.base).port;
    for (const type of ['application/json', 'text/plain']) {
      const r = await new Promise((resolve, reject) => {
        const req = http.request({
          host: '127.0.0.1',
          port,
          method: 'POST',
          path: '/api/runs',
          agent: false,
          headers: { 'content-type': type, 'content-length': 50 * 1024 * 1024 },
        });
        req.on('response', (res) => {
          let text = '';
          res.on('data', (c) => (text += c));
          res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text }));
        });
        req.on('error', reject);
        req.flushHeaders(); // the body never comes
      });
      assert.equal(r.status, 413, type);
      assert.equal(r.headers.connection, 'close');
      assert.equal(JSON.parse(r.text).error, 'body_too_large');
    }
  });

  test('an empty JSON body is 400 invalid_input', async () => {
    const r = await rawRequest(t.base, { method: 'POST', path: '/api/runs', headers: { 'content-type': 'application/json' }, body: '' });
    assert.equal(r.status, 400);
    assert.deepEqual(r.data, { error: 'invalid_input', message: 'Body is not valid JSON.' });
  });

  test('HttpError carries retry_after_s into the body and Retry-After; other errors are a bare 500', async () => {
    const router = createRouter();
    router.route('GET', '/busy', () => {
      throw new HttpError(429, 'rate_limited', 'Slow down.', { retryAfterS: 7 });
    });
    router.route('GET', '/boom', () => {
      throw new Error('secret internals');
    });
    const server = http.createServer(router.handle);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    try {
      let r = await api(base, 'GET', '/busy');
      assert.equal(r.status, 429);
      assert.equal(r.headers.get('retry-after'), '7');
      assert.deepEqual(r.data, { error: 'rate_limited', message: 'Slow down.', retry_after_s: 7 });
      r = await api(base, 'GET', '/boom');
      assert.equal(r.status, 500);
      assert.deepEqual(r.data, { error: 'internal', message: 'Internal error.' });
    } finally {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  });
});

test('createRouter: a :param without a registered validator is a programming error', () => {
  const router = createRouter();
  assert.throws(() => router.route('GET', '/api/runs/:id', () => {}), /no validator for :id/);
  router.param('id', /^[0-9A-Z]{26}$/);
  assert.doesNotThrow(() => router.route('GET', '/api/runs/:id', () => {}));
});
