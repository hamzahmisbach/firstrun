// LLM client (docs/ARCHITECTURE.md section 8 flow): timeout, 429 / 5xx / network retry, length
// retry, repair turns, fallback model, disabled mode. fetch is mocked; nothing leaves the process.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { z } from 'zod';
import { LlmError, createDelimiter, createLlm, extractJson } from '../llm/client.mjs';

const Shape = z.strictObject({ answer: z.string().max(20), n: z.number().int() });
const CONFIG = {
  base_url: 'https://llm.test/v1',
  seed: 7,
  prompt_version: 'test.1',
  calls: {
    thing: { model: 'primary-model', fallback_model: 'fallback-model', json_mode: 'json_schema', max_completion_tokens: 512, temperature: 0, timeout_ms: 1000, retries: 1 },
    plain: { model: 'primary-model', fallback_model: 'fallback-model', json_mode: 'json_object', max_completion_tokens: 512, temperature: 0.3, timeout_ms: 1000, retries: 0 },
  },
};

function reply(content, { status = 200, finish = 'stop', headers = {} } = {}) {
  const body = status === 200 ? { choices: [{ message: { role: 'assistant', content }, finish_reason: finish }] } : { error: { code: status } };
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (k) => headers[k.toLowerCase()] ?? null },
    text: async () => JSON.stringify(body),
  };
}

/** A fetch whose answers are consumed in order; each may be a response, an Error to throw, or a function of the request. */
function mockFetch(script) {
  const calls = [];
  const fetch = async (url, init) => {
    const body = JSON.parse(init.body);
    calls.push({ url, body, headers: init.headers, signal: init.signal });
    const next = script.shift();
    if (next === undefined) throw new Error(`unexpected fetch #${calls.length}`);
    const value = typeof next === 'function' ? next(body) : next;
    if (value instanceof Error) throw value;
    return value;
  };
  return { fetch, calls };
}

function llmWith(script, extra = {}) {
  const sleeps = [];
  const logs = [];
  const m = mockFetch(script);
  const llm = createLlm({
    apiKey: 'test-key',
    config: CONFIG,
    fetch: m.fetch,
    sleep: async (ms) => void sleeps.push(ms),
    log: (r) => logs.push(r),
    ...extra,
  });
  return { llm, calls: m.calls, sleeps, logs };
}

const PROMPT = { system: 'You answer with JSON.', user: 'SENTINEL_USER_TEXT_9f1 what is the answer' };

test('extractJson: fences, prose around, garbage', () => {
  assert.deepEqual(extractJson('```json\n{"a":1}\n```'), { a: 1 });
  assert.deepEqual(extractJson('Sure! {"a":{"b":[1,2]}} hope this helps'), { a: { b: [1, 2] } });
  assert.equal(extractJson('no json here'), undefined);
  assert.equal(extractJson('{"broken":'), undefined);
  assert.equal(extractJson(null), undefined);
});

test('createDelimiter: random tag per call, both markers present', () => {
  const a = createDelimiter();
  const b = createDelimiter();
  assert.notEqual(a.tag, b.tag);
  const f = a.field('CMD', 'echo hi');
  assert.ok(f.includes(`<<<fr:data:${a.tag}>>>`) && f.includes(`<<<fr:end:${a.tag}>>>`) && f.includes('echo hi'));
});

test('happy path: json_schema request shape, data + meta, modelsUsed', async () => {
  const { llm, calls } = llmWith([reply('{"answer":"42","n":1}')]);
  const { data, meta } = await llm.callJson('thing', PROMPT, Shape);
  assert.deepEqual(data, { answer: '42', n: 1 });
  assert.equal(meta.model, 'primary-model');
  assert.equal(meta.attempts, 1);
  assert.equal(meta.repairs, 0);
  assert.equal(meta.fallback_model_used, false);
  assert.equal(meta.prompt_version, 'test.1');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://llm.test/v1/chat/completions');
  assert.equal(calls[0].headers.authorization, 'Bearer test-key');
  const body = calls[0].body;
  assert.equal(body.model, 'primary-model');
  assert.equal(body.max_completion_tokens, 512);
  assert.equal(body.max_tokens, undefined);
  assert.equal(body.seed, 7);
  assert.deepEqual(body.reasoning, { enabled: false });
  assert.equal(body.response_format.type, 'json_schema');
  assert.equal(body.response_format.json_schema.strict, true);
  assert.equal(body.response_format.json_schema.schema.additionalProperties, false);
  assert.equal(body.tools, undefined);
  assert.deepEqual(body.messages.map((m) => m.role), ['system', 'user']);
  assert.ok(calls[0].signal instanceof AbortSignal);
  assert.deepEqual(llm.modelsUsed(), [{ role: 'thing', model: 'primary-model', calls: 1, ms: llm.modelsUsed()[0].ms, fallback: false }]);
});

test('json_object mode and fenced answers', async () => {
  const { llm, calls } = llmWith([reply('```json\n{"answer":"ok","n":2}\n```')]);
  const { data } = await llm.callJson('plain', PROMPT, Shape);
  assert.deepEqual(data, { answer: 'ok', n: 2 });
  assert.deepEqual(calls[0].body.response_format, { type: 'json_object' });
  assert.equal(calls[0].body.temperature, 0.3);
});

test('repair turn: schema failure is sent back with the issues, then accepted', async () => {
  const { llm, calls } = llmWith([reply('{"answer":"x","n":1,"extra":true}'), reply('{"answer":"x","n":1}')]);
  const { data, meta } = await llm.callJson('thing', PROMPT, Shape);
  assert.deepEqual(data, { answer: 'x', n: 1 });
  assert.equal(meta.attempts, 2);
  assert.equal(meta.repairs, 1);
  const msgs = calls[1].body.messages;
  assert.deepEqual(msgs.map((m) => m.role), ['system', 'user', 'assistant', 'user']);
  assert.ok(msgs[2].content.includes('"extra"'));
  assert.ok(/extra/.test(msgs[3].content) && /corrected JSON only/.test(msgs[3].content));
});

test('fallback model after the primary keeps failing validation', async () => {
  const { llm, calls } = llmWith([reply('not json at all'), reply('{"nope":1}'), reply('{"answer":"fb","n":3}')]);
  const { data, meta } = await llm.callJson('thing', PROMPT, Shape);
  assert.deepEqual(data, { answer: 'fb', n: 3 });
  assert.equal(meta.model, 'fallback-model');
  assert.equal(meta.fallback_model_used, true);
  assert.equal(meta.attempts, 3);
  assert.deepEqual(calls.map((c) => c.body.model), ['primary-model', 'primary-model', 'fallback-model']);
  assert.equal(calls[2].body.messages.length, 2, 'fallback model starts a fresh conversation');
  assert.equal(llm.modelsUsed()[0].model, 'fallback-model');
});

test('every model failing -> LlmError with code, modelsUsed marks fallback', async () => {
  const { llm } = llmWith([reply('{}'), reply('{}'), reply('{}'), reply('{}')]);
  await assert.rejects(llm.callJson('thing', PROMPT, Shape), (err) => err instanceof LlmError && err.code === 'invalid' && err.meta.attempts === 4);
  const [u] = llm.modelsUsed();
  assert.equal(u.fallback, true);
  assert.equal(u.calls, 4);
});

test('429 waits Retry-After (capped at 5 s) and retries once', async () => {
  const { llm, sleeps, calls } = llmWith([reply('', { status: 429, headers: { 'retry-after': '30' } }), reply('{"answer":"ok","n":1}')]);
  const { data } = await llm.callJson('plain', PROMPT, Shape);
  assert.equal(data.answer, 'ok');
  assert.deepEqual(sleeps, [5000]);
  assert.equal(calls.length, 2);
});

test('5xx retried once per model, then the fallback model, then LlmError http', async () => {
  const { llm, calls } = llmWith([reply('', { status: 503 }), reply('', { status: 502 }), reply('', { status: 500 }), reply('', { status: 504 })]);
  await assert.rejects(llm.callJson('plain', PROMPT, Shape), (err) => err.code === 'http' && err.meta.status === 504);
  assert.deepEqual(calls.map((c) => c.body.model), ['primary-model', 'primary-model', 'fallback-model', 'fallback-model']);
});

test('4xx other than 429 is not retried on the same model', async () => {
  const { llm, calls } = llmWith([reply('', { status: 400 }), reply('{"answer":"fb","n":1}')]);
  const { meta } = await llm.callJson('plain', PROMPT, Shape);
  assert.equal(meta.model, 'fallback-model');
  assert.equal(calls.length, 2);
});

test('network error retried once; timeout goes straight to the fallback model', async () => {
  const net = Object.assign(new Error('socket hang up'), { name: 'FetchError' });
  let r = llmWith([net, reply('{"answer":"ok","n":1}')]);
  assert.equal((await r.llm.callJson('plain', PROMPT, Shape)).meta.model, 'primary-model');
  assert.equal(r.calls.length, 2);

  const timeout = Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' });
  r = llmWith([timeout, reply('{"answer":"ok","n":1}')]);
  const { meta } = await r.llm.callJson('plain', PROMPT, Shape);
  assert.equal(meta.model, 'fallback-model');
  assert.equal(r.calls.length, 2);

  r = llmWith([timeout, timeout]);
  await assert.rejects(r.llm.callJson('plain', PROMPT, Shape), (err) => err.code === 'timeout');
});

test('finish_reason length: retried once with doubled max_completion_tokens (cap 8192)', async () => {
  const { llm, calls } = llmWith([reply('{"answer":"tru', { finish: 'length' }), reply('{"answer":"full","n":1}')]);
  const { data } = await llm.callJson('plain', PROMPT, Shape);
  assert.equal(data.answer, 'full');
  assert.deepEqual(calls.map((c) => c.body.max_completion_tokens), [512, 1024]);
});

test('oversized answers are rejected without parsing', async () => {
  const { llm } = llmWith([reply(`{"answer":"${'x'.repeat(70 * 1024)}"}`), reply('{"answer":"ok","n":1}')]);
  const { meta } = await llm.callJson('plain', PROMPT, Shape);
  assert.equal(meta.model, 'fallback-model');
});

test('disabled (or no key): no network, LlmError disabled, usage row with fallback true', async () => {
  for (const extra of [{ disabled: true }, { apiKey: '' }, { apiKey: undefined }]) {
    const { llm, calls } = llmWith([reply('{"answer":"never","n":0}')], extra);
    assert.equal(llm.enabled, false);
    await assert.rejects(llm.callJson('thing', PROMPT, Shape), (err) => err instanceof LlmError && err.code === 'disabled');
    assert.equal(calls.length, 0);
    assert.deepEqual(llm.modelsUsed(), [{ role: 'thing', model: null, calls: 0, ms: 0, fallback: true }]);
  }
});

test('unknown call name and abort signal', async () => {
  const { llm, calls } = llmWith([reply('{"answer":"x","n":1}')]);
  await assert.rejects(llm.callJson('nope', PROMPT, Shape), (err) => err.code === 'config');
  const ac = new AbortController();
  ac.abort();
  await assert.rejects(llm.callJson('thing', PROMPT, Shape, { signal: ac.signal }), (err) => err.code === 'aborted');
  assert.equal(calls.length, 0);
});

test('deadline: bounds the request timeout and skips attempts and the fallback model when no time is left', async () => {
  let r = llmWith([reply('{"answer":"ok","n":1}')]);
  const { meta } = await r.llm.callJson('plain', PROMPT, Shape, { deadline: performance.now() + 60_000 });
  assert.equal(meta.model, 'primary-model');

  r = llmWith([reply('{"answer":"ok","n":1}')]);
  await assert.rejects(r.llm.callJson('plain', PROMPT, Shape, { deadline: performance.now() + 500 }), (err) => err.code === 'timeout');
  assert.equal(r.calls.length, 0, 'no request starts with under a second left');

  // Primary fails validation after a slow answer, then there is no time for the fallback model.
  const slowBad = async () => {
    await new Promise((resolve) => setTimeout(resolve, 300));
    return reply('{"nope":1}');
  };
  r = llmWith([slowBad, reply('{"answer":"fb","n":1}')]);
  const deadline = performance.now() + 1200;
  await assert.rejects(r.llm.callJson('plain', PROMPT, Shape, { deadline }), (err) => err.code === 'invalid');
  assert.equal(r.calls.length, 1);
  assert.ok(r.calls[0].signal instanceof AbortSignal);
});

test('logs carry sizes and digests, never prompt or answer text; onRaw gets the raw answer', async () => {
  const answer = '{"answer":"SENTINEL_ANSWER_7c2","n":1}';
  const { llm, logs } = llmWith([reply('{"bad":1}'), reply(answer)]);
  const raws = [];
  await llm.callJson('thing', PROMPT, Shape, { onRaw: (t) => raws.push(t) });
  const text = JSON.stringify(logs);
  assert.ok(logs.length >= 2);
  assert.ok(!text.includes('SENTINEL_USER_TEXT_9f1'));
  assert.ok(!text.includes('SENTINEL_ANSWER_7c2'));
  assert.ok(logs.some((r) => r.msg === 'llm_response' && typeof r.sha256 === 'string' && r.bytes > 0));
  assert.deepEqual(raws, ['{"bad":1}', answer]);
});
