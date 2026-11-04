// Shared test helpers: the full app on an ephemeral port, a temp fixtures folder, a tiny SSE client.
// (node --test also loads this file as a test file; it defines no tests, so that is harmless.)
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { loadConfig } from '../config.mjs';
import { createApp } from '../http/routes.mjs';

export const ACCESS_CODE = 'test-access-code-0123456789abcdef';

export const DEFAULT_SAMPLES = {
  hello: {
    'command.txt': 'echo hello\r\n',
    'claim.txt': '  prints hello\n',
    'meta.json': '{"title":"Hello","description":"Prints hello"}',
    'expected.json': '{"level":"CLEAN"}',
  },
};

export function writeSamples(dir, samples) {
  mkdirSync(dir, { recursive: true });
  for (const [id, files] of Object.entries(samples)) {
    mkdirSync(path.join(dir, id), { recursive: true });
    for (const [name, content] of Object.entries(files)) writeFileSync(path.join(dir, id, name), content);
  }
}

/**
 * Start the real app (stub lifecycle unless app.lifecycle is given) on 127.0.0.1:<random>.
 * `samples: null` leaves the samples folder missing.
 */
export async function startApp({ env = {}, samples = DEFAULT_SAMPLES, app: appOpts = {} } = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'firstrun-test-'));
  const samplesDir = path.join(dir, 'samples');
  if (samples) writeSamples(samplesDir, samples);
  const config = loadConfig({
    FIRSTRUN_LISTEN: '127.0.0.1:0',
    FIRSTRUN_SAMPLES_DIR: samplesDir,
    FIRSTRUN_KILL_SWITCH_FILE: path.join(dir, 'KILL_SWITCH'),
    FIRSTRUN_RUNS_DIR: path.join(dir, 'runs'),
    FIRSTRUN_ACCESS_CODE: ACCESS_CODE,
    ...env,
  });
  const logs = [];
  const app = await createApp(config, { log: (record) => logs.push(record), stub: { stepMs: 5 }, ...appOpts });
  const server = http.createServer(app.handle);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    base,
    app,
    server,
    logs,
    dir,
    config,
    async close() {
      await app.shutdown({ graceMs: 1000 });
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** fetch wrapper: `json` is sent as application/json, `ip` becomes X-Forwarded-For. */
export async function api(base, method, pathname, { json, body, headers = {}, ip } = {}) {
  const h = { ...headers };
  if (ip) h['x-forwarded-for'] = ip;
  let payload = body;
  if (json !== undefined) {
    payload = JSON.stringify(json);
    h['content-type'] ??= 'application/json';
  }
  const res = await fetch(base + pathname, { method, headers: h, body: payload });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  return { status: res.status, headers: res.headers, data, text };
}

export const postRun = (base, json, opts = {}) => api(base, 'POST', '/api/runs', { json, ...opts });

/** Raw node:http request (full control over headers and body framing). */
export function rawRequest(base, { method = 'GET', path: pathname = '/', headers = {}, body, chunks } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(base + pathname, { method, headers, agent: false }, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (c) => (text += c));
      res.on('end', () => {
        let data = null;
        try {
          data = JSON.parse(text);
        } catch {
          data = null;
        }
        resolve({ status: res.statusCode, headers: res.headers, text, data });
      });
    });
    req.on('error', reject);
    if (chunks) for (const c of chunks) req.write(c);
    req.end(body);
  });
}

/** Minimal EventSource-like reader that records every message, comment and retry field. */
export function openSse(url, headers = {}) {
  const stream = { status: 0, headers: {}, messages: [], comments: [], retries: [], raw: '', firstLine: null };
  let buffer = '';
  const listeners = new Set();
  const notify = () => {
    for (const listener of [...listeners]) listener();
  };

  function parseBlock(block) {
    const fields = {};
    for (const line of block.split('\n')) {
      if (line.startsWith(':')) {
        stream.comments.push(line);
        continue;
      }
      const i = line.indexOf(':');
      const name = i === -1 ? line : line.slice(0, i);
      let value = i === -1 ? '' : line.slice(i + 1);
      if (value.startsWith(' ')) value = value.slice(1);
      fields[name] = name === 'data' && fields.data !== undefined ? `${fields.data}\n${value}` : value;
    }
    if (fields.retry !== undefined) stream.retries.push(Number(fields.retry));
    if (fields.data !== undefined) {
      stream.messages.push({ id: Number(fields.id), event: fields.event, data: JSON.parse(fields.data) });
    }
  }

  const req = http.get(url, { headers: { accept: 'text/event-stream', ...headers }, agent: false });
  stream.ended = new Promise((resolve) => {
    req.on('response', (res) => {
      stream.status = res.statusCode;
      stream.headers = res.headers;
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        stream.raw += chunk;
        stream.firstLine ??= stream.raw.split('\n')[0];
        buffer += chunk;
        let i;
        while ((i = buffer.indexOf('\n\n')) !== -1) {
          parseBlock(buffer.slice(0, i));
          buffer = buffer.slice(i + 2);
        }
        notify();
      });
      res.on('close', () => {
        notify();
        resolve(stream);
      });
      notify();
    });
    req.on('error', () => resolve(stream));
  });
  stream.ids = () => stream.messages.map((m) => m.id);
  stream.events = () => stream.messages.map((m) => m.event);
  stream.waitFor = (predicate, timeoutMs = 3000) =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        listeners.delete(check);
        reject(new Error(`SSE condition not met; ids so far: [${stream.ids()}]`));
      }, timeoutMs);
      function check() {
        if (!predicate(stream)) return;
        clearTimeout(timer);
        listeners.delete(check);
        resolve(stream);
      }
      listeners.add(check);
      check();
    });
  stream.close = () => req.destroy();
  return stream;
}

/** A lifecycle the test drives: emits two events, waits for release(), then finishes. */
export function gatedLifecycle() {
  let release;
  const gate = new Promise((resolve) => (release = resolve));
  const lifecycle = async (run, ctx) => {
    ctx.emit('run.started', { sample_id: run.sample_id, command_sha256: run.command_sha256, claim: run.input.claim });
    ctx.emit('exec.started', { container_id: null, timeout_s: 60 });
    await gate;
    ctx.emit('exec.finished', { exit_code: 0, timed_out: false });
    ctx.emit('verdict', { verdict: { level: 'CLEAN', rule_ids: [], coverage_notes: [] }, findings: [] });
    ctx.done({ schema_version: 1, run_id: run.run_id, verdict: { level: 'CLEAN', rule_ids: [], coverage_notes: [] } });
  };
  return { lifecycle, release: () => release() };
}
