// Tiny node:http router: literal segments plus validated :params, JSON request bodies only,
// uniform JSON errors {error, message, retry_after_s?} (section 10). No framework.
import { performance } from 'node:perf_hooks';
import { LIMITS } from '../config.mjs';
import { clientIp } from './ratelimit.mjs';

export class HttpError extends Error {
  /** @param {{retryAfterS?: number, headers?: object, close?: boolean, fields?: object}} [opts] fields: extra JSON body fields */
  constructor(status, code, message, { retryAfterS, headers, close, fields } = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.retryAfterS = retryAfterS;
    this.headers = headers;
    this.close = close;
    this.fields = fields;
  }
}

export function sendJson(res, status, body, headers = {}) {
  const payload = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': payload.length,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...headers,
  });
  res.end(payload);
}

function sendError(res, err) {
  const body = { error: err.code, message: err.message, ...err.fields };
  const headers = { ...err.headers };
  if (err.retryAfterS != null) {
    body.retry_after_s = err.retryAfterS;
    headers['Retry-After'] = String(err.retryAfterS);
  }
  if (err.close) headers.Connection = 'close';
  sendJson(res, err.status, body, headers);
}

const utf8 = new TextDecoder('utf-8', { fatal: true });

const tooLarge = (limits, close) =>
  new HttpError(413, 'body_too_large', `Body must be at most ${limits.bodyMaxBytes} bytes.`, { close });

async function readJsonBody(req, limits) {
  // A huge declared body is refused before anything else, and the connection is not drained.
  if (Number(req.headers['content-length']) > limits.bodyDrainMaxBytes) throw tooLarge(limits, true);
  const [mediaType, ...params] = String(req.headers['content-type'] ?? '').split(';');
  const charset = params
    .map((p) => p.trim().toLowerCase())
    .find((p) => p.startsWith('charset='))
    ?.slice(8)
    .replaceAll('"', '');
  if (mediaType.trim().toLowerCase() !== 'application/json' || (charset && charset !== 'utf-8' && charset !== 'utf8')) {
    throw new HttpError(415, 'unsupported_media_type', 'Content-Type must be application/json.');
  }
  const raw = await readBody(req, limits);
  let text;
  try {
    text = utf8.decode(raw);
  } catch {
    throw new HttpError(400, 'invalid_input', 'Body is not valid UTF-8.');
  }
  try {
    return JSON.parse(text);
  } catch {
    // Never surface or log the parser message: V8 quotes a slice of the input in it.
    throw new HttpError(400, 'invalid_input', 'Body is not valid JSON.');
  }
}

/**
 * Read at most bodyMaxBytes. A larger body is read to the end and dropped (up to
 * bodyDrainMaxBytes) so the 413 reaches the client on a healthy connection; past that the
 * connection is closed after the 413.
 */
function readBody(req, limits) {
  const { bodyMaxBytes, bodyDrainMaxBytes } = limits;
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    const finish = (settle, value) => {
      req.off('data', onData);
      req.off('end', onEnd);
      req.off('error', onError);
      req.off('close', onClose);
      settle(value);
    };
    const onData = (chunk) => {
      size += chunk.length;
      if (size <= bodyMaxBytes) {
        chunks.push(chunk);
      } else if (size > bodyDrainMaxBytes) {
        req.pause();
        finish(reject, tooLarge(limits, true));
      } else {
        chunks.length = 0;
      }
    };
    const onEnd = () =>
      size > bodyMaxBytes ? finish(reject, tooLarge(limits, false)) : finish(resolve, Buffer.concat(chunks, size));
    const onError = (err) => finish(reject, err);
    const onClose = () => finish(reject, Object.assign(new Error('request aborted'), { code: 'ECONNRESET' }));
    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onError);
    req.on('close', onClose);
  });
}

/**
 * @param {{log?: Function, limits?: typeof LIMITS.http}} [opts]
 * Handlers get ctx = {req, res, ip, path, params, query, body, json(status, body, headers)}.
 */
export function createRouter({ log = () => {}, limits = LIMITS.http } = {}) {
  const routes = [];
  const validators = new Map();

  /** Every :name in a pattern needs a validator; a value that fails it means 404. */
  function param(name, re) {
    validators.set(name, re);
  }

  function route(method, pattern, handler, { json = false } = {}) {
    const segments = pattern
      .split('/')
      .slice(1)
      .map((s) => {
        if (!s.startsWith(':')) return { literal: s };
        const name = s.slice(1);
        if (!validators.has(name)) throw new Error(`route ${pattern}: no validator for :${name}`);
        return { name, re: validators.get(name) };
      });
    routes.push({ method, pattern, segments, handler, json });
  }

  function match(path) {
    const parts = path.split('/').slice(1);
    const hits = [];
    for (const r of routes) {
      if (r.segments.length !== parts.length) continue;
      const params = {};
      const ok = r.segments.every((seg, i) => {
        if (seg.literal !== undefined) return seg.literal === parts[i];
        if (!seg.re.test(parts[i])) return false;
        params[seg.name] = parts[i];
        return true;
      });
      if (ok) hits.push({ route: r, params });
    }
    return hits;
  }

  async function handle(req, res) {
    const started = performance.now();
    const ip = clientIp(req);
    const url = req.url ?? '/';
    const q = url.indexOf('?');
    const path = q === -1 ? url : url.slice(0, q);
    res.once('close', () =>
      log({
        msg: 'http',
        method: req.method,
        path: path.slice(0, 200),
        status: res.statusCode,
        ms: Math.round(performance.now() - started),
        ip,
      }),
    );
    try {
      const hits = path.startsWith('/') ? match(path) : [];
      if (hits.length === 0) throw new HttpError(404, 'not_found', 'Not found.');
      const hit = hits.find((h) => h.route.method === req.method);
      if (!hit) {
        const allow = [...new Set(hits.map((h) => h.route.method))].sort().join(', ');
        throw new HttpError(405, 'method_not_allowed', `Method not allowed; use ${allow}.`, {
          headers: { Allow: allow },
        });
      }
      const ctx = {
        req,
        res,
        ip,
        path,
        params: hit.params,
        query: new URLSearchParams(q === -1 ? '' : url.slice(q + 1)),
        body: undefined,
        json: (status, body, headers) => sendJson(res, status, body, headers),
      };
      if (hit.route.json) ctx.body = await readJsonBody(req, limits);
      await hit.route.handler(ctx);
      if (!res.headersSent) throw new Error(`${hit.route.method} ${hit.route.pattern} sent no response`);
    } catch (err) {
      if (res.headersSent || req.socket.destroyed) {
        if (!res.writableEnded) res.destroy();
        return;
      }
      if (err instanceof HttpError) {
        sendError(res, err);
        return;
      }
      log({ level: 'error', msg: 'http.unhandled', method: req.method, path: path.slice(0, 200), err: err?.stack ?? String(err) });
      sendError(res, new HttpError(500, 'internal', 'Internal error.'));
    }
  }

  return { param, route, handle };
}
