// Server-Sent Events fan-out, one hub per run (section 10.1 "Reconnect", 10.2).
// Every message gets id n (per-run counter from 1) and is kept in a ring buffer, so a client that
// reconnects with Last-Event-ID (or ?after=n) gets exactly the messages it missed, then live ones.
import { LIMITS } from '../config.mjs';

export const SSE_HEADERS = Object.freeze({
  'Content-Type': 'text/event-stream; charset=utf-8',
  'Cache-Control': 'no-cache, no-transform',
  'X-Accel-Buffering': 'no',
});

const TERMINAL_EVENTS = new Set(['run.done', 'run.error']);

export class RunHub {
  #opts;
  #onDrop;
  #buf = []; // { id, frame, size }, oldest first
  #bytes = 0;
  #nextId = 1;
  #clients = new Set();
  #ended = false;

  constructor(runId, opts, onDrop) {
    this.runId = runId;
    this.#opts = opts;
    this.#onDrop = onDrop;
  }

  get lastId() {
    return this.#nextId - 1;
  }

  get ended() {
    return this.#ended;
  }

  /** Append a message, fan it out, and close all streams after run.done / run.error. */
  publish(event, fields = {}) {
    if (this.#ended) return this.lastId; // nothing may follow a terminal event
    const { run_id: _r, ts_ms: _t, ...rest } = fields;
    const id = this.#nextId++;
    // JSON.stringify escapes \n and \r, so data is always a single line.
    const data = JSON.stringify({ run_id: this.runId, ts_ms: Date.now(), ...rest });
    const frame = `id: ${id}\nevent: ${event}\ndata: ${data}\n\n`;
    const size = Buffer.byteLength(frame);
    this.#buf.push({ id, frame, size });
    this.#bytes += size;
    while (this.#buf.length > this.#opts.maxMessages || (this.#bytes > this.#opts.maxBytes && this.#buf.length > 1)) {
      this.#bytes -= this.#buf.shift().size;
    }
    for (const client of this.#clients) client.write(frame);
    if (TERMINAL_EVENTS.has(event)) this.#end();
    return id;
  }

  /**
   * Start a stream on `res`: retry line, replay of messages with id > afterId, then live messages.
   * `onClose` runs exactly once when the stream goes away (used to release the rate-limit slot).
   */
  attach(res, afterId, onClose = () => {}) {
    const opts = this.#opts;
    const client = {
      res,
      timer: null,
      write(chunk) {
        if (res.destroyed || res.writableEnded) return;
        res.write(chunk);
        if (res.writableLength > opts.maxPendingBytes) res.destroy(); // too slow; it can resume later
      },
    };
    let closed = false;
    res.once('close', () => {
      if (closed) return;
      closed = true;
      clearInterval(client.timer);
      this.#clients.delete(client);
      onClose();
    });

    res.writeHead(200, SSE_HEADERS);
    res.flushHeaders();
    const after = Math.min(afterId, this.lastId); // an id from the future means "caught up"
    let chunk = `retry: ${opts.retryMs}\n\n`;
    for (const m of this.#buf) if (m.id > after) chunk += m.frame;
    client.write(chunk);

    if (this.#ended) {
      res.end();
      return;
    }
    this.#clients.add(client);
    client.timer = setInterval(() => client.write(`: hb ${Date.now()}\n\n`), opts.heartbeatMs);
    client.timer.unref();
  }

  /** End every open stream without finishing the run (server shutdown). */
  closeClients() {
    for (const client of this.#clients) {
      clearInterval(client.timer);
      client.res.end();
    }
  }

  #end() {
    this.#ended = true;
    this.closeClients();
    const timer = setTimeout(() => this.#onDrop(this), this.#opts.retainAfterEndMs);
    timer.unref();
  }
}

export class SseHubs {
  #hubs = new Map();
  #opts;

  constructor(opts = {}) {
    this.#opts = { ...LIMITS.sse, ...opts };
  }

  create(runId) {
    const hub = new RunHub(runId, this.#opts, (h) => {
      if (this.#hubs.get(runId) === h) this.#hubs.delete(runId);
    });
    this.#hubs.set(runId, hub);
    return hub;
  }

  get(runId) {
    return this.#hubs.get(runId);
  }

  closeAll() {
    for (const hub of this.#hubs.values()) hub.closeClients();
  }
}
