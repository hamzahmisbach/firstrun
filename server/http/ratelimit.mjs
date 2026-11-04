// Token buckets per client and for the whole instance (section 11). In-memory, LRU-capped,
// pruned every minute. All numbers come from LIMITS.rate in config.mjs.
import { isIP } from 'node:net';
import { LIMITS } from '../config.mjs';

const LOOPBACK = new Set(['127.0.0.1', '::ffff:127.0.0.1', '::1']);

/**
 * Client IP: the last X-Forwarded-For value when the peer is loopback (Caddy replaces the header
 * with the address it saw, section 10.1), otherwise the TCP peer address.
 */
export function clientIp(req) {
  const peer = req.socket?.remoteAddress ?? '';
  if (LOOPBACK.has(peer)) {
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string') {
      const last = xff.split(',').at(-1).trim();
      if (isIP(last)) return unmapIpv4(last);
    }
  }
  return unmapIpv4(peer) || 'unknown';
}

function unmapIpv4(ip) {
  return ip.startsWith('::ffff:') && isIP(ip.slice(7)) === 4 ? ip.slice(7) : ip;
}

/** Bucket key: IPv4 as is, IPv6 by /64 (one subscriber usually owns a whole /64). */
export function rateKey(ip) {
  if (isIP(ip) !== 6) return ip;
  let s = ip.split('%')[0].toLowerCase();
  const v4 = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(s);
  if (v4) {
    const [a, b, c, d] = v4.slice(1).map(Number);
    s = `${s.slice(0, v4.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head, tail] = s.split('::');
  const h = head ? head.split(':') : [];
  const t = tail === undefined ? null : tail ? tail.split(':') : [];
  const groups = t === null ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  return `${groups.slice(0, 4).map((g) => parseInt(g, 16).toString(16)).join(':')}::/64`;
}

function refill(bucket, rule, now) {
  const elapsed = now - bucket.at;
  if (elapsed > 0) {
    bucket.tokens = Math.min(rule.capacity, bucket.tokens + (elapsed * rule.capacity) / rule.perMs);
    bucket.at = now;
  }
}

function waitMs(bucket, rule) {
  return bucket.tokens >= 1 ? 0 : Math.ceil(((1 - bucket.tokens) * rule.perMs) / rule.capacity);
}

const toSeconds = (ms) => Math.max(1, Math.ceil(ms / 1000));

export class RateLimiter {
  #rules;
  #now;
  #maxKeys;
  #entries = new Map(); // rateKey -> { buckets: {policy: bucket[]}, blockedUntil, streams }
  #globalRuns;
  #globalStreams = 0;
  #timer;

  constructor({ rules = LIMITS.rate, now = Date.now, maxKeys = rules.maxKeys } = {}) {
    this.#rules = rules;
    this.#now = now;
    this.#maxKeys = maxKeys;
    this.#globalRuns = { tokens: rules.globalRuns.capacity, at: now() };
    this.#timer = setInterval(() => this.prune(), rules.pruneEveryMs);
    this.#timer.unref();
  }

  /** Consume one token from every bucket of `policy` ("postRun", "getRun", ...) or none at all. */
  take(policy, ip) {
    const rules = this.#rules[policy];
    if (!Array.isArray(rules)) throw new Error(`unknown rate-limit policy ${policy}`);
    const now = this.#now();
    const entry = this.#entry(rateKey(ip));
    const buckets = (entry.buckets[policy] ??= rules.map((r) => ({ tokens: r.capacity, at: now })));
    let wait = 0;
    buckets.forEach((b, i) => {
      refill(b, rules[i], now);
      wait = Math.max(wait, waitMs(b, rules[i]));
    });
    if (wait > 0) return { ok: false, retryAfterS: toSeconds(wait) };
    for (const b of buckets) b.tokens -= 1;
    return { ok: true };
  }

  /** Seconds left on a wrong-access-code block, 0 when not blocked. */
  blockedFor(ip) {
    const entry = this.#entries.get(rateKey(ip));
    const left = entry ? entry.blockedUntil - this.#now() : 0;
    return left > 0 ? toSeconds(left) : 0;
  }

  /** Record a wrong access code; the IP is blocked for blockMs once its bucket runs dry. */
  wrongCode(ip) {
    const rule = this.#rules.wrongCode;
    const now = this.#now();
    const entry = this.#entry(rateKey(ip));
    const bucket = (entry.buckets.wrongCode ??= [{ tokens: rule.capacity, at: now }])[0];
    refill(bucket, rule, now);
    bucket.tokens = Math.max(0, bucket.tokens - 1);
    if (bucket.tokens < 1) entry.blockedUntil = now + rule.blockMs;
    return { blocked: entry.blockedUntil > now };
  }

  /** Global hourly run budget; only called for runs that are actually accepted. */
  takeGlobalRun() {
    const rule = this.#rules.globalRuns;
    refill(this.#globalRuns, rule, this.#now());
    const wait = waitMs(this.#globalRuns, rule);
    if (wait > 0) return { ok: false, retryAfterS: toSeconds(wait) };
    this.#globalRuns.tokens -= 1;
    return { ok: true };
  }

  /** Reserve an SSE slot. Returns { ok, release } or { ok: false, reason: "ip" | "global" }. */
  openStream(ip) {
    if (this.#globalStreams >= this.#rules.sseConcurrentGlobal) return { ok: false, reason: 'global' };
    const entry = this.#entry(rateKey(ip));
    if (entry.streams >= this.#rules.sseConcurrentPerIp) return { ok: false, reason: 'ip' };
    entry.streams += 1;
    this.#globalStreams += 1;
    let released = false;
    return {
      ok: true,
      release: () => {
        if (released) return;
        released = true;
        entry.streams -= 1;
        this.#globalStreams -= 1;
      },
    };
  }

  get streams() {
    return this.#globalStreams;
  }

  get size() {
    return this.#entries.size;
  }

  /** Drop entries that carry no state (all buckets full, no block, no open stream). */
  prune() {
    const now = this.#now();
    for (const [key, entry] of this.#entries) {
      if (entry.streams > 0 || entry.blockedUntil > now) continue;
      const idle = Object.entries(entry.buckets).every(([policy, buckets]) => {
        const rules = policy === 'wrongCode' ? [this.#rules.wrongCode] : this.#rules[policy];
        return buckets.every((b, i) => {
          refill(b, rules[i], now);
          return b.tokens >= rules[i].capacity;
        });
      });
      if (idle) this.#entries.delete(key);
    }
  }

  close() {
    clearInterval(this.#timer);
  }

  #entry(key) {
    let entry = this.#entries.get(key);
    if (entry) {
      this.#entries.delete(key); // move to the LRU tail
    } else {
      entry = { buckets: {}, blockedUntil: 0, streams: 0 };
      if (this.#entries.size >= this.#maxKeys) this.#evictOldest();
    }
    this.#entries.set(key, entry);
    return entry;
  }

  #evictOldest() {
    // Keep entries with open streams so the stream counters stay correct.
    for (const [key, entry] of this.#entries) {
      if (entry.streams === 0) {
        this.#entries.delete(key);
        return;
      }
    }
  }
}
