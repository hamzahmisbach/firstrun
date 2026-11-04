// Normalized event schema (docs/ARCHITECTURE.md 7.4) and the per-run evidence limits (7.3, 6.6).
// Required fields are strict, extra fields pass through: consumers must ignore what they do not
// know, and the orchestrator may add fields without touching this file.
import { z } from 'zod';
import { LIMITS } from '../config.mjs';

const KiB = 1024;
const MiB = 1024 * KiB;

export const EVIDENCE_LIMITS = Object.freeze({
  caps: Object.freeze({
    'proc.exec': 2000,
    'file.open': 5000,
    'net.connect': 1000,
    'shim.call': 500,
    sinkhole: 2000, // per sinkhole kind
    total: LIMITS.output.eventsPerRun, // canary.hit and exec.finished are exempt
  }),
  matcher: Object.freeze({
    bodyMaxBytes: 2 * MiB, // first bytes of bodies/<id>.bin
    scanBudgetBytes: 64 * MiB, // per run; beyond it coverage.scan_truncated = true
    minPatternBytes: 24,
  }),
  tail: Object.freeze({
    tracePollMs: 20,
    sinkholePollMs: 50,
    readChunkBytes: 256 * KiB,
    maxLineBytes: 4 * MiB, // a longer line is dropped and counted as a decode error
  }),
  sinkPort: 9009, // tcpsink.py listener; a udp.datagram reporting it has no real original port
  shimPrefix: '/opt/firstrun/shims/',
  t0Marker: '/opt/firstrun/launch',
});

export const SOURCES = ['gvisor', 'sinkhole', 'orchestrator'];
export const WHERE = ['url', 'header', 'body', 'dns', 'tcp_bytes', 'stdout', 'stderr'];

const envelope = {
  run_id: z.string().regex(/^[0-9A-Z]{26}$/),
  seq: z.number().int().positive(),
  ts_ms: z.number().int().nonnegative(),
  t_rel_ms: z.number().int(),
};
const gvisor = { ...envelope, source: z.literal('gvisor') };
const sinkhole = { ...envelope, source: z.literal('sinkhole') };
const orchestrator = { ...envelope, source: z.literal('orchestrator') };

const port = z.number().int().min(0).max(65535);

export const EVENT_SCHEMAS = {
  'proc.exec': z.looseObject({
    ...gvisor,
    kind: z.literal('proc.exec'),
    pid: z.number().int(),
    ppid: z.number().int(),
    exe: z.string().startsWith('/'),
    argv: z.array(z.string()),
    cwd: z.string().optional(),
    interp: z.string().optional(),
  }),
  'file.open': z.looseObject({
    ...gvisor,
    kind: z.literal('file.open'),
    pid: z.number().int(),
    path: z.string().startsWith('/'),
    access: z.enum(['read', 'write', 'create']),
    decoy_id: z.string().optional(),
    ok: z.literal(false).optional(),
    errno: z.number().int().optional(),
  }),
  'net.connect': z.looseObject({
    ...gvisor,
    kind: z.literal('net.connect'),
    pid: z.number().int(),
    family: z.enum(['inet', 'inet6', 'unix']),
    dst_ip: z.string().nullable(),
    dst_port: port.nullable(),
    path: z.string().optional(),
  }),
  'shim.call': z.looseObject({
    ...gvisor,
    kind: z.literal('shim.call'),
    tool: z.string().min(1),
    args: z.array(z.string()),
    pid: z.number().int().optional(),
  }),
  'dns.query': z.looseObject({
    ...sinkhole,
    kind: z.literal('dns.query'),
    name: z.string(),
    qtype: z.string(),
    ts_src: z.string().optional(),
  }),
  'http.request': z.looseObject({
    ...sinkhole,
    kind: z.literal('http.request'),
    method: z.string(),
    host: z.string(),
    port: port.nullable(),
    path: z.string(),
    body_len: z.number().int().nullable(),
    body_ref: z.string().optional(),
    scheme: z.string().optional(),
    status: z.number().int().optional(),
    canned: z.boolean().optional(),
  }),
  'tls.clienthello': z.looseObject({
    ...sinkhole,
    kind: z.literal('tls.clienthello'),
    sni: z.string(),
    port: port.nullable(),
    alpn: z.array(z.string()).optional(),
  }),
  'tls.failed': z.looseObject({
    ...sinkhole,
    kind: z.literal('tls.failed'),
    sni: z.string(),
    port: port.nullable(),
    error: z.string(),
  }),
  'tcp.connect': z.looseObject({
    ...sinkhole,
    kind: z.literal('tcp.connect'),
    orig_dst_port: port.nullable(),
    bytes_in: z.number().int().nonnegative(),
    looks_like_tls: z.boolean(),
    sni: z.string().nullable().optional(),
  }),
  'udp.datagram': z.looseObject({
    ...sinkhole,
    kind: z.literal('udp.datagram'),
    orig_dst_port: port.optional(),
    len: z.number().int().nonnegative(),
  }),
  'canary.hit': z.looseObject({
    ...orchestrator,
    kind: z.literal('canary.hit'),
    decoy_id: z.string(),
    category: z.string(),
    form: z.string(),
    where: z.enum(WHERE),
    // null for stdout/stderr hits, which are not tied to a sinkhole event
    event_seq: z.number().int().positive().nullable(),
  }),
  'exec.finished': z.looseObject({
    ...orchestrator,
    kind: z.literal('exec.finished'),
    exit_code: z.number().int().nullable(),
    timed_out: z.boolean(),
    coverage: z.looseObject({}).optional(),
  }),
};

export const KINDS = Object.freeze(Object.keys(EVENT_SCHEMAS));
export const SINKHOLE_KINDS = Object.freeze(['dns.query', 'http.request', 'tls.clienthello', 'tls.failed', 'tcp.connect', 'udp.datagram']);

export const EventSchema = z.discriminatedUnion('kind', Object.values(EVENT_SCHEMAS));

/** Returns the validated event, or throws a ZodError (kind and field path only, no values). */
export function validateEvent(event) {
  return EventSchema.parse(event);
}

export function safeValidateEvent(event) {
  return EventSchema.safeParse(event);
}

/** Per-decoy manifest entry (5.3), as produced by run/canary.mjs and stored in the report. */
export const DecoySchema = z.looseObject({
  id: z.string().regex(/^[a-z][a-z0-9_]*$/),
  path: z.string().startsWith('~/').nullable(),
  category: z.string(),
  value: z.string().nullable(),
  forms: z.array(z.enum(['raw', 'b64x3', 'b64b64x3', 'url', 'hex', 'base32'])),
});

export const DecoysSchema = z.array(DecoySchema);

export function emptyCoverage() {
  return {
    mode: 'trace',
    gvisor_dropped: 0,
    decode_errors: 0,
    pre_t0: 0,
    dedup: 0,
    capped: {},
    scan_truncated: false,
    oom_killed: false,
    // Additional counters (7.4 allows extra fields): framework records dropped after T0, reads
    // filtered as loader noise, records of unknown type or family, events that failed validation.
    framework: 0,
    noise: 0,
    ignored: 0,
    invalid: 0,
    sink_closed: false,
    t0_ms: null,
  };
}
