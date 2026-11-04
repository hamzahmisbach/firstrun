// Runtime configuration (env, validated with zod) and every numeric limit in one place
// (docs/ARCHITECTURE.md section 11: "semua angka ada di server/config.mjs").
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';

const KiB = 1024;
const MiB = 1024 * KiB;
const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;

export const VERSION = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version;

/** Curated sample ids (section 10.1). */
export const SAMPLE_ID_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;

function deepFreeze(obj) {
  for (const value of Object.values(obj)) {
    if (value && typeof value === 'object' && !Object.isFrozen(value)) deepFreeze(value);
  }
  return Object.freeze(obj);
}

export const LIMITS = deepFreeze({
  http: {
    bodyMaxBytes: 64 * KiB, // 413 above this (Caddy enforces the same limit in front)
    bodyDrainMaxBytes: 1 * MiB, // oversized bodies up to this are read and dropped before the 413
    keepAliveTimeoutMs: 125 * SECOND, // above Caddy's 2 min upstream keepalive, so Caddy closes idle sockets first
  },
  input: {
    commandMaxBytes: 16 * KiB, // 16384 bytes of UTF-8 after normalization
    claimMaxChars: 300, // Unicode code points
    accessCodeMinChars: 24,
    sampleFileMaxBytes: 64 * KiB, // fixtures/samples/<id>/*.txt|json read at startup
  },
  queue: {
    concurrency: 2,
    maxWaiting: 8,
  },
  rate: {
    // Token buckets per client IP: `capacity` tokens, refilled continuously over `perMs`.
    postRun: [
      { capacity: 5, perMs: 10 * MINUTE },
      { capacity: 20, perMs: HOUR },
    ],
    wrongCode: { capacity: 10, perMs: HOUR, blockMs: HOUR }, // then every POST from that IP is 429 for 1 h
    getRun: [{ capacity: 120, perMs: MINUTE }],
    sseOpen: [{ capacity: 30, perMs: MINUTE }],
    getOther: [{ capacity: 300, perMs: MINUTE }],
    globalRuns: { capacity: 60, perMs: HOUR }, // accepted runs only
    sseConcurrentPerIp: 4,
    sseConcurrentGlobal: 100,
    tooManyStreamsRetryAfterS: 5,
    maxKeys: 10_000, // LRU cap on tracked IPs
    pruneEveryMs: MINUTE,
  },
  sse: {
    maxMessages: 5000, // ring buffer per run
    maxBytes: 4 * MiB,
    retryMs: 2000, // first line of every stream: "retry: 2000"
    heartbeatMs: 15 * SECOND,
    retainAfterEndMs: 10 * MINUTE, // buffer kept after run.done / run.error, then 204
    maxPendingBytes: 8 * MiB, // a client this far behind is disconnected (it can resume via Last-Event-ID)
  },
  runs: {
    retainAfterEndMs: HOUR, // in-memory run state (and day-1 report) after the run ends
    maxFinished: 200,
    sweepEveryMs: MINUTE,
  },
  retryAfterS: {
    runsDisabled: 30,
    queueFull: 30,
    storageUnavailable: 10,
  },
  sandbox: {
    execTimeoutS: 60,
    watchdogS: 75,
    memoryMb: 512,
    cpus: 1,
    pidsLimit: 128,
  },
  unwrap: {
    maxLayers: 5,
    retriesPerLayer: 3,
    budgetMs: 120 * SECOND,
  },
  output: {
    streamMaxBytes: 1 * MiB, // stdout / stderr captured from the sandbox
    previewMaxBytes: 32 * KiB,
    llmOutputMaxBytes: 64 * KiB,
    eventsPerRun: 5000,
    reportMaxBytes: 4 * MiB,
    sinkholeBodyMaxBytes: 2 * MiB, // mitmproxy body_size_limit
  },
  disk: {
    minFreeBytes: 2 * 1024 * MiB, // below this POST /api/runs answers 503 runs_disabled
  },
  shutdownGraceMs: 10 * SECOND,
});

const DEFAULT_SAMPLES_DIR = fileURLToPath(new URL('../fixtures/samples/', import.meta.url));
const LISTEN_RE = /^(?:\[([0-9a-fA-F:.]+)\]|([^:\s[\]]+)):(\d{1,5})$/;
const flag = (fallback) => z.enum(['0', '1']).default(fallback).transform((v) => v === '1');
const filePath = (fallback) => z.string().default(fallback).transform((p) => path.resolve(p));

const EnvSchema = z.object({
  FIRSTRUN_LISTEN: z
    .string()
    .regex(LISTEN_RE, 'expected host:port, e.g. 127.0.0.1:3000')
    .default('127.0.0.1:3000')
    .transform((value) => {
      const m = LISTEN_RE.exec(value);
      return { host: m[1] ?? m[2], port: Number(m[3]) };
    })
    .refine((l) => l.port <= 65535, 'port must be 0..65535'),
  FIRSTRUN_PUBLIC_URL: z
    .url({ protocol: /^https?$/, error: 'expected an http(s) URL, e.g. https://firstrun.example.org' })
    .transform((u) => u.replace(/\/+$/, ''))
    .optional(),
  FIRSTRUN_ACCESS_CODE: z
    .string()
    .min(LIMITS.input.accessCodeMinChars, `must be at least ${LIMITS.input.accessCodeMinChars} characters`)
    .optional(),
  FIRSTRUN_FREEFORM: flag('1'),
  FIRSTRUN_KILL_SWITCH: flag('0'),
  FIRSTRUN_KILL_SWITCH_FILE: filePath('/srv/firstrun/KILL_SWITCH'),
  FIRSTRUN_RUNS_DIR: filePath('/srv/firstrun/runs'),
  FIRSTRUN_SAMPLES_DIR: filePath(DEFAULT_SAMPLES_DIR),
});

/**
 * Parse FIRSTRUN_* env vars. Empty values count as unset. Throws with the variable names and
 * problems, never the values (FIRSTRUN_ACCESS_CODE is a secret).
 */
export function loadConfig(env = process.env) {
  const picked = Object.fromEntries(
    Object.entries(env).filter(([key, value]) => key.startsWith('FIRSTRUN_') && value !== ''),
  );
  const parsed = EnvSchema.safeParse(picked);
  if (!parsed.success) {
    const lines = parsed.error.issues.map((i) => `${i.path.join('.') || 'env'}: ${i.message}`);
    throw new Error(`invalid configuration:\n  ${lines.join('\n  ')}`);
  }
  const e = parsed.data;
  const accessCodeSha256 =
    e.FIRSTRUN_ACCESS_CODE === undefined ? null : createHash('sha256').update(e.FIRSTRUN_ACCESS_CODE, 'utf8').digest();
  return {
    listen: e.FIRSTRUN_LISTEN,
    publicUrl: e.FIRSTRUN_PUBLIC_URL ?? null,
    // Only the digest is kept: the code itself is never stored, logged, or echoed.
    accessCodeSha256,
    freeform: e.FIRSTRUN_FREEFORM,
    killSwitch: e.FIRSTRUN_KILL_SWITCH,
    killSwitchFile: e.FIRSTRUN_KILL_SWITCH_FILE,
    runsDir: e.FIRSTRUN_RUNS_DIR,
    samplesDir: e.FIRSTRUN_SAMPLES_DIR,
  };
}
