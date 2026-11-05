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
const DAY = 24 * HOUR;

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
    bodyMaxBytes: 64 * KiB, // 413 above this (nginx stops anything over 128 KiB in front)
    bodyDrainMaxBytes: 1 * MiB, // oversized bodies up to this are read and dropped before the 413
    keepAliveTimeoutMs: 125 * SECOND, // above nginx's 60 s upstream keepalive, so nginx closes idle sockets first
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
    retainAfterEndMs: HOUR, // in-memory run state after the run ends (reports also live in storage)
    maxFinished: 200,
    sweepEveryMs: MINUTE,
  },
  retryAfterS: {
    runsDisabled: 30,
    queueFull: 30,
    storageUnavailable: 10,
  },
  sandbox: {
    execTimeoutS: 60, // `timeout -s KILL` inside the container (sandbox/launch)
    watchdogS: 75, // `docker kill` from outside
    unwrapTimeoutS: 20, // harness containers (5.1, unwrap variant)
    unwrapWatchdogS: 30,
    memoryMb: 512,
    cpus: 1,
    // The plan says 128, but the cgroup counts the sentry and systrap helper threads as well as the
    // sandboxed processes: with 128 a loop of background `sleep`s died at about 42 concurrent
    // processes (measured on the VM). Installers like npm and pip fork far more than that, so 256
    // leaves roughly 100 real processes while a fork bomb still hits the wall long before the host
    // does; the memory cap and the 60 s wall clock remain the real backstop.
    pidsLimit: 256,
    nofile: 1024,
    fsizeBytes: 104857600,
    sinkhole: { memoryMb: 256, cpus: 0.5, pidsLimit: 64 },
    sinkholeReadyMs: 15 * SECOND, // network + sinkhole took 3.9-5.6 s on the VM; the plan's 5 s was too tight
    cidfileWaitMs: 10 * SECOND,
    evidenceGraceMs: 1500, // after exit: let the sidecar and sinkhole tails drain
    dockerCommandTimeoutMs: 30 * SECOND, // every short docker command (create, inspect, rm, kill, ps)
    // Exit 137 alone is not a timeout (OOM kill and self-inflicted SIGKILL look the same): a run
    // timed out only when the watchdog fired, `timeout` returned 124, or it ran this close to the limit.
    timeoutSlackMs: 2 * SECOND,
  },
  llm: {
    contractWaitMs: 20 * SECOND, // how long step 11 waits for claim-to-contract before the fallback (8.1)
    reviewWaitMs: 20 * SECOND, // how long step 11 waits for the AI code review before the rules verdict stands alone (8.7)
    // What the AI reviewer is shown (8.7): the pasted command, decoded layers and an allowlisted
    // summary of what was recorded, each cut to these sizes (the prompt says what was cut).
    review: {
      commandMaxChars: 8000,
      layersMax: 5,
      layerMaxChars: 4000,
      programsMax: 40,
      programMaxChars: 160,
      writesMax: 30,
      hostsMax: 20,
      credentialReadsMax: 10,
    },
  },
  unwrap: {
    maxLayers: 5,
    retriesPerLayer: 3,
    budgetMs: 45 * SECOND, // the user is watching; was 120 s in the plan, cut 2026-11-04 after real runs
    harnessStdoutMaxBytes: 256 * KiB,
    harnessStderrMaxBytes: 16 * KiB,
  },
  output: {
    streamMaxBytes: 1 * MiB, // stdout / stderr captured from the sandbox
    previewMaxBytes: 32 * KiB,
    llmOutputMaxBytes: 64 * KiB,
    eventsPerRun: 5000,
    reportMaxBytes: 4 * MiB,
    sinkholeBodyMaxBytes: 2 * MiB, // mitmproxy body_size_limit
  },
  storage: {
    cacheMaxReports: 200,
    cacheTtlMs: HOUR,
    headBucketCacheMs: 5 * MINUTE,
    spoolRetryEveryMs: MINUTE,
    spoolMaxAgeMs: DAY, // a report that could not be uploaded for a day is dropped from the spool (S3 mode only)
    retentionEveryMs: DAY,
  },
  janitor: {
    sweepEveryMs: MINUTE,
    orphanAgeMs: 10 * MINUTE, // containers, networks, trace files, runsc logs and run dirs left behind by a crash
    failedRunKeepMs: DAY, // sinkhole/ of a failed run is kept (0700) this long for debugging
    unknownLogMaxBytes: 4 * MiB, // runsc appends to <unknown>.<command>.log on every container delete
  },
  health: {
    dockerCacheMs: 30 * SECOND,
    diskCacheMs: 10 * SECOND,
    sidecarHeartbeatMaxAgeMs: 60 * SECOND,
    sidecarWaitMs: 10 * SECOND, // at startup
    selfcheckTimeoutMs: 90 * SECOND,
  },
  disk: {
    minFreeBytes: 2 * 1024 * MiB, // below this POST /api/runs answers 503 runs_disabled
  },
  shutdownGraceMs: 10 * SECOND,
});

const DEFAULT_SAMPLES_DIR = fileURLToPath(new URL('../fixtures/samples/', import.meta.url));
const DEFAULT_WEB_DIR = fileURLToPath(new URL('../web/', import.meta.url));
const LISTEN_RE = /^(?:\[([0-9a-fA-F:.]+)\]|([^:\s[\]]+)):(\d{1,5})$/;
const flag = (fallback) => z.enum(['0', '1']).default(fallback).transform((v) => v === '1');
const filePath = (fallback) => z.string().default(fallback).transform((p) => path.resolve(p));
const S3_KEYS = ['FIRSTRUN_S3_ENDPOINT', 'FIRSTRUN_S3_BUCKET', 'FIRSTRUN_S3_ACCESS_KEY', 'FIRSTRUN_S3_SECRET_KEY'];

const EnvSchema = z
  .object({
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
    FIRSTRUN_TRACE_DIR: filePath('/srv/firstrun/trace'),
    // runsc --debug-log directory (infra/docker/daemon.json): <cid>.boot.log carries the strace
    // lines for file deletes, renames, chmods and links (docs/ARCHITECTURE.md 7.6).
    FIRSTRUN_RUNSC_LOG_DIR: filePath('/var/log/firstrun/runsc'),
    FIRSTRUN_SPOOL_DIR: filePath('/srv/firstrun/spool'),
    FIRSTRUN_SINK_SOCKET: filePath('/run/firstrun/gvisor-sink.sock'),
    FIRSTRUN_SAMPLES_DIR: filePath(DEFAULT_SAMPLES_DIR),
    FIRSTRUN_WEB_DIR: filePath(DEFAULT_WEB_DIR),
    // The strace fallback (7.5) was never built: the go/no-go on gVisor trace points passed.
    FIRSTRUN_EVIDENCE: z
      .enum(['trace', 'strace'], { error: 'expected trace' })
      .default('trace')
      .refine((v) => v !== 'strace', 'the strace fallback is not implemented (docs/ARCHITECTURE.md 7.5); use trace'),
    FIRSTRUN_LLM_DISABLED: flag('0'),
    FIRSTRUN_S3_ENDPOINT: z.url({ protocol: /^https$/, error: 'expected an https URL, e.g. https://sgp1.vultrobjects.com' }).optional(),
    FIRSTRUN_S3_BUCKET: z.string().regex(/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/, 'expected an S3 bucket name').optional(),
    FIRSTRUN_S3_ACCESS_KEY: z.string().min(1).optional(),
    FIRSTRUN_S3_SECRET_KEY: z.string().min(1).optional(),
    FIRSTRUN_REPORT_TTL_DAYS: z.coerce.number().int().min(1).max(3650).default(30),
    VULTR_INFERENCE_API_KEY: z.string().min(8, 'must be at least 8 characters').optional(),
    VULTR_INFERENCE_BASE_URL: z
      .url({ protocol: /^https$/, error: 'expected an https URL' })
      .default('https://api.vultrinference.com/v1')
      .transform((u) => u.replace(/\/+$/, '')),
    // Development only: a directory whose files shadow server/ modules (stand-ins for modules that
    // other people are still writing). Never set in production.
    FIRSTRUN_DEV_MODULES_DIR: z.string().transform((p) => path.resolve(p)).optional(),
  })
  .refine(
    (e) => {
      const set = S3_KEYS.filter((k) => e[k] !== undefined).length;
      return set === 0 || set === S3_KEYS.length;
    },
    { message: `set all of ${S3_KEYS.join(', ')} or none (local spool mode)`, path: ['FIRSTRUN_S3_*'] },
  );

/**
 * Parse FIRSTRUN_* and VULTR_* env vars. Empty values count as unset. Throws with the variable
 * names and problems, never the values (several of them are secrets).
 */
export function loadConfig(env = process.env) {
  const picked = Object.fromEntries(
    Object.entries(env).filter(([key, value]) => (key.startsWith('FIRSTRUN_') || key.startsWith('VULTR_')) && value !== ''),
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
    traceDir: e.FIRSTRUN_TRACE_DIR,
    runscLogDir: e.FIRSTRUN_RUNSC_LOG_DIR,
    spoolDir: e.FIRSTRUN_SPOOL_DIR,
    sinkSocket: e.FIRSTRUN_SINK_SOCKET,
    samplesDir: e.FIRSTRUN_SAMPLES_DIR,
    webDir: e.FIRSTRUN_WEB_DIR,
    evidence: e.FIRSTRUN_EVIDENCE,
    llmDisabled: e.FIRSTRUN_LLM_DISABLED,
    // null = no Object Storage credentials: reports stay in the local spool (10.4), runs still work.
    s3:
      e.FIRSTRUN_S3_ENDPOINT === undefined
        ? null
        : {
            endpoint: e.FIRSTRUN_S3_ENDPOINT,
            bucket: e.FIRSTRUN_S3_BUCKET,
            accessKey: e.FIRSTRUN_S3_ACCESS_KEY,
            secretKey: e.FIRSTRUN_S3_SECRET_KEY,
          },
    reportTtlDays: e.FIRSTRUN_REPORT_TTL_DAYS,
    inference: { apiKey: e.VULTR_INFERENCE_API_KEY ?? null, baseUrl: e.VULTR_INFERENCE_BASE_URL },
    devModulesDir: e.FIRSTRUN_DEV_MODULES_DIR ?? null,
  };
}
