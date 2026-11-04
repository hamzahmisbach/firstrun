// Bootstrap: validate env, load peer modules, build storage, LLM client, lifecycle and janitor,
// listen on FIRSTRUN_LISTEN (127.0.0.1:3000; Caddy is the only public entry), then run the startup
// self-tests (sidecar socket, docker, scripts/selfcheck.sh). Until they pass accepting_runs stays
// false and /healthz answers 503: fail closed (section 11), but observable.
// Logs are one JSON object per line on stdout (journald). Never log command text, claims or codes.
import http from 'node:http';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { stat } from 'node:fs/promises';
import { LIMITS, VERSION, loadConfig } from './config.mjs';
import { createApp, createHealthProbes } from './http/routes.mjs';
import { createDocker } from './run/docker.mjs';
import { createJanitor } from './run/janitor.mjs';
import { createLifecycle, loadModules } from './run/lifecycle.mjs';
import { createStorage } from './storage/index.mjs';

function log(record) {
  process.stdout.write(`${JSON.stringify({ ts: new Date().toISOString(), level: 'info', ...record })}\n`);
}

let config;
try {
  config = loadConfig(process.env);
} catch (err) {
  process.stderr.write(`firstrun: ${err.message}\n`);
  process.exit(1);
}

process.on('uncaughtException', (err) => {
  log({ level: 'fatal', msg: 'uncaught_exception', err: err?.stack ?? String(err) });
  process.exit(1);
});
process.on('unhandledRejection', (err) => {
  log({ level: 'fatal', msg: 'unhandled_rejection', err: err?.stack ?? String(err) });
  process.exit(1);
});

const SELFCHECK = fileURLToPath(new URL('../scripts/selfcheck.sh', import.meta.url));

const docker = createDocker({ log });
const { modules, missing } = await loadModules({ devDir: config.devModulesDir, log });
if (missing.length) log({ level: 'warn', msg: 'modules.missing', modules: missing, note: 'deterministic fallbacks in use' });

const storage = await createStorage({ config, log });
if (storage.mode === 'local') log({ level: 'warn', msg: 'storage.local', note: 'no FIRSTRUN_S3_* credentials; reports stay in the spool' });

let llm = null;
if (modules.llmClient) {
  const disabled = config.llmDisabled || !config.inference.apiKey;
  llm = modules.llmClient({ apiKey: config.inference.apiKey, baseUrl: config.inference.baseUrl, disabled, log });
  if (disabled) log({ level: 'warn', msg: 'llm.disabled', reason: config.llmDisabled ? 'FIRSTRUN_LLM_DISABLED=1' : 'no VULTR_INFERENCE_API_KEY' });
}

let staticHandler = null;
try {
  const { createStatic } = await import('./http/static.mjs');
  staticHandler = await createStatic(config.webDir);
} catch (err) {
  if (err?.code !== 'ERR_MODULE_NOT_FOUND') log({ level: 'error', msg: 'static.load_failed', err: err?.message ?? String(err) });
  else log({ level: 'warn', msg: 'static.missing', note: 'http/static.mjs not present; /r/:id serves a placeholder' });
}

const health = createHealthProbes({ config, docker, storage });
const lifecycle = createLifecycle({ config, llm, storage, docker, modules, log });
const app = await createApp(config, { log, lifecycle, storage, health, staticHandler });
app.setAccepting(false, 'startup self-test pending');
const janitor = createJanitor({ config, docker, storage, isActive: app.isActive, log });

const server = http.createServer(app.handle);
server.keepAliveTimeout = LIMITS.http.keepAliveTimeoutMs;

server.on('error', (err) => {
  log({ level: 'fatal', msg: 'listen_failed', code: err.code, listen: `${config.listen.host}:${config.listen.port}` });
  process.exit(1);
});

server.listen(config.listen.port, config.listen.host, () => {
  const { address, port } = server.address();
  log({
    msg: 'listening',
    version: VERSION,
    listen: `${address}:${port}`,
    storage: storage.mode,
    llm: llm ? 'on' : 'off',
    evidence: config.evidence,
    samples: app.samples.size,
    freeform: app.freeformEnabled,
    modules_missing: missing,
  });
  if (!config.publicUrl) log({ level: 'warn', msg: 'FIRSTRUN_PUBLIC_URL is not set; report_url will be relative' });
  if (config.freeform && !app.freeformEnabled) {
    log({ level: 'warn', msg: 'FIRSTRUN_ACCESS_CODE is not set; free-form runs are disabled' });
  }
  void selfTest();
});

/** Sidecar socket (wait up to 10 s), docker, then scripts/selfcheck.sh (netcheck under runsc). */
async function selfTest() {
  const started = Date.now();
  let sidecar = false;
  while (Date.now() - started < LIMITS.health.sidecarWaitMs) {
    try {
      if ((await stat(config.sinkSocket)).isSocket()) {
        sidecar = true;
        break;
      }
    } catch {
      // not yet
    }
    await sleep(250);
  }
  const fail = (reason, extra = {}) => {
    health.selfTest.status = 'failed';
    health.selfTest.detail = reason;
    app.setAccepting(false, `self-test failed: ${reason}`);
    log({ level: 'error', msg: 'selftest.failed', reason, ...extra });
  };
  if (!sidecar) return fail('sidecar socket missing');
  try {
    await docker.version();
  } catch (err) {
    return fail('docker unreachable', { err: err?.message ?? String(err) });
  }
  const r = await docker.runScript(SELFCHECK, ['--work-dir', `${config.runsDir}/_selfcheck`, '--sink-socket', config.sinkSocket], {
    env: { FIRSTRUN_RUNS_DIR: config.runsDir, FIRSTRUN_SINK_SOCKET: config.sinkSocket, FIRSTRUN_TRACE_DIR: config.traceDir },
  });
  const lines = `${r.stdout}\n${r.stderr}`.split('\n').map((l) => l.trim()).filter(Boolean);
  if (!r.ok) return fail('selfcheck.sh failed', { code: r.code, lines: lines.slice(-20) });
  health.selfTest.status = 'ok';
  app.setAccepting(true);
  janitor.start();
  log({ msg: 'selftest.ok', ms: Date.now() - started, lines: lines.filter((l) => l.startsWith('PASS')).length });
}

let stopping = false;
async function stop(signal) {
  if (stopping) {
    log({ level: 'warn', msg: 'forced_exit', signal });
    process.exit(1);
  }
  stopping = true;
  log({ msg: 'shutdown', signal });
  janitor.stop();
  server.close(); // no new connections
  server.closeIdleConnections();
  await app.shutdown({ graceMs: LIMITS.shutdownGraceMs });
  server.closeAllConnections();
  log({ msg: 'stopped' });
  process.exit(0);
}

process.on('SIGINT', () => void stop('SIGINT'));
process.on('SIGTERM', () => void stop('SIGTERM'));
