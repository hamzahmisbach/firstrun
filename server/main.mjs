// Bootstrap: validate env, build the app, listen on FIRSTRUN_LISTEN (127.0.0.1:3000; Caddy is the
// only public entry), shut down gracefully on SIGINT / SIGTERM.
// Logs are one JSON object per line on stdout (journald). Never log command text, claims or codes.
import http from 'node:http';
import { LIMITS, VERSION, loadConfig } from './config.mjs';
import { createApp } from './http/routes.mjs';

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

// TODO(day 2+): self-tests before listening (sidecar socket, docker ping, scripts/netcheck.sh);
// a failure must leave accepting_runs false and /healthz at 503 (fail closed, section 11).
const app = await createApp(config, { log });

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
    lifecycle: 'stub',
    samples: app.samples.size,
    freeform: app.freeformEnabled,
  });
  if (!config.publicUrl) log({ level: 'warn', msg: 'FIRSTRUN_PUBLIC_URL is not set; report_url will be relative' });
  if (config.freeform && !app.freeformEnabled) {
    log({ level: 'warn', msg: 'FIRSTRUN_ACCESS_CODE is not set; free-form runs are disabled' });
  }
});

let stopping = false;
async function stop(signal) {
  if (stopping) {
    log({ level: 'warn', msg: 'forced_exit', signal });
    process.exit(1);
  }
  stopping = true;
  log({ msg: 'shutdown', signal });
  server.close(); // no new connections
  server.closeIdleConnections();
  await app.shutdown({ graceMs: LIMITS.shutdownGraceMs });
  server.closeAllConnections();
  log({ msg: 'stopped' });
  process.exit(0);
}

process.on('SIGINT', () => void stop('SIGINT'));
process.on('SIGTERM', () => void stop('SIGTERM'));
