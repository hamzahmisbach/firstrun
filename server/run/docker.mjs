// The only place that starts a child process (section 11 "Tidak ada shell di host"): every Docker
// call is execFile("/usr/bin/docker", argv) with shell:false and MINIMAL_ENV, argv built from
// constants plus a validated run_id. The command text never becomes an argument: it is bind-mounted
// as /work/cmd.sh. The attached `docker run` uses spawn (shell:false) only because execFile cannot
// cap stdout without killing the client, and killing the client would lose the exit code.
import { execFile, spawn } from 'node:child_process';
import { LIMITS } from '../config.mjs';
import { RUN_ID_RE } from './ids.mjs';

export const DOCKER_BIN = '/usr/bin/docker';
export const BASH_BIN = '/usr/bin/bash';
export const SANDBOX_IMAGE = 'firstrun/sandbox:latest';
export const SINKHOLE_IMAGE = 'firstrun/sinkhole:latest';
export const RUN_LABEL = 'firstrun.run';

/** Child processes never inherit process.env (API keys, S3 secrets, access code). */
export const MINIMAL_ENV = Object.freeze({
  PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
  HOME: '/srv/firstrun',
  LANG: 'C.UTF-8',
});

const SAMPLE_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;
const CONTAINER_ID_RE = /^[0-9a-f]{12,64}$/;

/** Harness interpreter map (8.3): the LLM's language name never reaches docker except through this. */
export const INTERPRETERS = Object.freeze({
  bash: Object.freeze({ interp: 'bash', ext: 'sh' }),
  python3: Object.freeze({ interp: 'python3', ext: 'py' }),
  node: Object.freeze({ interp: 'node', ext: 'js' }),
  pwsh: Object.freeze({ interp: 'pwsh', ext: 'ps1' }),
});

export class DockerError extends Error {
  constructor(message, { code = null, signal = null, stderr = '', argv0 = '' } = {}) {
    super(message);
    this.exitCode = code;
    this.signal = signal;
    this.stderr = stderr;
    this.argv0 = argv0;
  }
}

export function assertRunId(id) {
  if (typeof id !== 'string' || !RUN_ID_RE.test(id)) throw new TypeError('invalid run id');
  return id;
}

function assertContainerId(id) {
  if (typeof id !== 'string' || !CONTAINER_ID_RE.test(id)) throw new TypeError('invalid container id');
  return id;
}

export const names = {
  network: (id) => `fr-${assertRunId(id)}`,
  sandbox: (id) => `fr-${assertRunId(id)}-sb`,
  sinkhole: (id) => `fr-${assertRunId(id)}-sink`,
  unwrap: (id, n) => `fr-${assertRunId(id)}-uw${Number.isInteger(n) && n >= 0 ? n : 0}`,
};

// ---------------------------------------------------------------------------------------------
// argv builders (exact flags from docs/ARCHITECTURE.md 5.1, 6.1, 6.2)

/** 6.1 */
export function networkCreateArgs(id) {
  return [
    'network',
    'create',
    '--internal',
    '-o',
    'com.docker.network.bridge.gateway_mode_ipv4=isolated',
    '--label',
    `${RUN_LABEL}=${assertRunId(id)}`,
    names.network(id),
  ];
}

export function networkRmArgs(id) {
  return ['network', 'rm', names.network(id)];
}

/** 6.2 */
export function sinkholeRunArgs({ id, runDir, sampleId = null }) {
  assertRunId(id);
  const sample = sampleId && SAMPLE_RE.test(sampleId) ? sampleId : 'none';
  const s = LIMITS.sandbox.sinkhole;
  return [
    'run',
    '-d',
    '--name',
    names.sinkhole(id),
    '--network',
    names.network(id),
    '--hostname',
    'sink',
    '--cap-drop',
    'ALL',
    '--cap-add',
    'NET_ADMIN',
    '--cap-add',
    'NET_BIND_SERVICE',
    '--cap-add',
    'SETUID',
    '--cap-add',
    'SETGID',
    '--security-opt',
    'no-new-privileges',
    '--read-only',
    '--tmpfs',
    '/tmp:rw,size=64m',
    '--tmpfs',
    '/run:rw,size=8m',
    '--mount',
    `type=bind,src=${runDir}/sinkhole,dst=/sinkhole`,
    '--memory',
    `${s.memoryMb}m`,
    '--memory-swap',
    `${s.memoryMb}m`,
    '--cpus',
    String(s.cpus),
    '--pids-limit',
    String(s.pidsLimit),
    '-e',
    `FIRSTRUN_SAMPLE=${sample}`,
    '--label',
    `${RUN_LABEL}=${id}`,
    '--label',
    'firstrun.phase=sinkhole',
    '--log-driver',
    'none',
    '--stop-timeout',
    '1',
    SINKHOLE_IMAGE,
  ];
}

/** `docker inspect -f` with a constant format string: the sinkhole's IP on the run network. */
export function inspectSinkIpArgs(id) {
  return ['inspect', '-f', `{{(index .NetworkSettings.Networks "${names.network(id)}").IPAddress}}`, names.sinkhole(id)];
}

/**
 * 5.1 (execute) and its unwrap variant: --network none, no /seed and no resolv.conf mount,
 * FIRSTRUN_PHASE=unwrap, FIRSTRUN_TIMEOUT=20, label firstrun.phase=unwrap, INTERP/EXT for launch.
 */
export function sandboxRunArgs({ id, runDir, phase = 'execute', language = null, unwrapIndex = 0 }) {
  assertRunId(id);
  const s = LIMITS.sandbox;
  const unwrap = phase === 'unwrap';
  if (phase !== 'execute' && !unwrap) throw new TypeError('phase must be execute or unwrap');
  const interp = unwrap ? INTERPRETERS[language] : null;
  if (unwrap && !interp) throw new TypeError('unsupported harness language');
  const name = unwrap ? names.unwrap(id, unwrapIndex) : names.sandbox(id);
  const cidfile = unwrap ? `${runDir}/unwrap-${unwrapIndex}.cid` : `${runDir}/sb.cid`;
  const argv = ['run', '--name', name, '--cidfile', cidfile, '--runtime=runsc'];
  if (unwrap) argv.push('--network', 'none');
  else argv.push('--network', names.network(id), '--hostname', 'devbox');
  argv.push(
    '--read-only',
    '--tmpfs',
    '/home/dev:rw,size=256m,mode=0700,uid=1000,gid=1000',
    '--tmpfs',
    '/tmp:rw,size=256m,mode=1777',
    '--tmpfs',
    '/var/tmp:rw,size=32m,mode=1777',
  );
  if (!unwrap) argv.push('--mount', `type=bind,src=${runDir}/seed,dst=/seed,ro`);
  // Harness files live in unwrap/, not work/: the loop runs while the execute container has
  // work/ mounted, and the command must not see (or read) the LLM's harnesses.
  argv.push('--mount', `type=bind,src=${runDir}/${unwrap ? 'unwrap' : 'work'},dst=/work,ro`);
  if (!unwrap) argv.push('--mount', `type=bind,src=${runDir}/resolv.conf,dst=/etc/resolv.conf,ro`);
  argv.push(
    '--user',
    '1000:1000',
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges',
    '--memory',
    `${s.memoryMb}m`,
    '--memory-swap',
    `${s.memoryMb}m`,
    '--cpus',
    String(s.cpus),
    '--pids-limit',
    String(s.pidsLimit),
    '--ulimit',
    `nofile=${s.nofile}:${s.nofile}`,
    '--ulimit',
    `fsize=${s.fsizeBytes}`,
    '-e',
    'HOME=/home/dev',
    '-e',
    'USER=dev',
    '-e',
    'SHELL=/bin/bash',
    '-e',
    'LANG=C.UTF-8',
    '-e',
    'TERM=xterm-256color',
    '-e',
    'PATH=/opt/firstrun/shims:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    '-e',
    'SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt',
    '-e',
    'REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt',
    '-e',
    'NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/firstrun-test-ca.crt',
    '-e',
    'GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt',
    '-e',
    `FIRSTRUN_PHASE=${unwrap ? 'unwrap' : 'execute'}`,
    '-e',
    `FIRSTRUN_TIMEOUT=${unwrap ? s.unwrapTimeoutS : s.execTimeoutS}`,
  );
  if (unwrap) argv.push('-e', `INTERP=${interp.interp}`, '-e', `EXT=${interp.ext}`);
  argv.push(
    '--label',
    `${RUN_LABEL}=${id}`,
    '--label',
    `firstrun.phase=${unwrap ? 'unwrap' : 'execute'}`,
    '--log-driver',
    'none',
    '--stop-timeout',
    '1',
    SANDBOX_IMAGE,
  );
  return argv;
}

export function rmArgs(containerNames) {
  return ['rm', '-f', ...containerNames];
}

export function killArgs(containerName) {
  return ['kill', containerName];
}

export function inspectOomArgs(containerName) {
  return ['inspect', '-f', '{{.State.OOMKilled}}', containerName];
}

export const versionArgs = () => ['version', '--format', '{{.Server.Version}}'];

/** Janitor: every container with our label, oldest first is not guaranteed. */
export const psArgs = () => ['ps', '-a', '--filter', `label=${RUN_LABEL}`, '--format', `{{.ID}}\t{{.Names}}\t{{.Label "${RUN_LABEL}"}}`];
export const networkLsArgs = () => ['network', 'ls', '--filter', `label=${RUN_LABEL}`, '--format', '{{.ID}}\t{{.Name}}'];
export const inspectCreatedArgs = (ref) => ['inspect', '-f', '{{.Created}}', ref];
export const networkInspectArgs = (ref) => ['network', 'inspect', '-f', '{{.Created}}\t{{len .Containers}}', ref];

// ---------------------------------------------------------------------------------------------
// Process execution

const clip = (text, max = 500) => (text.length > max ? `${text.slice(0, max)}...` : text);

/**
 * @param {object} [opts]
 * @param {string} [opts.bin]  the docker binary (tests substitute node)
 * @param {Function} [opts.log]
 */
export function createDocker({ bin = DOCKER_BIN, bash = BASH_BIN, log = () => {} } = {}) {
  /** Short command: resolves {stdout, stderr}; rejects DockerError on a non-zero exit. */
  function run(argv, { timeoutMs = LIMITS.sandbox.dockerCommandTimeoutMs } = {}) {
    return new Promise((resolve, reject) => {
      execFile(
        bin,
        argv,
        { shell: false, env: MINIMAL_ENV, timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024, windowsHide: true },
        (err, stdout, stderr) => {
          if (err) {
            reject(
              new DockerError(`docker ${argv[0]} failed: ${clip(String(stderr).trim() || err.message)}`, {
                code: err.code ?? null,
                signal: err.signal ?? null,
                stderr: clip(String(stderr)),
                argv0: argv[0],
              }),
            );
            return;
          }
          resolve({ stdout: String(stdout), stderr: String(stderr) });
        },
      );
    });
  }

  /**
   * Attached `docker run`: stdout and stderr are captured up to `maxBytes` each (the rest is
   * counted and dropped, never blocking the container). Returns {pid, done}; `done` resolves to
   * {code, signal, stdout, stderr, stdoutBytes, stderrBytes, truncated} and never rejects for a
   * non-zero exit, only when the process could not be spawned.
   */
  function runAttached(argv, { maxBytes = LIMITS.output.streamMaxBytes, maxStderrBytes = maxBytes } = {}) {
    const child = spawn(bin, argv, { shell: false, env: MINIMAL_ENV, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const capture = (stream, cap) => {
      const state = { chunks: [], kept: 0, total: 0, truncated: false };
      stream.on('data', (chunk) => {
        state.total += chunk.length;
        if (state.kept >= cap) {
          state.truncated = true;
          return;
        }
        const room = cap - state.kept;
        const piece = chunk.length > room ? chunk.subarray(0, room) : chunk;
        if (piece.length < chunk.length) state.truncated = true;
        state.chunks.push(piece);
        state.kept += piece.length;
      });
      return state;
    };
    const out = capture(child.stdout, maxBytes);
    const err = capture(child.stderr, maxStderrBytes);
    const done = new Promise((resolve, reject) => {
      let spawnError = null;
      child.once('error', (e) => {
        spawnError = e;
      });
      child.once('close', (code, signal) => {
        if (spawnError && code === null && signal === null) {
          reject(new DockerError(`could not start docker: ${spawnError.message}`, { argv0: argv[0] }));
          return;
        }
        resolve({
          code,
          signal,
          stdout: Buffer.concat(out.chunks, out.kept),
          stderr: Buffer.concat(err.chunks, err.kept),
          stdoutBytes: out.total,
          stderrBytes: err.total,
          truncated: out.truncated || err.truncated,
        });
      });
    });
    return { pid: child.pid ?? null, done };
  }

  /**
   * Startup self-check: `bash <script> [args]` with the same minimal env (plus what the script
   * needs). The script path is a constant chosen by main.mjs, never input.
   */
  function runScript(script, args = [], { timeoutMs = LIMITS.health.selfcheckTimeoutMs, env = {} } = {}) {
    return new Promise((resolve) => {
      execFile(
        bash,
        [script, ...args],
        { shell: false, env: { ...MINIMAL_ENV, ...env }, timeout: timeoutMs, maxBuffer: 1024 * 1024, windowsHide: true },
        (err, stdout, stderr) => {
          resolve({ ok: !err, code: err?.code ?? 0, stdout: String(stdout), stderr: String(stderr) });
        },
      );
    });
  }

  return {
    run,
    runAttached,
    runScript,
    /** Conveniences used by the lifecycle, the janitor and the health probe. */
    version: () => run(versionArgs()).then((r) => r.stdout.trim()),
    rmForce: (containers) => run(rmArgs(containers)).catch((e) => log({ level: 'debug', msg: 'docker.rm', err: e.message })),
    networkRm: (id) => run(networkRmArgs(id)).catch((e) => log({ level: 'debug', msg: 'docker.network_rm', err: e.message })),
    kill: (name) => run(killArgs(name)).catch((e) => log({ level: 'debug', msg: 'docker.kill', err: e.message })),
    oomKilled: (name) =>
      run(inspectOomArgs(name))
        .then((r) => r.stdout.trim() === 'true')
        .catch(() => false),
  };
}

export { assertContainerId };
