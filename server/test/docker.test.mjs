// run/docker.mjs: exact argv for 5.1 / 6.1 / 6.2 and the unwrap variant, run_id validation,
// MINIMAL_ENV, and the attached-run capture cap (using node as a stand-in for the docker binary).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { LIMITS } from '../config.mjs';
import {
  INTERPRETERS,
  MINIMAL_ENV,
  createDocker,
  inspectSinkIpArgs,
  names,
  networkCreateArgs,
  networkRmArgs,
  psArgs,
  rmArgs,
  sandboxRunArgs,
  sinkholeRunArgs,
} from '../run/docker.mjs';

const ID = 'ABCDEFGHJKMNPQRSTVWXYZ0123';
const RUN_DIR = `/srv/firstrun/runs/${ID}`;

test('6.1 network create and 6.2 sinkhole run: exact flags', () => {
  assert.deepEqual(networkCreateArgs(ID), [
    'network', 'create', '--internal', '-o', 'com.docker.network.bridge.gateway_mode_ipv4=isolated',
    '--label', `firstrun.run=${ID}`, `fr-${ID}`,
  ]);
  assert.deepEqual(networkRmArgs(ID), ['network', 'rm', `fr-${ID}`]);
  const sink = sinkholeRunArgs({ id: ID, runDir: RUN_DIR, sampleId: 'canary' }).join(' ');
  assert.equal(
    sink,
    `run -d --name fr-${ID}-sink --network fr-${ID} --hostname sink ` +
      '--cap-drop ALL --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE --cap-add SETUID --cap-add SETGID ' +
      '--security-opt no-new-privileges --read-only --tmpfs /tmp:rw,size=64m --tmpfs /run:rw,size=8m ' +
      `--mount type=bind,src=${RUN_DIR}/sinkhole,dst=/sinkhole --memory 256m --memory-swap 256m --cpus 0.5 --pids-limit 64 ` +
      `-e FIRSTRUN_SAMPLE=canary --label firstrun.run=${ID} --label firstrun.phase=sinkhole --log-driver none --stop-timeout 1 ` +
      'firstrun/sinkhole:latest',
  );
  assert.ok(sinkholeRunArgs({ id: ID, runDir: RUN_DIR, sampleId: null }).includes('FIRSTRUN_SAMPLE=none'));
  assert.ok(sinkholeRunArgs({ id: ID, runDir: RUN_DIR, sampleId: 'Bad Id' }).includes('FIRSTRUN_SAMPLE=none'));
  assert.deepEqual(inspectSinkIpArgs(ID), ['inspect', '-f', `{{(index .NetworkSettings.Networks "fr-${ID}").IPAddress}}`, `fr-${ID}-sink`]);
});

test('5.1 sandbox run: exact flags (execute)', () => {
  const argv = sandboxRunArgs({ id: ID, runDir: RUN_DIR });
  assert.equal(
    argv.join(' '),
    `run --name fr-${ID}-sb --cidfile ${RUN_DIR}/sb.cid --runtime=runsc --network fr-${ID} --hostname devbox --read-only ` +
      '--tmpfs /home/dev:rw,size=256m,mode=0700,uid=1000,gid=1000 --tmpfs /tmp:rw,size=256m,mode=1777 --tmpfs /var/tmp:rw,size=32m,mode=1777 ' +
      `--mount type=bind,src=${RUN_DIR}/seed,dst=/seed,ro --mount type=bind,src=${RUN_DIR}/work,dst=/work,ro ` +
      `--mount type=bind,src=${RUN_DIR}/resolv.conf,dst=/etc/resolv.conf,ro --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges ` +
      `--memory 512m --memory-swap 512m --cpus 1 --pids-limit ${LIMITS.sandbox.pidsLimit} --ulimit nofile=1024:1024 --ulimit fsize=104857600 ` +
      '-e HOME=/home/dev -e USER=dev -e SHELL=/bin/bash -e LANG=C.UTF-8 -e TERM=xterm-256color ' +
      '-e PATH=/opt/firstrun/shims:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin ' +
      '-e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt -e REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt ' +
      '-e NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/firstrun-test-ca.crt -e GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt ' +
      `-e FIRSTRUN_PHASE=execute -e FIRSTRUN_TIMEOUT=60 --label firstrun.run=${ID} --label firstrun.phase=execute ` +
      '--log-driver none --stop-timeout 1 firstrun/sandbox:latest',
  );
  assert.ok(!argv.includes('--rm'), 'no --rm: the orchestrator removes it in finally');
  for (const a of argv) assert.doesNotMatch(a, /FIRSTRUN_S3|VULTR|ACCESS_CODE/, 'no secrets in the sandbox env');
});

test('5.1 unwrap variant: --network none, no /seed, no resolv.conf, phase/timeout/interp env, label', () => {
  const argv = sandboxRunArgs({ id: ID, runDir: RUN_DIR, phase: 'unwrap', language: 'python3', unwrapIndex: 2 });
  const s = argv.join(' ');
  assert.ok(s.startsWith(`run --name fr-${ID}-uw2 --cidfile ${RUN_DIR}/unwrap-2.cid --runtime=runsc --network none --read-only`));
  assert.ok(!s.includes('dst=/seed') && !s.includes('resolv.conf') && !s.includes('--hostname'));
  assert.ok(s.includes(`--mount type=bind,src=${RUN_DIR}/unwrap,dst=/work,ro`), 'harnesses come from unwrap/, not work/');
  assert.ok(!s.includes(`src=${RUN_DIR}/work`));
  assert.ok(s.includes('-e FIRSTRUN_PHASE=unwrap -e FIRSTRUN_TIMEOUT=20 -e INTERP=python3 -e EXT=py'));
  assert.ok(s.includes('--label firstrun.phase=unwrap'));
  assert.throws(() => sandboxRunArgs({ id: ID, runDir: RUN_DIR, phase: 'unwrap', language: 'perl' }), /unsupported/);
  assert.deepEqual(Object.keys(INTERPRETERS).sort(), ['bash', 'node', 'pwsh', 'python3']);
});

test('run ids are validated before they reach any argv; names helper', () => {
  for (const bad of ['', 'abc', `${ID}x`, 'ABCDEFGHJKMNPQRSTVWXYZ012;', null, 12]) {
    assert.throws(() => networkCreateArgs(bad), TypeError, String(bad));
    assert.throws(() => sandboxRunArgs({ id: bad, runDir: RUN_DIR }), TypeError, String(bad));
    assert.throws(() => sinkholeRunArgs({ id: bad, runDir: RUN_DIR }), TypeError, String(bad));
  }
  assert.equal(names.sandbox(ID), `fr-${ID}-sb`);
  assert.equal(names.unwrap(ID, 3), `fr-${ID}-uw3`);
  assert.deepEqual(rmArgs(['a', 'b']), ['rm', '-f', 'a', 'b']);
  assert.ok(psArgs().includes('label=firstrun.run'));
});

test('MINIMAL_ENV never carries process.env', () => {
  assert.deepEqual(Object.keys(MINIMAL_ENV).sort(), ['HOME', 'LANG', 'PATH']);
  assert.ok(Object.isFrozen(MINIMAL_ENV));
});

test('runAttached caps stdout/stderr, counts every byte and keeps the exit code', async () => {
  const docker = createDocker({ bin: process.execPath });
  const script = `
    const big = Buffer.alloc(300 * 1024, 0x61);
    for (let i = 0; i < 4; i++) process.stdout.write(big);
    process.stderr.write('err-line\\n');
    process.stdout.on('drain', () => {});
    setTimeout(() => process.exit(7), 50);
  `;
  const r = await docker.runAttached(['-e', script], { maxBytes: 256 * 1024 }).done;
  assert.equal(r.code, 7);
  assert.equal(r.stdoutBytes, 1200 * 1024);
  assert.equal(r.stdout.length, 256 * 1024);
  assert.equal(r.truncated, true);
  assert.equal(r.stderr.toString(), 'err-line\n');
  assert.equal(r.stderrBytes, 9);
});

test('run() rejects with DockerError carrying the exit code', async () => {
  const docker = createDocker({ bin: process.execPath });
  await assert.rejects(docker.run(['-e', 'process.stderr.write("nope"); process.exit(3)']), (err) => err.exitCode === 3 && /nope/.test(err.message));
  const ok = await docker.run(['-e', 'process.stdout.write("1.2.3")']);
  assert.equal(ok.stdout, '1.2.3');
});
