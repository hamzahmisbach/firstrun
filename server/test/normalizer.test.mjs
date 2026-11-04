import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createNormalizer, isNoiseRead, nsToMs, parseSockaddr } from '../evidence/normalizer.mjs';
import { EVIDENCE_LIMITS, validateEvent } from '../evidence/schema.mjs';
import { parseDnsLine } from '../evidence/sinkhole-tail.mjs';

const RUN_ID = '3M7Q2KX9V4B8NR6TZC5JH1WDYE';
const CID = 'f'.repeat(64);
const T0_NS = 1793793307329319132n;
const decoys = [
  { id: 'aws_secret', path: '~/.aws/credentials', category: 'cloud_credentials', value: 'FRCAPTUREFIXTURETOKEN234', forms: ['raw'] },
  { id: 'ssh_key', path: '~/.ssh/id_ed25519', category: 'ssh_private_key', value: 'FRCAPTUREFIXTURETOKEN235', forms: ['raw'] },
  { id: 'pw', path: null, category: 'phished_input', value: 'FRCAPTURESHIMTOKEN234567', forms: ['raw'] },
];

let clock = T0_NS - 1000000000n;
function ctx(pid, extra = {}) {
  clock += 1000000n;
  return { time_ns: String(clock), thread_group_id: pid, container_id: CID, cwd: '/home/dev', ...extra };
}
const rec = (type, msg) => ({ src: 'gvisor', conn: 2, recv_ms: 0, type, dropped: 0, container_id: CID, msg });
const exec = (pid, ppid, binary_path, argv, extra = {}) =>
  rec(3, { context_data: ctx(pid, { parent_thread_group_id: ppid, thread_id: pid, process_name: 'x' }), binary_path, argv, execfn: binary_path, ...extra });
const openAt = (pid, pathname, extra = {}) => rec(7, { context_data: ctx(pid), exit: { result: '3' }, sysno: '257', fd: '-100', pathname, ...extra });
const connect = (pid, address) => rec(10, { context_data: ctx(pid), sysno: '42', fd: '3', address });
const sockaddr = (bytes) => Buffer.concat([Buffer.from(bytes), Buffer.alloc(20, 0xaa)]).toString('base64');

function setup(opts = {}) {
  const events = [];
  const n = createNormalizer({ runId: RUN_ID, decoys, onEvent: (e) => events.push(e), ...opts });
  return { n, events };
}

/** Pre-T0 setup, the T0 marker, timeout and bash framework execs, as entry.sh/launch produce them. */
function boot(n) {
  n.gvisor(rec(1, { context_data: { time_ns: String(T0_NS - 5000000n), container_id: CID }, id: CID, args: ['/opt/firstrun/entry.sh'] }));
  n.gvisor(exec(2, 1, '/usr/bin/cp', ['cp', '-r', '/seed/home/.', '/home/dev/']));
  n.gvisor(openAt(2, '/seed/home/.aws/credentials'));
  n.gvisor(openAt(2, '/home/dev/.aws/credentials', { flags: 577, mode: 438 }));
  n.gvisor(exec(3, 1, '/usr/bin/chmod', ['chmod', '600', '/home/dev/.aws/credentials']));
  clock = T0_NS - 1000000n;
  n.gvisor(exec(1, 0, '/opt/firstrun/launch', ['/opt/firstrun/launch']));
  n.gvisor(openAt(1, '/dev/null'));
  n.gvisor(exec(1, 0, '/usr/bin/timeout', ['timeout', '-s', 'KILL', '60', 'bash', '--noprofile', '--norc', '/work/cmd.sh']));
  n.gvisor(exec(5, 1, '/usr/bin/bash', ['bash', '--noprofile', '--norc', '/work/cmd.sh']));
  n.gvisor(openAt(5, '/work/cmd.sh'));
  n.gvisor(openAt(5, '/dev/null', { flags: 577, mode: 438 }));
}

test('T0 gating: everything before the launch execve is dropped and counted, nothing after is lost', () => {
  const { n, events } = setup();
  assert.equal(n.t0(), null);
  boot(n);
  assert.equal(n.t0(), Number(T0_NS / 1000000n));
  assert.equal(n.pidT0(), 1);
  assert.equal(n.pidRoot(), 5);
  assert.deepEqual(events, [], 'setup and framework records produce no events');
  const c = n.coverage();
  assert.equal(c.pre_t0, 5, 'container.Start, cp, two opens, chmod');
  assert.equal(c.framework, 5, 'launch, timeout, bash, cmd.sh open, /dev/null by pid_root');
  assert.equal(c.noise, 1, '/dev/null read by launch');
  assert.equal(c.t0_ms, n.t0());

  n.gvisor(exec(6, 5, '/usr/bin/cat', ['cat', '.aws/credentials']));
  n.gvisor(openAt(6, '.aws/credentials'));
  assert.equal(events.length, 2);
  assert.equal(events[0].kind, 'proc.exec');
  assert.deepEqual([events[0].pid, events[0].ppid, events[0].exe, events[0].argv, events[0].cwd], [6, 5, '/usr/bin/cat', ['cat', '.aws/credentials'], '/home/dev']);
  assert.equal(events[0].interp, undefined);
  assert.equal(events[0].seq, 1);
  assert.ok(events[0].t_rel_ms >= 0);
  assert.equal(events[1].kind, 'file.open');
  assert.deepEqual([events[1].path, events[1].access, events[1].decoy_id, events[1].pid], ['/home/dev/.aws/credentials', 'read', 'aws_secret', 6]);
  for (const e of events) validateEvent(e);

  // A late record stamped before T0 (clock skew, reordering) is still dropped.
  n.gvisor(rec(7, { context_data: { time_ns: String(T0_NS - 1n), thread_group_id: 6, container_id: CID, cwd: '/' }, pathname: '/home/dev/.ssh/id_ed25519' }));
  assert.equal(events.length, 2);
  assert.equal(n.coverage().pre_t0, 6);
});

test('execve: shim prefix in execfn, binary_path or argv[0] -> shim.call; interp kept when different', () => {
  const { n, events } = setup();
  boot(n);
  n.gvisor(exec(20, 5, '/opt/firstrun/shims/_shim', ['/opt/firstrun/shims/crontab', '-l'], { execfn: '/opt/firstrun/shims/crontab' }));
  n.gvisor(openAt(20, '/seed/shim-canaries.json'));
  n.gvisor(exec(21, 5, '/usr/bin/dash', ['osascript', '-e', 'display dialog'], { execfn: '/opt/firstrun/shims/osascript' }));
  n.gvisor(exec(22, 5, '/usr/bin/dash', ['/opt/firstrun/shims/sudo', 'id'], { execfn: undefined }));
  n.gvisor(exec(23, 5, '/usr/bin/python3.12', ['python3', '-c', 'x'], { execfn: '/usr/bin/python3' }));
  n.gvisor(exec(24, 5, '/usr/bin/bash', ['bash', '/work/cmd.sh'])); // not the framework root: ppid != pid_t0
  n.gvisor(exec(25, 5, '/usr/bin/env', ['./run.sh'], { execfn: 'run.sh' }));
  assert.deepEqual(events.map((e) => e.kind), ['shim.call', 'shim.call', 'shim.call', 'proc.exec', 'proc.exec', 'proc.exec']);
  assert.deepEqual(events.slice(0, 3).map((e) => [e.tool, e.args, e.pid]), [
    ['crontab', ['-l'], 20],
    ['osascript', ['-e', 'display dialog'], 21],
    ['sudo', ['id'], 22],
  ]);
  assert.deepEqual([events[3].exe, events[3].interp], ['/usr/bin/python3', '/usr/bin/python3.12']);
  assert.deepEqual([events[4].exe, events[4].pid], ['/usr/bin/bash', 24]);
  assert.deepEqual([events[5].exe, events[5].interp], ['/home/dev/run.sh', '/usr/bin/env']);
  assert.equal(n.coverage().framework, 6, 'shim-canaries open by the shim pid is framework');
  for (const e of events) validateEvent(e);
});

test('open: access from flags, failed writes kept with ok:false, failed reads and loader noise dropped, decoy paths mapped', () => {
  const { n, events } = setup();
  boot(n);
  n.gvisor(openAt(7, '/etc/ld.so.cache', { flags: 524288 }));
  n.gvisor(openAt(7, '/lib/x86_64-linux-gnu/libc.so.6', { flags: 524288 }));
  n.gvisor(openAt(7, '/usr/share/zoneinfo/UTC'));
  n.gvisor(openAt(7, '/proc/self/maps'));
  n.gvisor(openAt(7, '/etc/passwd'));
  n.gvisor(openAt(7, '/etc/shadow', { exit: { errorno: '13' } })); // failed read: counted only
  n.gvisor(openAt(7, '/usr/local/blocked.txt', { flags: 577, mode: 438, exit: { errorno: '13' } }));
  n.gvisor(openAt(7, '/tmp/x', { flags: 1 }));
  n.gvisor(openAt(7, '/home/dev/.bashrc', { flags: 1025 })); // O_WRONLY|O_APPEND
  n.gvisor(openAt(7, '/seed/home/.ssh/id_ed25519'));
  n.gvisor(openAt(7, 'id_ed25519', { fd: '4', fd_path: '/home/dev/.ssh' }));
  n.gvisor(openAt(7, '../dev/.ssh/../.aws/./credentials'));
  n.gvisor(openAt(7, '/home/dev/.ssh', { flags: 65536 })); // O_DIRECTORY
  n.gvisor(openAt(7, '/etc/crontab', { flags: 64 }));
  assert.deepEqual(
    events.map((e) => [e.path, e.access, e.decoy_id ?? null, e.ok ?? true, e.errno ?? null]),
    [
      ['/usr/local/blocked.txt', 'create', null, false, 13],
      ['/tmp/x', 'write', null, true, null],
      ['/home/dev/.bashrc', 'write', null, true, null],
      ['/seed/home/.ssh/id_ed25519', 'read', 'ssh_key', true, null],
      ['/home/dev/.ssh/id_ed25519', 'read', 'ssh_key', true, null],
      ['/home/dev/.aws/credentials', 'read', 'aws_secret', true, null],
      ['/home/dev/.ssh', 'read', null, true, null],
      ['/etc/crontab', 'create', null, true, null],
    ],
  );
  assert.equal(n.coverage().noise, 1 + 6);
  for (const e of events) validateEvent(e);
});

test('open: sandbox internals never reach the user: /opt/firstrun reads, /dev/null and /dev/tty any access', () => {
  const { n, events } = setup();
  boot(n);
  n.gvisor(openAt(7, '/opt/firstrun/launch'));
  n.gvisor(openAt(7, '/opt/firstrun/shims/launchctl'));
  n.gvisor(openAt(7, '/opt/firstrun/entry.sh', { flags: 524288 }));
  n.gvisor(openAt(7, '/dev/tty', { flags: 2 })); // bash startup, O_RDWR
  n.gvisor(openAt(8, '/dev/null', { flags: 577, mode: 438 })); // >/dev/null from a non-root pid
  n.gvisor(openAt(8, '/dev/null', { flags: 1 }));
  n.gvisor(openAt(8, '/dev/tty'));
  // Must still pass: writes/creates under /opt/firstrun, failed writes to the devices, other devices.
  n.gvisor(openAt(8, '/opt/firstrun/shims/sudo', { flags: 1 }));
  n.gvisor(openAt(8, '/opt/firstrun/evil', { flags: 577, mode: 438, exit: { errorno: '13' } }));
  n.gvisor(openAt(8, '/dev/null', { flags: 1, exit: { errorno: '13' } }));
  n.gvisor(openAt(8, '/dev/sda', { flags: 1 }));
  n.gvisor(openAt(8, '/opt/other/tool'));
  // /dev/tty: every bash opens it O_RDWR at startup and fails ENXIO; noise for any pid, any result.
  n.gvisor(openAt(5, '/dev/tty', { flags: 2, exit: { errorno: '6' } }));
  n.gvisor(openAt(9, '/dev/tty', { flags: 2, exit: { errorno: '6' } })); // child bash from `| bash`
  n.gvisor(openAt(9, '/dev/tty', { flags: 577, exit: { errorno: '6' } }));
  assert.deepEqual(
    events.map((e) => [e.path, e.access, e.ok ?? true]),
    [
      ['/opt/firstrun/shims/sudo', 'write', true],
      ['/opt/firstrun/evil', 'create', false],
      ['/dev/null', 'write', false],
      ['/dev/sda', 'write', true],
      ['/opt/other/tool', 'read', true],
    ],
  );
  assert.equal(n.coverage().noise, 1 + 10, 'three /opt/firstrun reads, five /dev/tty opens, two /dev/null');
  assert.equal(n.coverage().framework, 5);
  for (const e of events) validateEvent(e);
});

test('open: dedup per (pid, path, access)', () => {
  const { n, events } = setup();
  boot(n);
  n.gvisor(openAt(7, '/home/dev/.aws/credentials'));
  n.gvisor(openAt(7, '/home/dev/.aws/credentials'));
  n.gvisor(openAt(8, '/home/dev/.aws/credentials'));
  n.gvisor(openAt(7, '/home/dev/.aws/credentials', { flags: 1 }));
  assert.equal(events.length, 3);
  assert.equal(n.coverage().dedup, 1);
});

test('connect: sockaddr parsing for inet, inet6, unix (abstract too); other families ignored; dedup', () => {
  assert.deepEqual(parseSockaddr(sockaddr([2, 0, 0x01, 0xbb, 10, 213, 0, 17])), { family: 'inet', dst_ip: '10.213.0.17', dst_port: 443 });
  assert.deepEqual(parseSockaddr('AgAAUAEBAQEAAAAAAAAAAA=='), { family: 'inet', dst_ip: '1.1.1.1', dst_port: 80 });
  const v6 = [10, 0, 0x1f, 0x90, 0, 0, 0, 0, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
  assert.deepEqual(parseSockaddr(sockaddr(v6)), { family: 'inet6', dst_ip: '2001:db8::1', dst_port: 8080 });
  const mapped = [10, 0, 0, 53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1];
  assert.deepEqual(parseSockaddr(sockaddr(mapped)), { family: 'inet6', dst_ip: '::ffff:127.0.0.1', dst_port: 53 });
  assert.deepEqual(parseSockaddr(sockaddr([1, 0, ...Buffer.from('/var/run/nscd/socket'), 0, 0x41, 0x42])), { family: 'unix', dst_ip: null, dst_port: null, path: '/var/run/nscd/socket' });
  assert.deepEqual(parseSockaddr(sockaddr([1, 0, 0, ...Buffer.from('dbus'), 0])), { family: 'unix', dst_ip: null, dst_port: null, path: '@dbus' });
  assert.deepEqual(parseSockaddr(sockaddr([16, 0, 0, 0])), { family: null });
  assert.deepEqual(parseSockaddr('AA=='), { family: null });
  assert.deepEqual(parseSockaddr(''), { family: null });

  const { n, events } = setup();
  boot(n);
  n.gvisor(connect(6, sockaddr([1, 0, ...Buffer.from('/var/run/nscd/socket'), 0])));
  n.gvisor(connect(6, sockaddr([1, 0, ...Buffer.from('/var/run/nscd/socket'), 0])));
  n.gvisor(connect(6, sockaddr([16, 0, 0, 0]))); // netlink
  n.gvisor(connect(6, sockaddr([2, 0, 0x01, 0xbb, 10, 213, 0, 17])));
  n.gvisor(connect(7, sockaddr([2, 0, 0x01, 0xbb, 10, 213, 0, 17])));
  assert.deepEqual(
    events.map((e) => [e.kind, e.pid, e.family, e.dst_ip, e.dst_port, e.path ?? null]),
    [
      ['net.connect', 6, 'unix', null, null, '/var/run/nscd/socket'],
      ['net.connect', 6, 'inet', '10.213.0.17', 443, null],
      ['net.connect', 7, 'inet', '10.213.0.17', 443, null],
    ],
  );
  assert.equal(n.coverage().dedup, 1);
  assert.equal(n.coverage().ignored, 1);
  for (const e of events) validateEvent(e);
});

test('sinkhole records: normalized without T0 gating, but wait for T0 to get t_rel_ms; udp 9009 stripped', async () => {
  const { n, events } = setup();
  const t0Ms = Number(T0_NS / 1000000n);
  const pending = n.sinkhole({ kind: 'tls.clienthello', sni: 'example.test', port: 443, alpn: ['h2'], ts_ms: t0Ms + 300 });
  assert.equal(events.length, 0, 'held until T0 is known');
  boot(n);
  const first = await pending;
  assert.deepEqual([first.kind, first.sni, first.port, first.alpn, first.t_rel_ms, first.seq], ['tls.clienthello', 'example.test', 443, ['h2'], 300, 1]);

  const r = {
    kind: 'http.request', id: 'r2', ts_ms: t0Ms + 600, scheme: 'https', http_version: 'HTTP/2.0', method: 'POST', host: 'collector.example.test', port: 443,
    path: '/upload', query: 'a=1', headers: { 'x-secret': 'FRCAPTUREFIXTURETOKEN234' }, body_len: 100, body_sha256: 'ab', body_b64: 'eA==', response: { status: 200, canned: false },
  };
  const http = await n.sinkhole(r);
  assert.deepEqual([http.method, http.host, http.port, http.path, http.body_len, http.scheme, http.status, http.canned, http.id], ['POST', 'collector.example.test', 443, '/upload', 100, 'https', 200, false, 'r2']);
  for (const k of ['headers', 'query', 'body_b64', 'http_version', 'response']) assert.equal(k in http, false, `${k} must not reach SSE/report`);
  const ref = await n.sinkhole({ ...r, id: 'r3', body_b64: undefined, body_ref: 'bodies/r3.bin', body_len: 300000 });
  assert.equal(ref.body_ref, 'bodies/r3.bin');
  const streamed = await n.sinkhole({ ...r, id: 'r4', body_b64: undefined, body_len: null });
  assert.equal(streamed.body_len, null);

  const dns = await n.sinkhole(parseDnsLine('dnsmasq[15]: query[AAAA] example.test from 10.213.0.18', t0Ms + 100));
  assert.deepEqual([dns.kind, dns.name, dns.qtype, dns.ts_src, dns.t_rel_ms], ['dns.query', 'example.test', 'AAAA', 'arrival', 100]);
  assert.equal(parseDnsLine('dnsmasq[15]: config example.test is 10.213.0.17'), null);
  assert.equal(parseDnsLine('dnsmasq[15]: started, version 2.90 cachesize 150'), null);

  const tcp = await n.sinkhole({ kind: 'tcp.connect', src_port: 1, orig_dst_ip: '10.213.0.17', orig_dst_port: 4444, bytes_in: 5, first_bytes_hex: '68656c6c6f', looks_like_tls: false, ts_ms: t0Ms + 900 });
  assert.deepEqual([tcp.orig_dst_port, tcp.bytes_in, tcp.looks_like_tls, 'first_bytes_hex' in tcp], [4444, 5, false, false]);
  const udpBug = await n.sinkhole({ kind: 'udp.datagram', src_port: 2, orig_dst_port: 9009, len: 4, first_bytes_hex: '70696e67', ts_ms: t0Ms + 950 });
  assert.equal('orig_dst_port' in udpBug, false, 'listener port means unknown');
  const udpOk = await n.sinkhole({ kind: 'udp.datagram', src_port: 2, orig_dst_port: 5354, len: 4, first_bytes_hex: '70696e67', ts_ms: t0Ms + 960 });
  assert.equal(udpOk.orig_dst_port, 5354);
  const failed = await n.sinkhole({ kind: 'tls.failed', sni: 'x.test', port: 443, error: 'handshake', ts_ms: t0Ms + 970 });
  assert.equal(failed.error, 'handshake');
  assert.equal(await n.sinkhole({ kind: 'weird' }), null);
  assert.equal(n.coverage().ignored, 1);
  assert.deepEqual(events.map((e) => e.seq), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
  for (const e of events) validateEvent(e);
});

test('caps per kind and total; canary.hit is exempt; sink.closed and dropped counts reach coverage', () => {
  const limits = { ...EVIDENCE_LIMITS, caps: { 'proc.exec': 2, 'file.open': 1, 'net.connect': 1, 'shim.call': 1, sinkhole: 1, total: 4 } };
  const { n, events } = setup({ limits });
  boot(n);
  for (let i = 0; i < 4; i++) n.gvisor(exec(30 + i, 5, '/usr/bin/id', ['id']));
  n.gvisor(openAt(40, '/tmp/a'));
  n.gvisor(openAt(40, '/tmp/b'));
  n.gvisor(openAt(40, '/tmp/c'));
  n.gvisor(exec(41, 5, '/opt/firstrun/shims/_shim', ['/opt/firstrun/shims/sudo'], { execfn: '/opt/firstrun/shims/sudo' }));
  n.gvisor(exec(42, 5, '/opt/firstrun/shims/_shim', ['/opt/firstrun/shims/sudo'], { execfn: '/opt/firstrun/shims/sudo' }));
  n.orchestrator({ kind: 'canary.hit', decoy_id: 'aws_secret', category: 'cloud_credentials', form: 'raw', where: 'body', event_seq: 3 });
  n.gvisor(connect(43, sockaddr([2, 0, 0, 80, 1, 1, 1, 1])));
  n.gvisor({ ...connect(44, sockaddr([2, 0, 0, 80, 1, 1, 1, 2])), dropped: 7 });
  n.gvisor({ src: 'gvisor', kind: 'sink.closed', conn: 2, received: 10, dropped: 7, decode_errors: 1, ignored: 0, capped: 0, container_id: CID });
  assert.deepEqual(events.map((e) => e.kind), ['proc.exec', 'proc.exec', 'file.open', 'shim.call', 'canary.hit']);
  const c = n.coverage();
  assert.deepEqual(c.capped, { 'proc.exec': 2, 'file.open': 2, 'shim.call': 1, total: 2 });
  assert.equal(c.gvisor_dropped, 7);
  assert.equal(c.decode_errors, 1);
  assert.equal(c.sink_closed, true);
  assert.equal(c.mode, 'trace');
});

test('invalid events are counted, never delivered', () => {
  const logs = [];
  const { n, events } = setup({ log: (r) => logs.push(r) });
  boot(n);
  n.orchestrator({ kind: 'canary.hit', decoy_id: 'aws_secret' });
  assert.equal(events.length, 0);
  assert.equal(n.coverage().invalid, 1);
  assert.equal(logs[0].warn, 'invalid_event');
  assert.equal(JSON.stringify(logs).includes('FRCAPTURE'), false, 'log carries no values');
});

test('finish(): sinkhole records without a T0 are emitted relative to their first timestamp', async () => {
  const { n, events } = setup();
  const a = n.sinkhole({ kind: 'dns.query', name: 'a.test', qtype: 'A', ts_ms: 5000 });
  const b = n.sinkhole({ kind: 'dns.query', name: 'b.test', qtype: 'A', ts_ms: 5250 });
  n.finish();
  assert.deepEqual((await Promise.all([a, b])).map((e) => e.t_rel_ms), [0, 250]);
  assert.equal(events.length, 2);
  assert.equal(n.t0(), null);
});

test('helpers: nsToMs and isNoiseRead', () => {
  assert.equal(nsToMs('1793793307329319132'), 1793793307329);
  assert.equal(nsToMs(undefined), null);
  assert.equal(nsToMs('x'), null);
  assert.equal(isNoiseRead('/usr/lib/x.so'), true);
  assert.equal(isNoiseRead('/home/dev/.ssh/config'), false);
  assert.equal(isNoiseRead('/etc/crontab'), false);
  assert.equal(isNoiseRead('/etc/ssl/certs/ca-certificates.crt'), true);
});
