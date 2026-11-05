// 7.6: the runsc strace log parser (fileops-reader) and the normalizer's file-change events. The
// sample lines are verbatim from the VM (runsc release-20261102.0); the hostile ones are the same
// format with names an attacker can choose.
import assert from 'node:assert/strict';
import { appendFileSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';
import { createFileopsReader, logTimeToMs, parseRecord } from '../evidence/fileops-reader.mjs';
import { createNormalizer } from '../evidence/normalizer.mjs';
import { EVIDENCE_LIMITS, FILEOP_KINDS, validateEvent } from '../evidence/schema.mjs';

const CID = 'b6e3ad97ba7d1711a265df3b6b94bfac14f543b3421d11572a6d25fbe8f2e25a';
const RUN = '3M7Q2KX9V4B8NR6TZC5JH1WDYE';
const P = 'I1105 06:01:00.643325       1 strace.go:600] ';
const line = (task, rest) => `${P}[${task}] ${rest}`;
const LAUNCH = line('   1:   1', 'entry.sh X execve(0x5634c4bf1540 /opt/firstrun/launch, 0x5634c4bf1578 ["/opt/firstrun/launch"], 0x5634c4bf1588 ["HOME=/home/dev", "PWD=/home/dev"]) = 0 (0x0) (14.076µs)');

const tmp = [];
after(() => {
  for (const d of tmp) rmSync(d, { recursive: true, force: true });
});

// --- parseRecord ------------------------------------------------------------------------------

test('parseRecord: verbatim VM lines for every traced form', () => {
  const r = parseRecord(line('  52:  52', 'rm X unlinkat(AT_FDCWD /tmp, 0x55bacbdd02e0 a, 0x0) = 0 (0x0) (14.799µs)'));
  assert.equal(r.syscall, 'unlinkat');
  assert.equal(r.pid, 52);
  assert.equal(r.comm, 'rm');
  assert.equal(r.ok, true);
  assert.deepEqual(r.readings, [[{ type: 'fd', fd: 0xffffff9c, path: '/tmp' }, { type: 'path', path: 'a' }, { type: 'hex', value: 0 }]]);

  const mv = parseRecord(line('  46:  46', 'mv X renameat2(AT_FDCWD /home/dev, 0x7ed184647dca /tmp/zz/a, 0xffffff9c, 0x7ed184647dd4 /tmp/zz/b, 0x1) = 0 (0x0) (27.542µs)'));
  assert.equal(mv.readings.length, 1);
  assert.equal(mv.readings[0][1].path, '/tmp/zz/a');
  assert.equal(mv.readings[0][2].value, 0xffffff9c);
  assert.equal(mv.readings[0][3].path, '/tmp/zz/b');

  const ln = parseRecord(line('  54:  54', 'ln X linkat(AT_FDCWD /home/dev/Documents, 0x7ebe717b1db9 /home/dev/.npmrc, 0xffffff9c, 0x7ebe717b1dca /tmp/hard, 0x0) = -1 errno=18 (cross-device link) (22.042µs)'));
  assert.equal(ln.ok, false);
  assert.equal(ln.errno, 18);
  assert.equal(ln.ret, -1);

  const sym = parseRecord(line('  53:  53', 'ln X symlinkat(0x7ed34469adb0 /home/dev/.aws/credentials, AT_FDCWD /home/dev/Documents, 0x7ed34469adcb /tmp/lnk) = 0 (0x0) (19.366µs)'));
  assert.deepEqual(sym.readings[0].map((a) => a.path), ['/home/dev/.aws/credentials', '/home/dev/Documents', '/tmp/lnk']);

  const rmdir = parseRecord(line('  55:  55', 'rm X unlinkat(AT_FDCWD /home/dev/Documents, 0x5621ca8382e0 /home/dev/.ssh, 0x200) = 0 (0x0) (14.577µs)'));
  assert.equal(rmdir.readings[0][2].value, 0x200);

  const chmod = parseRecord(line('   3:   3', 'chmod X fchmodat(AT_FDCWD /home/dev, 0x558bcc3e9310 /home/dev/.ssh, 0o700) = 0 (0x0) (9.027µs)'));
  assert.equal(chmod.readings[0][2].value, 0o700);

  const fch = parseRecord(line('  68:  68', 'python3 X fchmod(0x3 /home/dev/Documents/renamed.bin, 0o644) = 0 (0x0) (3.186µs)'));
  assert.deepEqual(fch.readings[0][0], { type: 'fd', fd: 3, path: '/home/dev/Documents/renamed.bin' });
  const typed = parseRecord(line('  54:  54', 'mv X fchmod(0x4 /tmp/moved, S_IFREG|0o600) = 0 (0x0) (4.509µs)'));
  assert.equal(typed.readings[0][1].value, 0o600);
  const mkdirat = parseRecord(line('   2:   2', 'cp X mkdirat(0x3 /home/dev, 0x56527233e02a ./.ssh, 0x1ed) = 0 (0x0) (10.048µs)'));
  assert.deepEqual(mkdirat.readings[0].map((a) => a.path ?? a.value), ['/home/dev', './.ssh', 0o755]);

  const mkdir = parseRecord(line('  45:  45', 'mkdir X mkdir(0x7ee0f43c2dd3 /tmp, 0o777) = -1 errno=17 (file exists) (8.826µs)'));
  assert.equal(mkdir.ok, false);
  assert.equal(mkdir.errno, 17);

  const clone = parseRecord(line('   1:   1', 'timeout X clone(CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|0x11, 0x0, 0x0, 0x7ebd6bc40a10, 0x0) = 44 (0x2c) (868.034µs)'));
  assert.equal(clone.syscall, 'clone');
  assert.equal(clone.ret, 44);

  const chdir = parseRecord(line('  44:  44', 'bash X chdir(0x556653a1fa00 /home/dev/Documents) = 0 (0x0) (13.024µs)'));
  assert.equal(chdir.readings[0][0].path, '/home/dev/Documents');
  const fchdir = parseRecord(line('  53:  53', 'python3 X fchdir(0x3 /home/dev/Downloads) = 0 (0x0) (6.322µs)'));
  assert.equal(fchdir.readings[0][0].path, '/home/dev/Downloads');

  const exec = parseRecord(LAUNCH);
  assert.equal(exec.syscall, 'execve');
  assert.equal(exec.readings[0][0].path, '/opt/firstrun/launch');
  assert.equal(exec.ok, true);
});

test('parseRecord: null, undecodable and bad-fd arguments name nothing but still parse', () => {
  const nul = parseRecord(line('  53:  53', 'python3 X unlink(<null>) = -1 errno=14 (bad address) (4.428µs)'));
  assert.deepEqual(nul.readings, [[{ type: 'path', path: null }]]);
  const bad = parseRecord(line('  53:  53', 'python3 X chmod(0x1 (error decoding path: bad address), 0o600) = -1 errno=14 (bad address) (3.557µs)'));
  assert.equal(bad.readings[0][0].path, null);
  const fd = parseRecord(line('  53:  53', 'python3 X unlinkat(0x63 (bad FD), 0x7ee56ba4de20 nofd, 0x0) = -1 errno=9 (bad file number) (2.896µs)'));
  assert.deepEqual(fd.readings[0][0], { type: 'fd', fd: 0x63, path: null });
  assert.equal(fd.readings[0][1].path, 'nofd');
});

test('parseRecord: only strace exit lines of traced syscalls; enter lines and other log lines are null', () => {
  assert.equal(parseRecord(line('  52:  52', 'rm E unlinkat(AT_FDCWD /tmp, 0x55bacbdd02e0 a, 0x0)')), null);
  assert.equal(parseRecord('I1105 05:52:59.787153       1 loader.go:1230] Platform: systrap'), null);
  assert.equal(parseRecord(line('  52:  52', 'cat X openat(AT_FDCWD /tmp, 0x55 a, 0x0) = 3 (0x3) (1µs)')), null);
  assert.equal(parseRecord('garbage'), null);
  assert.equal(parseRecord(''), null);
});

test('parseRecord: a name holding a result string or quotes is read whole (the result is anchored at the end)', () => {
  const r = parseRecord(line('  59:  59', 'rm X unlinkat(AT_FDCWD /tmp, 0x55a9e32a52e0 q"uo,te) = 0 (0x0) (3µs), 0x0) = 0 (0x0) (14.387µs)'));
  assert.equal(r.readings.length, 1);
  assert.equal(r.readings[0][1].path, 'q"uo,te) = 0 (0x0) (3µs)');
  assert.equal(r.ok, true);
  const tab = parseRecord(line('  63:  63', 'rm X unlinkat(AT_FDCWD /tmp, 0x5566dafb12e0 tab\there, 0x0) = 0 (0x0) (16.05µs)'));
  assert.equal(tab.readings[0][1].path, 'tab\there');
});

test('parseRecord: a name holding an argument separator yields every reading, the honest one first', () => {
  // cwd is "/home/dev/.aws" and the name is "x, 0x55 /tmp/../../config": the real target is ~/.aws/config
  const r = parseRecord(line('  60:  60', 'rm X unlinkat(AT_FDCWD /home/dev/.aws, 0x55 x, 0x55 /tmp/../../config, 0x0) = 0 (0x0) (3µs)'));
  assert.equal(r.readings.length, 2);
  assert.deepEqual(r.readings.map((a) => [a[0].path, a[1].path]), [
    ['/home/dev/.aws', 'x, 0x55 /tmp/../../config'],
    ['/home/dev/.aws, 0x55 x', '/tmp/../../config'],
  ]);
  // Both halves hostile: the cwd itself carries a separator.
  const h = parseRecord(line('  61:  61', 'rm X unlinkat(AT_FDCWD /home/dev/.aws/x, 0x55 /tmp/zzz, 0x0) = 0 (0x0) (3µs), 0x55 ../credentials, 0x0) = 0 (0x0) (3µs)'));
  assert.ok(h.readings.some((a) => a[0].path === '/home/dev/.aws/x, 0x55 /tmp/zzz, 0x0) = 0 (0x0) (3µs)' && a[1].path === '../credentials'));
  // Two-path syscalls: every split of both names.
  const mv = parseRecord(line('  62:  62', 'mv X renameat2(AT_FDCWD /tmp, 0x7e a, 0x55 b, 0xffffff9c, 0x7e c, 0x1) = 0 (0x0) (3µs)'));
  assert.ok(mv.readings.length >= 2);
  assert.ok(mv.readings.some((a) => a[1].path === 'a, 0x55 b' && a[3].path === 'c'));
});

test('parseRecord: the split search is bounded and says so', () => {
  const name = Array.from({ length: 40 }, (_, i) => `n${i}, 0x55 `).join('');
  const r = parseRecord(line('  70:  70', `rm X unlinkat(AT_FDCWD /tmp, 0x55 ${name}end, 0x0) = 0 (0x0) (3µs)`), { maxSplits: 8 });
  assert.ok(r.readings.length >= 1);
  assert.ok(r.readings.length <= 9);
  assert.equal(r.splits_capped, true);
});

test('parseRecord: a raw comm containing " X unlink(" does not hide the real syscall', () => {
  const r = parseRecord(line('  52:  52', 'a X unlink( X unlinkat(AT_FDCWD /tmp, 0x55 x, 0x0) = 0 (0x0) (3µs)'));
  assert.equal(r.syscall, 'unlinkat');
  assert.equal(r.comm, 'a X unlink(');
  assert.equal(r.readings[0][1].path, 'x');
});

test('parseRecord: a record cut before its result is malformed but keeps the readable head', () => {
  const r = parseRecord(line('  52:  52', 'rm X unlinkat(AT_FDCWD /home/dev, 0x55bacbdd02e0 /home/dev/.aws/a'));
  assert.equal(r.malformed, true);
  assert.deepEqual(r.partial, { dir: '/home/dev', path: '/home/dev/.aws/a' });
  // Cut inside the cwd: the cwd prefix is the head.
  const c = parseRecord(line('  52:  52', 'rm X unlinkat(AT_FDCWD /home/dev/.aws/x'));
  assert.equal(c.malformed, true);
  assert.deepEqual(c.partial, { dir: null, path: '/home/dev/.aws/x' });
  // A plain syscall: no dir.
  const u = parseRecord(line('  68:  68', 'python3 X unlink(0x7ecfd79a2450 book'));
  assert.deepEqual(u.partial, { dir: null, path: 'book' });
});

test('logTimeToMs: current year, local time, and a December log read in January is last year', () => {
  const now = new Date(2026, 10, 5, 12, 0, 0).getTime();
  assert.equal(logTimeToMs('11', '05', '06', '01', '00', '643325', now), new Date(2026, 10, 5, 6, 1, 0, 643).getTime());
  const jan = new Date(2027, 0, 2, 0, 0, 0).getTime();
  assert.equal(logTimeToMs('12', '31', '23', '59', '59', '000000', jan), new Date(2026, 11, 31, 23, 59, 59, 0).getTime());
});

// --- createFileopsReader ----------------------------------------------------------------------

async function withReader(text, { pre = '', limits = EVIDENCE_LIMITS } = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'firstrun-fileops-'));
  tmp.push(dir);
  const file = path.join(dir, `${CID}.boot.log`);
  const records = [];
  const errors = [];
  const reader = createFileopsReader({ logDir: dir, containerId: CID, pollMs: 5, limits, onRecord: (r) => records.push(r), onError: (e) => errors.push(e) });
  if (pre) writeFileSync(file, pre);
  reader.start();
  await sleep(20);
  const cut = Math.floor(text.length / 2);
  appendFileSync(file, text.slice(0, cut));
  appendFileSync(file, text.slice(cut));
  await sleep(40);
  await reader.stop();
  return { reader, records, errors, dir, file };
}

test('reader: joins the continuation line a name with a line break produces, skips other log lines', async () => {
  const text = [
    'I1105 05:52:59.787153       1 loader.go:1230] Platform: systrap',
    line('  52:  52', 'rm X unlinkat(AT_FDCWD /tmp, 0x55bacbdd02e0 a'),
    'b, 0x0) = 0 (0x0) (14.799µs)',
    line('  53:  53', 'rm X unlinkat(AT_FDCWD /tmp, 0x55bacbdd02e0 c, 0x0) = 0 (0x0) (1µs)'),
    '',
  ].join('\n');
  const { reader, records } = await withReader(text);
  assert.equal(records.length, 2);
  assert.equal(records[0].readings[0][1].path, 'a\nb');
  assert.equal(records[1].readings[0][1].path, 'c');
  assert.deepEqual(reader.stats(), { lines: 2, records: 2, malformed: 0, ambiguous: 0, capped: 0, stray: 0, overlong: 0 });
  assert.equal(await reader.exists(), true);
});

test('reader: a forged log line inside a name splits the record; the head survives as malformed, the forgery stands alone', async () => {
  const text = [
    line('  52:  52', 'rm X unlinkat(AT_FDCWD /home/dev, 0x55 /home/dev/.aws/a'),
    line('  52:  52', 'rm X unlinkat(AT_FDCWD /tmp, 0x55 /tmp/zzz, 0x0) = 0 (0x0) (3µs)'),
    'b/../credentials, 0x0) = 0 (0x0) (3µs)',
    '',
  ].join('\n');
  const { reader, records } = await withReader(text);
  assert.equal(records.length, 2);
  assert.equal(records[0].malformed, true);
  assert.equal(records[0].partial.path, '/home/dev/.aws/a');
  // The forged line parses on its own, and the continuation joins it as one more reading of its
  // own record: a name that fakes a result before its line break cannot hide what follows.
  assert.equal(records[1].ok, true);
  assert.equal(records[1].readings[0][1].path, '/tmp/zzz');
  assert.equal(records[1].readings[1][1].path, '/tmp/zzz, 0x0) = 0 (0x0) (3µs)\nb/../credentials');
  assert.equal(reader.stats().malformed, 1);
});

test('reader: gVisor\'s own unprefixed lines after a complete record are not part of its name', async () => {
  const text = [
    line('  52:  52', 'rm X unlinkat(AT_FDCWD /tmp, 0x55bacbdd02e0 a, 0x0) = 0 (0x0) (14.799µs)'),
    '[06:26:07.955630]\t                      \t╭─ runsc boot                        ',
    '[06:26:07.974598]\t+18 968µs ▉▉▉▉▉▉▉▉▉▉▉▉\t├─ Go code running: 18 968µs         ',
    line('  52:  52', 'rm X unlinkat(AT_FDCWD /tmp, 0x55bacbdd02e0 b, 0x0) = 0 (0x0) (1µs)'),
    '',
  ].join('\n');
  const { reader, records } = await withReader(text);
  assert.deepEqual(records.map((r) => r.readings.length), [1, 1]);
  assert.deepEqual(records.map((r) => r.readings[0][1].path), ['a', 'b']);
  assert.equal(reader.stats().malformed, 0);
});

test('reader: the last record is flushed at stop, a stray continuation and the line cap are counted', async () => {
  const limits = { ...EVIDENCE_LIMITS, fileops: { ...EVIDENCE_LIMITS.fileops, maxLines: 2 } };
  // An unprefixed line before any strace line is gVisor's boot table (not counted); one after a
  // non-strace log line is a stray.
  const text = [
    'boot table',
    line('  1:  1', 'rm X unlink(0x7e a) = 0 (0x0) (1µs)'),
    'I1105 05:52:59.787153       1 loader.go:1230] Platform: systrap',
    'orphan continuation',
    line('  1:  1', 'rm X unlink(0x7e b) = 0 (0x0) (1µs)'),
    line('  1:  1', 'rm X unlink(0x7e c) = 0 (0x0) (1µs)'),
    '',
  ].join('\n');
  const { reader, records } = await withReader(text, { limits });
  assert.deepEqual(records.map((r) => r.readings[0][0].path), ['a', 'b']);
  assert.equal(reader.stats().stray, 1);
  assert.equal(reader.stats().capped, 1);
});

test('reader: a missing log is reported by exists(), a symlinked or non-regular one is refused', async (t) => {
  const dir = mkdtempSync(path.join(tmpdir(), 'firstrun-fileops-'));
  tmp.push(dir);
  const none = createFileopsReader({ logDir: dir, containerId: CID, pollMs: 5, onRecord: () => {} });
  none.start();
  await sleep(15);
  await none.stop();
  assert.equal(await none.exists(), false);
  writeFileSync(path.join(dir, 'real.log'), `${line('  1:  1', 'rm X unlink(0x7e a) = 0 (0x0) (1µs)')}\n`);
  try {
    symlinkSync(path.join(dir, 'real.log'), path.join(dir, `${CID}.boot.log`), 'file');
  } catch (err) {
    t.diagnostic(`symlink not permitted here (${err.code}); a directory stands in for the log`);
    mkdirSync(path.join(dir, `${CID}.boot.log`));
  }
  const errors = [];
  const records = [];
  const linked = createFileopsReader({ logDir: dir, containerId: CID, pollMs: 5, onRecord: (r) => records.push(r), onError: (e) => errors.push(e) });
  linked.start();
  await sleep(30);
  await linked.stop();
  assert.equal(records.length, 0);
  assert.ok(errors.some((e) => e.code === 'ENOTREGULAR'));
  assert.throws(() => createFileopsReader({ logDir: dir, containerId: 'short', onRecord: () => {} }), /64 hex/);
});

// --- normalizer -------------------------------------------------------------------------------

function normalizer(decoys = []) {
  const events = [];
  const n = createNormalizer({ runId: RUN, decoys, onEvent: (e) => events.push(e) });
  return { n, events, feed: (text) => n.fileop(parseRecord(line(...text))) };
}

test('normalizer: the launch execve of the strace stream is the T0 gate; entry.sh work before it is pre_t0', () => {
  const { n, events, feed } = normalizer();
  feed(['   2:   2', 'cp X mkdirat(0x3 /home/dev, 0x56527233e02a ./.ssh, 0x1ed) = 0 (0x0) (10µs)']);
  feed(['   3:   3', 'chmod X fchmodat(AT_FDCWD /home/dev, 0x558bcc3e9310 /home/dev/.ssh, 0o700) = 0 (0x0) (9µs)']);
  assert.equal(events.length, 0);
  assert.equal(n.fileopsT0(), false);
  n.fileop(parseRecord(LAUNCH));
  assert.equal(n.fileopsT0(), true);
  feed(['  47:  47', 'rm X unlinkat(AT_FDCWD /home/dev, 0x560ba8b7a2e0 /tmp/zz/b, 0x0) = 0 (0x0) (37µs)']);
  assert.equal(events.length, 1);
  assert.equal(events[0].kind, 'file.delete');
  assert.equal(events[0].path, '/tmp/zz/b');
  assert.equal(events[0].ok, true);
  assert.equal(n.coverage().pre_t0, 2);
  validateEvent(events[0]);
});

test('normalizer: every syscall form maps to its event kind with absolute paths, decoys tagged on both ends', () => {
  const decoys = [
    { id: 'aws_secret', path: '~/.aws/credentials', category: 'cloud_credentials', value: 'FRX', forms: [] },
    { id: 'npm_token', path: '~/.npmrc', category: 'package_manager_token', value: 'FRY', forms: [] },
  ];
  const { events, feed, n } = normalizer(decoys);
  n.fileop(parseRecord(LAUNCH));
  feed(['  46:  46', 'mv X renameat2(AT_FDCWD /home/dev, 0x7e .aws/credentials, 0xffffff9c, 0x7e /tmp/moved, 0x1) = 0 (0x0) (27µs)']);
  feed(['  53:  53', 'ln X symlinkat(0x7e /home/dev/.npmrc, AT_FDCWD /home/dev/Documents, 0x7e /tmp/lnk) = 0 (0x0) (19µs)']);
  feed(['  54:  54', 'ln X linkat(AT_FDCWD /home/dev/Documents, 0x7e /home/dev/.npmrc, 0xffffff9c, 0x7e /tmp/hard, 0x0) = -1 errno=18 (cross-device link) (22µs)']);
  feed(['  55:  55', 'rm X unlinkat(0x4 /home/dev/.ssh, 0x56 known_hosts, 0x0) = 0 (0x0) (35µs)']);
  feed(['  55:  55', 'rm X unlinkat(AT_FDCWD /home/dev/Documents, 0x56 /home/dev/.ssh, 0x200) = 0 (0x0) (14µs)']);
  feed(['  56:  56', 'python3 X unlink(0x7e /home/dev/.git-credentials) = 0 (0x0) (112µs)']);
  feed(['  52:  52', 'chmod X fchmodat(AT_FDCWD /home/dev/Documents, 0x55 /home/dev/.bashrc, 0o600) = 0 (0x0) (7µs)']);
  feed(['  68:  68', 'python3 X truncate(0x7e /home/dev/Documents/renamed.bin, 0x3) = 0 (0x0) (11µs)']);
  feed(['  68:  68', 'python3 X ftruncate(0x3 /home/dev/Documents/renamed.bin, 0x1) = 0 (0x0) (5µs)']);
  feed(['  68:  68', 'python3 X fchmod(0x3 /home/dev/Documents/renamed.bin, 0o644) = 0 (0x0) (3µs)']);
  feed(['  68:  68', 'python3 X mkdir(0x7e /tmp/pydir, 0o777) = 0 (0x0) (13µs)']);
  feed(['  68:  68', 'python3 X rmdir(0x7e /tmp/pydir) = 0 (0x0) (11µs)']);
  feed(['  45:  45', 'mkdir X mkdir(0x7e /tmp, 0o777) = -1 errno=17 (file exists) (8µs)']);
  feed(['  68:  68', 'python3 X rename(0x7e /tmp/a, 0x7e /home/dev/.npmrc) = 0 (0x0) (16µs)']);
  const kinds = events.map((e) => e.kind);
  assert.deepEqual(kinds, ['file.rename', 'file.link', 'file.link', 'file.delete', 'dir.remove', 'file.delete', 'file.chmod', 'file.truncate', 'file.truncate', 'file.chmod', 'dir.create', 'dir.remove', 'file.rename']);
  for (const e of events) validateEvent(e);
  assert.equal(events[0].from, '/home/dev/.aws/credentials');
  assert.equal(events[0].to, '/tmp/moved');
  assert.equal(events[0].decoy_id, 'aws_secret');
  assert.deepEqual([events[1].from, events[1].to, events[1].link, events[1].decoy_id], ['/home/dev/.npmrc', '/tmp/lnk', 'symlink', 'npm_token']);
  assert.deepEqual([events[2].ok, events[2].errno, events[2].link], [false, 18, 'hard']);
  assert.equal(events[3].path, '/home/dev/.ssh/known_hosts');
  assert.equal(events[4].path, '/home/dev/.ssh');
  assert.equal(events[6].mode, 0o600);
  assert.equal(events[10].mode, 0o777);
  assert.equal(events[12].to_decoy_id, 'npm_token');
  assert.equal(n.coverage().noise, 1); // the failed mkdir of /tmp
});

test('normalizer: relative names resolve through chdir, fchdir, AT_FDCWD and clone inheritance; unknown cwd is HOME and flagged', () => {
  const { events, feed, n } = normalizer();
  n.fileop(parseRecord(LAUNCH));
  feed(['  44:  44', 'bash X chdir(0x55 /home/dev/Documents) = 0 (0x0) (13µs)']);
  feed(['  44:  44', 'bash X clone(CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|0x11, 0x0, 0x0, 0x7e, 0x0) = 53 (0x35) (1ms)']);
  feed(['  53:  53', 'python3 X unlink(0x7e book-notes.txt) = 0 (0x0) (39µs)']);
  feed(['  53:  53', 'python3 X chdir(0x7e ../Pictures) = 0 (0x0) (13µs)']);
  feed(['  53:  53', 'python3 X unlink(0x7e a.jpg) = 0 (0x0) (39µs)']);
  feed(['  53:  53', 'python3 X fchdir(0x3 /home/dev/Downloads) = 0 (0x0) (6µs)']);
  feed(['  53:  53', 'python3 X rename(0x7e x.csv, 0x7e y.csv) = 0 (0x0) (16µs)']);
  feed(['  60:  60', 'rm X unlinkat(AT_FDCWD /home/dev/x, 0x55 a, 0x0) = 0 (0x0) (32µs)']);
  feed(['  60:  60', 'rm X unlink(0x7e b) = 0 (0x0) (32µs)']);
  feed(['  99:  99', 'perl X unlink(0x7e orphan) = 0 (0x0) (32µs)']);
  assert.deepEqual(
    events.map((e) => e.path ?? `${e.from}->${e.to}`),
    ['/home/dev/Documents/book-notes.txt', '/home/dev/Pictures/a.jpg', '/home/dev/Downloads/x.csv->/home/dev/Downloads/y.csv', '/home/dev/x/a', '/home/dev/x/b', '/home/dev/orphan'],
  );
  assert.equal(events[5].cwd_assumed, true);
  assert.equal(events[4].cwd_assumed, undefined);
});

test('normalizer: a symlink the run created is followed for later file changes and opens', () => {
  const decoys = [{ id: 'aws_secret', path: '~/.aws/credentials', category: 'cloud_credentials', value: 'FRX', forms: [] }];
  const { events, feed, n } = normalizer(decoys);
  const t0 = { type: 3, msg: { execfn: '/opt/firstrun/launch', argv: ['/opt/firstrun/launch'], context_data: { thread_group_id: 1, parent_thread_group_id: 0, cwd: '/home/dev', time_ns: '1000000000' } } };
  n.gvisor(t0);
  n.fileop(parseRecord(LAUNCH));
  feed(['  70:  70', 'ln X symlinkat(0x7e /home/dev/.aws, AT_FDCWD /home/dev, 0x7e /tmp/L) = 0 (0x0) (19µs)']);
  feed(['  71:  71', 'rm X unlinkat(AT_FDCWD /home/dev, 0x55 /tmp/L/credentials, 0x0) = 0 (0x0) (32µs)']);
  n.gvisor({ type: 7, msg: { fd: -100, pathname: '/tmp/L/config', flags: 0, exit: { result: 3 }, context_data: { thread_group_id: 72, cwd: '/home/dev', time_ns: '2000000000' } } });
  assert.equal(events[1].kind, 'file.delete');
  assert.equal(events[1].path, '/home/dev/.aws/credentials');
  assert.equal(events[1].decoy_id, 'aws_secret');
  assert.equal(events[2].kind, 'file.open');
  assert.equal(events[2].path, '/home/dev/.aws/config');
});

test('normalizer: hostile names produce alt_paths and partial events, never a crash or a missing record', () => {
  const { events, feed, n } = normalizer();
  n.fileop(parseRecord(LAUNCH));
  // The honest reading normalizes to the file the kernel really resolved; the other reading is kept.
  feed(['  60:  60', 'rm X unlinkat(AT_FDCWD /home/dev/.aws, 0x55 x, 0x55 /tmp/../../config, 0x0) = 0 (0x0) (3µs)']);
  assert.equal(events[0].path, '/home/dev/.aws/config');
  assert.deepEqual(events[0].alt_paths, ['/config']);
  // The cwd is a nested hostile dir ".aws/x, 0x55 /tmp/zzz, 0x0) = 0 (0x0) (3µs)" (three levels), so
  // three ".." reach the real credentials; that reading is present whichever one comes first.
  feed(['  61:  61', 'rm X unlinkat(AT_FDCWD /home/dev/.aws/x, 0x55 /tmp/zzz, 0x0) = 0 (0x0) (3µs), 0x55 ../../../credentials, 0x0) = 0 (0x0) (3µs)']);
  assert.ok([events[1].path, ...(events[1].alt_paths ?? [])].includes('/home/dev/.aws/credentials'), JSON.stringify(events[1]));
  n.fileop(parseRecord(line('  62:  62', 'rm X unlinkat(AT_FDCWD /home/dev, 0x55 /home/dev/.kube/a')));
  assert.equal(events[2].partial, true);
  assert.equal(events[2].path, '/home/dev/.kube/a');
  n.fileop(parseRecord(line('  63:  63', 'rm X unlinkat(AT_FDCWD /home/dev/.kube/a')));
  assert.equal(events[3].path, '/home/dev/.kube/a');
  n.fileop(parseRecord(line('  64:  64', 'mv X renameat2(AT_FDCWD /home/dev, 0x7e .ssh/config, 0xffffff9c, 0x7e x')));
  assert.equal(events[4].kind, 'file.rename');
  assert.equal(events[4].partial, true);
  assert.equal(events[4].from, '/home/dev/x');
  for (const e of events) validateEvent(e);
  assert.equal(n.fileop(null), null);
  assert.equal(n.fileop({ syscall: 'unlinkat', pid: 1, readings: [] }), null);
  assert.equal(n.fileop({ syscall: 'nonsense', pid: 1, ok: true, readings: [[]] }), null);
});

test('normalizer: file-change caps are per kind and exempt from the total cap; chmod repeats are deduped', () => {
  const limits = { ...EVIDENCE_LIMITS, caps: { ...EVIDENCE_LIMITS.caps, 'file.delete': 3, total: 2 } };
  const events = [];
  const n = createNormalizer({ runId: RUN, onEvent: (e) => events.push(e), limits });
  n.fileop(parseRecord(LAUNCH));
  for (let i = 0; i < 5; i++) n.fileop(parseRecord(line('  1:  1', `rm X unlink(0x7e /tmp/f${i}) = 0 (0x0) (1µs)`)));
  n.fileop(parseRecord(line('  1:  1', 'chmod X chmod(0x7e /tmp/f0, 0o600) = 0 (0x0) (1µs)')));
  n.fileop(parseRecord(line('  1:  1', 'chmod X chmod(0x7e /tmp/f0, 0o600) = 0 (0x0) (1µs)')));
  assert.equal(events.filter((e) => e.kind === 'file.delete').length, 3);
  assert.equal(events.filter((e) => e.kind === 'file.chmod').length, 1);
  assert.equal(n.coverage().capped['file.delete'], 2);
  assert.equal(n.coverage().capped.total, undefined);
  assert.equal(n.coverage().dedup, 1);
  assert.ok(FILEOP_KINDS.every((k) => Number.isInteger(EVIDENCE_LIMITS.caps[k])));
});
