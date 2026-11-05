// fixtures/captures/fileops: a runsc boot log recorded on the VM (release-20261102.0) for the
// command in command.sh, read through the reader and the normalizer the way the lifecycle does,
// then through the rules with the seeded paths the command touched.
import assert from 'node:assert/strict';
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { createFileopsReader } from '../evidence/fileops-reader.mjs';
import { createNormalizer } from '../evidence/normalizer.mjs';
import { validateEvent } from '../evidence/schema.mjs';
import { evaluate } from '../rules/engine.mjs';
import { createCanaries } from '../run/canary.mjs';

const CAPTURE = fileURLToPath(new URL('../../fixtures/captures/fileops/', import.meta.url));
const RUN = '3M7Q2KX9V4B8NR6TZC5JH1WDYE';

const tmp = [];
after(() => {
  for (const d of tmp) rmSync(d, { recursive: true, force: true });
});

test('capture: the VM boot log yields the expected file-change events, no malformed records, and the rules flag it', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'firstrun-fileops-'));
  tmp.push(dir);
  const cid = readFileSync(path.join(CAPTURE, 'container_id.txt'), 'utf8').trim();
  const text = readFileSync(path.join(CAPTURE, 'boot.log'));
  const file = path.join(dir, `${cid}.boot.log`);
  const { decoys } = createCanaries();
  const events = [];
  const n = createNormalizer({ runId: RUN, decoys, onEvent: (e) => events.push(e) });
  const errors = [];
  const reader = createFileopsReader({ logDir: dir, containerId: cid, pollMs: 5, onRecord: (r) => n.fileop(r), onError: (e) => errors.push(e) });
  reader.start();
  await sleep(10);
  writeFileSync(file, text.subarray(0, 70000));
  await sleep(30);
  appendFileSync(file, text.subarray(70000));
  await sleep(60);
  await reader.stop();
  assert.deepEqual(errors, []);

  const stats = reader.stats();
  assert.equal(stats.malformed, 0, JSON.stringify(stats));
  assert.equal(stats.stray, 0, "gVisor's boot timing table precedes the first strace line and is neither joined nor counted");
  assert.ok(stats.lines > 400);
  assert.equal(n.fileopsT0(), true);
  assert.ok(n.coverage().pre_t0 > 50, 'entry.sh setup (cp, chmod) is gated out');
  for (const e of events) validateEvent(e);
  const by = (kind) => events.filter((e) => e.kind === kind);
  const paths = (kind) => by(kind).map((e) => e.path ?? e.from);

  // rm in two cwds, then chmod, mv across tmpfs (rename fails EXDEV, mv copies and deletes), ln -s
  assert.ok(paths('file.delete').includes('/home/dev/Documents/budget-2026.xlsx'));
  assert.ok(paths('file.delete').includes('/home/dev/Pictures/IMG_20260902_091533.jpg'));
  const idOf = (p) => decoys.find((d) => d.path === p).id;
  const npmrc = by('file.chmod').find((e) => e.path === '/home/dev/.npmrc');
  assert.deepEqual([npmrc.mode, npmrc.ok, npmrc.decoy_id], [0o644, true, idOf('~/.npmrc')]);
  const mv = by('file.rename').find((e) => e.from === '/home/dev/.aws/credentials');
  assert.deepEqual([mv.to, mv.ok, mv.errno, mv.decoy_id], ['/tmp/moved', false, 18, idOf('~/.aws/credentials')]);
  const cred = by('file.delete').find((e) => e.path === '/home/dev/.aws/credentials');
  assert.deepEqual([cred.ok, cred.decoy_id], [true, idOf('~/.aws/credentials')]);
  assert.ok(by('file.chmod').some((e) => e.path === '/tmp/moved' && e.mode === 0o600), 'S_IFREG|0o600 is read as 0o600');
  const link = by('file.link').find((e) => e.to === '/tmp/L');
  assert.deepEqual([link.from, link.link, link.ok], ['/home/dev/.ssh', 'symlink', true]);
  // rm -rf of a folder goes through a dirfd; the folder itself is AT_REMOVEDIR
  assert.ok(paths('file.delete').includes('/home/dev/.config/gh/hosts.yml'));
  assert.ok(paths('dir.remove').includes('/home/dev/.config/gh'));
  // mkdir -p walks with relative chdir; the hostile dir names come through verbatim
  assert.ok(paths('dir.create').includes('/home/dev/.aws/x, 0x55 '));
  assert.ok(paths('dir.create').includes('/home/dev/.aws/x, 0x55 /tmp'));
  const sep = by('file.delete').find((e) => e.path === '/home/dev/.aws/config');
  assert.deepEqual(sep.alt_paths, ['/config']);
  // a directory named with a line break: continuation lines rejoined, `rm ../config` resolved
  assert.ok(paths('dir.create').includes('/home/dev/.kube/a\nb'));
  assert.ok(paths('file.delete').includes('/home/dev/.kube/config'));
  // a name that ends like a result
  assert.ok(paths('file.delete').includes('/tmp/q"uo,te) = 0 (0x0) (3µs)'));
  // python in-process: chdir then plain rename/truncate/chmod/link; a forked child inherits the cwd
  const src = '/home/dev/projects/acme-app/src';
  const ren = by('file.rename').find((e) => e.from === `${src}/index.js`);
  assert.equal(ren.to, `${src}/index.old`);
  assert.ok(paths('file.truncate').includes(`${src}/index.old`));
  assert.ok(by('file.chmod').some((e) => e.path === `${src}/index.old` && e.mode === 0o600));
  assert.ok(by('file.link').some((e) => e.from === `${src}/index.old` && e.to === `${src}/hard.js` && e.link === 'hard'));
  const child = by('file.delete').find((e) => e.path === `${src}/db.js`);
  assert.equal(child.cwd_assumed, undefined, 'the forked child got its cwd from the clone line');
  // mktemp -d ... rm -rf "$T"
  const tmpDir = paths('dir.create').find((p) => p.startsWith('/tmp/tmp.'));
  assert.ok(tmpDir);
  assert.equal(paths('file.delete').filter((p) => p.startsWith(`${tmpDir}/`)).length, 3);
  assert.ok(paths('dir.remove').includes(tmpDir));
  assert.ok(events.every((e) => e.partial !== true));

  // Rules: the decoy deletion and the existing-file changes are findings; the tmp cleanup is not.
  const seededPaths = [
    '/home/dev/Documents/budget-2026.xlsx',
    '/home/dev/Pictures/IMG_20260902_091533.jpg',
    '/home/dev/.npmrc',
    '/home/dev/.aws/credentials',
    '/home/dev/.aws/config',
    '/home/dev/.config/gh/config.yml',
    '/home/dev/.config/gh/hosts.yml',
    '/home/dev/.kube/config',
    `${src}/index.js`,
    `${src}/db.js`,
    '/home/dev/.ssh/id_ed25519',
  ];
  const { findings, verdict } = evaluate({ events, contract: {}, decoys, seededPaths });
  assert.equal(verdict.level, 'SUSPICIOUS');
  const titles = findings.map((f) => `${f.rule_id}: ${f.title}`);
  assert.ok(titles.includes('decoy.write: Deleted ~/.aws/credentials (fake cloud credentials)'), titles.join('\n'));
  assert.ok(titles.some((t) => t.startsWith('decoy.write: Deleted ~/.config/gh/hosts.yml (fake ')), titles.join('\n'));
  assert.ok(titles.some((t) => t.startsWith('decoy.write: Changed permissions of ~/.npmrc (fake ')), titles.join('\n'));
  const existing = findings.find((f) => f.rule_id === 'fs.existing_file_changed');
  assert.ok(existing, titles.join('\n'));
  assert.equal(existing.severity, 'medium');
  assert.match(existing.title, /^Deleted \d+, moved 1 and linked 1 files that were already on this computer$/, titles.join('\n'));
  const seqs = new Set(existing.event_seqs);
  assert.ok(seqs.has(child.seq) && seqs.has(ren.seq) && seqs.has(link.seq), JSON.stringify(existing));
  // ~/.aws/config is a decoy in the real manifest, so its deletion (read through the hostile
  // separator) lands in decoy.write; either way the hidden reading is a finding.
  assert.ok(findings.some((f) => (f.rule_id === 'decoy.write' || f.rule_id === 'fs.existing_file_changed') && f.event_seqs.includes(sep.seq)), titles.join('\n'));
  assert.ok(!seqs.has(by('file.delete').find((e) => e.path.startsWith(`${tmpDir}/`)).seq));
});
