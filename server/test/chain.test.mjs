// web/chain.js: arranging recorded events into who started what. Pure, so no browser is needed.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildProcessChains, flagLevel, isFlagged, nodeLabel } from '../../web/chain.js';

let seq = 0;
const ev = (kind, t, extra = {}) => ({ kind, t_rel_ms: t, seq: ++seq, ...extra });
const exec = (pid, ppid, argv, t, extra = {}) => ev('proc.exec', t, { pid, ppid, argv, exe: `/usr/bin/${argv[0]}`, ...extra });
const shape = (node) => {
  const { program, args } = nodeLabel(node);
  return { program, args, items: node.items.map((i) => (i.type === 'child' ? shape(i.node) : i.ev.kind)) };
};
const childByName = (node, name) => node.items.find((i) => i.type === 'child' && nodeLabel(i.node).program === name)?.node;

test('the reported BASH_ENV run: a child shell reads the script it was never given, then starts id', () => {
  const [run] = buildProcessChains([
    exec(47, 44, ['bash', '-c', 'echo FIRST_CHILD'], 130),
    ev('file.open', 162, { pid: 47, path: '/tmp/x/init.sh', access: 'read' }),
    ev('file.open', 162, { pid: 47, path: '/tmp/x/execution.log', access: 'create' }),
    ev('file.open', 172, { pid: 48, path: '/tmp/x/execution.log', access: 'create' }), // the redirect, before the exec
    exec(48, 47, ['id'], 177),
    ev('net.connect', 205, { pid: 48, family: 'unix', path: '/var/run/nscd/socket' }),
    exec(49, 44, ['bash', '-c', 'echo SECOND_CHILD'], 217),
  ]);
  assert.equal(run.programs, 3);
  assert.equal(run.roots.length, 1);
  const top = run.roots[0];
  assert.equal(top.isCommand, true, 'the shell behind every program is the top');
  assert.equal(top.pid, 44);
  assert.deepEqual(top.items.map((i) => shape(i.node)), [
    { program: 'bash', args: '-c echo FIRST_CHILD', items: ['file.open', 'file.open', { program: 'id', args: '', items: ['file.open', 'net.connect'] }] },
    { program: 'bash', args: '-c echo SECOND_CHILD', items: [] },
  ]);
  assert.equal(top.items[0].node.parentUnknown, false);
  assert.deepEqual(run.unattached, []);
});

test('fake internet records go to the program that last connected to that port, alerts follow their record', () => {
  const http = ev('http.request', 336, { method: 'POST', host: 'x.test', port: 443, body_len: 100 });
  const [run] = buildProcessChains([
    exec(50, 44, ['curl', '-X', 'POST', 'https://x.test'], 153),
    ev('net.connect', 249, { pid: 50, dst_port: 53, dst_ip: '10.0.0.2' }),
    ev('net.connect', 251, { pid: 50, dst_port: 443, dst_ip: '10.0.0.2' }),
    ev('tls.clienthello', 269, { sni: 'x.test', port: 443 }),
    ev('dns.query', 289, { name: 'x.test' }),
    http,
    ev('canary.hit', 391, { decoy_id: 'aws_secret', event_seq: http.seq, where: 'body' }),
  ]);
  const curl = childByName(run.roots[0], 'curl');
  assert.deepEqual(curl.items.map((i) => i.ev.kind), ['net.connect', 'net.connect', 'tls.clienthello', 'dns.query', 'http.request', 'canary.hit']);
  assert.equal(curl.flag, 2, 'a fake key leaving marks the program');
  assert.equal(run.roots[0].flag, 2, 'and what started it');
  assert.deepEqual(run.unattached, []);
});

test('the later of two programs on a port gets the record; a small clock difference is allowed', () => {
  const [run] = buildProcessChains([
    exec(60, 44, ['curl', 'a'], 10),
    ev('net.connect', 20, { pid: 60, dst_port: 443 }),
    exec(61, 44, ['wget', 'b'], 30),
    ev('net.connect', 500, { pid: 61, dst_port: 443 }),
    ev('http.request', 100, { host: 'a.test', port: 443 }),
    ev('http.request', 495, { host: 'b.test', port: 443 }),
  ]);
  const hosts = (node) => node.items.filter((i) => i.ev.kind === 'http.request').map((i) => i.ev.host);
  assert.deepEqual(hosts(childByName(run.roots[0], 'curl')), ['a.test']);
  assert.deepEqual(hosts(childByName(run.roots[0], 'wget')), ['b.test']);
});

test('a record that matches no connection is kept apart, not guessed', () => {
  const [run] = buildProcessChains([exec(70, 44, ['ls'], 10), ev('dns.query', 20, { name: 'x.test' }), ev('canary.hit', 30, { decoy_id: 'k', where: 'stdout' })]);
  assert.deepEqual(run.unattached.map((e) => e.kind), ['dns.query', 'canary.hit']);
});

test('a second sandbox run gets its own tree, even when process ids repeat', () => {
  const runs = buildProcessChains([
    exec(45, 44, ['first'], 10),
    exec(45, 44, ['second'], 1800, { attempt: 2 }),
    ev('file.open', 1810, { pid: 45, path: '/x', access: 'read', attempt: 2 }),
  ]);
  assert.deepEqual(runs.map((r) => r.attempt), [1, 2]);
  assert.equal(childByName(runs[0].roots[0], 'first').items.length, 0);
  assert.equal(childByName(runs[1].roots[0], 'second').items.length, 1);
});

test('a process that turns into another program keeps one node; the later program is a line in it', () => {
  const [run] = buildProcessChains([exec(80, 44, ['sh', 'wrapper'], 10), exec(80, 44, ['python3', 'app.py'], 20)]);
  const sh = childByName(run.roots[0], 'sh');
  assert.deepEqual(sh.items.map((i) => i.ev.argv[0]), ['python3']);
  assert.equal(run.programs, 1);
});

test('the shell that ran the command shows what it did itself', () => {
  const [run] = buildProcessChains([ev('file.open', 10, { pid: 44, path: '/x', access: 'read' }), exec(45, 44, ['cat'], 20)]);
  assert.equal(run.roots.length, 1);
  assert.equal(run.roots[0].isCommand, true);
  assert.deepEqual(nodeLabel(run.roots[0]), { program: '', args: '' });
  assert.equal(run.roots[0].items[0].type, 'event');
  assert.equal(run.roots[0].items[1].type, 'child');
  assert.equal(run.programs, 1);
});

test('tool stand-ins count as programs; with no recorded parent they hang under the command, marked', () => {
  const [run] = buildProcessChains([
    ev('file.open', 10, { pid: 44, path: '/tmp/', access: 'read' }),
    exec(45, 44, ['rm', '-rf', '/x'], 20),
    ev('shim.call', 30, { pid: 46, tool: 'crontab', args: ['-l'], classification: 'unexplained' }),
  ]);
  const top = run.roots[0];
  assert.equal(run.roots.length, 1);
  assert.equal(run.programs, 2);
  const shim = childByName(top, 'crontab');
  assert.deepEqual(nodeLabel(shim), { program: 'crontab', args: '-l' });
  assert.equal(shim.parentUnknown, true);
  assert.equal(childByName(top, 'rm').parentUnknown, false);
  assert.equal(top.flag, 1, 'an attached stand-in still marks the top');
});

test('a tool stand-in with a recorded parent goes under that parent', () => {
  const [run] = buildProcessChains([exec(45, 44, ['sh', 'setup.sh'], 10), ev('shim.call', 20, { pid: 46, ppid: 45, tool: 'systemctl', args: ['enable', 'x'] })]);
  const shim = childByName(childByName(run.roots[0], 'sh'), 'systemctl');
  assert.equal(shim.parentUnknown, false);
});

test('a parent seen only through a child stays one node; a second unknown parent hangs under the first', () => {
  const [run] = buildProcessChains([exec(45, 44, ['a'], 10), exec(46, 44, ['b'], 20), exec(90, 1, ['daemon'], 30)]);
  const top = run.roots[0];
  assert.equal(run.roots.length, 1);
  assert.equal(top.pid, 44);
  const orphanParent = top.items.find((i) => i.node.pid === 1).node;
  assert.equal(orphanParent.parentUnknown, true);
  assert.equal(nodeLabel(orphanParent.items[0].node).program, 'daemon');
});

test('a fork that never ran a program folds into the program it is a copy of', () => {
  const [run] = buildProcessChains([
    exec(46, 44, ['bash', 'install.sh'], 10),
    ev('file.open', 20, { pid: 57, path: '/tmp/out', access: 'create', forks: [[57, 46]] }), // a redirect inside $(...)
    exec(64, 57, ['curl', 'https://x.test'], 30, { forks: [[58, 57], [59, 58]] }), // recorded parents, no events of their own
    exec(65, 59, ['sed', 's/a/b/'], 40),
    ev('file.open', 50, { pid: 44, path: '/y', access: 'create', classification: 'unexplained' }),
    ev('file.open', 60, { pid: 90, path: '/z', access: 'read', forks: [[90, 44]] }), // a fork of the top
  ]);
  const top = run.roots[0];
  assert.equal(run.programs, 3);
  assert.equal(run.roots.length, 1);
  const bash = childByName(top, 'bash');
  assert.deepEqual(bash.items.map((i) => (i.type === 'child' ? nodeLabel(i.node).program : i.ev.path)), ['/tmp/out', 'curl', 'sed']);
  assert.equal(bash.items[1].node.parentUnknown, false);
  assert.deepEqual(top.items.map((i) => (i.type === 'child' ? nodeLabel(i.node).program : i.ev.path)), ['bash', '/y', '/z']);
});

test('a flag inside a folded fork still marks the programs above it', () => {
  const [run] = buildProcessChains([
    exec(46, 44, ['bash', 'install.sh'], 10),
    ev('file.open', 20, { pid: 57, path: '/k', access: 'read', classification: 'forbidden', decoy_id: 'k', forks: [[57, 46]] }),
  ]);
  const bash = childByName(run.roots[0], 'bash');
  assert.equal(bash.flag, 2);
  assert.equal(run.roots[0].flag, 2);
});

test('an older report without fork links keeps the fork apart instead of guessing its parent', () => {
  const [run] = buildProcessChains([
    exec(46, 44, ['bash', 'install.sh'], 10),
    exec(64, 57, ['curl', 'https://x.test'], 30),
  ]);
  const top = run.roots[0];
  const fork = top.items.find((i) => i.node.pid === 57).node;
  assert.equal(fork.parentUnknown, true);
  assert.deepEqual(nodeLabel(fork), { program: '', args: '' });
  assert.equal(nodeLabel(fork.items[0].node).program, 'curl');
});

test('with no process lacking a program there is no invented top', () => {
  const runs = buildProcessChains([ev('shim.call', 10, { pid: 46, tool: 'crontab', args: [] }), ev('shim.call', 20, { pid: 47, tool: 'sudo', args: [] })]);
  assert.equal(runs[0].roots.length, 2);
  assert.ok(runs[0].roots.every((r) => !r.isCommand && !r.parentUnknown));
});

test('a flag marks every program above it, and only those, at the worst level below', () => {
  const [run] = buildProcessChains([
    exec(1, 0, ['bash'], 1),
    exec(2, 1, ['sh'], 2),
    exec(3, 2, ['cat'], 3),
    ev('file.open', 4, { pid: 3, path: '/k', access: 'read', classification: 'forbidden', decoy_id: 'k' }),
    exec(4, 1, ['ls'], 5),
    exec(5, 1, ['tar'], 6),
    ev('file.open', 7, { pid: 5, path: '/y', access: 'create', classification: 'unexplained' }),
  ]);
  const bash = childByName(run.roots[0], 'bash');
  assert.equal(run.roots[0].flag, 2);
  assert.equal(bash.flag, 2);
  assert.equal(childByName(bash, 'sh').flag, 2);
  assert.equal(childByName(bash, 'ls').flag, 0);
  assert.equal(childByName(bash, 'tar').flag, 1);
  assert.equal(isFlagged({ classification: 'baseline' }), false);
  assert.equal(isFlagged({ classification: 'unexplained' }), true);
  assert.equal(flagLevel({ kind: 'canary.hit' }), 2);
  assert.equal(flagLevel({ classification: 'unexplained' }), 1);
  assert.equal(flagLevel({ classification: 'explained' }), 0);
});

test('reused ids that form a loop are cut, and bad input does not throw', () => {
  const [run] = buildProcessChains([exec(5, 6, ['a'], 1), exec(6, 5, ['b'], 2), exec(7, 7, ['c'], 3)]);
  const seen = new Set();
  const walk = (n) => {
    assert.ok(!seen.has(n), 'no node appears twice');
    seen.add(n);
    for (const i of n.items) if (i.type === 'child') walk(i.node);
  };
  run.roots.forEach(walk);
  assert.equal(seen.size, 3);
  assert.deepEqual(buildProcessChains(null), []);
  assert.deepEqual(buildProcessChains([null, 'x', 3]), []);
  const [odd] = buildProcessChains([{ kind: 'proc.exec', pid: 'x' }, { kind: 'file.open', pid: 1.5 }, { pid: 9 }]);
  assert.equal(odd.unattached.length, 2);
  assert.equal(odd.programs, 0);
});

test('a very deep chain does not overflow', () => {
  const events = Array.from({ length: 5000 }, (_, i) => exec(i + 1, i, ['sh'], i));
  events.push(ev('file.open', 6000, { pid: 5000, path: '/k', access: 'read', classification: 'forbidden' }));
  const [run] = buildProcessChains(events);
  assert.equal(run.programs, 5000);
  assert.equal(run.roots.length, 1);
  assert.equal(run.roots[0].flag, 2);
});
