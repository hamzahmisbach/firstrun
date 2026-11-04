// Integration: the real capture (fixtures/captures/basic) is appended to temp files while
// createEvidence tails them, so the file tails, the normalizer and the matcher are exercised
// together the way the lifecycle will drive them.
import assert from 'node:assert/strict';
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { createEvidence } from '../evidence/index.mjs';
import { validateEvent } from '../evidence/schema.mjs';
import { createCanaries } from '../run/canary.mjs';

const CAPTURE = fileURLToPath(new URL('../../fixtures/captures/basic/', import.meta.url));
const TOKEN = 'FRCAPTUREFIXTURETOKEN234';
const PW = 'FRCAPTURESHIMTOKEN234567';

const tmp = [];
after(() => {
  for (const d of tmp) rmSync(d, { recursive: true, force: true });
});

function lines(name) {
  return readFileSync(path.join(CAPTURE, name), 'utf8').split('\n').filter(Boolean);
}

/** Append `text` in two halves split mid-line, to prove partial lines are buffered. */
function appendSplit(file, text) {
  const cut = Math.floor(text.length / 2);
  appendFileSync(file, text.slice(0, cut));
  appendFileSync(file, text.slice(cut));
}

function manifestForCapture() {
  const { decoys } = createCanaries();
  for (const d of decoys) {
    if (d.id === 'aws_secret') d.value = TOKEN;
    if (d.id === 'pw') d.value = PW;
  }
  return decoys;
}

test('createEvidence on the basic capture, fed through real file tails', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'firstrun-evidence-'));
  tmp.push(root);
  const sinkholeDir = path.join(root, 'sinkhole');
  const traceDir = path.join(root, 'trace');
  mkdirSync(sinkholeDir);
  mkdirSync(traceDir);
  const cid = readFileSync(path.join(CAPTURE, 'container_id.txt'), 'utf8').trim();
  const runId = readFileSync(path.join(CAPTURE, 'run_id.txt'), 'utf8').trim();
  const traceFile = path.join(traceDir, `${cid}.jsonl`);
  const trace = lines('trace.jsonl');
  const sinkEvents = lines('events.jsonl');
  const dns = lines('dns.log');
  const tcp = lines('tcp.jsonl');

  const delivered = [];
  const alerts = [];
  const logs = [];
  const evidence = createEvidence({
    runId,
    sinkholeDir,
    traceDir,
    decoys: manifestForCapture(),
    onEvent: (e) => delivered.push(e),
    onAlert: (e) => alerts.push(e),
    log: (r) => logs.push(r),
  });

  // Sinkhole starts first (dnsmasq startup lines are already in dns.log); the trace file exists
  // before attach with the first records, as the cidfile race in 7.2 allows.
  writeFileSync(path.join(sinkholeDir, 'dns.log'), `${dns.slice(0, 4).join('\n')}\n`);
  evidence.startSinkhole();
  assert.equal(evidence.t0Seen(), false);
  writeFileSync(traceFile, `${trace.slice(0, 60).join('\n')}\n`);
  evidence.attachSandbox(cid);

  // Interleave the sources in rough wall-clock order, in uneven chunks.
  const traceChunks = [[60, 115], [115, 300], [300, 420], [420, 600], [600, 700], [700, trace.length - 1]];
  const schedule = [
    () => appendSplit(traceFile, `${trace.slice(...traceChunks[0]).join('\n')}\n`),
    () => appendFileSync(traceFile, `${trace.slice(...traceChunks[1]).join('\n')}\n`),
    () => appendFileSync(path.join(sinkholeDir, 'dns.log'), `${dns.slice(4, 8).join('\n')}\n`),
    () => appendSplit(path.join(sinkholeDir, 'events.jsonl'), `${sinkEvents.slice(0, 2).join('\n')}\n`),
    () => appendFileSync(traceFile, `${trace.slice(...traceChunks[2]).join('\n')}\n`),
    () => appendFileSync(path.join(sinkholeDir, 'dns.log'), `${dns.slice(8, 16).join('\n')}\n`),
    () => appendSplit(path.join(sinkholeDir, 'events.jsonl'), `${sinkEvents.slice(2).join('\n')}\n`),
    () => appendFileSync(traceFile, `${trace.slice(...traceChunks[3]).join('\n')}\n`),
    () => appendFileSync(path.join(sinkholeDir, 'dns.log'), `${dns.slice(16).join('\n')}\n`),
    () => appendFileSync(path.join(sinkholeDir, 'tcp.jsonl'), `${tcp[0]}\n`),
    () => appendFileSync(traceFile, `${trace.slice(...traceChunks[4]).join('\n')}\n`),
    () => appendFileSync(path.join(sinkholeDir, 'tcp.jsonl'), `${tcp[1]}\n`),
    () => appendFileSync(traceFile, `${trace.slice(...traceChunks[5]).join('\n')}\n`),
  ];
  for (const step of schedule) {
    step();
    await sleep(35);
  }
  await sleep(80);
  assert.equal(evidence.t0Seen(), true, 'T0 marker seen while tailing');
  // The sidecar writes sink.closed when the container exits; stop() waits for it.
  setTimeout(() => appendFileSync(traceFile, `${trace[trace.length - 1]}\n`), 150);
  const { events, coverage } = await evidence.stop({ graceMs: 3000 });

  // Envelope and delivery.
  assert.ok(events.length > 30);
  assert.deepEqual(delivered, events, 'onEvent got every event in arrival order');
  events.forEach((e, i) => {
    assert.equal(e.seq, i + 1);
    assert.equal(e.run_id, runId);
    validateEvent(e);
  });
  const t0 = coverage.t0_ms;
  assert.equal(t0, 1793793307329);
  for (const e of events) {
    assert.equal(e.t_rel_ms, e.ts_ms - t0);
    if (e.source === 'gvisor') assert.ok(e.t_rel_ms >= 0, `${e.kind} after T0`);
  }

  // Pre-T0 setup and framework are gone (7.3).
  const execs = events.filter((e) => e.kind === 'proc.exec');
  const opens = events.filter((e) => e.kind === 'file.open');
  assert.equal(execs.some((e) => /\/(cp|chmod|timeout)$/.test(e.exe)), false, 'cp/chmod/timeout dropped');
  assert.equal(execs.some((e) => e.argv.includes('/work/cmd.sh') || e.exe === '/opt/firstrun/launch'), false);
  assert.equal(opens.some((e) => e.path === '/work/cmd.sh' || e.path === '/seed/shim-canaries.json'), false);
  assert.equal(opens.some((e) => e.path === '/dev/null' || e.path === '/dev/tty' || e.path.startsWith('/opt/firstrun/')), false, 'sandbox internals never shown');
  assert.equal(opens.some((e) => e.path.startsWith('/seed/home/') || e.path.startsWith('/lib/') || e.path.startsWith('/usr/lib/') || e.path.startsWith('/etc/ld.so')), false);
  assert.equal(opens.some((e) => e.access === 'read' && e.ok === false), false, 'failed reads are counted only');
  assert.equal(evidence.pidRoot(), 5);

  // The user's command, as it ran (stdout.txt of the capture lists the steps).
  assert.deepEqual(
    execs.map((e) => path.posix.basename(e.exe)),
    ['id', 'stat', 'cat', 'cat', 'curl', 'curl', 'curl', 'getent', 'python3', 'python3', 'curl'],
  );
  assert.ok(execs.filter((e) => e.exe === '/usr/bin/python3').every((e) => e.interp === '/usr/bin/python3.12'), 'execfn is the exe, binary_path the interp');
  const awsReads = opens.filter((e) => e.path === '/home/dev/.aws/credentials');
  assert.deepEqual(awsReads.map((e) => [e.pid, e.access, e.decoy_id]), [[9, 'read', 'aws_secret'], [12, 'read', 'aws_secret']], 'cat and curl --data-binary @file');
  const blocked = opens.find((e) => e.path === '/usr/local/blocked.txt');
  assert.deepEqual([blocked.pid, blocked.access, blocked.ok, blocked.errno], [5, 'create', false, 13], 'write to the read-only rootfs');
  const shim = events.filter((e) => e.kind === 'shim.call');
  assert.deepEqual(shim.map((e) => [e.tool, e.args, e.pid]), [['crontab', ['-l'], 20]]);

  // Network from inside: sinkhole IP for names, the literal IP attempt, the nscd socket probes.
  const connects = events.filter((e) => e.kind === 'net.connect');
  assert.ok(connects.some((e) => e.family === 'inet' && e.dst_ip === '10.213.0.17' && e.dst_port === 443 && e.pid === 10));
  assert.ok(connects.some((e) => e.family === 'inet' && e.dst_ip === '10.213.0.17' && e.dst_port === 53));
  assert.ok(connects.some((e) => e.family === 'inet' && e.dst_ip === '10.213.0.17' && e.dst_port === 4444 && e.pid === 17));
  assert.ok(connects.some((e) => e.family === 'inet' && e.dst_ip === '1.1.1.1' && e.dst_port === 80 && e.pid === 19));
  assert.ok(connects.some((e) => e.family === 'unix' && e.path === '/var/run/nscd/socket' && e.dst_ip === null && e.dst_port === null));
  assert.equal(connects.filter((e) => e.pid === 6 && e.family === 'unix').length, 1, 'repeated nscd probes dedup');

  // Sinkhole side.
  const dnsEvents = events.filter((e) => e.kind === 'dns.query');
  assert.equal(dnsEvents.length, 11, 'one per query[...] line; dnsmasq startup and config lines are not events');
  assert.deepEqual([...new Set(dnsEvents.map((e) => e.name))], ['example.test', 'collector.example.test', 'plain.example.test', 'lookup.example.test', 'raw.example.test']);
  assert.ok(dnsEvents.every((e) => e.ts_src === 'arrival' && ['A', 'AAAA'].includes(e.qtype)));
  const https = events.filter((e) => e.kind === 'http.request');
  assert.deepEqual(https.map((e) => [e.method, e.host, e.port, e.path, e.body_len, e.scheme, e.status]), [
    ['GET', 'example.test', 443, '/hello', 0, 'https', 200],
    ['POST', 'collector.example.test', 443, '/upload', 100, 'https', 200],
    ['GET', 'plain.example.test', 80, '/path', 0, 'http', 200],
  ]);
  assert.ok(https.every((e) => !('headers' in e) && !('body_b64' in e) && !('query' in e)));
  assert.deepEqual(events.filter((e) => e.kind === 'tls.clienthello').map((e) => [e.sni, e.port, e.alpn]), [['example.test', 443, ['h2', 'http/1.1']], ['collector.example.test', 443, ['h2', 'http/1.1']]]);
  const tcpEv = events.find((e) => e.kind === 'tcp.connect');
  assert.deepEqual([tcpEv.orig_dst_port, tcpEv.bytes_in, tcpEv.looks_like_tls, 'first_bytes_hex' in tcpEv], [4444, 5, false, false]);
  const udpEv = events.find((e) => e.kind === 'udp.datagram');
  assert.deepEqual([udpEv.len, 'orig_dst_port' in udpEv], [4, false], 'redirected port 9009 is not a real destination');

  // Canary: the POST body is ~/.aws/credentials verbatim -> one raw hit tied to that request.
  const post = https[1];
  assert.deepEqual(
    alerts.map((e) => [e.kind, e.decoy_id, e.category, e.form, e.where, e.event_seq, e.source]),
    [['canary.hit', 'aws_secret', 'cloud_credentials', 'raw', 'body', post.seq, 'orchestrator']],
  );
  assert.deepEqual(events.filter((e) => e.kind === 'canary.hit'), alerts);
  assert.ok(alerts[0].seq > post.seq);

  // Coverage.
  assert.equal(coverage.mode, 'trace');
  assert.equal(coverage.gvisor_dropped, 0);
  assert.equal(coverage.decode_errors, 0);
  assert.ok(coverage.pre_t0 >= 100, `pre_t0=${coverage.pre_t0}`);
  assert.ok(coverage.framework >= 5);
  assert.ok(coverage.noise > 300);
  assert.ok(coverage.dedup > 0);
  assert.deepEqual(coverage.capped, {});
  assert.equal(coverage.scan_truncated, false);
  assert.equal(coverage.oom_killed, false);
  assert.equal(coverage.sink_closed, true);
  assert.equal(coverage.invalid, 0);
  assert.equal(coverage.tail_errors, undefined);
  assert.ok(coverage.scanned_bytes > 0);
  // Nothing logged carries values.
  assert.equal(JSON.stringify(logs).includes(TOKEN), false);
  // The stdout of the capture carries the shim's pw canary (crontab -l printed it by design):
  // scanOutput ignores pw, but a file token on stdout is reported.
  assert.deepEqual(evidence.scanOutput(readFileSync(path.join(CAPTURE, 'stdout.txt')), 'stdout'), []);
  assert.equal(alerts.length, 1);
  const stderrHits = evidence.scanOutput(Buffer.from(`debug: ${TOKEN}\n`), 'stderr');
  assert.deepEqual(stderrHits.map((h) => [h.decoy_id, h.where, h.form]), [['aws_secret', 'stderr', 'raw']]);
  assert.equal(alerts.length, 2);
  assert.equal(alerts[1].event_seq, null);
});

test('createEvidence: without a manifest value the credentials read is still a decoy, but no hit', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'firstrun-evidence-'));
  tmp.push(root);
  const sinkholeDir = path.join(root, 'sinkhole');
  const traceDir = path.join(root, 'trace');
  mkdirSync(sinkholeDir);
  mkdirSync(traceDir);
  const cid = readFileSync(path.join(CAPTURE, 'container_id.txt'), 'utf8').trim();
  const alerts = [];
  const evidence = createEvidence({
    runId: 'CAP00000000000001793793301',
    sinkholeDir,
    traceDir,
    decoys: createCanaries().decoys, // fresh random tokens: none of them is in the capture
    onEvent: () => {},
    onAlert: (e) => alerts.push(e),
  });
  evidence.startSinkhole();
  for (const name of ['events.jsonl', 'dns.log', 'tcp.jsonl']) writeFileSync(path.join(sinkholeDir, name), readFileSync(path.join(CAPTURE, name)));
  evidence.attachSandbox(cid);
  writeFileSync(path.join(traceDir, `${cid}.jsonl`), readFileSync(path.join(CAPTURE, 'trace.jsonl')));
  const { events, coverage } = await evidence.stop({ graceMs: 2000 });
  assert.equal(alerts.length, 0);
  assert.ok(events.some((e) => e.kind === 'file.open' && e.path === '/home/dev/.aws/credentials' && e.decoy_id === 'aws_secret'));
  assert.equal(coverage.sink_closed, true);
  assert.equal(events.filter((e) => e.kind === 'http.request').length, 3);
});

test('createEvidence: stop() without T0 still returns sinkhole events and no T0', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'firstrun-evidence-'));
  tmp.push(root);
  const sinkholeDir = path.join(root, 'sinkhole');
  mkdirSync(sinkholeDir);
  const evidence = createEvidence({ runId: 'CAP00000000000001793793301', sinkholeDir, traceDir: path.join(root, 'trace'), decoys: [], onEvent: () => {} });
  evidence.startSinkhole();
  writeFileSync(path.join(sinkholeDir, 'dns.log'), 'dnsmasq[15]: query[A] a.test from 10.0.0.2\n');
  await sleep(120);
  const { events, coverage } = await evidence.stop({ graceMs: 100 });
  assert.equal(evidence.t0Seen(), false);
  assert.equal(coverage.t0_ms, null);
  assert.deepEqual(events.map((e) => [e.kind, e.name, e.t_rel_ms]), [['dns.query', 'a.test', 0]]);
  assert.throws(() => evidence.attachSandbox('nothex'));
});
