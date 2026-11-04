// Rules (section 9), report trimming (10.3) and the template explanation (8.4). Fixture folders
// under fixtures/rules/<case>/ are loaded automatically (9.4). Set UPDATE_GOLDEN=1 to refresh
// expected.full.json for the golden cases.
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { buildExplanationInput } from '../explain/input.mjs';
import { Explanation, NEXT_STEP, RULE_NOTES, renderTemplateExplanation } from '../explain/template.mjs';
import { CLASSIFICATIONS, FindingSchema, RULE_IDS, VerdictSchema, evaluate, NOTE_CLEAN_MEANS, NOTE_DOWNLOAD, NOTE_LIMITS, NOTE_SINKHOLED } from '../rules/engine.mjs';
import { decoyDirs, hostMatches, matchGlob, writeGroup } from '../rules/paths.mjs';
import { REPORT_LIMITS, buildReport, truncateUtf8, utf8Bytes } from '../run/report.mjs';

const FIXTURES = fileURLToPath(new URL('../../fixtures/rules/', import.meta.url));
const GOLDEN = new Set(['canary_http_body', 'installer_explained', 'shim_osascript_pw_exfil']);

function readJson(p, fallback) {
  return existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : fallback;
}

function loadCase(name) {
  const dir = path.join(FIXTURES, name);
  const events = readFileSync(path.join(dir, 'events.jsonl'), 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l));
  const meta = readJson(path.join(dir, 'meta.json'), {});
  return {
    name,
    dir,
    input: {
      events,
      contract: readJson(path.join(dir, 'contract.json'), {}),
      decoys: readJson(path.join(dir, 'decoys.json'), []),
      layers: readJson(path.join(dir, 'layers.json'), []),
      coverage: readJson(path.join(dir, 'coverage.json'), undefined),
      ...meta,
    },
    expected: readJson(path.join(dir, 'expected.json'), {}),
  };
}

const CASES = readdirSync(FIXTURES, { withFileTypes: true })
  .filter((d) => d.isDirectory() && !d.name.startsWith('_'))
  .map((d) => loadCase(d.name));

function severityCounts(findings) {
  const out = {};
  for (const f of findings) out[f.severity] = (out[f.severity] ?? 0) + 1;
  return out;
}

function seededShuffle(arr, seed) {
  const out = arr.slice();
  let s = seed;
  for (let i = out.length - 1; i > 0; i--) {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    const j = s % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

const SEV = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const LEVEL = { CLEAN: 0, SUSPICIOUS: 1, MALICIOUS: 2 };

assert.ok(CASES.length >= 20, 'fixtures/rules has the 9.4 cases');

// --- fixture cases ---------------------------------------------------------------------------

for (const c of CASES) {
  test(`fixture ${c.name}: verdict and rule_ids`, () => {
    const { findings, verdict } = evaluate(c.input);
    assert.equal(verdict.level, c.expected.level, JSON.stringify(findings, null, 1));
    assert.deepEqual(verdict.rule_ids, c.expected.rule_ids);
    assert.deepEqual(severityCounts(findings), c.expected.severity_counts, JSON.stringify(findings, null, 1));
    if (c.expected.findings_count !== undefined) assert.equal(findings.length, c.expected.findings_count);
    const ids = new Set(findings.map((f) => f.rule_id));
    for (const r of c.expected.rules_present ?? []) assert.ok(ids.has(r), `expected rule ${r}`);
    for (const r of c.expected.rules_absent ?? []) assert.ok(!ids.has(r), `unexpected rule ${r}`);
    for (const r of c.expected.rule_ids) assert.ok(ids.has(r), `rule_ids entry ${r} has a finding`);
    for (const note of c.expected.notes_include ?? []) assert.ok(verdict.coverage_notes.includes(note), `missing note: ${note}\n${verdict.coverage_notes.join('\n')}`);
    assert.equal(verdict.coverage_notes[0], verdict.level === 'CLEAN' ? NOTE_CLEAN_MEANS : NOTE_LIMITS);
    assert.equal(verdict.coverage_notes[1], NOTE_SINKHOLED);
    assert.ok(verdict.level === 'CLEAN' || !verdict.coverage_notes.includes(NOTE_CLEAN_MEANS), 'CLEAN wording only under a CLEAN banner');
  });
}

// --- invariants (9.4) ------------------------------------------------------------------------

test('invariant: deterministic, also with shuffled events', () => {
  for (const c of CASES) {
    const a = JSON.stringify(evaluate(c.input));
    const b = JSON.stringify(evaluate(c.input));
    const shuffled = JSON.stringify(evaluate({ ...c.input, events: seededShuffle(c.input.events, 7) }));
    assert.equal(a, b, c.name);
    assert.equal(a, shuffled, `${c.name}: event order must not matter`);
  }
});

test('invariant: adding an outbound canary.hit makes any fixture MALICIOUS; adding events never lowers the level', () => {
  for (const c of CASES) {
    const base = evaluate(c.input);
    const maxSeq = Math.max(0, ...c.input.events.map((e) => e.seq));
    const extraHttp = { run_id: 'X', seq: maxSeq + 1, ts_ms: 1, t_rel_ms: 1, source: 'sinkhole', kind: 'http.request', method: 'POST', host: 'leak.test', port: 443, path: '/', body_len: 40 };
    const hit = { run_id: 'X', seq: maxSeq + 2, ts_ms: 1, t_rel_ms: 1, source: 'orchestrator', kind: 'canary.hit', decoy_id: 'aws_secret', category: 'cloud_credentials', form: 'b64x3', where: 'body', event_seq: maxSeq + 1 };
    const withHit = evaluate({ ...c.input, events: [...c.input.events, extraHttp, hit] });
    assert.equal(withHit.verdict.level, 'MALICIOUS', c.name);
    assert.ok(withHit.verdict.rule_ids.includes('exfil.canary_outbound'), c.name);
    // Adding assorted events never lowers the level.
    const extras = [
      { kind: 'proc.exec', source: 'gvisor', pid: 9, ppid: 1, exe: '/usr/bin/ls', argv: ['ls'] },
      { kind: 'file.open', source: 'gvisor', pid: 9, path: '/tmp/a', access: 'create' },
      { kind: 'dns.query', source: 'sinkhole', name: 'added.test', qtype: 'A' },
    ].map((e, i) => ({ run_id: 'X', seq: maxSeq + 10 + i, ts_ms: 1, t_rel_ms: 1, ...e }));
    const more = evaluate({ ...c.input, events: [...c.input.events, ...extras] });
    assert.ok(LEVEL[more.verdict.level] >= LEVEL[base.verdict.level], c.name);
  }
});

test('invariant: a wider contract never raises the level or any finding severity', () => {
  for (const c of CASES) {
    const base = evaluate(c.input);
    const wide = {
      ...c.input.contract,
      expected_hosts: [...(c.input.contract.expected_hosts ?? []), '*.test', 'collector.test', 'example.test', '203.0.113.9'],
      expected_write_paths: [...(c.input.contract.expected_write_paths ?? []), '~/**', '/tmp/**', '/etc/**', '/opt/**'],
      expected_processes: [...(c.input.contract.expected_processes ?? []), 'python3', 'node', 'nc', 'crontab', 'sudo', 'aws', 'npm', 'git', 'ssh'],
      allowed_decoy_categories: ['cloud_credentials', 'package_manager_token', 'vcs_token', 'ssh_private_key'],
    };
    const wider = evaluate({ ...c.input, contract: wide });
    assert.ok(LEVEL[wider.verdict.level] <= LEVEL[base.verdict.level], `${c.name}: ${base.verdict.level} -> ${wider.verdict.level}`);
    const baseBy = new Map(base.findings.map((f) => [`${f.rule_id}:${f.title}`, f]));
    for (const f of wider.findings) {
      const b = baseBy.get(`${f.rule_id}:${f.title}`);
      if (b) assert.ok(SEV[f.severity] <= SEV[b.severity], `${c.name}: ${f.rule_id} ${b.severity} -> ${f.severity}`);
    }
    // NEVER_ALLOWED and outbound canary hits are immune to the contract.
    for (const f of base.findings) {
      if (f.rule_id === 'exfil.canary_outbound') assert.ok(wider.findings.some((w) => w.id === f.id && w.severity === 'critical'), c.name);
    }
  }
});

test('invariant: NEVER_ALLOWED categories cannot be explained by the contract', () => {
  const c = CASES.find((x) => x.name === 'wallet_allowed_is_ignored');
  const { findings } = evaluate(c.input);
  for (const f of findings) {
    assert.equal(f.classification, 'forbidden', f.title);
    assert.equal(f.severity, 'high', f.title);
  }
});

test('invariant: shapes, unique ids, event_seqs exist, titles never carry a decoy value', () => {
  for (const c of CASES) {
    const { findings, verdict, classifications } = evaluate(c.input);
    VerdictSchema.parse(verdict);
    const seqs = new Set(c.input.events.map((e) => e.seq));
    const ids = new Set();
    for (const f of findings) {
      FindingSchema.parse(f);
      assert.ok(!ids.has(f.id), `${c.name}: duplicate id ${f.id}`);
      ids.add(f.id);
      assert.ok(f.id.startsWith(f.rule_id + ':'));
      for (const s of f.event_seqs) assert.ok(seqs.has(s), `${c.name}: ${f.id} references seq ${s}`);
      for (const d of c.input.decoys) {
        if (!d.value) continue;
        assert.ok(!f.title.includes(d.value), `${c.name}: title leaks ${d.id}`);
        assert.ok(!f.title.toLowerCase().includes(d.value.toLowerCase()), `${c.name}: title leaks ${d.id} (case)`);
        assert.ok(!f.title.includes(Buffer.from(d.value).toString('base64')), `${c.name}: title leaks ${d.id} base64`);
        assert.ok(!f.title.includes(Buffer.from(d.value).toString('hex')), `${c.name}: title leaks ${d.id} hex`);
      }
    }
    for (const [seq, cls] of Object.entries(classifications)) {
      assert.ok(seqs.has(Number(seq)));
      assert.ok(CLASSIFICATIONS.includes(cls));
    }
    assert.equal(verdict.rule_ids.length, new Set(verdict.rule_ids).size);
    assert.deepEqual(verdict.rule_ids, [...verdict.rule_ids].sort());
    if (verdict.level === 'CLEAN') assert.deepEqual(verdict.rule_ids, []);
    // Findings are sorted by severity desc, then first seq asc.
    for (let i = 1; i < findings.length; i++) {
      const a = findings[i - 1];
      const b = findings[i];
      assert.ok(SEV[a.severity] >= SEV[b.severity], c.name);
    }
  }
});

test('invariant: every rule id in 9.2 has a positive and a negative fixture', () => {
  const present = new Map(RULE_IDS.map((r) => [r, []]));
  const absent = new Map(RULE_IDS.map((r) => [r, []]));
  for (const c of CASES) {
    const ids = new Set(evaluate(c.input).findings.map((f) => f.rule_id));
    for (const r of RULE_IDS) (ids.has(r) ? present : absent).get(r).push(c.name);
  }
  for (const r of RULE_IDS) {
    assert.ok(present.get(r).length > 0, `no fixture triggers ${r}`);
    assert.ok(absent.get(r).length > 0, `no fixture leaves ${r} untriggered`);
  }
});

test('invariant: verdict mapping follows the severity scale exactly', () => {
  for (const c of CASES) {
    const { findings, verdict } = evaluate(c.input);
    const max = Math.max(-1, ...findings.map((f) => SEV[f.severity]));
    const expected = max >= SEV.critical ? 'MALICIOUS' : max >= SEV.medium ? 'SUSPICIOUS' : 'CLEAN';
    assert.equal(verdict.level, expected, c.name);
    const deciding = [...new Set(findings.filter((f) => SEV[f.severity] >= SEV.medium).map((f) => f.rule_id))].sort();
    assert.deepEqual(verdict.rule_ids, deciding, c.name);
  }
});

test('golden: findings for the demo-like cases are frozen in expected.full.json', () => {
  for (const c of CASES.filter((x) => GOLDEN.has(x.name))) {
    const { findings, verdict } = evaluate(c.input);
    const file = path.join(c.dir, 'expected.full.json');
    const actual = JSON.stringify({ verdict, findings }, null, 2) + '\n';
    if (process.env.UPDATE_GOLDEN === '1' || !existsSync(file)) {
      writeFileSync(file, actual);
      continue;
    }
    assert.equal(actual, readFileSync(file, 'utf8'), `${c.name}: golden drift (UPDATE_GOLDEN=1 to accept)`);
  }
});

test('performance: 50 000 synthetic events evaluate in well under 100 ms (warm)', () => {
  const events = [];
  for (let i = 1; i <= 50_000; i++) {
    const k = i % 5;
    const base = { run_id: 'X', seq: i, ts_ms: i, t_rel_ms: i, source: 'gvisor' };
    if (k === 0) events.push({ ...base, kind: 'file.open', pid: 5, path: `/home/dev/proj/f${i}`, access: 'create' });
    else if (k === 1) events.push({ ...base, kind: 'proc.exec', pid: 5, ppid: 1, exe: '/usr/bin/cc', argv: ['cc', `f${i}.c`] });
    else if (k === 2) events.push({ ...base, kind: 'file.open', pid: 5, path: `/usr/share/x/${i}`, access: 'read' });
    else if (k === 3) events.push({ ...base, source: 'sinkhole', kind: 'dns.query', name: `h${i % 50}.test`, qtype: 'A' });
    else events.push({ ...base, source: 'sinkhole', kind: 'http.request', method: 'GET', host: `h${i % 50}.test`, port: 443, path: '/', body_len: 0 });
  }
  const input = { events, contract: {}, decoys: CASES[0].input.decoys };
  evaluate(input); // warm-up
  let best = Infinity;
  let findings = [];
  for (let i = 0; i < 3; i++) {
    const t = performance.now();
    ({ findings } = evaluate(input));
    best = Math.min(best, performance.now() - t);
  }
  assert.ok(findings.length <= 200, 'findings are capped at 200');
  assert.ok(best < 100, `best of 3 took ${best.toFixed(1)} ms`);
});

test('findings cap: beyond 200 groups the rest is merged into the last net.unexpected_host/fs.unexpected_write', () => {
  const events = [];
  for (let i = 1; i <= 300; i++) {
    events.push({ run_id: 'X', seq: i, ts_ms: i, t_rel_ms: i, source: 'sinkhole', kind: 'http.request', method: 'GET', host: `h${i}.test`, port: 443, path: '/', body_len: 0 });
  }
  events.push({ run_id: 'X', seq: 301, ts_ms: 1, t_rel_ms: 1, source: 'orchestrator', kind: 'exec.finished', exit_code: 0, timed_out: false });
  const { findings, verdict } = evaluate({ events, contract: {}, decoys: [] });
  assert.equal(findings.length, 200);
  assert.equal(verdict.level, 'SUSPICIOUS');
  const last = findings[199];
  assert.equal(last.rule_id, 'net.unexpected_host');
  assert.ok(last.title.includes('100 more findings merged here'));
  assert.ok(last.event_seqs.length <= 50);
});

// --- targeted engine behaviour ---------------------------------------------------------------

const EV = (seq, kind, fields) => ({ run_id: 'X', seq, ts_ms: seq, t_rel_ms: seq, source: 'gvisor', kind, ...fields });
const DECOYS = CASES[0].input.decoys;

test('engine: canary.hit with any non-stdout `where` is outbound and critical, whatever the contract', () => {
  for (const where of ['url', 'header', 'body', 'dns', 'tcp_bytes', 'http.body', 'dns.name', 'tls.sni', 'tcp.first_bytes', 'udp.first_bytes', 'weird']) {
    const events = [
      EV(1, 'http.request', { source: 'sinkhole', method: 'GET', host: 'a.test', port: 443, path: '/', body_len: 0 }),
      EV(2, 'canary.hit', { source: 'orchestrator', decoy_id: 'aws_secret', category: 'cloud_credentials', form: 'raw', where, event_seq: 1 }),
    ];
    const { verdict, findings } = evaluate({ events, contract: { expected_hosts: ['a.test'], allowed_decoy_categories: ['cloud_credentials'] }, decoys: DECOYS });
    assert.equal(verdict.level, 'MALICIOUS', where);
    const f = findings.find((x) => x.rule_id === 'exfil.canary_outbound');
    assert.equal(f.title, 'Fake credential from ~/.aws/credentials was sent to a.test');
    assert.deepEqual(f.event_seqs, [1, 2]);
    assert.equal(f.classification, 'forbidden');
  }
});

test('engine: exfil.read_then_send needs open before send, a forbidden SENSITIVE open, and no outbound hit', () => {
  const open = EV(1, 'file.open', { pid: 5, path: '/home/dev/.aws/credentials', access: 'read', decoy_id: 'aws_secret' });
  const send = EV(2, 'http.request', { source: 'sinkhole', method: 'PUT', host: 'c.test', port: 443, path: '/', body_len: 9 });
  const r1 = evaluate({ events: [open, send], contract: {}, decoys: DECOYS });
  assert.ok(r1.findings.some((f) => f.rule_id === 'exfil.read_then_send' && f.event_seqs.join() === '1,2'));
  assert.equal(r1.verdict.level, 'MALICIOUS');
  // Explained open: no read_then_send.
  const r2 = evaluate({ events: [open, send], contract: { allowed_decoy_categories: ['cloud_credentials'] }, decoys: DECOYS });
  assert.ok(!r2.findings.some((f) => f.rule_id === 'exfil.read_then_send'));
  // ssh_meta is not SENSITIVE.
  const meta = EV(1, 'file.open', { pid: 5, path: '/home/dev/.ssh/config', access: 'read', decoy_id: 'ssh_config' });
  const r3 = evaluate({ events: [meta, send], contract: {}, decoys: DECOYS });
  assert.ok(!r3.findings.some((f) => f.rule_id === 'exfil.read_then_send'));
  // Explained host: no send.
  const r4 = evaluate({ events: [open, send], contract: { expected_hosts: ['c.test'] }, decoys: DECOYS });
  assert.ok(!r4.findings.some((f) => f.rule_id === 'exfil.read_then_send'));
  // GET with no body is not a send.
  const get = { ...send, method: 'GET', body_len: 0 };
  const r5 = evaluate({ events: [open, get], contract: {}, decoys: DECOYS });
  assert.ok(!r5.findings.some((f) => f.rule_id === 'exfil.read_then_send'));
});

test('engine: unknown decoy id is treated as a sensitive credential read', () => {
  const { findings, verdict } = evaluate({ events: [EV(1, 'file.open', { pid: 5, path: '/home/dev/.secret', access: 'read', decoy_id: 'nope' })], contract: { allowed_decoy_categories: ['cloud_credentials'] }, decoys: DECOYS });
  assert.equal(verdict.level, 'SUSPICIOUS');
  assert.equal(findings[0].rule_id, 'decoy.credential_read');
  assert.equal(findings[0].severity, 'high');
});

test('engine: /seed/home twin of a decoy dir counts as listing the credential directory', () => {
  const { findings } = evaluate({ events: [EV(1, 'file.open', { pid: 5, path: '/seed/home/.aws', access: 'read' })], contract: {}, decoys: DECOYS });
  assert.equal(findings[0].rule_id, 'decoy.dir_enum');
  assert.equal(findings[0].title, 'Opened credential directory ~/.aws');
});

test('engine: baseline writes and contract writes produce no finding; startup writes in the contract stay a low finding', () => {
  const events = [
    EV(1, 'file.open', { pid: 5, path: '/tmp/a', access: 'create' }),
    EV(2, 'file.open', { pid: 5, path: '/home/dev/.cache/x', access: 'write' }),
    EV(3, 'file.open', { pid: 5, path: '/dev/null', access: 'write' }),
    EV(4, 'file.open', { pid: 5, path: '/home/dev/.acme/bin/acme', access: 'create' }),
    EV(5, 'file.open', { pid: 5, path: '/home/dev/.zshrc', access: 'write' }),
    EV(6, 'file.open', { pid: 5, path: '/home/dev/.config/fish/config.fish', access: 'write' }),
  ];
  const { findings, classifications } = evaluate({ events, contract: { expected_write_paths: ['~/.acme/**', '~/.zshrc'] }, decoys: DECOYS });
  assert.deepEqual(
    findings.map((f) => [f.rule_id, f.severity, f.classification]),
    [
      ['fs.shell_startup_write', 'high', 'unexplained'],
      ['fs.shell_startup_write', 'low', 'explained'],
    ],
  );
  assert.equal(classifications['1'], 'baseline', '/tmp write is allowed for any command, not explained by the claim');
  assert.equal(classifications['4'], 'explained');
  assert.equal(classifications['6'], 'unexplained');
});

test('engine: `baseline` marks what any command may do; `explained` only what the contract matched', () => {
  const events = [
    EV(1, 'file.open', { pid: 5, path: '/dev/tty', access: 'write' }),
    EV(2, 'net.connect', { pid: 5, family: 'inet', dst_ip: '10.9.0.2', dst_port: 53 }),
    EV(3, 'net.connect', { pid: 5, family: 'inet', dst_ip: '10.9.0.2', dst_port: 443 }),
    EV(4, 'net.connect', { pid: 5, family: 'unix', dst_ip: null, dst_port: null, path: '/tmp/s' }),
    EV(5, 'net.connect', { pid: 5, family: 'inet', dst_ip: '127.0.0.1', dst_port: 80 }),
    EV(6, 'dns.query', { source: 'sinkhole', name: '2.0.9.10.in-addr.arpa', qtype: 'PTR' }),
    EV(7, 'dns.query', { source: 'sinkhole', name: 'example.test', qtype: 'A' }),
    EV(8, 'http.request', { source: 'sinkhole', method: 'GET', host: 'example.test', port: 443, path: '/', body_len: 0 }),
    EV(9, 'exec.finished', { source: 'orchestrator', exit_code: 0, timed_out: false }),
  ];
  const { classifications, findings, verdict } = evaluate({ events, contract: { expected_hosts: ['example.test'] }, decoys: [], sinkIp: '10.9.0.2' });
  assert.deepEqual(classifications, { 1: 'baseline', 2: 'baseline', 3: 'baseline', 4: 'baseline', 5: 'baseline', 6: 'baseline', 7: 'explained', 8: 'explained', 9: 'baseline' });
  assert.deepEqual(findings, []);
  assert.equal(verdict.level, 'CLEAN');
  for (const f of findings) assert.notEqual(f.classification, 'baseline', 'findings never carry baseline');
});

test('engine: proc.interpreter_inline alone is low (CLEAN); hidden_code still fires on an exec marker', () => {
  const inline = EV(1, 'proc.exec', { pid: 5, ppid: 1, exe: '/usr/bin/python3', argv: ['python3', '-c', 'print(2+2)'] });
  const r = evaluate({ events: [inline], contract: {}, decoys: [] });
  assert.equal(r.verdict.level, 'CLEAN');
  assert.deepEqual(r.findings.map((f) => [f.rule_id, f.severity]), [['proc.interpreter_inline', 'low']]);
  const layer = { index: 1, parent: 0, method: 'base64', bytes_len: 10, text: 'eval x', truncated: false, markers: { exec: ['eval'], remote: [], decode: [], opaque: 0 }, llm_assisted: false, status: 'ok' };
  const r2 = evaluate({ events: [inline], contract: {}, decoys: [], layers: [layer] });
  assert.ok(r2.findings.some((f) => f.rule_id === 'unwrap.hidden_code'));
  assert.ok(!r2.verdict.coverage_notes.includes(NOTE_DOWNLOAD), 'no remote marker, no download note');
});

test('engine: download note only with a remote marker or an empty-answered GET, never for upload-only', () => {
  const uploadOnly = CASES.find((x) => x.name === 'send_then_read');
  assert.ok(!evaluate(uploadOnly.input).verdict.coverage_notes.includes(NOTE_DOWNLOAD));
  const getOnly = CASES.find((x) => x.name === 'dns_then_host');
  assert.ok(evaluate(getOnly.input).verdict.coverage_notes.includes(NOTE_DOWNLOAD));
  const layerRemote = { index: 1, parent: 0, method: 'base64', bytes_len: 10, text: 'curl x', truncated: false, markers: { exec: [], remote: ['curl'], decode: [], opaque: 0 }, llm_assisted: false, status: 'ok' };
  assert.ok(evaluate({ events: [], contract: {}, decoys: [], layers: [layerRemote] }).verdict.coverage_notes.includes(NOTE_DOWNLOAD));
  assert.ok(evaluate({ events: [], contract: {}, decoys: [], unwrap: { stopped: 'remote' } }).verdict.coverage_notes.includes(NOTE_DOWNLOAD));
  const malicious = CASES.find((x) => x.name === 'canary_http_body');
  const notes = evaluate(malicious.input).verdict.coverage_notes;
  assert.equal(notes[0], NOTE_LIMITS);
  assert.ok(!notes.includes(NOTE_CLEAN_MEANS));
});

test('engine: fs.unexpected_write groups by ~/<dir> or top-level dir and counts files', () => {
  const events = [
    EV(1, 'file.open', { pid: 5, path: '/home/dev/.local/bin/a', access: 'create' }),
    EV(2, 'file.open', { pid: 5, path: '/home/dev/.local/share/b', access: 'create' }),
    EV(3, 'file.open', { pid: 5, path: '/home/dev/.local/bin/a', access: 'write' }),
    EV(4, 'file.open', { pid: 5, path: '/opt/thing/c', access: 'create' }),
    EV(5, 'file.open', { pid: 5, path: '/home/dev/notes.txt', access: 'create' }),
  ];
  const { findings } = evaluate({ events, contract: {}, decoys: DECOYS });
  assert.deepEqual(
    findings.map((f) => f.title).sort(),
    ['Wrote 1 file under /opt not covered by the claim', 'Wrote 1 file under ~/notes.txt not covered by the claim', 'Wrote 2 files under ~/.local not covered by the claim'],
  );
});

test('engine: net.ip_literal uses sinkIp when given, private ranges otherwise; loopback and unix never', () => {
  const ev = (seq, dst_ip, family = 'inet') => EV(seq, 'net.connect', { pid: 5, family, dst_ip, dst_port: 443 });
  const r1 = evaluate({ events: [ev(1, '10.5.0.2'), ev(2, '10.5.0.3'), ev(3, '127.0.0.1'), ev(4, null, 'unix'), ev(5, '::1', 'inet6')], contract: {}, decoys: [], sinkIp: '10.5.0.2' });
  assert.deepEqual(r1.findings.map((f) => f.title), ['Attempted a direct connection to 10.5.0.3:443, skipping name lookup']);
  const r2 = evaluate({ events: [ev(1, '10.5.0.2'), ev(2, '192.168.1.9'), ev(3, '198.51.100.7')], contract: {}, decoys: [] });
  assert.deepEqual(r2.findings.map((f) => f.title), ['Attempted a direct connection to 198.51.100.7:443, skipping name lookup']);
  const r3 = evaluate({ events: [ev(1, '198.51.100.7')], contract: { expected_hosts: ['198.51.100.7'] }, decoys: [] });
  assert.equal(r3.findings[0].severity, 'info');
  assert.equal(r3.verdict.level, 'CLEAN');
});

test('engine: shells are ignored, but a shell running a file this run wrote is proc.exec_written_file', () => {
  const events = [
    EV(1, 'proc.exec', { pid: 5, ppid: 1, exe: '/bin/bash', argv: ['bash', '-c', 'echo hi'] }),
    EV(2, 'file.open', { pid: 5, path: '/tmp/payload.sh', access: 'create' }),
    EV(3, 'proc.exec', { pid: 6, ppid: 5, exe: '/bin/sh', argv: ['sh', '/tmp/payload.sh'] }),
  ];
  const { findings } = evaluate({ events, contract: {}, decoys: [] });
  assert.deepEqual(findings.map((f) => [f.rule_id, f.event_seqs]), [['proc.exec_written_file', [3]]]);
  // Only a prior write counts: exec first, then the write (baseline /tmp) is nothing at all.
  const { findings: none } = evaluate({ events: [events[2], { ...events[1], seq: 4 }], contract: {}, decoys: [] });
  assert.deepEqual(none.map((f) => f.rule_id), []);
});

test('engine: exec/coverage inputs without an exec.finished event still drive run.timeout and notes', () => {
  const { findings, verdict } = evaluate({ events: [EV(1, 'proc.exec', { pid: 5, ppid: 1, exe: '/usr/bin/sleep', argv: ['sleep', '999'] })], contract: {}, decoys: [], exec: { exit_code: 137, timed_out: true } });
  assert.ok(findings.some((f) => f.rule_id === 'run.timeout' && f.event_seqs.length === 0 && f.id === 'run.timeout:0'));
  assert.equal(verdict.level, 'SUSPICIOUS');
  assert.ok(!verdict.coverage_notes.some((n) => n.includes('exit code')), 'a timeout has its own note, not the exit-code one');
  const plain = evaluate({ events: [], contract: {}, decoys: [], exec: { exit_code: 2, timed_out: false } });
  assert.ok(plain.verdict.coverage_notes.some((n) => n.startsWith('The command ended with an error (exit code 2), so part of it may not have run')));
});

test('engine: run.oom comes from coverage.oom_killed, with its own note and no exit-code note', () => {
  const r = evaluate({ events: [EV(1, 'exec.finished', { source: 'orchestrator', exit_code: 137, timed_out: false })], contract: {}, decoys: [], coverage: { oom_killed: true } });
  assert.deepEqual(r.verdict.rule_ids, ['run.oom']);
  assert.equal(r.verdict.level, 'SUSPICIOUS');
  assert.deepEqual(r.findings.filter((f) => f.rule_id === 'run.oom').map((f) => [f.severity, f.classification, f.event_seqs]), [['medium', 'unexplained', [1]]]);
  assert.ok(r.verdict.coverage_notes.some((n) => n.startsWith('The command used more memory than the sandbox allows')));
  assert.ok(!r.verdict.coverage_notes.some((n) => n.includes('exit code')));
  const none = evaluate({ events: [EV(1, 'exec.finished', { source: 'orchestrator', exit_code: 0, timed_out: false })], contract: {}, decoys: [], coverage: { oom_killed: false } });
  assert.ok(!none.findings.some((f) => f.rule_id === 'run.oom'));
});

test('engine: any harness stop other than a clean finish adds the "could not be fully decoded" note', () => {
  const NOTE = 'Inner layers of the command could not be fully decoded; the verdict rests on runtime evidence only.';
  const base = { events: [EV(1, 'exec.finished', { source: 'orchestrator', exit_code: 0, timed_out: false })], contract: {}, decoys: [] };
  for (const reason of ['aborted', 'gave_up', 'too_large', 'budget', 'max_layers', 'llm_disabled', 'remote', 'something_new', '', undefined]) {
    const r = evaluate({ ...base, unwrap: { stopped: 'needs_harness', harness: { stoppedReason: reason } } });
    assert.ok(r.verdict.coverage_notes.includes(NOTE), `reason ${JSON.stringify(reason)}`);
  }
  const clean = evaluate({ ...base, unwrap: { stopped: 'needs_harness', harness: { stoppedReason: 'clean' } } });
  assert.ok(!clean.verdict.coverage_notes.includes(NOTE), 'clean finish');
  // `remote` also means the next layer lives on the network.
  const remote = evaluate({ ...base, unwrap: { stopped: 'needs_harness', harness: { stoppedReason: 'remote' } } });
  assert.ok(remote.verdict.coverage_notes.includes(NOTE_DOWNLOAD));
  // No harness ran at all: no note.
  assert.ok(!evaluate({ ...base, unwrap: { stopped: 'clean', harness: null } }).verdict.coverage_notes.includes(NOTE));
  assert.ok(!evaluate(base).verdict.coverage_notes.includes(NOTE));
});

test('engine: ignores unknown kinds and malformed events', () => {
  const { verdict } = evaluate({ events: [null, 1, { kind: 'file.open' }, EV(1, 'future.kind', { x: 1 }), EV(2, 'exec.finished', { exit_code: 0, timed_out: false })], contract: null, decoys: null });
  assert.equal(verdict.level, 'CLEAN');
  assert.ok(verdict.coverage_notes.some((n) => n.startsWith('No activity observed')));
});

test('engine: shim titles describe the tool and quote the call, never an inferred intent', () => {
  const { findings } = evaluate({ events: [EV(1, 'shim.call', { tool: 'crontab', args: ['-l'] }), EV(2, 'shim.call', { tool: 'sudo', args: ['-n', 'true'] })], contract: {}, decoys: [] });
  const titles = findings.map((f) => f.title).sort();
  assert.deepEqual(titles, [
    'Called crontab, a tool that manages scheduled tasks and services (crontab -l)',
    'Called sudo, a tool that runs commands with elevated privileges (sudo -n true)',
  ]);
  for (const t of titles) assert.ok(!/tried to register|tried to run/i.test(t));
});

test('engine: a shim argument that echoes a decoy value is scrubbed from the title', () => {
  const value = DECOYS.find((d) => d.id === 'aws_secret').value;
  const { findings } = evaluate({ events: [EV(1, 'shim.call', { tool: 'open', args: [`https://x.test/?k=${value}`] })], contract: {}, decoys: DECOYS });
  assert.ok(!findings[0].title.includes(value));
  assert.ok(findings[0].title.includes('[token]'));
});

// --- paths helpers ---------------------------------------------------------------------------

test('paths: glob matcher is anchored, ** spans slashes, * one segment, ~ expands', () => {
  assert.ok(matchGlob('~/.nvm/**', '/home/dev/.nvm/a/b/c'));
  assert.ok(matchGlob('~/.nvm/**', '/home/dev/.nvm/'));
  assert.ok(!matchGlob('~/.nvm/**', '/home/dev/.nvm'));
  assert.ok(matchGlob('~/.config/powershell/*.ps1', '/home/dev/.config/powershell/profile.ps1'));
  assert.ok(!matchGlob('~/.config/powershell/*.ps1', '/home/dev/.config/powershell/sub/profile.ps1'));
  assert.ok(matchGlob('/etc/cron*/**', '/etc/cron.d/job'));
  assert.ok(!matchGlob('/tmp/**', '/tmpfoo/x'));
  assert.ok(!matchGlob('/tmp/**', 'x/tmp/y'));
  assert.ok(matchGlob('/dev/null', '/dev/null'));
  assert.ok(!matchGlob('/dev/null', '/dev/null2'));
  assert.ok(!matchGlob('a.b', 'aXb'));
});

test('paths: host matching is exact or *.suffix, case-insensitive, IPs exact', () => {
  assert.ok(hostMatches(['Example.Test'], 'example.test.'));
  assert.ok(hostMatches(['*.example.test'], 'a.b.example.test'));
  assert.ok(!hostMatches(['*.example.test'], 'example.test'));
  assert.ok(!hostMatches(['example.test'], 'notexample.test'));
  assert.ok(hostMatches(['203.0.113.9'], '203.0.113.9'));
  assert.ok(!hostMatches(['203.0.113.9'], '203.0.113.90'));
  assert.ok(!hostMatches(['example.test'], ''));
  assert.ok(!hostMatches(null, 'x'));
});

test('paths: writeGroup and decoyDirs', () => {
  assert.equal(writeGroup('/home/dev/.npm/x/y'), '~/.npm');
  assert.equal(writeGroup('/seed/home/.npm/x'), '~/.npm');
  assert.equal(writeGroup('/opt/a/b'), '/opt');
  assert.equal(writeGroup('/x'), '/');
  const dirs = decoyDirs(DECOYS);
  assert.ok(dirs.has('/home/dev/.aws'));
  assert.ok(dirs.has('/seed/home/.aws'));
  assert.ok(!dirs.has('/home/dev'), 'HOME itself is never a decoy dir');
  assert.ok(dirs.has('/home/dev/.config/Exodus/exodus.wallet'));
});

// --- report ----------------------------------------------------------------------------------

function sampleReportArgs(overrides = {}) {
  const c = CASES.find((x) => x.name === 'canary_http_body');
  const { findings, verdict, classifications } = evaluate(c.input);
  return {
    run: { run_id: '7K2Q4W5E6R7T8Y9U0I1O2P3A4S', created_at: '2026-11-04T05:12:33.120Z', input: { command: 'curl x | bash', claim: 'installs acme', sample_id: 'canary' } },
    layers: [],
    contract: c.input.contract,
    contractMeta: { source: 'fallback', prompt_version: 't' },
    events: c.input.events,
    findings,
    verdict,
    explanation: renderTemplateExplanation(buildExplanationInput({ input: { claim: 'installs acme' }, verdict, findings, layers: [], contract: c.input.contract, events: c.input.events, decoys: c.input.decoys })),
    explanationMeta: { source: 'template' },
    decoys: c.input.decoys,
    coverage: { mode: 'trace', gvisor_dropped: 0, capped: {} },
    output: { stdout_preview: 'hi', stderr_preview: '', stdout_bytes: 2, stderr_bytes: 0, truncated: false },
    timing: { total_ms: 1 },
    modelsUsed: [],
    classifications,
    ...overrides,
  };
}

test('report: 10.3 shape, classifications applied, events sorted by (t_rel_ms, seq)', () => {
  const r = buildReport(sampleReportArgs());
  assert.equal(r.schema_version, 1);
  for (const k of ['run_id', 'created_at', 'input', 'layers', 'contract', 'contract_meta', 'events', 'findings', 'verdict', 'explanation', 'explanation_meta', 'decoys', 'coverage', 'output', 'timing', 'models_used']) {
    assert.ok(k in r, k);
  }
  assert.equal(r.input.sample_id, 'canary');
  const open = r.events.find((e) => e.kind === 'file.open');
  assert.equal(open.classification, 'forbidden');
  const hit = r.events.find((e) => e.kind === 'canary.hit');
  assert.equal(hit.classification, 'forbidden');
  for (let i = 1; i < r.events.length; i++) assert.ok(r.events[i - 1].t_rel_ms <= r.events[i].t_rel_ms);
  assert.equal(r.coverage.mode, 'trace');
  assert.deepEqual(r.coverage.tls_unreadable, []);
  assert.equal(r.coverage.report_trimmed, undefined);
  assert.ok(utf8Bytes(r) < REPORT_LIMITS.reportMaxBytes);
});

test('report: per-field caps (layer text 64 KiB, previews 32 KiB, explanation 4 KiB)', () => {
  const big = 'é'.repeat(100_000);
  const r = buildReport(
    sampleReportArgs({
      layers: [{ index: 1, parent: 0, method: 'base64', bytes_len: 1, text: big, truncated: false, markers: { exec: [], remote: [], decode: [], opaque: 0 }, llm_assisted: false, status: 'ok' }],
      output: { stdout_preview: big, stderr_preview: 'x', stdout_bytes: 200_000, stderr_bytes: 1, truncated: false },
      explanation: { verdict_echo: 'MALICIOUS', headline: 'h', paragraphs: ['p'.repeat(600), 'q'.repeat(600), 'r'.repeat(600)], finding_notes: Array.from({ length: 20 }, (_, i) => ({ finding_id: `f${i}`, text: 't'.repeat(200) })), next_step: 'n' },
    }),
  );
  assert.ok(Buffer.byteLength(r.layers[0].text, 'utf8') <= REPORT_LIMITS.layerTextMaxBytes);
  assert.equal(r.layers[0].truncated, true);
  assert.ok(!r.layers[0].text.includes('�'), 'no split character');
  assert.ok(Buffer.byteLength(r.output.stdout_preview, 'utf8') <= REPORT_LIMITS.previewMaxBytes);
  assert.equal(r.output.truncated, true);
  assert.ok(utf8Bytes(r.explanation) <= REPORT_LIMITS.explanationMaxBytes);
  assert.equal(r.explanation.verdict_echo, 'MALICIOUS');
});

test('report: whole-report trimming drops unreferenced events first and records it', () => {
  const events = [];
  for (let i = 1; i <= 20_000; i++) {
    events.push({ run_id: 'X', seq: i, ts_ms: i, t_rel_ms: i, source: 'gvisor', kind: 'file.open', pid: 5, path: `/home/dev/proj/${'f'.repeat(200)}${i}`, access: 'create' });
  }
  const { findings, verdict, classifications } = evaluate({ events, contract: {}, decoys: [] });
  const referenced = new Set(findings.flatMap((f) => f.event_seqs));
  const r = buildReport(sampleReportArgs({ events, findings, verdict, classifications, decoys: [], contract: {} }));
  assert.ok(utf8Bytes(r) <= REPORT_LIMITS.reportMaxBytes);
  assert.ok(r.events.length < events.length);
  assert.ok(r.coverage.report_trimmed.events_dropped > 0);
  for (const s of referenced) assert.ok(r.events.some((e) => e.seq === s), `referenced seq ${s} kept`);
  assert.ok(r.coverage.notes.some((n) => n.startsWith('Report was trimmed')));
  assert.deepEqual(r.findings, findings, 'findings and verdict are never trimmed');
  assert.deepEqual(r.verdict, verdict);
});

test('report: deterministic for the same input', () => {
  assert.equal(JSON.stringify(buildReport(sampleReportArgs())), JSON.stringify(buildReport(sampleReportArgs())));
});

test('truncateUtf8 never splits a multi-byte character', () => {
  const s = 'aé漢😀';
  for (let n = 0; n <= Buffer.byteLength(s); n++) {
    const t = truncateUtf8(s, n);
    assert.ok(!t.includes('�'));
    assert.ok(Buffer.byteLength(t) <= n);
    assert.ok(s.startsWith(t));
  }
});

// --- explanation input + template ------------------------------------------------------------

test('explanation input: allowlisted projection never carries decoy values, bodies, argv or stdout', () => {
  const c = CASES.find((x) => x.name === 'canary_http_body');
  const value = c.input.decoys.find((d) => d.id === 'aws_secret').value;
  const events = c.input.events.map((e) =>
    e.kind === 'http.request' ? { ...e, body_ref: 'bodies/r2.bin', headers: { 'x-token': value }, body_b64: Buffer.from(value).toString('base64') } : e,
  );
  events.push({ run_id: 'X', seq: 99, ts_ms: 1, t_rel_ms: 1, source: 'gvisor', kind: 'proc.exec', pid: 1, ppid: 1, exe: '/usr/bin/curl', argv: ['curl', '-d', value] });
  events.push({ run_id: 'X', seq: 100, ts_ms: 1, t_rel_ms: 1, source: 'gvisor', kind: 'shim.call', tool: 'open', args: [value] });
  const { findings, verdict } = evaluate({ ...c.input, events });
  const input = buildExplanationInput({ input: { claim: 'installs acme', command: value }, verdict, findings, layers: [{ index: 1, method: 'base64', llm_assisted: false, text: 'x'.repeat(5000) }], contract: c.input.contract, events, decoys: c.input.decoys, stdout: value });
  const json = JSON.stringify(input);
  for (const d of c.input.decoys) {
    if (!d.value) continue;
    assert.ok(!json.includes(d.value), d.id);
    assert.ok(!json.includes(Buffer.from(d.value).toString('base64')), `${d.id} base64`);
    assert.ok(!json.includes(Buffer.from(d.value).toString('hex')), `${d.id} hex`);
  }
  assert.ok(!json.includes('body_b64') && !json.includes('headers') && !json.includes('argv') && !json.includes('"args"'));
  assert.deepEqual(Object.keys(input).sort(), ['claim', 'contract', 'coverage_notes', 'findings', 'layers', 'verdict']);
  assert.equal(input.layers[0].preview.length, 300);
  const hit = input.findings.find((f) => f.rule_id === 'exfil.canary_outbound');
  assert.equal(hit.evidence_summary, 'canary from ~/.aws/credentials seen base64-encoded in the body of an HTTP request to host collector.test (POST); POST to collector.test with 612 bytes');
  for (const f of input.findings) assert.ok([...f.evidence_summary].length <= 200);
  assert.deepEqual(Object.keys(input.findings[0]).sort(), ['classification', 'evidence_summary', 'id', 'rule_id', 'severity', 'title']);
});

test('template: each level renders a valid Explanation with the fixed headline and next_step', () => {
  for (const name of ['clean_echo', 'installer_unexplained_rc', 'canary_http_body', 'no_activity', 'print_only']) {
    const c = CASES.find((x) => x.name === name);
    const { findings, verdict } = evaluate(c.input);
    const input = buildExplanationInput({ input: { claim: 'installs nvm' }, verdict, findings, layers: [], contract: c.input.contract, events: c.input.events, decoys: c.input.decoys });
    const e = renderTemplateExplanation(input);
    Explanation.parse(e);
    assert.equal(e.verdict_echo, verdict.level);
    assert.equal(e.next_step, NEXT_STEP[verdict.level]);
    assert.equal(e.paragraphs.length, 3);
    assert.ok(e.paragraphs[0].includes('"installs nvm"'));
    assert.ok(e.paragraphs[2].startsWith(`Keep in mind: ${verdict.coverage_notes[0]}`));
    assert.ok(!JSON.stringify(e).match(/https?:\/\//i));
    for (const n of e.finding_notes) assert.ok(findings.some((f) => f.id === n.finding_id));
    if (verdict.level === 'CLEAN') assert.equal(e.headline, 'Nothing beyond the claim was observed in this run');
    if (verdict.level === 'SUSPICIOUS') assert.match(e.headline, /^\d+ things? the claim does not explain$/);
    if (verdict.level === 'MALICIOUS') assert.equal(e.headline, findings.find((f) => f.severity === 'critical').title);
  }
});

test('template: CLEAN text never claims the command is safe; every rule has a plain-English note', () => {
  const c = CASES.find((x) => x.name === 'clean_echo');
  const { findings, verdict } = evaluate(c.input);
  const e = renderTemplateExplanation(buildExplanationInput({ input: { claim: 'prints hello' }, verdict, findings, layers: [], contract: c.input.contract }));
  // The mandatory note says "not proof that the command is safe"; nothing else may say "safe".
  const text = JSON.stringify(e).toLowerCase().split('not proof that the command is safe').join('');
  assert.ok(!/\bsafe\b/.test(text) && !/\bharmless\b/.test(text) && !/\bnothing to worry\b/.test(text), text);
  assert.ok(e.paragraphs[1].startsWith('In the sandbox nothing suspicious was seen'));
  for (const r of RULE_IDS) {
    assert.ok(typeof RULE_NOTES[r] === 'string' && RULE_NOTES[r].length > 0 && RULE_NOTES[r].length <= 200, r);
    assert.ok(!/canary|sinkhole|exfil|gvisor|decoy/i.test(RULE_NOTES[r]), `${r}: jargon in note`);
  }
});

test('template: tolerates an empty or malformed input and still fails safe', () => {
  const e = renderTemplateExplanation({});
  Explanation.parse(e);
  assert.equal(e.verdict_echo, 'SUSPICIOUS');
  const e2 = renderTemplateExplanation({ verdict: { level: 'MALICIOUS' }, findings: [{ id: 'x', rule_id: 'exfil.canary_outbound', severity: 'critical', title: 'T'.repeat(500), evidence_summary: 'see https://evil.test/x' }], coverage_notes: ['n'.repeat(900)] });
  Explanation.parse(e2);
  assert.equal(e2.headline.length, 120);
  assert.ok(!e2.paragraphs[1].includes('https://'));
});
