// web/ui.js: text from a run must read the way it is. Only the parts that need no browser.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { describeEvent, showControls } from '../../web/ui.js';

test('direction controls are written out instead of obeyed', () => {
  assert.equal(showControls('curl ‮tset.live'), 'curl [U+202E]tset.live');
  for (const c of ['؜', '‎', '‏', '‪', '‫', '‬', '‭', '⁦', '⁧', '⁨', '⁩']) {
    assert.match(showControls(`a${c}b`), /^a\[U\+[0-9A-F]{4}\]b$/);
  }
});

test('ordinary text, right-to-left letters included, is left alone', () => {
  for (const s of ['curl https://x.test/k', 'مرحبا', 'שלום', 'naïve', '日本語', 'a\nb\tc']) assert.equal(showControls(s), s);
  assert.equal(showControls(42), '42');
});

test('event descriptions cannot carry a direction control', () => {
  const d = describeEvent({ kind: 'dns.query', name: 'a‮b.test', qtype: 'A' });
  assert.equal(d.text, 'Looked up a[U+202E]b.test');
});
