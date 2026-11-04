import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RUN_ID_RE, isRunId, newRunId } from '../run/ids.mjs';

test('newRunId: 26 characters of [0-9A-Z], unique', () => {
  const ids = Array.from({ length: 5000 }, newRunId);
  for (const id of ids) {
    assert.equal(id.length, 26);
    assert.match(id, RUN_ID_RE);
    assert.match(id, /^[0-9A-HJKMNP-TV-Z]+$/, 'Crockford alphabet: no I, L, O, U');
  }
  assert.equal(new Set(ids).size, ids.length);
});

test('newRunId: carries 128 random bits (25 full characters + 3 bits)', () => {
  const ids = Array.from({ length: 5000 }, newRunId);
  const firstChars = new Set(ids.map((id) => id[0]));
  const lastChars = new Set(ids.map((id) => id[25]));
  assert.equal(firstChars.size, 32, 'first character uses all 32 symbols');
  assert.ok(lastChars.size <= 8, 'last character holds only the 3 leftover bits');
});

test('isRunId: rejects anything but ^[0-9A-Z]{26}$', () => {
  assert.equal(isRunId(newRunId()), true);
  assert.equal(isRunId('7K2Q4W5E6R7T8Y9U0I1O2P3A4S'), true, 'example id from the docs');
  for (const bad of [
    '',
    '7k2q4w5e6r7t8y9u0i1o2p3a4s',
    '7K2Q4W5E6R7T8Y9U0I1O2P3A4',
    '7K2Q4W5E6R7T8Y9U0I1O2P3A4SX',
    '7K2Q4W5E6R7T8Y9U0I1O2P3A4-',
    '../../../../etc/passwd/AAA',
    '7K2Q4W5E6R7T8Y9U0I1O2P3A4S\n',
    null,
    undefined,
    42,
  ]) {
    assert.equal(isRunId(bad), false, JSON.stringify(bad));
  }
});
