import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  Contract,
  DECOY_CATEGORIES,
  Explanation,
  Harness,
  NEVER_ALLOWED,
  SCHEMAS,
  toJsonSchema,
} from '../llm/schemas.mjs';

const nvm = {
  summary: 'Installs nvm, the Node version manager, into the home directory',
  expected_hosts: ['raw.githubusercontent.com', 'github.com'],
  expected_write_paths: ['~/.nvm/**', '~/.bashrc'],
  expected_processes: ['git', 'curl', 'wget'],
  allowed_decoy_categories: [],
  notes: '',
};

test('Contract: accepts the few-shot, rejects unknown keys, bad enums and overlong strings', () => {
  assert.ok(Contract.safeParse(nvm).success);
  assert.equal(Contract.safeParse({ ...nvm, verdict: 'CLEAN' }).success, false);
  assert.equal(Contract.safeParse({ ...nvm, allowed_decoy_categories: ['everything'] }).success, false);
  assert.equal(Contract.safeParse({ ...nvm, summary: 'x'.repeat(301) }).success, false);
  assert.equal(Contract.safeParse({ ...nvm, summary: '   ' }).success, false);
  assert.equal(Contract.safeParse({ ...nvm, expected_hosts: Array(33).fill('a.b') }).success, false);
  const { notes, ...missing } = nvm;
  assert.equal(Contract.safeParse(missing).success, false);
});

test('Harness: language and output kind are enums; harness text bounded', () => {
  const ok = { language: 'bash', harness: 'eval() { printf "%s\\n" "$*"; }', replaced: [{ sink: 'eval', with: 'printf' }], expected_output_kind: 'script', notes: '' };
  assert.ok(Harness.safeParse(ok).success);
  assert.equal(Harness.safeParse({ ...ok, language: 'ruby' }).success, false);
  assert.equal(Harness.safeParse({ ...ok, harness: '' }).success, false);
  assert.equal(Harness.safeParse({ ...ok, harness: 'x'.repeat(32769) }).success, false);
  assert.equal(Harness.safeParse({ ...ok, expected_output_kind: 'malware' }).success, false);
  assert.equal(Harness.safeParse({ ...ok, run_it: true }).success, false);
});

test('Explanation: verdict enum, 1-3 paragraphs, strict notes', () => {
  const ok = { verdict_echo: 'CLEAN', headline: 'Fine', paragraphs: ['a'], finding_notes: [], next_step: '' };
  assert.ok(Explanation.safeParse(ok).success);
  assert.equal(Explanation.safeParse({ ...ok, verdict_echo: 'SAFE' }).success, false);
  assert.equal(Explanation.safeParse({ ...ok, paragraphs: [] }).success, false);
  assert.equal(Explanation.safeParse({ ...ok, paragraphs: ['a', 'b', 'c', 'd'] }).success, false);
  assert.equal(Explanation.safeParse({ ...ok, finding_notes: [{ finding_id: 'x', text: 'y', severity: 'low' }] }).success, false);
  assert.equal(Explanation.safeParse({ ...ok, html: '<b>' }).success, false);
});

test('toJsonSchema: strict objects, no $schema, enums preserved', () => {
  for (const [name, schema] of Object.entries(SCHEMAS)) {
    const js = toJsonSchema(schema);
    assert.equal(js.$schema, undefined, name);
    assert.equal(js.type, 'object', name);
    assert.equal(js.additionalProperties, false, name);
    assert.deepEqual(Object.keys(js.properties), js.required, name);
  }
  assert.deepEqual(toJsonSchema(Explanation).properties.verdict_echo.enum, ['CLEAN', 'SUSPICIOUS', 'MALICIOUS']);
});

test('decoy categories: NEVER_ALLOWED is a subset, categories unique', () => {
  assert.equal(new Set(DECOY_CATEGORIES).size, DECOY_CATEGORIES.length);
  for (const c of NEVER_ALLOWED) assert.ok(DECOY_CATEGORIES.includes(c), c);
});
