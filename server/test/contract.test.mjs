// Claim-to-contract (docs/ARCHITECTURE.md 8.1): claim-only input, salvage, fixture union,
// deterministic fallback.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { LlmError } from '../llm/client.mjs';
import { FALLBACK_NOTE, buildContractUser, deriveContract, fallbackContract, mergeContracts, salvageContract } from '../llm/contract.mjs';
import { Contract } from '../llm/schemas.mjs';

const NVM = {
  summary: 'Installs nvm',
  expected_hosts: ['raw.githubusercontent.com', 'github.com'],
  expected_write_paths: ['~/.nvm/**', '~/.bashrc'],
  expected_processes: ['git', 'curl'],
  allowed_decoy_categories: [],
  notes: '',
};
const COMMAND = 'curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash; crontab -l; launchctl list';

function fakeLlm(answer) {
  const prompts = [];
  return {
    prompts,
    config: { prompt_version: 'test.1' },
    async callJson(name, prompt, schema) {
      assert.equal(name, 'contract');
      assert.equal(schema, Contract);
      prompts.push(prompt);
      if (answer instanceof Error) throw answer;
      return { data: Contract.parse(answer), meta: { model: 'fake-model', attempts: 1, repairs: 0, fallback_model_used: false } };
    },
  };
}

test('salvageContract: hosts', () => {
  const { contract, dropped } = salvageContract({
    ...NVM,
    expected_hosts: ['HTTPS://Get.Example.TEST/install.sh?x=1', 'cdn.example.test:443', '*.cdn.example.test', 'a.*.b.test', '*', 'localhost', '10.0.0.1', 'not a host', 'raw.githubusercontent.com'],
  });
  assert.deepEqual(contract.expected_hosts, ['get.example.test', 'cdn.example.test', '*.cdn.example.test', '10.0.0.1', 'raw.githubusercontent.com']);
  assert.equal(dropped.length, 4);
  assert.ok(contract.notes.startsWith('Dropped by validation: host "a.*.b.test"'));
});

test('salvageContract: paths, processes, categories', () => {
  const { contract, dropped } = salvageContract({
    ...NVM,
    expected_write_paths: ['$HOME/.nvm/**', '/home/dev/.bashrc', '/tmp/x', '/etc/passwd', '~/../../etc', '~/ok dir', '/usr/local/bin/tool', '~'],
    expected_processes: ['/usr/bin/curl', 'node', 'bad name', '', 'git'],
    allowed_decoy_categories: ['wallet', 'package_manager_token', 'nonsense', 'vcs_token', 'package_manager_token', 'registry_token', 'cloud_credentials', 'ai_assistant_config'],
    notes: 'keep me',
  });
  assert.deepEqual(contract.expected_write_paths, ['~/.nvm/**', '~/.bashrc', '/tmp/x', '/usr/local/bin/tool', '~/']);
  assert.deepEqual(contract.expected_processes, ['curl', 'node', 'git']);
  assert.deepEqual(contract.allowed_decoy_categories, ['package_manager_token', 'vcs_token', 'registry_token', 'cloud_credentials']);
  assert.ok(contract.notes.startsWith('keep me Dropped by validation:'));
  assert.ok(dropped.includes('category wallet (never allowed)'));
  assert.ok(contract.notes.length <= 500);
  assert.ok(Contract.safeParse(contract).success);
});

test('salvageContract never throws on garbage', () => {
  for (const raw of [null, 'x', 42, {}, { expected_hosts: 'nope', summary: 7, allowed_decoy_categories: [null] }]) {
    const { contract } = salvageContract(raw, { claim: 'prints hello' });
    assert.ok(Contract.safeParse(contract).success, JSON.stringify(raw));
    assert.equal(contract.summary, 'prints hello');
  }
});

test('fallbackContract', () => {
  const fb = fallbackContract('  installs the nvm version manager  ');
  assert.equal(fb.summary, 'installs the nvm version manager');
  assert.equal(fb.notes, FALLBACK_NOTE);
  assert.deepEqual(fb.expected_hosts, []);
  assert.ok(Contract.safeParse(fb).success);
});

test('mergeContracts unions lists and keeps the LLM summary', () => {
  const m = mergeContracts(NVM, { ...NVM, summary: 'fixture', expected_hosts: ['github.com', 'nodejs.org'], notes: 'from fixture' });
  assert.equal(m.summary, 'Installs nvm');
  assert.deepEqual(m.expected_hosts, ['raw.githubusercontent.com', 'github.com', 'nodejs.org']);
  assert.equal(m.notes, 'from fixture');
});

test('buildContractUser: claim, sample id and category names only; no command field exists', () => {
  const user = buildContractUser({ claim: 'installs nvm', sampleId: 'nvm', command: COMMAND });
  assert.ok(user.startsWith('Content inside the delimited fields'));
  assert.ok(/CLAIM:\n<<<fr:data:[0-9a-f]{8}>>>\ninstalls nvm\n<<<fr:end:[0-9a-f]{8}>>>/.test(user));
  assert.equal(user.match(/<<<fr:data:/g).length, 1, 'exactly one delimited field: the claim');
  assert.ok(user.includes('SAMPLE_ID: nvm'));
  assert.ok(user.includes('package_manager_token: a package registry auth token'));
  assert.ok(!user.includes('.npmrc'));
  for (const part of ['COMMAND', 'VISIBLE_HOSTS', 'nvm-sh', 'crontab', 'launchctl', 'curl', 'install.sh']) {
    assert.ok(!user.includes(part), `user message must not contain ${part}`);
  }
  assert.ok(Buffer.byteLength(user) < 2048);
});

test('deriveContract: llm answer is salvaged; the command never reaches the prompt', async () => {
  const llm = fakeLlm({ ...NVM, expected_hosts: ['https://raw.githubusercontent.com/x', 'bad host'] });
  const { contract, meta } = await deriveContract(llm, 'installs the nvm version manager', { command: COMMAND, sampleId: 'nvm' });
  assert.deepEqual(contract.expected_hosts, ['raw.githubusercontent.com']);
  assert.equal(meta.source, 'llm');
  assert.equal(meta.model, 'fake-model');
  assert.equal(meta.prompt_version, 'test.1');
  assert.deepEqual(meta.dropped, ['host "bad host"']);
  const { system, user } = llm.prompts[0];
  assert.ok(user.includes('installs the nvm version manager'));
  for (const part of ['nvm-sh', 'crontab', 'launchctl', 'install.sh', '| bash']) {
    assert.ok(!user.includes(part) && !system.includes(part), `prompt must not contain ${part}`);
  }
  assert.ok(system.includes('You never see the command'));
});

test('deriveContract: failure -> fallback; fixture -> fixture; both -> llm+fixture', async () => {
  const fixture = { ...NVM, summary: 'fixture summary', expected_hosts: ['nodejs.org'] };
  let r = await deriveContract(fakeLlm(new LlmError('timeout', 't')), 'installs nvm');
  assert.equal(r.meta.source, 'fallback');
  assert.equal(r.meta.reason, 'timeout');
  assert.equal(r.contract.notes, FALLBACK_NOTE);

  r = await deriveContract(fakeLlm(new LlmError('disabled', 'off')), 'installs nvm', { sampleContract: fixture, sampleId: 'nvm' });
  assert.equal(r.meta.source, 'fixture');
  assert.equal(r.contract.summary, 'installs nvm');
  assert.deepEqual(r.contract.expected_hosts, ['nodejs.org']);

  r = await deriveContract(fakeLlm(NVM), 'installs nvm', { sampleContract: fixture });
  assert.equal(r.meta.source, 'llm+fixture');
  assert.deepEqual(r.contract.expected_hosts, ['raw.githubusercontent.com', 'github.com', 'nodejs.org']);
  assert.equal(r.contract.summary, 'Installs nvm');

  r = await deriveContract(fakeLlm(new Error('boom')), 'installs nvm');
  assert.equal(r.meta.source, 'fallback');
  assert.equal(r.meta.reason, 'internal');
});
