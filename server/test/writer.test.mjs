// Explanation writer (docs/ARCHITECTURE.md 8.4): post-validation and the template fallback.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canaryPatterns, minimalTemplateExplanation, validateExplanation, writeExplanation } from '../explain/writer.mjs';
import { LlmError } from '../llm/client.mjs';
import { Explanation } from '../llm/schemas.mjs';

const INPUT = {
  claim: 'installs the Acme CLI',
  verdict: { level: 'SUSPICIOUS', rule_ids: ['net.unexpected_host'], coverage_notes: ['Network was sinkholed.'] },
  findings: [
    { id: 'net.unexpected_host:12', rule_id: 'net.unexpected_host', severity: 'medium', classification: 'unexplained', title: 'Contacted collector.test, which the claim does not mention', evidence_summary: 'GET to collector.test' },
  ],
  contract: { summary: 'Installs the Acme CLI from its download host', expected_hosts: ['get.acme.test'], expected_write_paths: [], expected_processes: ['curl'], allowed_decoy_categories: [] },
  layers: [],
  coverage_notes: ['Network was sinkholed.'],
};
const DECOYS = [{ id: 'aws_secret', path: '~/.aws/credentials', category: 'cloud_credentials', value: 'FRQ7K2ABCDEFGHIJKLMNOP23', forms: ['raw', 'b64x3', 'b64b64x3', 'url', 'hex', 'base32'] }];

const good = (extra = {}) => ({
  verdict_echo: 'SUSPICIOUS',
  headline: 'The installer also talked to a server the claim does not mention',
  paragraphs: ['You were told it installs the Acme CLI.', 'It contacted collector.test; see https://collector.test/x for details.'],
  finding_notes: [{ finding_id: 'net.unexpected_host:12', text: 'Unexpected server.' }, { finding_id: 'made.up:1', text: 'nope' }],
  next_step: 'Read the unexplained items before deciding',
  ...extra,
});

function fakeLlm(answer) {
  const prompts = [];
  return {
    prompts,
    config: { prompt_version: 'test.1' },
    async callJson(name, prompt, schema) {
      assert.equal(name, 'explanation');
      assert.equal(schema, Explanation);
      prompts.push(prompt);
      if (answer instanceof Error) throw answer;
      return { data: Explanation.parse(typeof answer === 'function' ? answer() : answer), meta: { model: 'fake-model', attempts: 1, repairs: 0, fallback_model_used: false } };
    },
  };
}

const template = (input) => ({ verdict_echo: input.verdict.level, headline: 'TEMPLATE', paragraphs: ['t'], finding_notes: [], next_step: 't' });

test('llm answer: urls stripped, unknown finding ids dropped, meta names the model', async () => {
  const llm = fakeLlm(good());
  const { explanation, meta } = await writeExplanation(llm, INPUT, { decoys: DECOYS, template });
  assert.equal(meta.source, 'llm');
  assert.equal(meta.model, 'fake-model');
  assert.equal(explanation.verdict_echo, 'SUSPICIOUS');
  assert.ok(!explanation.paragraphs[1].includes('https://') && explanation.paragraphs[1].includes('collector.test/x'));
  assert.deepEqual(explanation.finding_notes.map((n) => n.finding_id), ['net.unexpected_host:12']);
  assert.ok(Explanation.safeParse(explanation).success);
  const { system, user } = llm.prompts[0];
  assert.ok(system.includes('already decided: SUSPICIOUS'));
  assert.ok(user.includes('installs the Acme CLI') && /<<<fr:data:[0-9a-f]{8}>>>/.test(user));
  assert.ok(!user.includes(DECOYS[0].value));
});

test('verdict mismatch, canary echo, empty text -> template with a reason', async () => {
  const cases = [
    [good({ verdict_echo: 'CLEAN' }), 'verdict_mismatch'],
    [good({ paragraphs: [`token ${DECOYS[0].value} leaked`] }), 'canary'],
    [good({ headline: Buffer.from(DECOYS[0].value).toString('base64') }), 'canary'],
    [good({ next_step: Buffer.from(DECOYS[0].value).toString('hex').toUpperCase() }), 'canary'],
    [good({ paragraphs: ['https://'] }), 'empty'],
  ];
  for (const [answer, reason] of cases) {
    const { explanation, meta } = await writeExplanation(fakeLlm(answer), INPUT, { decoys: DECOYS, template });
    assert.equal(meta.source, 'template', reason);
    assert.equal(meta.reason, reason);
    assert.equal(explanation.headline, 'TEMPLATE');
  }
});

test('internal vocabulary and "matched/confirmed/safe" on CLEAN fall back to the template', async () => {
  const cleanInput = { ...INPUT, verdict: { level: 'CLEAN', rule_ids: [], coverage_notes: [] }, findings: [] };
  const clean = (extra) => ({ ...good({ verdict_echo: 'CLEAN', finding_notes: [] }), ...extra });
  // Internal vocabulary is rewritten in place, never rejected; hyphenated quotes are left alone.
  const reworded = await writeExplanation(
    fakeLlm(good({
      headline: 'Hidden layers were decoded by the harness',
      paragraphs: ['The contract for this claim expected nothing else.', 'The network was sinkholed, so the sinkhole saw it print zlib-layer-ok.'],
      finding_notes: [{ finding_id: 'net.unexpected_host:12', text: `The layer printed it. ${'x'.repeat(178)}` }],
    })),
    INPUT,
    { template },
  );
  assert.equal(reworded.meta.source, 'llm');
  assert.equal(reworded.explanation.headline, 'Hidden hidden parts were decoded by the decoder');
  assert.equal(reworded.explanation.paragraphs[0], 'The what you were told for this claim expected nothing else.');
  assert.equal(reworded.explanation.paragraphs[1], 'The network was answered by a fake internet, so the fake internet saw it print zlib-layer-ok.');
  assert.ok(reworded.explanation.finding_notes[0].text.startsWith('The hidden part printed it.'));
  assert.ok([...reworded.explanation.finding_notes[0].text].length <= 200);
  assert.ok(Explanation.safeParse(reworded.explanation).success);
  // Overclaiming on CLEAN is still rejected.
  const cases = [
    [cleanInput, clean({ headline: 'Claim matched: nothing suspicious seen' })],
    [cleanInput, clean({ paragraphs: ['This command is safe.'] })],
    [cleanInput, clean({ next_step: 'Confirmed as described.' })],
  ];
  for (const [input, answer] of cases) {
    const { meta } = await writeExplanation(fakeLlm(answer), input, { template });
    assert.equal(meta.reason, 'wording', JSON.stringify(answer).slice(0, 80));
  }
  // "safe" is only banned for CLEAN; a SUSPICIOUS text may say "not safe".
  const ok = await writeExplanation(fakeLlm(good({ paragraphs: ['Treat it as not safe to run.'] })), INPUT, { template });
  assert.equal(ok.meta.source, 'llm');
  const okClean = await writeExplanation(fakeLlm(clean({ headline: 'Nothing suspicious was seen in this run', paragraphs: ['It only printed a message.'] })), cleanInput, { template });
  assert.equal(okClean.meta.source, 'llm');
  // A negated "safe" is the sentence the reader must hear; it passes on CLEAN.
  const negated = await writeExplanation(
    fakeLlm(clean({ headline: 'Nothing suspicious was seen in this run', paragraphs: ['One short run is not proof that the command is safe. It cannot show it is safe to run.'] })),
    cleanInput,
    { template },
  );
  assert.equal(negated.meta.source, 'llm');
});

test('llm failure or no verdict -> template; default template is the RULES one', async () => {
  let r = await writeExplanation(fakeLlm(new LlmError('disabled', 'off')), INPUT, { template });
  assert.equal(r.meta.source, 'template');
  assert.equal(r.meta.reason, 'disabled');
  r = await writeExplanation(fakeLlm(good()), { ...INPUT, verdict: { level: 'WAT' } }, { template });
  assert.equal(r.meta.reason, 'no_verdict');
  r = await writeExplanation(fakeLlm(new LlmError('timeout', 't')), INPUT);
  assert.equal(r.meta.source, 'template');
  assert.ok(Explanation.safeParse(r.explanation).success);
  assert.equal(r.explanation.verdict_echo, 'SUSPICIOUS');
  assert.ok(r.explanation.headline.includes('the claim does not explain'));
});

test('oversized answers shed finding notes, then fall back', () => {
  const notes = Array.from({ length: 20 }, (_, i) => ({ finding_id: `f${i}`, text: 'x'.repeat(200) }));
  const input = { ...INPUT, findings: notes.map((n) => ({ id: n.finding_id, rule_id: 'r', severity: 'low', title: 't' })) };
  const r = validateExplanation(good({ finding_notes: notes, paragraphs: ['p'] }), input);
  assert.ok(r.explanation && Buffer.byteLength(JSON.stringify(r.explanation)) <= 4096 && r.explanation.finding_notes.length < 20);
  const big = validateExplanation({ ...good(), paragraphs: ['y'.repeat(600), 'y'.repeat(600), 'y'.repeat(600)], headline: 'h'.repeat(120), next_step: 'n'.repeat(200), finding_notes: notes }, input);
  assert.ok(big.explanation.finding_notes.length < 20);
});

test('canaryPatterns covers the manifest forms; short values ignored', () => {
  const p = canaryPatterns(DECOYS);
  const v = DECOYS[0].value;
  assert.ok(p.includes(v.toLowerCase()));
  assert.ok(p.includes(Buffer.from(v).toString('base64').toLowerCase()));
  assert.ok(p.includes(Buffer.from(v).toString('hex')));
  assert.ok(p.includes('iziva2jbqmdeizdgijkuiy2mju2vaucqgiztq'.toLowerCase()) || p.some((x) => /^[a-z2-7]{38,40}$/.test(x)));
  const shifted = Buffer.from(`x${v}`).toString('base64').toLowerCase();
  assert.ok(p.some((x) => x.length >= 20 && shifted.includes(x)), 'base64 at a shifted alignment is still matched');
  assert.deepEqual(canaryPatterns([{ value: 'short' }, { value: 7 }]), []);
});

test('minimal template is schema-valid for every level', () => {
  for (const level of ['CLEAN', 'SUSPICIOUS', 'MALICIOUS']) {
    const e = minimalTemplateExplanation({ ...INPUT, verdict: { level }, findings: level === 'MALICIOUS' ? [{ id: 'x:1', rule_id: 'x', severity: 'critical', title: 'Bad thing' }] : INPUT.findings });
    assert.ok(Explanation.safeParse(e).success, level);
    assert.equal(e.verdict_echo, level);
  }
});
