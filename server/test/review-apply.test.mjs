// The AI reviewer ratchet (review/apply.mjs): only ever raises, never past SUSPICIOUS, and keeps
// the coverage notes consistent with the level it produces.
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { NOTE_CLEAN_MEANS, NOTE_LIMITS, NOTE_SINKHOLED } from '../rules/engine.mjs';
import { LEVELS, NOTE_REVIEW_NOTED, NOTE_REVIEW_RAISED, REVIEW_FINDING_ID, REVIEW_RULE_ID, applyReview } from '../review/apply.mjs';

const RANK = Object.fromEntries(LEVELS.map((l, i) => [l, i]));
const RAISING = { risk: 'high', summary: 'adds a cron job the claim does not mention', reasons: ['crontab line'] };

const REVIEWS = {
  null: null,
  malformed: 'not an object',
  'risk none': { risk: 'none', summary: 'fine', reasons: ['looks like the claim'] },
  'no reasons': { risk: 'high', summary: 'bad', reasons: [] },
  'high with reasons': RAISING,
};

function verdictAt(level) {
  return { level, rule_ids: [], coverage_notes: [level === 'CLEAN' ? NOTE_CLEAN_MEANS : NOTE_LIMITS, NOTE_SINKHOLED] };
}

describe('applyReview', () => {
  test('raising CLEAN replaces the CLEAN-only coverage note with the neutral one', () => {
    const verdict = verdictAt('CLEAN');
    const before = structuredClone(verdict);
    const out = applyReview({ verdict, findings: [], review: RAISING });
    assert.equal(out.raised, true);
    assert.equal(out.applied, true);
    assert.equal(out.verdict.level, 'SUSPICIOUS');
    assert.deepEqual(out.verdict.coverage_notes, [NOTE_LIMITS, NOTE_SINKHOLED, NOTE_REVIEW_RAISED]);
    assert.equal(out.verdict.coverage_notes.includes(NOTE_CLEAN_MEANS), false);
    assert.deepEqual(out.verdict.rule_ids, [REVIEW_RULE_ID]);
    assert.equal(out.findings.length, 1);
    assert.equal(out.findings[0].id, REVIEW_FINDING_ID);
    assert.deepEqual(verdict, before, 'input verdict not mutated');
  });

  test('the level never decreases, over every input level and review shape', () => {
    for (const level of LEVELS) {
      for (const [name, review] of Object.entries(REVIEWS)) {
        const verdict = verdictAt(level);
        const findings = [{ id: 'x:0', rule_id: 'x', severity: 'high', title: 'T', event_seqs: [1] }];
        const out = applyReview({ verdict, findings, review });
        const label = `${level} / ${name}`;
        assert.ok(RANK[out.verdict.level] >= RANK[level], label);
        assert.equal(out.verdict.level === 'MALICIOUS', level === 'MALICIOUS', `${label}: never MALICIOUS unless the input was`);
        assert.equal(verdict.level, level, `${label}: input not mutated`);
        assert.equal(findings.length, 1, `${label}: input findings not mutated`);
        if (name !== 'high with reasons') {
          assert.equal(out.applied, false, label);
          assert.equal(out.verdict, verdict, `${label}: a non-raising review changes nothing`);
        }
      }
    }
  });

  test('MALICIOUS stays MALICIOUS; the note added is the "noted" one and no note is swapped', () => {
    const out = applyReview({ verdict: verdictAt('MALICIOUS'), findings: [], review: RAISING });
    assert.equal(out.verdict.level, 'MALICIOUS');
    assert.equal(out.raised, false);
    assert.equal(out.applied, true);
    assert.deepEqual(out.verdict.coverage_notes, [NOTE_LIMITS, NOTE_SINKHOLED, NOTE_REVIEW_NOTED]);
  });

  test('SUSPICIOUS stays SUSPICIOUS with the finding added after the deciding ones', () => {
    const findings = [
      { id: 'a:0', rule_id: 'a', severity: 'high', title: 'A', event_seqs: [1] },
      { id: 'b:0', rule_id: 'b', severity: 'low', title: 'B', event_seqs: [2] },
    ];
    const out = applyReview({ verdict: verdictAt('SUSPICIOUS'), findings, review: RAISING });
    assert.equal(out.verdict.level, 'SUSPICIOUS');
    assert.equal(out.raised, false);
    assert.equal(out.applied, true);
    assert.deepEqual(out.findings.map((f) => f.id), ['a:0', REVIEW_FINDING_ID, 'b:0']);
    assert.equal(out.findings[1].observed, false);
    assert.deepEqual(out.verdict.coverage_notes, [NOTE_LIMITS, NOTE_SINKHOLED, NOTE_REVIEW_NOTED]);
    assert.deepEqual(findings.map((f) => f.id), ['a:0', 'b:0'], 'input findings not mutated');
  });

  test('a stray CLEAN note on a non-CLEAN input is left alone (nothing was raised)', () => {
    const verdict = { level: 'SUSPICIOUS', rule_ids: [], coverage_notes: [NOTE_CLEAN_MEANS] };
    const out = applyReview({ verdict, findings: [], review: RAISING });
    assert.deepEqual(out.verdict.coverage_notes, [NOTE_CLEAN_MEANS, NOTE_REVIEW_NOTED]);
  });
});
