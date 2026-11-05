// The one-way ratchet for the AI reviewer (docs/ARCHITECTURE.md 8.7). Pure: no I/O, no clock.
//
// The reviewer reads attacker-controlled text, so its answer can only ever *raise* a verdict,
// never lower one, and it can never produce MALICIOUS: that level is reserved for proof from the
// sandbox (critical findings, section 9.3). A fooled model therefore causes at most a false alarm
// (SUSPICIOUS) or a miss, and a miss is exactly what the rules alone give today.
import { REVIEW_RISKS } from '../llm/schemas.mjs';
import { NOTE_CLEAN_MEANS, NOTE_LIMITS } from '../rules/engine.mjs';

export const LEVELS = Object.freeze(['CLEAN', 'SUSPICIOUS', 'MALICIOUS']);
const RANK = Object.freeze(Object.fromEntries(LEVELS.map((l, i) => [l, i])));
const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });

/** The highest level the reviewer can reach on its own. */
export const REVIEW_CEILING = 'SUSPICIOUS';
export const REVIEW_RULE_ID = 'ai.review';
export const REVIEW_FINDING_ID = 'ai.review:0';
export const REVIEW_SEVERITY = 'medium';
const TITLE_PREFIX = 'AI reviewer, reading the code (not observed in the sandbox): ';
const TITLE_MAX = 300;

export const NOTE_REVIEW_RAISED =
  'The AI reviewer read the code and raised the verdict; that part comes from reading the command, not from anything observed in the sandbox.';
export const NOTE_REVIEW_NOTED =
  'The AI reviewer read the code and added a concern; that part comes from reading the command, not from anything observed in the sandbox.';

/** True when a (verified) review asks for a raise: a risk above none backed by at least one reason. */
export function reviewRaises(review) {
  if (!review || typeof review !== 'object') return false;
  if (!REVIEW_RISKS.includes(review.risk) || review.risk === 'none') return false;
  return Array.isArray(review.reasons) && review.reasons.length > 0;
}

function cut(text, max) {
  const chars = [...String(text ?? '')];
  return chars.length > max ? chars.slice(0, max - 1).join('') + '…' : chars.join('');
}

/** The single finding a verified raise adds (9.2 shape plus explicit provenance fields). */
export function reviewFinding(review) {
  const summary = String(review?.summary ?? '').replace(/\s+/g, ' ').trim() || 'the command would do more than the claim says';
  return {
    id: REVIEW_FINDING_ID,
    rule_id: REVIEW_RULE_ID,
    severity: REVIEW_SEVERITY,
    classification: 'unexplained',
    title: cut(TITLE_PREFIX + summary, TITLE_MAX),
    event_seqs: [],
    // Provenance: this finding was not observed; it is the AI's reading of the code.
    source: 'ai_review',
    observed: false,
  };
}

/**
 * Apply the ratchet. Returns new objects; the inputs are not mutated.
 *
 * Guarantees, for any input whatsoever:
 *   - `verdict.level` never decreases, and never exceeds the input level unless the input level
 *     was below REVIEW_CEILING (so the output is never MALICIOUS unless the input was);
 *   - a level that is not one of LEVELS is passed through untouched;
 *   - a review that does not raise (null, risk none, no reasons, malformed) changes nothing.
 *
 * @param {{verdict: object, findings?: object[], review?: object|null}} args
 * @returns {{verdict: object, findings: object[], raised: boolean, applied: boolean}}
 *   raised = the level went up; applied = the `ai.review` finding was added (also when the level
 *   was already at or above the ceiling, so the reader still sees the reason).
 */
export function applyReview({ verdict, findings, review }) {
  const v = verdict && typeof verdict === 'object' ? verdict : {};
  const list = Array.isArray(findings) ? findings.slice() : [];
  const unchanged = { verdict: v, findings: list, raised: false, applied: false };
  if (!LEVELS.includes(v.level)) return unchanged;
  if (!reviewRaises(review)) return unchanged;
  if (list.some((f) => f && f.rule_id === REVIEW_RULE_ID)) return unchanged; // idempotent

  const level = RANK[v.level] >= RANK[REVIEW_CEILING] ? v.level : REVIEW_CEILING;
  const raised = level !== v.level;
  const finding = reviewFinding(review);
  // Findings are ordered severity desc; the review finding goes after the last deciding one.
  let at = list.findIndex((f) => (SEVERITY_RANK[f?.severity] ?? 0) < SEVERITY_RANK[REVIEW_SEVERITY]);
  if (at === -1) at = list.length;
  list.splice(at, 0, finding);
  const ruleIds = [...new Set([...(Array.isArray(v.rule_ids) ? v.rule_ids : []), REVIEW_RULE_ID])].sort();
  // "CLEAN means ..." (engine.mjs buildCoverageNotes) only fits under a CLEAN banner: once the
  // level rises it becomes the neutral limit note, as the engine itself writes for non-CLEAN.
  const notes = (Array.isArray(v.coverage_notes) ? v.coverage_notes : []).map((n) => (raised && n === NOTE_CLEAN_MEANS ? NOTE_LIMITS : n));
  notes.push(raised ? NOTE_REVIEW_RAISED : NOTE_REVIEW_NOTED);
  return {
    verdict: { ...v, level, rule_ids: ruleIds, coverage_notes: notes },
    findings: list,
    raised,
    applied: true,
  };
}
