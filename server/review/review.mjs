// The AI reviewer (docs/ARCHITECTURE.md 8.7). One LLM call after the first run. It answers two
// questions: what would this do on a real computer, and did it stop before showing that because of
// something in the sandbox. Both answers are distrusted: quotes are checked against the code, and
// the only things they can cause are a raise (review/apply.mjs) and one more sandbox run under
// settings from a fixed menu (review/knobs.mjs). Neither can lower a verdict.
import { readFileSync } from 'node:fs';
import { LIMITS } from '../config.mjs';
import { LlmError, UNTRUSTED_PREAMBLE, createDelimiter } from '../llm/client.mjs';
import { Review } from '../llm/schemas.mjs';
import { buildReviewInput, makeScrubber } from './input.mjs';
import { knobsChangeAnything, resolveKnobs } from './knobs.mjs';

const SYSTEM_PROMPT = readFileSync(new URL('../llm/prompts/review.md', import.meta.url), 'utf8');
const MIN_QUOTE_CHARS = 3;

const squeeze = (s) => String(s ?? '').replace(/\s+/g, ' ').trim();

/** Full-line comments are written by the command's author and never count as code that runs. */
export function stripCommentLines(text) {
  return String(text ?? '')
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('#'))
    .join('\n');
}

/** The texts a quote may come from: the command and decoded layers, without comment lines. */
function codeTexts(reviewInput) {
  const layers = Array.isArray(reviewInput?.layers) ? reviewInput.layers.map((l) => l?.text) : [];
  return [reviewInput?.command, ...layers].filter((t) => typeof t === 'string').map((t) => comparable(stripCommentLines(t)));
}

/** Models drop or escape quote characters when copying shell code into JSON; compare without them. */
const comparable = (s) => squeeze(String(s ?? '').replace(/["'`\\]/g, ''));

function quoteFound(quote, texts) {
  const q = comparable(quote);
  return q.length >= MIN_QUOTE_CHARS && texts.some((t) => t.includes(q));
}

/**
 * Host-side checks on a schema-valid answer. Reasons without a real quote are dropped, a risk with
 * no reason left becomes "none", and a retry needs a setting that changes anything.
 * @returns {{review: object, retry: object|null, dropped: number}}
 */
export function verifyReview(data, reviewInput, { decoys = [] } = {}) {
  const scrub = makeScrubber(decoys);
  const texts = codeTexts(reviewInput);
  const clean = (s) => squeeze(scrub(s));
  const reasons = [];
  let dropped = 0;
  for (const r of data.reasons ?? []) {
    if (quoteFound(r.quote, texts)) reasons.push({ what: clean(r.what), why: clean(r.why), quote: clean(r.quote) });
    else dropped += 1;
  }
  const risk = data.risk !== 'none' && reasons.length > 0 ? data.risk : 'none';
  const review = {
    risk,
    summary: clean(data.summary),
    real_machine_effects: risk === 'none' ? [] : (data.real_machine_effects ?? []).map(clean).filter(Boolean),
    reasons: risk === 'none' ? [] : reasons,
  };
  // A second run is safe whatever the model's reason: the settings come from fixed menus, the host owns
  // the values, and only what is then observed counts. The quote therefore does not decide whether it
  // happens (this model often garbles a line full of quote marks while choosing the right setting). It
  // only decides whether the model's words are shown: no real quote, no model text on the page.
  let retry = null;
  const asked = data.retry;
  if (asked?.needed === true) {
    const knobs = resolveKnobs(asked, decoys);
    const grounded = quoteFound(asked.quote, texts);
    if (knobsChangeAnything(knobs)) retry = { why: grounded ? clean(asked.why) : '', quote: grounded ? clean(asked.quote) : '', knobs };
  }
  return { review, retry, dropped };
}

function buildUser(reviewInput) {
  const d = createDelimiter();
  const parts = [UNTRUSTED_PREAMBLE, d.field('CLAIM', reviewInput.claim), d.field('COMMAND', reviewInput.command)];
  for (const layer of reviewInput.layers) parts.push(d.field(`LAYER_${layer.index}`, layer.text));
  parts.push(d.field('RECORDED_IN_THE_SANDBOX', JSON.stringify(reviewInput.recorded)));
  if (reviewInput.truncation.length) parts.push(`NOT_SHOWN: ${reviewInput.truncation.join('; ')}`);
  return parts.join('\n\n');
}

/**
 * Never throws: a failed call means the rules verdict stands and meta.source says why.
 * @param {ReturnType<import('../llm/client.mjs').createLlm>} llm
 * @param {{input: object, layers?: object[], events?: object[], exec?: object, decoys?: object[], sinkIp?: string|null}} args
 * @param {{signal?: AbortSignal, onRaw?: Function, waitMs?: number}} [opts]
 * @returns {Promise<{review: object|null, retry: object|null, meta: object}>} meta.source: llm | failed
 */
export async function reviewRun(llm, args, { signal, onRaw, waitMs = LIMITS.llm.reviewWaitMs } = {}) {
  const started = performance.now();
  const promptVersion = llm?.config?.prompt_version ?? null;
  const ms = () => Math.round(performance.now() - started);
  const reviewInput = buildReviewInput(args);
  let answer;
  try {
    answer = await llm.callJson('review', { system: SYSTEM_PROMPT, user: buildUser(reviewInput) }, Review, {
      signal,
      onRaw,
      deadline: performance.now() + waitMs,
    });
  } catch (err) {
    return { review: null, retry: null, meta: { source: 'failed', prompt_version: promptVersion, reason: err instanceof LlmError ? err.code : 'internal', ms: ms() } };
  }
  const { review, retry, dropped } = verifyReview(answer.data, reviewInput, { decoys: args.decoys });
  return {
    review,
    retry,
    meta: {
      source: 'llm',
      prompt_version: promptVersion,
      model: answer.meta.model,
      attempts: answer.meta.attempts,
      repairs: answer.meta.repairs,
      fallback_model_used: answer.meta.fallback_model_used,
      dropped_reasons: dropped,
      ms: ms(),
    },
  };
}
