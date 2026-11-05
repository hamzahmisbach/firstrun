// Explanation writer (docs/ARCHITECTURE.md 8.4). The verdict is already decided; the LLM only
// narrates it from an allowlisted projection (explain/input.mjs). Anything that fails validation,
// disagrees with the verdict, carries a canary value or cannot be produced falls back to the
// deterministic template from explain/template.mjs.
import { readFileSync } from 'node:fs';
import { LlmError, UNTRUSTED_PREAMBLE, createDelimiter } from '../llm/client.mjs';
import { Explanation, VERDICT_LEVELS } from '../llm/schemas.mjs';

const SYSTEM_PROMPT = readFileSync(new URL('../llm/prompts/explanation.md', import.meta.url), 'utf8');
const EXPLANATION_MAX_BYTES = 4 * 1024;
const URL_SCHEME_RE = /https?:\/\//gi;
// Internal vocabulary is rewritten in place rather than rejected: rejecting sent too many good
// answers to the template (a quoted "zlib-layer-ok" was enough). Words inside a name are left alone:
// zlib-layer-ok, layer.example.test, layer.txt and ~/.config/contract/app.yaml are facts, not jargon.
const VOCABULARY = [
  [/(?<![\w./-])contracts?(?![\w/-]|\.\w)/gi, 'what you were told'],
  [/(?<![\w./-])harness(?:es)?(?![\w/-]|\.\w)/gi, 'decoder'],
  [/(?<![\w./-])layers(?![\w/-]|\.\w)/gi, 'hidden parts'],
  [/(?<![\w./-])layer(?![\w/-]|\.\w)/gi, 'hidden part'],
  [/(?<![\w./-])sinkholed(?![\w/-]|\.\w)/gi, 'answered by a fake internet'],
  [/(?<![\w./-])sinkholes?(?![\w/-]|\.\w)/gi, 'fake internet'],
];
// For CLEAN: "matched", "confirmed" and a positive "safe" are out; "not proof that it is safe"
// is the one thing the reader must hear, so negated phrases are stripped before the check.
const NEGATED_SAFE_RE = /\b(?:not|no|never|cannot|can't|does not|doesn't|is not|isn't|nothing|without)\b[^.!?\n]{0,60}?\bsafe\b/gi;
const BANNED_CLEAN_RE = /\b(?:matched|matches|confirmed|confirms|safe)\b/i;

// template.mjs belongs to Agent RULES and may land after this file; until then a minimal stand-in
// keeps the writer (and the LLM-disabled path) working.
let templateFromRules = null;
try {
  ({ renderTemplateExplanation: templateFromRules } = await import('./template.mjs'));
} catch (err) {
  if (err?.code !== 'ERR_MODULE_NOT_FOUND') throw err;
}

const NEXT_STEP = {
  CLEAN: 'Consistent with the claim within this run\'s limits',
  SUSPICIOUS: 'Read the unexplained items before deciding',
  MALICIOUS: 'Do not run this on your machine',
};

/** Minimal 8.4 template, used only when explain/template.mjs is not available. */
export function minimalTemplateExplanation(input) {
  const level = VERDICT_LEVELS.includes(input?.verdict?.level) ? input.verdict.level : 'SUSPICIOUS';
  const findings = Array.isArray(input?.findings) ? input.findings : [];
  const critical = findings.find((f) => f.severity === 'critical');
  const headline =
    level === 'CLEAN'
      ? 'Nothing beyond the claim was observed in this run'
      : level === 'MALICIOUS' && critical
        ? String(critical.title).slice(0, 120)
        : `${findings.length} things the claim does not explain`;
  const paragraphs = [`You were told: ${input?.claim ?? ''}. ${input?.contract?.summary ?? ''}`.trim().slice(0, 600)];
  const top = findings.slice(0, 3).map((f) => `${f.title}${f.evidence_summary ? ` (${f.evidence_summary})` : ''}`);
  if (top.length) paragraphs.push(top.join(' ').slice(0, 600));
  const notes = Array.isArray(input?.coverage_notes) ? input.coverage_notes : [];
  if (notes.length) paragraphs.push(notes.join(' ').slice(0, 600));
  return {
    verdict_echo: level,
    headline,
    paragraphs: paragraphs.slice(0, 3),
    finding_notes: findings.slice(0, 20).map((f) => ({ finding_id: String(f.id).slice(0, 64), text: String(f.rule_id ?? '').slice(0, 200) })),
    next_step: NEXT_STEP[level],
  };
}

export const renderTemplateExplanation = templateFromRules ?? minimalTemplateExplanation;

// --- canary matcher over text (6.6 forms, lower-cased substring) ------------------------------

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/** Base64 of `value` at byte alignment k (0..2), with the characters that depend on neighbours removed. */
function alignedBase64(value, k) {
  const head = Buffer.alloc(k);
  const tail = Buffer.alloc((3 - ((value.length + k) % 3)) % 3);
  const enc = Buffer.concat([head, value, tail]).toString('base64').replace(/=+$/, '');
  const dropHead = [0, 2, 3][k];
  const dropTail = [0, 2, 3][tail.length];
  return enc.slice(dropHead, enc.length - dropTail);
}

/** All search patterns for the decoy values (8.4: "semua forms manifest"), lower-cased. */
export function canaryPatterns(decoys) {
  const out = new Set();
  for (const d of decoys ?? []) {
    if (typeof d?.value !== 'string' || d.value.length < 8) continue;
    const value = Buffer.from(d.value, 'utf8');
    out.add(d.value);
    for (let k = 0; k < 3; k += 1) {
      const b64 = alignedBase64(value, k);
      out.add(b64);
      out.add(alignedBase64(Buffer.from(b64, 'utf8'), 0));
    }
    out.add(encodeURIComponent(d.value));
    out.add(value.toString('hex'));
    out.add(base32(value));
  }
  return [...out].filter((p) => p.length >= 8).map((p) => p.toLowerCase());
}

function explanationStrings(e) {
  return [e.headline, ...e.paragraphs, ...e.finding_notes.map((n) => n.text), e.next_step];
}

function containsCanary(explanation, patterns) {
  const hay = explanationStrings(explanation).join('\n').toLowerCase();
  return patterns.some((p) => hay.includes(p));
}

function buildUser(input) {
  const d = createDelimiter();
  const json = (v) => JSON.stringify(v ?? null, null, 0);
  return [
    UNTRUSTED_PREAMBLE,
    d.field('CLAIM', String(input?.claim ?? '')),
    d.field('VERDICT', json(input?.verdict)),
    d.field('CONTRACT', json(input?.contract)),
    d.field('FINDINGS', json(input?.findings ?? [])),
    d.field('LAYERS', json(input?.layers ?? [])),
    d.field('COVERAGE_NOTES', json(input?.coverage_notes ?? [])),
    d.field('AI_READING_OF_THE_CODE', json(input?.ai_review ?? null)),
    `RAN_TWICE: ${input?.ran_twice === true}`,
  ].join('\n\n');
}

/**
 * Post-zod validation (8.4). Returns the cleaned explanation or `{reject: reason}`.
 */
export function validateExplanation(data, input, { patterns = [] } = {}) {
  if (data.verdict_echo !== input?.verdict?.level) return { reject: 'verdict_mismatch' };
  const known = new Set((input?.findings ?? []).map((f) => f.id));
  const strip = (s) => String(s).replace(URL_SCHEME_RE, '').trim();
  const explanation = {
    verdict_echo: data.verdict_echo,
    headline: strip(data.headline),
    paragraphs: data.paragraphs.map(strip).filter(Boolean),
    finding_notes: data.finding_notes.filter((n) => known.has(n.finding_id)).map((n) => ({ finding_id: n.finding_id, text: strip(n.text) })),
    next_step: strip(data.next_step),
  };
  if (!explanation.headline || explanation.paragraphs.length === 0) return { reject: 'empty' };
  if (containsCanary(explanation, patterns)) return { reject: 'canary' };
  // Wording for non-experts (8.4): internal vocabulary never reaches the reader, and a CLEAN
  // run is never described as proof. The template says it right; a wrong word drops the answer.
  const plain = (s, max) => [...VOCABULARY.reduce((t, [re, word]) => t.replace(re, word), s)].slice(0, max).join('');
  explanation.headline = plain(explanation.headline, 120);
  explanation.paragraphs = explanation.paragraphs.map((p) => plain(p, 600));
  explanation.finding_notes = explanation.finding_notes.map((n) => ({ ...n, text: plain(n.text, 200) }));
  explanation.next_step = plain(explanation.next_step, 200);
  const all = explanationStrings(explanation).join('\n');
  if (data.verdict_echo === 'CLEAN' && BANNED_CLEAN_RE.test(all.replace(NEGATED_SAFE_RE, ''))) return { reject: 'wording' };
  while (Buffer.byteLength(JSON.stringify(explanation)) > EXPLANATION_MAX_BYTES && explanation.finding_notes.length) {
    explanation.finding_notes.pop();
  }
  if (Buffer.byteLength(JSON.stringify(explanation)) > EXPLANATION_MAX_BYTES) return { reject: 'too_large' };
  return { explanation };
}

/**
 * @param {ReturnType<import('../llm/client.mjs').createLlm>} llm
 * @param {object} explanationInput from explain/input.mjs (claim, verdict, findings, contract, layers, coverage_notes)
 * @param {{decoys?: object[], template?: Function, signal?: AbortSignal, onRaw?: Function}} [opts]
 *   decoys: the 5.3 manifest, used only on the host to reject output that echoes a canary value
 * @returns {Promise<{explanation: object, meta: object}>} meta.source: llm | template
 */
export async function writeExplanation(llm, explanationInput, { decoys = [], template = renderTemplateExplanation, signal, onRaw } = {}) {
  const started = performance.now();
  const level = explanationInput?.verdict?.level;
  const promptVersion = llm?.config?.prompt_version ?? null;
  const finish = (explanation, meta) => ({
    explanation,
    meta: { prompt_version: promptVersion, ...meta, ms: Math.round(performance.now() - started) },
  });
  const fallback = (reason, extra = {}) => finish(template(explanationInput), { source: 'template', reason, ...extra });

  if (!VERDICT_LEVELS.includes(level)) return fallback('no_verdict');
  let answer;
  try {
    answer = await llm.callJson(
      'explanation',
      { system: SYSTEM_PROMPT.replaceAll('{{LEVEL}}', level), user: buildUser(explanationInput) },
      Explanation,
      { signal, onRaw },
    );
  } catch (err) {
    return fallback(err instanceof LlmError ? err.code : 'internal');
  }
  const checked = validateExplanation(answer.data, explanationInput, { patterns: canaryPatterns(decoys) });
  if (checked.reject) return fallback(checked.reject, { model: answer.meta.model });
  return finish(checked.explanation, {
    source: 'llm',
    model: answer.meta.model,
    attempts: answer.meta.attempts,
    repairs: answer.meta.repairs,
    fallback_model_used: answer.meta.fallback_model_used,
  });
}
