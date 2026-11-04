// Claim-to-contract (docs/ARCHITECTURE.md 8.1): the LLM sees the claim only, never the command
// (as pasted or unwrapped), answers a Contract from its own knowledge of the named tool, and the
// host salvages it entry by entry. Any failure degrades to the deterministic fallback contract;
// a run never fails here.
import { readFileSync } from 'node:fs';
import { LlmError, UNTRUSTED_PREAMBLE, createDelimiter } from './client.mjs';
import { Contract, DECOY_CATEGORIES, DECOY_CATEGORY_MEANINGS, NEVER_ALLOWED } from './schemas.mjs';

const SYSTEM_PROMPT = readFileSync(new URL('./prompts/contract.md', import.meta.url), 'utf8');

const MAX_ENTRIES = 32;
const HOST_RE = /^(\*\.)?([a-z0-9-]+\.)+[a-z0-9-]{2,}$/;
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const PATH_CHARS_RE = /^~?[A-Za-z0-9._/*-]+$/;
const PATH_PREFIXES = ['~/', '/tmp/', '/var/tmp/', '/opt/', '/usr/local/'];
const PROCESS_RE = /^[A-Za-z0-9._+-]+$/;

export const FALLBACK_NOTE =
  'Contract could not be generated; only the sandbox baseline (tmp and cache) is treated as expected.';

/** The deterministic contract when no LLM answer is usable (8.1). */
export function fallbackContract(claim) {
  return {
    summary: String(claim ?? '').trim().slice(0, 300) || '(no claim)',
    expected_hosts: [],
    expected_write_paths: [],
    expected_processes: [],
    allowed_decoy_categories: [],
    notes: FALLBACK_NOTE,
  };
}

function salvageHost(raw) {
  let host = String(raw ?? '')
    .trim()
    .toLowerCase();
  if (host.includes('://')) {
    try {
      host = new URL(host).hostname;
    } catch {
      return null;
    }
  } else {
    host = host.replace(/^\/\//, '').replace(/[/?#].*$/, '');
  }
  host = host.replace(/^\[|\]$/g, '').replace(/:\d+$/, '').replace(/\.$/, '');
  if (host.includes('*') && !host.startsWith('*.')) return null;
  if (host.startsWith('*.') && host.indexOf('*', 1) !== -1) return null;
  return HOST_RE.test(host) || IPV4_RE.test(host) ? host : null;
}

function salvagePath(raw) {
  let p = String(raw ?? '').trim();
  p = p.replace(/^\$HOME\//, '~/').replace(/^\$\{HOME\}\//, '~/').replace(/^\/home\/dev\//, '~/');
  if (p === '~' || p === '$HOME' || p === '/home/dev') p = '~/';
  if (!PATH_PREFIXES.some((prefix) => p.startsWith(prefix))) return null;
  if (!PATH_CHARS_RE.test(p) || p.includes('/../') || p.endsWith('/..')) return null;
  return p;
}

function salvageProcess(raw) {
  const name = String(raw ?? '')
    .trim()
    .split('/')
    .pop();
  return name && PROCESS_RE.test(name) ? name : null;
}

function uniq(list, max = MAX_ENTRIES) {
  return [...new Set(list)].slice(0, max);
}

/**
 * Deterministic salvage (8.1): bad entries are dropped one by one and listed in `notes`; the
 * contract is never rejected as a whole. Works on any object shaped like a Contract (LLM output
 * or a fixture file).
 * @returns {{contract: object, dropped: string[]}}
 */
export function salvageContract(raw, { claim = '' } = {}) {
  const src = raw && typeof raw === 'object' ? raw : {};
  const dropped = [];
  const keep = (kind, list, fn) => {
    const out = [];
    for (const item of Array.isArray(list) ? list : []) {
      const v = fn(item);
      if (v === null) dropped.push(`${kind} ${JSON.stringify(String(item).slice(0, 80))}`);
      else out.push(v);
    }
    return uniq(out);
  };
  const categories = uniq(
    (Array.isArray(src.allowed_decoy_categories) ? src.allowed_decoy_categories : []).filter((c) => {
      if (!DECOY_CATEGORIES.includes(c)) {
        dropped.push(`category ${JSON.stringify(String(c).slice(0, 40))}`);
        return false;
      }
      if (NEVER_ALLOWED.includes(c)) {
        dropped.push(`category ${c} (never allowed)`);
        return false;
      }
      return true;
    }),
    4,
  );
  const expected_hosts = keep('host', src.expected_hosts, salvageHost);
  const expected_write_paths = keep('path', src.expected_write_paths, salvagePath);
  const expected_processes = keep('process', src.expected_processes, salvageProcess);
  let notes = typeof src.notes === 'string' ? src.notes.trim() : '';
  if (dropped.length) {
    const suffix = `Dropped by validation: ${dropped.join(', ')}`;
    notes = notes ? `${notes} ${suffix}` : suffix;
  }
  const summary = (typeof src.summary === 'string' ? src.summary.trim() : '') || String(claim ?? '').trim().slice(0, 300) || '(no summary)';
  return {
    contract: {
      summary: summary.slice(0, 300),
      expected_hosts,
      expected_write_paths,
      expected_processes,
      allowed_decoy_categories: categories,
      notes: notes.slice(0, 500),
    },
    dropped,
  };
}

/** Union of two salvaged contracts (curated samples, 8.1): lists merged, LLM summary kept. */
export function mergeContracts(primary, extra) {
  const join = (key, max) => uniq([...primary[key], ...extra[key]], max);
  const notes = [primary.notes, extra.notes].filter(Boolean).join(' ').slice(0, 500);
  return {
    summary: primary.summary || extra.summary,
    expected_hosts: join('expected_hosts'),
    expected_write_paths: join('expected_write_paths'),
    expected_processes: join('expected_processes'),
    allowed_decoy_categories: join('allowed_decoy_categories', 4),
    notes,
  };
}

/**
 * User message of the contract call: the claim (delimited, 8.6.1), the optional sample id and the
 * decoy category names. Nothing else; in particular never the command, so that nothing in the
 * command can shape the expectations it is judged against.
 */
export function buildContractUser({ claim, sampleId = null }) {
  const d = createDelimiter();
  const categories = DECOY_CATEGORIES.map((c) => `${c}: ${DECOY_CATEGORY_MEANINGS[c]}`).join('\n');
  const parts = [UNTRUSTED_PREAMBLE, d.field('CLAIM', String(claim ?? '').slice(0, 300))];
  if (sampleId) parts.push(`SAMPLE_ID: ${sampleId}`);
  parts.push(`DECOY_CATEGORIES (names for allowed_decoy_categories):\n${categories}`);
  return parts.join('\n\n');
}

/**
 * @param {ReturnType<import('./client.mjs').createLlm>} llm
 * @param {string} claim
 * @param {{sampleContract?: object|null, sampleId?: string|null, signal?: AbortSignal, deadline?: number, onRaw?: Function}} [opts]
 *   sampleContract: fixtures/samples/<id>/contract.json for curated samples (merged with the LLM answer)
 * @returns {Promise<{contract: object, meta: object}>} meta.source: llm | llm+fixture | fixture | fallback
 */
export async function deriveContract(llm, claim, { sampleContract = null, sampleId = null, signal, deadline, onRaw } = {}) {
  const started = performance.now();
  const promptVersion = llm?.config?.prompt_version ?? null;
  const fixture = sampleContract ? salvageContract(sampleContract, { claim }) : null;
  const finish = (contract, meta) => ({
    contract,
    meta: { prompt_version: promptVersion, ...meta, ms: Math.round(performance.now() - started) },
  });

  let answer;
  try {
    answer = await llm.callJson('contract', { system: SYSTEM_PROMPT, user: buildContractUser({ claim, sampleId }) }, Contract, {
      signal,
      deadline,
      onRaw,
    });
  } catch (err) {
    const reason = err instanceof LlmError ? err.code : 'internal';
    if (fixture) {
      return finish({ ...fixture.contract, summary: String(claim ?? '').trim().slice(0, 300) || fixture.contract.summary }, {
        source: 'fixture',
        reason,
        dropped: fixture.dropped,
      });
    }
    return finish(fallbackContract(claim), { source: 'fallback', reason });
  }

  const { contract, dropped } = salvageContract(answer.data, { claim });
  const meta = {
    model: answer.meta.model,
    attempts: answer.meta.attempts,
    repairs: answer.meta.repairs,
    fallback_model_used: answer.meta.fallback_model_used,
  };
  if (fixture) {
    return finish(mergeContracts(contract, fixture.contract), { source: 'llm+fixture', ...meta, dropped: [...dropped, ...fixture.dropped] });
  }
  return finish(contract, { source: 'llm', ...meta, dropped });
}
