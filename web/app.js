// Landing page: samples, the free-form form (access code in sessionStorage), the live timeline.
import { $, append, clear, createRunView, el, errorText } from './ui.js';
import { fetchRun, openRunStream } from './sse.js';

const CODE_KEY = 'firstrun.accessCode';
const RUN_ID_RE = /^[0-9A-Z]{26}$/;
const LANDING_SECTIONS = ['hero', 'specimen', 'how', 'limits']; // hidden while a run is shown

const form = $('run-form');
const commandEl = $('command');
const claimEl = $('claim');
const codeEl = $('access-code');
const codeField = $('code-field');
const codeNote = $('code-note');
const submitBtn = $('submit');
const formError = $('form-error');
const samplesEl = $('samples');
const selectedBox = $('selected-sample');
const selectedTitle = $('selected-title');
const notice = $('notice');
const runCard = $('run');
const runViewEl = $('run-view');
const runIdLine = $('run-id-line');

let samples = [];
let selectedSample = null;
let stream = null;
let freeformDisabled = false;

// ---------------------------------------------------------------------------------------------
// Access code: sessionStorage only (section 11)

try {
  codeEl.value = sessionStorage.getItem(CODE_KEY) ?? '';
} catch {
  /* storage blocked: the field still works for this page */
}
codeEl.addEventListener('input', () => {
  try {
    if (codeEl.value) sessionStorage.setItem(CODE_KEY, codeEl.value);
    else sessionStorage.removeItem(CODE_KEY);
  } catch {
    /* ignore */
  }
});

// ---------------------------------------------------------------------------------------------
// Samples and health

async function loadSamples() {
  let data;
  try {
    const res = await fetch('/api/samples', { headers: { accept: 'application/json' } });
    data = res.ok ? await res.json() : null;
  } catch {
    data = null;
  }
  samples = Array.isArray(data?.samples) ? data.samples.filter((s) => typeof s?.id === 'string') : [];
  clear(samplesEl);
  if (samples.length === 0) {
    samplesEl.append(el('p', { class: 'muted small', text: 'No samples are available on this instance.' }));
    return;
  }
  for (const s of samples) {
    // Only what the person would have seen: the title and the claim. No command text, no
    // description of what is hidden, no expected verdict.
    const title = String(s.title ?? s.id).slice(0, 100);
    const claim = String(s.claim ?? '').slice(0, 300);
    const btn = el('button', { type: 'button', class: 'sample', 'aria-pressed': 'false', 'data-id': s.id, 'aria-label': `Example: ${title}, told “${claim}”` }, [
      el('span', { class: 'sample-title', text: title }),
      claim ? el('span', { class: 'sample-claim', text: claim }) : null,
    ]);
    btn.addEventListener('click', () => selectSample(s.id === selectedSample?.id ? null : s));
    samplesEl.append(btn);
  }
}

/** The code is only for your own commands: an example, or an instance without free-form, needs none. */
function syncCodeField() {
  const noCode = Boolean(selectedSample) || freeformDisabled;
  codeField.hidden = noCode;
  codeNote.hidden = !noCode;
  codeNote.textContent = selectedSample ? 'Examples need no access code.' : 'This instance only runs the examples.';
}

function selectSample(sample) {
  selectedSample = sample;
  for (const btn of samplesEl.querySelectorAll('.sample')) {
    btn.setAttribute('aria-pressed', sample && btn.dataset.id === sample.id ? 'true' : 'false');
  }
  if (sample) {
    commandEl.value = String(sample.command ?? '');
    claimEl.value = String(sample.claim ?? '');
    commandEl.readOnly = true;
    claimEl.readOnly = true;
    selectedTitle.textContent = String(sample.title ?? sample.id);
    selectedBox.hidden = false;
  } else {
    commandEl.readOnly = false;
    claimEl.readOnly = false;
    selectedBox.hidden = true;
    if (!freeformDisabled) commandEl.focus();
  }
  syncCodeField();
  updateCounter();
  hideFormError();
}

$('clear-sample').addEventListener('click', () => {
  selectSample(null);
  commandEl.value = '';
  claimEl.value = '';
  updateCounter();
});

async function checkHealth() {
  try {
    const res = await fetch('/healthz', { headers: { accept: 'application/json' } });
    const data = await res.json();
    if (data && data.accepting_runs === false) {
      showNotice('New runs are paused right now.', 'Existing reports still open. Try again in a little while.', 'warn');
    }
  } catch {
    /* the form still works; a failed POST will explain itself */
  }
}

function showNotice(title, text, tone = 'warn') {
  clear(notice);
  notice.className = `notice${tone === 'bad' ? ' is-bad' : tone === 'info' ? ' is-info' : ''}`;
  notice.append(el('div', {}, [el('strong', { text: title }), text ? el('span', { text }) : null]));
  notice.hidden = false;
}

// ---------------------------------------------------------------------------------------------
// Form

function updateCounter() {
  $('claim-counter').textContent = `${[...claimEl.value].length} / 300`;
}
claimEl.addEventListener('input', updateCounter);
updateCounter();

function showFormError(code, message, retryAfterS) {
  const { title, text } = errorText(code, message, retryAfterS);
  clear(formError);
  append(formError, el('p', { text: title }), text ? el('p', { class: 'small', text }) : null);
  formError.hidden = false;
  formError.focus?.();
}
function hideFormError() {
  formError.hidden = true;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  hideFormError();
  let body;
  const headers = { 'content-type': 'application/json', accept: 'application/json' };
  if (selectedSample) {
    body = { sample_id: selectedSample.id };
  } else {
    const command = commandEl.value;
    const claim = claimEl.value.trim();
    if (command.trim() === '') return showFormError('invalid_input', 'Paste the command first.');
    if (claim === '') return showFormError('invalid_input', 'Say in one line what you were told the command does.');
    if (freeformDisabled) return showFormError('freeform_disabled');
    const code = codeEl.value;
    if (!code) return showFormError('access_code_required');
    if (!/^[\x21-\x7e]+$/.test(code)) return showFormError('access_code_invalid', 'Codes contain only printable ASCII characters.');
    headers['x-firstrun-access-code'] = code;
    body = { command, claim };
  }

  submitBtn.disabled = true;
  submitBtn.textContent = 'Submitting…';
  try {
    let res;
    try {
      res = await fetch('/api/runs', { method: 'POST', headers, body: JSON.stringify(body) });
    } catch {
      return showFormError('network');
    }
    let data = null;
    try {
      data = await res.json();
    } catch {
      data = null;
    }
    if (res.status !== 202 || !data || !RUN_ID_RE.test(String(data.run_id))) {
      const code = data?.error ?? (res.status === 413 ? 'body_too_large' : 'internal');
      const retry = Number(data?.retry_after_s ?? res.headers.get('retry-after')) || undefined;
      if (code === 'freeform_disabled') {
        freeformDisabled = true;
        syncCodeField();
      }
      if (code === 'runs_disabled') showNotice('New runs are paused right now.', 'Try again in a little while.', 'warn');
      return showFormError(code, data?.message, retry);
    }
    startRun(data.run_id, { reportUrl: data.report_url, position: data.position, after: 0 });
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = 'Run it in the sandbox';
  }
});

// ---------------------------------------------------------------------------------------------
// Live run

function startRun(runId, { reportUrl, after = 0 } = {}) {
  const linkLead = el('span');
  stream?.close();
  clear(runViewEl);
  const url = typeof reportUrl === 'string' && reportUrl.includes(`/r/${runId}`) ? reportUrl : `/r/${runId}`;
  const runTitle = $('run-title');
  runTitle.textContent = 'Checking the command';
  const view = createRunView(runViewEl, {
    reportUrl: url,
    onDone: () => {
      runTitle.textContent = 'Check finished';
      linkLead.textContent = 'Report link: ';
    },
    onError: () => {
      runTitle.textContent = 'Check stopped';
      runIdLine.hidden = true;
    },
  });
  clear(runIdLine);
  linkLead.textContent = 'Report link, ready when the run finishes: ';
  const shareLink = url.startsWith('http') ? url : `${location.origin}${url}`;
  runIdLine.hidden = false;
  append(runIdLine, linkLead, el('a', { class: 'mono', href: url, text: shareLink }));
  runCard.hidden = false;
  for (const id of LANDING_SECTIONS) $(id).hidden = true;
  history.replaceState(null, '', `/?run=${runId}`);
  window.scrollTo({ top: 0 });
  $('run-title').focus?.({ preventScroll: true });

  let retries = 0;
  const open = (afterId) => {
    stream = openRunStream(runId, {
      after: afterId,
      onEvent: (name, data) => view.handle(name, data),
      onReconnecting: (on) => view.setReconnecting(on),
      onClosed: async (reason) => {
        if (reason === 'done') return;
        // Stream refused or buffer gone: ask the API where the run stands.
        const r = await fetchRun(runId);
        if (!r.ok) {
          view.handle('run.error', { code: r.data?.error ?? 'internal', message: r.data?.message, retryable: true });
          return;
        }
        const s = r.data;
        if (s.status === 'done' && s.report) {
          view.handle('verdict', { verdict: s.report.verdict, findings: s.report.findings });
          view.handle('run.done', { report_url: url, total_ms: s.report.timing?.total_ms });
        } else if (s.status === 'error') {
          view.handle('run.error', s.error ?? { code: 'internal' });
        } else if (retries++ < 30) {
          view.setReconnecting(true);
          setTimeout(() => open(stream?.lastId() ?? afterId), 2000);
        } else {
          view.handle('run.error', { code: 'network', retryable: true });
        }
      },
    });
  };
  open(after);
}

$('new-run').addEventListener('click', () => {
  stream?.close();
  stream = null;
  runCard.hidden = true;
  for (const id of LANDING_SECTIONS) $(id).hidden = false;
  history.replaceState(null, '', '/');
  selectSample(null);
  commandEl.value = '';
  claimEl.value = '';
  updateCounter();
  window.scrollTo({ top: 0 });
  commandEl.focus();
});

// ---------------------------------------------------------------------------------------------
// Boot

const params = new URLSearchParams(location.search);
const resumeId = params.get('run');
loadSamples();
checkHealth();
if (resumeId && RUN_ID_RE.test(resumeId)) {
  startRun(resumeId, { after: 0 });
}
