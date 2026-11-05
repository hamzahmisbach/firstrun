// Shared rendering for the landing page and the report page. Every value that comes from a run
// is untrusted: this file only ever uses textContent / createTextNode, never innerHTML.

// Direction controls make text read differently from what it says (U+202E shows "evil" as "live"),
// which a report must not allow, so they are written out instead of obeyed.
const DIRECTION_CONTROLS = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;
export const showControls = (s) => String(s).replace(DIRECTION_CONTROLS, (c) => `[U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}]`);

export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = showControls(value);
    else if (key === 'hidden') node.hidden = Boolean(value);
    else node.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of Array.isArray(children) ? children : [children]) {
    if (child === null || child === undefined || child === false) continue;
    node.append(typeof child === 'string' ? document.createTextNode(showControls(child)) : child);
  }
  return node;
}

/** append() that skips null/false children, like el() does. */
export function append(node, ...children) {
  for (const child of children) if (child) node.append(child);
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------------------------------------
// Formatting

const str = (v, max = 400) => {
  const s = showControls(typeof v === 'string' ? v : v === null || v === undefined ? '' : String(v));
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
};

export function homePath(p) {
  if (typeof p !== 'string') return '';
  if (p === '/home/dev') return '~';
  return p.startsWith('/home/dev/') ? `~/${p.slice('/home/dev/'.length)}` : p;
}

export function fmtMs(ms) {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return '';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
  return `${Math.floor(ms / 60_000)} min ${Math.round((ms % 60_000) / 1000)} s`;
}

export function fmtRel(ms) {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return '';
  const sign = ms < 0 ? '-' : '+';
  const abs = Math.abs(ms);
  return abs < 1000 ? `${sign}${Math.round(abs)}ms` : `${sign}${(abs / 1000).toFixed(abs < 10_000 ? 2 : 1)}s`;
}

export function fmtBytes(n) {
  if (typeof n !== 'number' || !Number.isFinite(n)) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function fmtDate(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

const argvText = (argv) => (Array.isArray(argv) ? argv.map((a) => str(a, 200)).join(' ') : '');

export const CATEGORY_LABEL = {
  ssh_private_key: 'SSH private key',
  ssh_meta: 'SSH metadata',
  cloud_credentials: 'cloud credentials',
  package_manager_token: 'package manager token',
  vcs_token: 'GitHub token',
  registry_token: 'container registry login',
  browser_profile: 'browser passwords and cookies',
  wallet: 'crypto wallet',
  ai_assistant_config: 'AI assistant login',
  project_secrets: 'project .env secrets',
  history: 'shell history',
  phished_input: 'typed-in password',
};

export const categoryLabel = (c) => CATEGORY_LABEL[c] ?? str(c, 60);

const FORM_LABEL = {
  raw: 'in plain text',
  b64x3: 'base64-encoded',
  b64b64x3: 'double base64-encoded',
  url: 'URL-encoded',
  hex: 'hex-encoded',
  base32: 'base32-encoded',
};
export const formLabel = (f) => FORM_LABEL[f] ?? (f ? `encoded as ${str(f, 40)}` : '');

const WHERE_LABEL = {
  url: 'the URL of a request',
  header: 'a request header',
  body: 'the body of a request',
  dns: 'a DNS lookup',
  tcp_bytes: 'a raw network connection',
  stdout: 'the command output',
  stderr: 'the command error output',
};
export const whereLabel = (w) => WHERE_LABEL[w] ?? (w ? str(w, 40) : 'outgoing traffic');

// ---------------------------------------------------------------------------------------------
// Events (section 7.4) in plain English

/**
 * @param {object} ev normalized event
 * @param {Map<number, object>} [bySeq] earlier events, to describe canary.hit by the request it was found in
 * @param {Map<string, object>} [decoys] decoy_id -> manifest entry, when known
 * @returns {{text: string, detail: string, tone: 'neutral'|'info'|'warn'|'bad', kind: string}}
 */
/** Shared ending for file changes: a touched fake credential stands out, and failures say so. */
function fileChangeDetail(out, ev, decoys) {
  if (ev.decoy_id) {
    const d = decoys.get(ev.decoy_id);
    out.detail = d?.category ? `Decoy ${categoryLabel(d.category)}, created for this run` : 'Decoy file, created for this run';
    out.tone = 'bad';
  }
  if (ev.ok === false) out.detail = [out.detail, `Failed${ev.errno ? ` (${str(ev.errno, 20)})` : ''}`].filter(Boolean).join('. ');
}

/** Second-try settings in plain words. The report and SSE only ever carry names, never values. */
export function describeSettings(settings) {
  const s = settings && typeof settings === 'object' ? settings : {};
  const parts = [];
  if (Array.isArray(s.set_env) && s.set_env.length) parts.push(`provided ${s.set_env.map((n) => str(n, 40)).join(', ')}`);
  if (s.hostname && s.hostname !== 'devbox') parts.push(`named the machine ${str(s.hostname, 40)}`);
  if (s.answer_yes) parts.push('answered yes to questions');
  if (s.skip_sleep) parts.push('skipped waiting');
  return parts.join(', ');
}

export function describeEvent(ev, bySeq = new Map(), decoys = new Map()) {
  const kind = str(ev?.kind, 40);
  const out = { text: '', detail: '', tone: 'neutral', kind };
  const cls = ev?.classification;
  const decoyPath = (id, fallback) => homePath(decoys.get(id)?.path) || fallback || str(id, 60);
  switch (kind) {
    case 'proc.exec': {
      const argv = argvText(ev.argv);
      const exe = str(ev.exe, 200);
      out.text = `Ran ${basename(exe) || basename(argv.split(' ')[0]) || 'a program'}`;
      out.detail = argv || exe;
      break;
    }
    case 'file.open': {
      const p = homePath(ev.path) || '(unknown path)';
      const verb = ev.access === 'write' ? 'Wrote to' : ev.access === 'create' ? 'Created' : 'Read';
      if (ev.decoy_id) {
        const d = decoys.get(ev.decoy_id);
        out.text = `${verb} a fake credential file: ${p}`;
        out.detail = d?.category ? `Decoy ${categoryLabel(d.category)}, created for this run` : 'Decoy file, created for this run';
        out.tone = 'bad';
      } else {
        out.text = `${verb} ${p}`;
        if (ev.ok === false) out.detail = `Failed${ev.errno ? ` (${str(ev.errno, 20)})` : ''}`;
      }
      break;
    }
    case 'file.delete':
    case 'file.truncate':
    case 'file.chmod':
    case 'dir.remove':
    case 'dir.create': {
      const p = homePath(ev.path) || '(unknown path)';
      const verb = { 'file.delete': 'Deleted', 'file.truncate': 'Emptied', 'file.chmod': 'Changed the permissions of', 'dir.remove': 'Removed the folder', 'dir.create': 'Created the folder' }[kind];
      out.text = `${verb} ${p}`;
      fileChangeDetail(out, ev, decoys);
      break;
    }
    case 'file.rename': {
      out.text = `Moved ${homePath(ev.from) || '(unknown path)'}${ev.to ? ` to ${homePath(ev.to)}` : ''}`;
      fileChangeDetail(out, ev, decoys);
      break;
    }
    case 'file.link': {
      out.text = `Made a ${ev.link === 'symlink' ? 'shortcut' : 'second name'} for ${homePath(ev.from) || '(unknown path)'}`;
      out.detail = ev.to ? `At ${homePath(ev.to)}` : '';
      fileChangeDetail(out, ev, decoys);
      break;
    }
    case 'net.connect': {
      if (ev.family === 'unix') {
        out.text = `Connected to a local socket ${str(ev.path, 120)}`;
      } else {
        out.text = `Opened a connection to ${str(ev.dst_ip, 60)}:${str(ev.dst_port, 6)}`;
        out.detail = 'Inside the sandbox every address leads to the fake network';
      }
      break;
    }
    case 'shim.call': {
      const tool = str(ev.tool, 40);
      out.text = `Called the OS tool "${tool}" (recorded, not executed)`;
      out.detail = argvText([tool, ...(Array.isArray(ev.args) ? ev.args : [])]);
      out.tone = 'warn';
      break;
    }
    case 'dns.query':
      out.text = `Looked up ${str(ev.name, 253)}`;
      out.detail = `DNS ${str(ev.qtype, 10)} query, answered by the fake network`;
      break;
    case 'http.request': {
      const scheme = ev.scheme ? str(ev.scheme, 5) : ev.port === 443 ? 'https' : 'http';
      const bytes = typeof ev.body_len === 'number' && ev.body_len > 0 ? `, sent ${fmtBytes(ev.body_len)}` : '';
      out.text = `${str(ev.method, 10)} request to ${str(ev.host, 253)}${bytes}`;
      out.detail = `${scheme}://${str(ev.host, 253)}${str(ev.path, 300)}${ev.canned ? ' (answered with a canned file)' : ' (answered with an empty page)'}`;
      if (bytes) out.tone = 'warn';
      break;
    }
    case 'tls.clienthello':
      out.text = `Started an encrypted connection to ${str(ev.sni, 253)}`;
      out.detail = `Port ${str(ev.port, 6)}; the fake network decrypts it with a throwaway certificate`;
      break;
    case 'tls.failed':
      out.text = `Encrypted connection to ${str(ev.sni, 253)} could not be inspected`;
      out.detail = str(ev.error, 200);
      out.tone = 'warn';
      break;
    case 'tcp.connect':
      out.text = `Raw TCP connection to port ${str(ev.orig_dst_port, 6)}${ev.sni ? ` (${str(ev.sni, 253)})` : ''}`;
      out.detail = `${fmtBytes(ev.bytes_in ?? 0)} sent${ev.looks_like_tls ? ', looks like TLS' : ''}`;
      out.tone = 'warn';
      break;
    case 'udp.datagram':
      out.text = `Sent a UDP packet${ev.orig_dst_port ? ` to port ${str(ev.orig_dst_port, 6)}` : ''}`;
      out.detail = `${fmtBytes(ev.len ?? 0)}`;
      out.tone = 'warn';
      break;
    case 'canary.hit': {
      const via = bySeq.get(ev.event_seq);
      const target = via?.host ?? via?.sni ?? via?.name ?? '';
      const path = decoyPath(ev.decoy_id, ev.path);
      out.text = `Fake credential from ${path} found ${formLabel(ev.form)} in ${whereLabel(ev.where)}${target ? ` to ${str(target, 253)}` : ''}`;
      out.detail = `Decoy ${categoryLabel(ev.category)}; the value was made for this run and is worthless outside it`;
      out.tone = 'bad';
      break;
    }
    case 'exec.finished':
      out.text = ev.timed_out ? 'The command was stopped at the time limit' : `The command finished (exit code ${str(ev.exit_code, 6)})`;
      out.detail = ev.killed_by ? `Killed by ${str(ev.killed_by, 20)}` : '';
      if (ev.timed_out || (typeof ev.exit_code === 'number' && ev.exit_code !== 0)) out.tone = 'warn';
      break;
    default:
      out.text = kind ? `Event ${kind}` : 'Event';
      out.detail = summarizeUnknown(ev);
  }
  if (cls === 'forbidden') out.tone = 'bad';
  else if (cls === 'unexplained' && out.tone === 'neutral') out.tone = 'warn';
  else if (cls === 'explained' && out.tone !== 'bad') out.tone = 'info';
  // 'baseline' (allowed for any command) and unknown values keep the neutral tone.
  return out;
}

const basename = (p) => (typeof p === 'string' ? p.split('/').filter(Boolean).pop() ?? '' : '');

function summarizeUnknown(ev) {
  const skip = new Set(['run_id', 'seq', 'ts_ms', 't_rel_ms', 'source', 'kind', 'classification']);
  return Object.entries(ev ?? {})
    .filter(([k, v]) => !skip.has(k) && (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'))
    .map(([k, v]) => `${k}=${str(v, 80)}`)
    .join(' ');
}

export const CLASS_LABEL = {
  explained: 'explained by the claim',
  unexplained: 'not explained by the claim',
  forbidden: 'never acceptable',
  baseline: 'normal for any command',
};

/** Classification chip, or null for a missing or unknown classification (never a raw value). */
export function classChip(cls) {
  if (typeof cls !== 'string' || !Object.hasOwn(CLASS_LABEL, cls)) return null;
  return el('span', { class: `cls cls-${cls}`, text: CLASS_LABEL[cls] });
}

export const SOURCE_LABEL = { gvisor: 'sandbox', sinkhole: 'network', orchestrator: 'FirstRun' };

// ---------------------------------------------------------------------------------------------
// Verdict wording (section 9.3). CLEAN never says "safe".

export const VERDICT_WORD = { CLEAN: 'Clean', SUSPICIOUS: 'Suspicious', MALICIOUS: 'Malicious' };

export function verdictSentence(level) {
  switch (level) {
    case 'MALICIOUS':
      return 'This command did something you were not told about, and it was harmful.';
    case 'SUSPICIOUS':
      return 'This command did things the claim does not explain. Look at them before you decide.';
    case 'CLEAN':
      return 'Nothing suspicious was seen in this run. That is not proof the command is safe.';
    default:
      return 'No verdict.';
  }
}

export function verdictLead(level) {
  switch (level) {
    case 'MALICIOUS':
      return 'Do not run this on your machine.';
    case 'SUSPICIOUS':
      return 'Read the unexplained items before deciding.';
    case 'CLEAN':
      return 'Consistent with the claim, within what this sandbox can see.';
    default:
      return '';
  }
}

export const levelClass = (level) => (level === 'MALICIOUS' ? 'bad' : level === 'SUSPICIOUS' ? 'warn' : level === 'CLEAN' ? 'ok' : 'none');

/** The verdict word as a rubber stamp. It stays text, so a screen reader hears "Verdict: Malicious". */
export function verdictStamp(level, { tag = 'p', id } = {}) {
  const word = VERDICT_WORD[level] ?? (str(level, 20) || 'No verdict');
  return el(tag, { class: 'stamp', id }, [el('span', { class: 'visually-hidden', text: 'Verdict: ' }), word]);
}

export const SEVERITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Note' };

// ---------------------------------------------------------------------------------------------
// Errors (sections 10.1 and 10.2) in plain English

const ERRORS = {
  // HTTP
  invalid_input: 'The command or the claim was not accepted.',
  access_code_required: 'Running your own command needs an access code. Enter it below, or pick a sample.',
  access_code_invalid: 'That access code is not valid.',
  freeform_disabled: 'This instance only runs the curated samples. Pasting your own command is turned off.',
  unsupported_platform: 'FirstRun only runs Linux commands.',
  body_too_large: 'That command is too long for this service.',
  unsupported_media_type: 'The request was not understood.',
  rate_limited: 'Too many requests from your address.',
  queue_full: 'Every sandbox is busy and the queue is full.',
  runs_disabled: 'New runs are paused right now.',
  too_many_streams: 'Too many live views are open from your address.',
  not_found: 'There is no run with that id. Reports are kept for a limited time.',
  storage_unavailable: 'The report store did not answer.',
  // run.error
  sinkhole_not_ready: 'The fake network for this run did not come up, so nothing was executed.',
  sandbox_start_failed: 'The sandbox could not be started, so nothing was executed.',
  trace_unavailable: 'The evidence channel was not available, so the run was stopped. Without evidence there is no verdict.',
  evidence_sink_unavailable: 'The evidence channel was not available, so the run was stopped. Without evidence there is no verdict.',
  no_t0_marker: 'The sandbox started but its evidence never arrived, so there is no verdict.',
  llm_unavailable: 'The language model did not answer, and this step has no fallback.',
  storage_failed: 'The run finished but the report could not be saved.',
  internal: 'Something went wrong on our side.',
  network: 'FirstRun could not be reached. Check your connection and try again.',
};

/** @returns {{title: string, text: string}} */
export function errorText(code, message, retryAfterS) {
  const known = typeof code === 'string' && Object.hasOwn(ERRORS, code);
  const title = known ? ERRORS[code] : 'The request failed.';
  const parts = [];
  if (!known && message) parts.push(str(message, 300));
  if (known && (code === 'invalid_input' || code === 'unsupported_platform') && message) parts.push(str(message, 300));
  if (typeof retryAfterS === 'number' && retryAfterS > 0) {
    parts.push(retryAfterS < 90 ? `Try again in about ${Math.ceil(retryAfterS)} seconds.` : `Try again in about ${Math.ceil(retryAfterS / 60)} minutes.`);
  }
  return { title, text: parts.join(' ') };
}

// ---------------------------------------------------------------------------------------------
// Live run view: phases, alert banner, timeline, verdict. Fed with SSE events (section 10.2).

const PHASES = [
  ['queued', 'Queued'],
  ['unwrap', 'Unwrap'],
  ['exec', 'Run'],
  ['rules', 'Decide'],
  ['done', 'Report'],
];
const PHASE_INDEX = Object.fromEntries(PHASES.map(([id], i) => [id, i]));

/**
 * @param {HTMLElement} root empty container
 * @param {{reportUrl?: string, onDone?: (data: object) => void, onError?: (data: object) => void}} [opts]
 */
export function createRunView(root, opts = {}) {
  const bySeq = new Map();
  const decoys = new Map();
  const alerts = [];
  let phase = -1;
  let verdictLevel = null;

  const steps = PHASES.map(([id, label]) => el('li', { class: 'step', 'data-phase': id, text: label }));
  const stepList = el('ol', { class: 'rail', 'aria-label': 'Progress' }, steps);
  const status = el('p', { class: 'run-status', role: 'status' }, 'Waiting for the queue…');
  const alertTitle = el('h2', { class: 'alert-title' });
  const alertList = el('ul', { class: 'alert-list' });
  const alertBox = el('section', { class: 'alert', role: 'alert', hidden: true }, [
    el('div', { class: 'alert-mark', 'aria-hidden': 'true' }, '!'),
    el('p', { class: 'alert-kicker', text: 'Caught in the sandbox' }),
    alertTitle,
    alertList,
    el('p', { class: 'alert-note' }, 'Every credential in this sandbox was created for this run. The request was recorded by the fake network and never reached the internet. On your machine, this would have been your real key.'),
  ]);
  const verdictBox = el('section', { class: 'verdict-card', hidden: true, 'aria-live': 'polite' });
  const errorBox = el('section', { class: 'error-box gap-bottom', role: 'alert', hidden: true });
  const reconnect = el('p', { class: 'reconnect gap-bottom', role: 'status', hidden: true }, 'Connection lost. Reconnecting…');

  // Left: what was declared. Right: what was found, printed line by line as it happens.
  const claimLine = el('p', { class: 'declared-claim', text: 'Waiting for the run to start…' });
  const checklist = el('p', { class: 'declared-note', hidden: true });
  const layerList = el('ol', { class: 'declared-layers' });
  const layerGroup = el('div', { class: 'declared-group', hidden: true }, [el('h3', { class: 'label', text: 'Hidden code, decoded' }), layerList]);
  const declared = el('section', { class: 'declared', 'aria-label': 'What you were told' }, [
    el('div', { class: 'declared-inner' }, [
      el('div', { class: 'declared-group' }, [el('h2', { class: 'label', text: 'You were told' }), claimLine, checklist]),
      layerGroup,
    ]),
  ]);
  const timeline = el('ol', { class: 'feed', 'aria-live': 'polite', 'aria-relevant': 'additions' });
  const found = el('section', { class: 'found' }, [el('div', { class: 'found-head' }, [el('h2', { class: 'label', text: 'It actually did, as it happened' })]), timeline]);

  root.append(stepList, status, reconnect, alertBox, errorBox, verdictBox, el('div', { class: 'run-cols' }, [declared, found]));

  function setPhase(id, { back = false } = {}) {
    const i = PHASE_INDEX[id];
    if (i === undefined || (i < phase && !back)) return;
    phase = i;
    steps.forEach((s, j) => {
      s.classList.toggle('is-done', j < i);
      s.classList.toggle('is-current', j === i && id !== 'done');
      if (id === 'done' && j === i) s.classList.add('is-done');
      if (j === i) s.setAttribute('aria-current', 'step');
      else s.removeAttribute('aria-current');
    });
  }

  function addRow(rel, text, detail, tone = 'neutral', opts2 = {}) {
    const li = el('li', { class: `feed-item tone-${tone}${opts2.marker ? ' is-marker' : ''}` }, [
      el('span', { class: 'feed-time', text: typeof rel === 'number' ? fmtRel(rel) : rel || '' }),
      el('div', {}, [el('div', { class: 'feed-text', text }), detail ? el('div', { class: 'feed-detail', text: detail }) : null]),
    ]);
    timeline.append(li);
    return li;
  }

  function addLayer(title, text) {
    layerList.append(el('li', { class: 'layer-live' }, [el('span', { class: 'label', text: title }), text ? el('pre', { text }) : null]));
    layerGroup.hidden = false;
  }

  function handle(name, data) {
    const d = data ?? {};
    switch (name) {
      case 'run.queued': {
        setPhase('queued');
        const pos = typeof d.position === 'number' ? d.position : null;
        status.textContent = pos === null ? 'Queued.' : pos === 0 ? 'Starting a fresh sandbox…' : `Queued: ${pos} ${pos === 1 ? 'run' : 'runs'} ahead of you.`;
        addRow('', pos === 0 || pos === null ? 'Accepted; a sandbox is being prepared' : `Accepted; waiting behind ${pos} other ${pos === 1 ? 'run' : 'runs'}`, '', 'neutral', { marker: true });
        break;
      }
      case 'run.started':
        setPhase('unwrap');
        status.textContent = 'Preparing a disposable sandbox with fake credentials and a fake internet.';
        claimLine.textContent = d.claim ? `“${str(d.claim, 300)}”` : 'No claim was recorded.';
        addRow('', 'Run started: fresh sandbox, new decoy credentials', '', 'neutral', { marker: true });
        break;
      case 'unwrap.layer': {
        setPhase('unwrap');
        const layer = d.layer ?? {};
        if (layer.status === 'gave_up' || layer.status === 'too_large') {
          addLayer('Could not unwrap the inner layers', str(layer.reason, 200));
        } else {
          const how = layer.method === 'harness' ? 'run with execution disabled' : str(layer.method, 30);
          addLayer(`Layer ${str(layer.index, 4)}, ${how}`, str(layer.preview, 1200));
        }
        status.textContent = 'Peeling the encoded layers of the command.';
        break;
      }
      case 'contract.ready': {
        const c = d.contract ?? {};
        const hosts = Array.isArray(c.expected_hosts) && c.expected_hosts.length ? `Allowed hosts: ${c.expected_hosts.map((h) => str(h, 253)).join(', ')}.` : 'No network expected.';
        checklist.textContent = `Read as: ${str(c.summary, 300).replace(/[.]+$/, '') || 'nothing specific expected'}. ${hosts}`;
        checklist.hidden = false;
        break;
      }
      case 'exec.started':
        setPhase('exec', { back: d.attempt === 2 });
        status.textContent = `Running the command inside the sandbox (up to ${str(d.timeout_s, 5) || '60'} s).`;
        addRow(d.attempt === 2 ? '' : 0, d.attempt === 2 ? 'Second run started in a fresh sandbox' : 'Command started in the sandbox', `No internet, no real secrets, ${str(d.timeout_s, 5) || '60'} second limit`, 'neutral', { marker: true });
        break;
      case 'retry.started': {
        const changed = describeSettings(d.settings);
        status.textContent = 'Running it again under changed conditions, to see what it was waiting for.';
        addRow('', 'The code looks like it waits for something, so FirstRun runs it again', [str(d.why, 200), changed ? `This time: ${changed}` : ''].filter(Boolean).join(' '), 'info', { marker: true });
        break;
      }
      case 'evidence': {
        const ev = d.event ?? {};
        if (typeof ev.seq === 'number') bySeq.set(ev.seq, ev);
        if (ev.kind === 'file.open' && ev.decoy_id && ev.path) decoys.set(ev.decoy_id, { path: ev.path, category: ev.category });
        if (ev.kind === 'canary.hit') break; // rendered by the alert
        const desc = describeEvent(ev, bySeq, decoys);
        addRow(ev.t_rel_ms, desc.text, desc.detail, desc.tone);
        break;
      }
      case 'alert': {
        const ev = d.event ?? {};
        if (typeof ev.seq === 'number') bySeq.set(ev.seq, ev);
        const desc = describeEvent(ev, bySeq, decoys);
        alerts.push(ev);
        alertTitle.textContent = alerts.length === 1 ? 'Fake credential caught leaving the sandbox' : `${alerts.length} fake credentials caught leaving the sandbox`;
        alertList.append(el('li', { text: desc.text }));
        alertBox.hidden = false;
        if (alerts.length === 1) {
          // The containment moment: bring it into view once, then leave the scroll position alone.
          const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
          alertBox.scrollIntoView({ block: 'start', behavior: reduce ? 'auto' : 'smooth' });
        }
        addRow(ev.t_rel_ms, desc.text, desc.detail, 'bad');
        break;
      }
      case 'exec.finished': {
        setPhase('rules');
        const desc = describeEvent({ ...d, kind: 'exec.finished' });
        addRow(d.duration_ms, desc.text, [desc.detail, typeof d.duration_ms === 'number' ? `Ran for ${fmtMs(d.duration_ms)}` : ''].filter(Boolean).join('. '), desc.tone, { marker: true });
        addRow('', 'Sandbox destroyed: container, network and decoy files removed', '', 'neutral', { marker: true });
        status.textContent = 'Comparing what happened with what you were told.';
        break;
      }
      case 'teardown':
        break; // already described after exec.finished
      case 'verdict': {
        const v = d.verdict ?? {};
        verdictLevel = v.level;
        renderVerdict(v, Array.isArray(d.findings) ? d.findings : []);
        status.textContent = 'Verdict ready. Writing the explanation…';
        break;
      }
      case 'explanation': {
        const ex = d.explanation ?? {};
        const h = verdictBox.querySelector('.verdict-headline');
        if (h && ex.headline) h.textContent = str(ex.headline, 120);
        break;
      }
      case 'run.done': {
        setPhase('done');
        status.textContent = `Done in ${fmtMs(d.total_ms) || 'a moment'}.`;
        const url = typeof d.report_url === 'string' && /^(https?:\/\/[^\s]+)?\/r\/[0-9A-Z]{26}$/.test(d.report_url) ? d.report_url : opts.reportUrl;
        if (url) {
          const link = verdictBox.querySelector('.verdict-link');
          if (link) {
            link.hidden = false;
            link.href = url;
          }
        }
        addRow('', 'Report saved', '', 'neutral', { marker: true });
        opts.onDone?.(d);
        break;
      }
      case 'run.error': {
        const { title, text } = errorText(d.code, d.message);
        clear(errorBox);
        append(
          errorBox,
          el('h2', { class: 'error-title', text: 'This run could not finish' }),
          el('p', { text: title }),
          text ? el('p', { text }) : null,
          el('p', { class: 'small', text: d.retryable ? 'You can try again. No verdict was produced.' : 'No verdict was produced.' }),
        );
        errorBox.hidden = false;
        status.textContent = 'Stopped.';
        steps.forEach((s) => s.classList.remove('is-current'));
        addRow('', `Run stopped: ${title}`, str(d.stage ? `During ${d.stage}` : '', 40), 'bad', { marker: true });
        opts.onError?.(d);
        break;
      }
      default:
        break;
    }
  }

  function renderVerdict(v, findings) {
    clear(verdictBox);
    const level = str(v.level, 12);
    verdictBox.className = `verdict-card level-${levelClass(level)}`;
    append(
      verdictBox,
      el('div', { class: 'verdict-card-top' }, [
        verdictStamp(level),
        el('div', {}, [
          el('p', { class: 'verdict-sentence', text: verdictSentence(level) }),
          el('p', { class: 'verdict-headline', text: findings[0]?.title ? str(findings[0].title, 160) : verdictLead(level) }),
        ]),
      ]),
      findings.length
        ? el('ul', { class: 'verdict-findings' }, findings.slice(0, 5).map((f) => el('li', {}, [el('span', { class: `sev sev-${str(f.severity, 10)}`, text: SEVERITY_LABEL[f.severity] ?? str(f.severity, 10) }), str(f.title, 200)])))
        : null,
      el('div', {}, [el('a', { class: 'btn btn-primary verdict-link', hidden: true, href: '#' }, 'Open the full report')]),
    );
    verdictBox.hidden = false;
  }

  return {
    handle,
    setReconnecting(on) {
      reconnect.hidden = !on;
    },
    get verdictLevel() {
      return verdictLevel;
    },
  };
}
