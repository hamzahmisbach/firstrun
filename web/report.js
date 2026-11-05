// Report page for /r/<id>: GET /api/runs/:id, then render the section 10.3 report with textContent
// only. While the run is still going, the live view from ui.js takes over until run.done.
//
// Order for a non-expert: verdict + what to do next, told-versus-did side by side, plain words and
// findings. Everything else (hidden code, decoys, every event, output, timing, limits) sits behind
// tabs so the default page stays short.
import {
  $,
  SEVERITY_LABEL,
  SOURCE_LABEL,
  VERDICT_WORD,
  append,
  categoryLabel,
  classChip,
  clear,
  createRunView,
  describeEvent,
  describeSettings,
  el,
  errorText,
  fmtBytes,
  fmtDate,
  fmtMs,
  homePath,
  levelClass,
  verdictIcon,
  verdictLead,
  verdictSentence,
} from './ui.js';
import { fetchRun, openRunStream } from './sse.js';

const RUN_ID_RE = /^[0-9A-Z]{26}$/;
const runId = location.pathname.startsWith('/r/') ? location.pathname.slice(3) : '';
const str = (v, max = 400) => {
  const s = typeof v === 'string' ? v : v === null || v === undefined ? '' : String(v);
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
};
const arr = (v) => (Array.isArray(v) ? v : []);
const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

let stream = null;
const sampleTitles = new Map(); // sample_id -> title, from GET /api/samples (best effort)

async function loadSampleTitles() {
  try {
    const res = await fetch('/api/samples', { headers: { accept: 'application/json' } });
    const data = res.ok ? await res.json() : null;
    for (const s of Array.isArray(data?.samples) ? data.samples : []) {
      if (typeof s?.id === 'string' && typeof s.title === 'string') sampleTitles.set(s.id, s.title);
    }
  } catch {
    /* the id is shown instead */
  }
}

// ---------------------------------------------------------------------------------------------
// Load

async function load() {
  if (!RUN_ID_RE.test(runId)) return showError('not_found');
  const [r] = await Promise.all([fetchRun(runId), loadSampleTitles()]);
  if (!r.ok) return showError(r.data?.error ?? 'internal', r.data?.message, r.data?.retry_after_s, r.status === 503 || r.status === 429 || r.status === 0);
  const s = r.data;
  if (s.status === 'done' && s.report) return renderReport(s.report);
  if (s.status === 'error') return showError(s.error?.code ?? 'internal', s.error?.message, undefined, false, 'This run could not finish');
  showLive();
}

function showError(code, message, retryAfterS, canRetry = false, title = 'This report cannot be shown') {
  const { title: line, text } = errorText(code, message, retryAfterS);
  const box = $('error');
  clear(box);
  append(box, el('h2', { class: 'error-title', text: title }), el('p', { text: line }), text ? el('p', { text }) : null);
  const row = el('div', { class: 'btn-row' }, [el('a', { class: 'btn', href: '/' }, 'Check a command')]);
  if (canRetry) {
    const retry = el('button', { type: 'button', class: 'btn btn-primary' }, 'Try again');
    retry.addEventListener('click', () => {
      box.hidden = true;
      $('loading').hidden = false;
      load();
    });
    row.prepend(retry);
  }
  box.append(row);
  $('loading').hidden = true;
  $('live').hidden = true;
  box.hidden = false;
  document.title = 'FirstRun report';
}

function showLive() {
  $('loading').hidden = true;
  const liveRoot = $('run-view');
  clear(liveRoot);
  const view = createRunView(liveRoot, { reportUrl: location.href });
  $('live').hidden = false;
  let polls = 0;
  const finish = async () => {
    // The report is written just before run.done; give the cache a moment, then fetch it.
    const r = await fetchRun(runId);
    if (r.ok && r.data.status === 'done' && r.data.report) {
      $('live').hidden = true;
      renderReport(r.data.report);
    } else if (r.ok && r.data.status === 'error') {
      showError(r.data.error?.code ?? 'internal', r.data.error?.message, undefined, false, 'This run could not finish');
    } else if (polls++ < 10) {
      setTimeout(finish, 1500);
    }
  };
  let retries = 0;
  const open = (after) => {
    stream = openRunStream(runId, {
      after,
      onEvent: (name, data) => {
        view.handle(name, data);
        if (name === 'run.done') setTimeout(finish, 400);
      },
      onReconnecting: (on) => view.setReconnecting(on),
      onClosed: async (reason) => {
        if (reason === 'done') return;
        const r = await fetchRun(runId);
        if (r.ok && (r.data.status === 'done' || r.data.status === 'error')) return finish();
        if (!r.ok) return showError(r.data?.error ?? 'internal', r.data?.message, r.data?.retry_after_s, true);
        if (retries++ < 30) setTimeout(() => open(stream?.lastId() ?? after), 2000);
      },
    });
  };
  open(0);
}

// ---------------------------------------------------------------------------------------------
// Report

function renderReport(report) {
  stream?.close();
  const root = $('report');
  clear(root);
  const verdict = obj(report.verdict);
  const level = str(verdict.level, 12);
  const explanation = obj(report.explanation);
  const events = arr(report.events).filter((e) => e && typeof e === 'object');
  const bySeq = new Map(events.filter((e) => typeof e.seq === 'number').map((e) => [e.seq, e]));
  const decoys = new Map(arr(report.decoys).filter((d) => d && typeof d.id === 'string').map((d) => [d.id, d]));
  const findings = arr(report.findings).filter((f) => f && typeof f === 'object');
  const input = obj(report.input);
  const notes = new Map(arr(explanation.finding_notes).filter((n) => n && typeof n.finding_id === 'string').map((n) => [n.finding_id, str(n.text, 200)]));
  const layers = arr(report.layers).filter((l) => l && typeof l === 'object');
  const output = obj(report.output);

  document.title = `${VERDICT_WORD[level] ?? 'Report'}: FirstRun report`;

  const tabs = [
    { id: 'code', label: 'Hidden code', count: layers.length, panel: renderLayers(layers, input) },
    { id: 'decoys', label: 'Fake credentials', count: decoys.size, panel: renderDecoys(decoys, events) },
    { id: 'events', label: 'Everything recorded', count: events.length, panel: renderEvents(events, bySeq, decoys) },
    output.stdout_preview || output.stderr_preview ? { id: 'output', label: 'Output', panel: renderOutput(output) } : null,
    { id: 'behind', label: 'Behind the scenes', panel: renderTiming(obj(report.timing), arr(report.models_used), obj(report.coverage)) },
    { id: 'limits', label: 'Limits of this run', panel: renderCoverage(verdict) },
  ].filter((t) => t && t.panel);

  append(
    root,
    renderHero(report, verdict, level, explanation, input),
    renderCompare(report, input, events, decoys),
    el('div', { class: 'explain-grid' }, [renderExplanation(explanation, report.explanation_meta), renderFindings(findings, bySeq, decoys, notes)]),
    renderReview(obj(report.review), obj(report.review_meta), arr(report.attempts)),
    renderTabs(tabs),
  );
  $('loading').hidden = true;
  root.hidden = false;
}

function renderHero(report, verdict, level, explanation, input) {
  const hero = el('section', { class: `verdict-hero level-${levelClass(level)}`, 'aria-labelledby': 'verdict-word' });
  const main = el('div', { class: 'verdict-main' }, [
    el('p', { class: 'verdict-label', text: 'Verdict' }),
    el('h1', { class: 'verdict-word', id: 'verdict-word' }, [verdictIcon(level), VERDICT_WORD[level] ?? (str(level, 20) || 'No verdict')]),
    el('p', { class: 'verdict-sentence', text: verdictSentence(level) }),
    explanation.headline ? el('p', { class: 'verdict-headline', text: str(explanation.headline, 160) }) : null,
    report.stub ? el('p', { class: 'verdict-meta', text: 'Stub build: the command was not executed; this report only exercises the pipeline.' }) : null,
  ]);

  const shareUrl = location.href.split('#')[0];
  const shareBtn = el('button', { type: 'button', class: 'btn btn-primary', id: 'share' }, 'Share this report');
  const shareStatus = el('span', { class: 'share-status', role: 'status', 'aria-live': 'polite' });
  shareBtn.addEventListener('click', async () => {
    try {
      if (navigator.share && /Mobi|Android/i.test(navigator.userAgent)) {
        await navigator.share({ title: document.title, url: shareUrl });
        shareStatus.textContent = 'Shared.';
        return;
      }
      await navigator.clipboard.writeText(shareUrl);
      shareStatus.textContent = 'Link copied to your clipboard.';
    } catch {
      shareStatus.textContent = `Copy this link: ${shareUrl}`;
    }
  });
  const side = el('div', { class: 'verdict-side' }, [
    el('div', { class: 'next-box' }, [
      el('p', { class: 'verdict-label', text: 'What to do next' }),
      el('p', { class: 'verdict-next', text: str(explanation.next_step, 200) || verdictLead(level) }),
    ]),
    el('div', { class: 'btn-row' }, [shareBtn, el('a', { class: 'btn', href: '/' }, 'Check another command')]),
    shareStatus,
    el('div', { class: 'report-meta' }, [
      report.created_at ? el('span', { text: `Run on ${fmtDate(report.created_at)}` }) : null,
      input.sample_id ? el('span', { text: `Example: ${str(sampleTitles.get(input.sample_id) ?? input.sample_id, 100)}` }) : null,
      el('span', { class: 'mono', text: str(report.run_id, 26) }),
    ]),
  ]);
  append(hero, main, side);
  return hero;
}

function renderCoverage(verdict) {
  const notes = arr(verdict.coverage_notes).filter((n) => typeof n === 'string' && n.trim());
  if (notes.length === 0) return null;
  return el('div', {}, [
    el('p', { class: 'muted', text: 'What this run could and could not see:' }),
    el('ul', { class: 'notes-list' }, notes.map((n) => el('li', {}, el('span', { text: str(n, 400) })))),
  ]);
}

function renderExplanation(explanation, meta) {
  const paragraphs = arr(explanation.paragraphs).filter((p) => typeof p === 'string' && p.trim());
  if (paragraphs.length === 0) return null;
  const source = obj(meta).source === 'llm' ? `Written by ${str(obj(meta).model, 60) || 'a language model'} on Vultr Serverless Inference from the findings; the verdict itself comes from fixed rules.` : 'Written from a template; the verdict comes from fixed rules.';
  return el('section', { class: 'card explain', 'aria-labelledby': 'explain-title' }, [
    el('h2', { id: 'explain-title', text: 'In plain words' }),
    ...paragraphs.slice(0, 3).map((p) => el('p', { class: 'para', text: str(p, 600) })),
    el('p', { class: 'source', text: source }),
  ]);
}

// AI reading of the code --------------------------------------------------------------------------

function renderReview(review, meta, attempts) {
  const second = obj(attempts[1]);
  const hasReview = typeof review.summary === 'string' && review.summary.trim() !== '';
  if (!hasReview && !second.attempt) return null;
  const risky = review.risk === 'concern' || review.risk === 'high';
  const reasons = arr(review.reasons).filter((r) => r && typeof r === 'object');
  const effects = arr(review.real_machine_effects).filter((e) => typeof e === 'string' && e.trim());
  const changed = describeSettings(second.settings);
  const model = str(meta.model, 60);
  return el('section', { class: `card ai-review${risky ? ' is-risky' : ''}`, 'aria-labelledby': 'review-title' }, [
    el('h2', { id: 'review-title', text: 'What an AI saw reading the code' }),
    el('p', { class: 'ai-review-tag', text: 'This is a reading of the code, not something observed in the sandbox. It can raise a verdict, never lower one.' }),
    hasReview ? el('p', { class: 'para', text: str(review.summary, 300) }) : null,
    effects.length ? el('ul', { class: 'ai-effects' }, effects.slice(0, 6).map((e) => el('li', { text: str(e, 200) }))) : null,
    reasons.length
      ? el('ul', { class: 'ai-reasons' }, reasons.slice(0, 6).map((r) => el('li', {}, [
          el('p', { text: `${str(r.what, 200)}. ${str(r.why, 300)}` }),
          el('code', { class: 'mono ai-quote', text: str(r.quote, 200) }),
        ])))
      : null,
    second.attempt
      ? el('div', { class: 'ai-second' }, [
          el('h3', { text: second.failed ? 'A second run was tried but could not start' : 'FirstRun ran it a second time' }),
          second.why ? el('p', { text: str(second.why, 200) }) : null,
          changed ? el('p', { class: 'muted', text: `This time it ${changed}.` }) : null,
          second.quote ? el('code', { class: 'mono ai-quote', text: str(second.quote, 200) }) : null,
        ])
      : null,
    model ? el('p', { class: 'source', text: `Read by ${model} on Vultr Serverless Inference.` }) : null,
  ]);
}

// Told vs did ------------------------------------------------------------------------------------

function observed(events, decoys) {
  const hosts = new Map(); // host -> classification (worst wins)
  const written = new Map();
  const programs = new Map();
  const credFiles = new Map();
  const tools = new Map();
  const uploads = [];
  const leaked = new Map();
  const rank = { forbidden: 3, unexplained: 2, explained: 1 };
  const worst = (map, key, cls) => {
    if (!key) return;
    const prev = map.get(key);
    if (!prev || (rank[cls] ?? 0) > (rank[prev] ?? 0)) map.set(key, cls ?? prev ?? null);
  };
  for (const ev of events) {
    const cls = ev.classification;
    switch (ev.kind) {
      case 'dns.query':
        worst(hosts, str(ev.name, 253), cls);
        break;
      case 'http.request':
        worst(hosts, str(ev.host, 253), cls);
        if (typeof ev.body_len === 'number' && ev.body_len > 0 && /^(POST|PUT|PATCH)$/i.test(String(ev.method))) uploads.push(ev);
        break;
      case 'tls.clienthello':
      case 'tls.failed':
        worst(hosts, str(ev.sni, 253), cls);
        break;
      case 'tcp.connect':
        if (ev.sni) worst(hosts, str(ev.sni, 253), cls);
        if (typeof ev.bytes_in === 'number' && ev.bytes_in > 0) uploads.push(ev);
        break;
      case 'file.open':
        if (ev.decoy_id) worst(credFiles, ev.decoy_id, cls);
        else if (ev.access === 'write' || ev.access === 'create') worst(written, homePath(ev.path), cls);
        break;
      case 'proc.exec': {
        const name = (typeof ev.exe === 'string' ? ev.exe : String(arr(ev.argv)[0] ?? '')).split('/').filter(Boolean).pop();
        if (name && !['bash', 'sh', 'dash', 'zsh'].includes(name)) worst(programs, str(name, 60), cls);
        break;
      }
      case 'shim.call':
        worst(tools, str(ev.tool, 40), cls);
        break;
      case 'canary.hit':
        worst(leaked, ev.decoy_id, 'forbidden');
        break;
      default:
    }
  }
  return { hosts, written, programs, credFiles, tools, uploads, leaked, decoys };
}

function listCell(map, { empty, labelFor = (k) => k, mono = true }) {
  if (map.size === 0) return el('span', { class: 'empty', text: empty });
  const items = [...map.entries()].slice(0, 12).map(([key, cls]) =>
    el('li', {}, [el('span', { class: mono ? 'mono' : '', text: labelFor(key) }), classChip(cls)]),
  );
  if (map.size > 12) items.push(el('li', { class: 'muted', text: `and ${map.size - 12} more` }));
  return el('ul', {}, items);
}

function plainList(values, empty, mono = true) {
  const v = arr(values).filter((x) => typeof x === 'string').slice(0, 12);
  if (v.length === 0) return el('span', { class: 'empty', text: empty });
  return el('ul', {}, v.map((x) => el('li', {}, el('span', { class: mono ? 'mono' : '', text: str(x, 253) }))));
}

function renderCompare(report, input, events, decoys) {
  const contract = obj(report.contract);
  const meta = obj(report.contract_meta);
  const o = observed(events, decoys);
  const decoyLabel = (id) => `${homePath(decoys.get(id)?.path) || id} (fake ${categoryLabel(decoys.get(id)?.category)})`;

  const summary = `${plural(events.length, 'recorded event')}: ${plural(o.hosts.size, 'host')} contacted, ${plural(o.credFiles.size, 'credential file')} touched, ${plural(o.uploads.length, 'upload')}, ${plural(o.leaked.size, 'fake credential')} leaked.`;

  const rows = [
    ['Network', plainList(contract.expected_hosts, 'No hosts expected'), listCell(o.hosts, { empty: 'No network activity' })],
    ['Files written', plainList(contract.expected_write_paths, 'No files expected'), listCell(o.written, { empty: 'No files written outside the sandbox baseline' })],
    ['Programs', plainList(contract.expected_processes, 'Nothing specific expected'), listCell(o.programs, { empty: 'Only the shell itself' })],
    [
      'Credentials',
      plainList(arr(contract.allowed_decoy_categories).map(categoryLabel), 'None: the claim gives no reason to read any credential', false),
      listCell(o.credFiles, { empty: 'No credential files touched', labelFor: decoyLabel }),
    ],
    [
      'Data sent out',
      el('span', { class: 'empty', text: 'Nothing, unless the claim says data is sent somewhere' }),
      o.uploads.length === 0
        ? el('span', { class: 'empty', text: 'Nothing uploaded' })
        : el('ul', {}, o.uploads.slice(0, 8).map((u) => el('li', {}, [el('span', { class: 'mono', text: u.kind === 'http.request' ? `${str(u.method, 8)} ${str(u.host, 253)}${str(u.path, 120)} (${fmtBytes(u.body_len)})` : `raw TCP port ${str(u.orig_dst_port, 6)} (${fmtBytes(u.bytes_in)})` }), classChip(u.classification)]))),
    ],
  ];
  if (o.tools.size) rows.push(['OS tools called', el('span', { class: 'empty', text: 'None expected' }), listCell(o.tools, { empty: '' })]);
  if (o.leaked.size) {
    rows.push(['Fake credentials leaked', el('span', { class: 'empty', text: 'Never acceptable' }), listCell(o.leaked, { empty: '', labelFor: decoyLabel })]);
  }

  const sourceText = meta.source === 'fallback' ? 'The claim could not be turned into a checklist; everything is treated as unexplained.' : meta.source === 'llm+fixture' ? 'Checklist written by a language model from the claim, merged with the example’s known-good list.' : meta.source === 'llm' ? 'Checklist written by a language model from the claim alone, before anything ran.' : '';
  const noteText = [sourceText, contract.notes ? str(contract.notes, 500) : ''].filter(Boolean).join(' ');

  const row = (label, told, did, extra = '') =>
    el('div', { class: `compare-row${extra}` }, [
      el('div', { class: 'compare-area', text: label }),
      el('div', { class: 'compare-cell', 'data-label': 'You were told' }, told),
      el('div', { class: 'compare-cell', 'data-label': 'It actually did' }, did),
    ]);

  return el('section', { class: 'card', 'aria-labelledby': 'compare-title' }, [
    el('h2', { id: 'compare-title', text: 'What you were told, against what it actually did' }),
    el('div', { class: 'compare-grid' }, [
      el('div', { class: 'compare-head', 'aria-hidden': 'true' }, [el('span'), el('span', { text: 'You were told' }), el('span', { class: 'did', text: 'It actually did' })]),
      row(
        'The claim',
        [el('p', { class: 'quote', text: `“${str(input.claim, 300)}”` }), contract.summary ? el('p', { class: 'muted small', text: `Read as: ${str(contract.summary, 300)}` }) : null],
        el('p', { text: summary }),
        ' is-claim',
      ),
      ...rows.map(([label, told, did]) => row(label, told, did)),
    ]),
    noteText ? el('p', { class: 'compare-note', text: noteText }) : null,
  ]);
}

// Findings --------------------------------------------------------------------------------------

function evidenceRow(ev, bySeq, decoys) {
  const d = describeEvent(ev, bySeq, decoys);
  return el('li', { class: `tone-${d.tone}` }, [el('span', { class: 'seq', text: `#${str(ev.seq, 6)}` }), el('div', {}, [el('div', { text: d.text }), d.detail ? el('div', { class: 'ev-detail', text: d.detail }) : null])]);
}

function renderFindings(findings, bySeq, decoys, notes) {
  const title = el('h2', { id: 'findings-title', class: 'section-title' }, ['Findings', el('span', { class: 'count', text: `${findings.length}` })]);
  if (findings.length === 0) {
    return el('section', { class: 'card', 'aria-labelledby': 'findings-title' }, [title, el('p', { class: 'muted', text: 'No findings: nothing in this run went beyond the claim or touched a decoy credential.' })]);
  }
  const items = findings.map((f) => {
    const cls = str(f.classification, 20);
    const seqs = arr(f.event_seqs).filter((s) => typeof s === 'number');
    const evs = seqs.map((s) => bySeq.get(s)).filter(Boolean);
    return el('li', { class: `finding is-${cls}` }, [
      el('div', { class: 'finding-head' }, [
        el('span', { class: `sev sev-${str(f.severity, 10)}`, text: SEVERITY_LABEL[f.severity] ?? str(f.severity, 10) }),
        el('span', { class: 'finding-title', text: str(f.title, 200) }),
      ]),
      notes.has(f.id) ? el('p', { class: 'finding-note', text: notes.get(f.id) }) : null,
      el('div', { class: 'finding-foot' }, [
        f.observed === false ? el('span', { class: 'cls cls-ai', text: 'AI reading, not observed' }) : classChip(cls),
        evs.length
          ? el('details', {}, [el('summary', { text: plural(evs.length, 'recorded event') }), el('ul', { class: 'evidence' }, evs.slice(0, 50).map((ev) => evidenceRow(ev, bySeq, decoys)))])
          : el('span', { class: 'muted small', text: `Rule ${str(f.rule_id, 60)}` }),
      ]),
    ]);
  });
  // The first findings carry the verdict (the server orders them by severity); the long tail of
  // low ones folds away so the page stays short.
  const SHOWN = 5;
  const rest = items.slice(SHOWN);
  return el('section', { class: 'card', 'aria-labelledby': 'findings-title' }, [
    title,
    el('ol', { class: 'findings' }, items.slice(0, SHOWN)),
    rest.length
      ? el('details', { class: 'findings-rest' }, [el('summary', { text: `Show ${plural(rest.length, 'more finding')}` }), el('ol', { class: 'findings', start: SHOWN + 1 }, rest)])
      : null,
  ]);
}

// Tabs --------------------------------------------------------------------------------------------

function renderTabs(tabs) {
  if (tabs.length === 0) return null;
  const list = el('div', { class: 'tablist', role: 'tablist', 'aria-label': 'Details' });
  const panels = [];
  const buttons = tabs.map((t, i) => {
    const btn = el('button', { type: 'button', class: 'tab', role: 'tab', id: `tab-${t.id}`, 'aria-controls': `panel-${t.id}`, 'aria-selected': i === 0 ? 'true' : 'false', tabindex: i === 0 ? '0' : '-1' }, [
      t.label,
      typeof t.count === 'number' ? el('span', { class: 'count', text: `${t.count}` }) : null,
    ]);
    const panel = el('div', { class: 'tabpanel', role: 'tabpanel', id: `panel-${t.id}`, 'aria-labelledby': `tab-${t.id}`, tabindex: '0', hidden: i !== 0 }, t.panel);
    panels.push(panel);
    return btn;
  });
  const select = (i, focus = false) => {
    buttons.forEach((b, j) => {
      b.setAttribute('aria-selected', i === j ? 'true' : 'false');
      b.tabIndex = i === j ? 0 : -1;
      panels[j].hidden = i !== j;
    });
    if (focus) buttons[i].focus();
  };
  buttons.forEach((b, i) => {
    b.addEventListener('click', () => select(i));
    b.addEventListener('keydown', (e) => {
      const n = buttons.length;
      const next = e.key === 'ArrowRight' ? (i + 1) % n : e.key === 'ArrowLeft' ? (i - 1 + n) % n : e.key === 'Home' ? 0 : e.key === 'End' ? n - 1 : -1;
      if (next === -1) return;
      e.preventDefault();
      select(next, true);
    });
  });
  list.append(...buttons);
  return el('section', { class: 'tabs', 'aria-label': 'Details of this run' }, [list, ...panels]);
}

// Layers and input --------------------------------------------------------------------------------

const METHOD_LABEL = {
  base64: 'base64', base64_utf16le: 'base64 (UTF-16, PowerShell style)', hex: 'hex', hex_escape: 'hex escapes', url: 'URL encoding',
  gzip: 'gzip', deflate: 'deflate', deflate_raw: 'raw deflate', vars: 'variable substitution', concat: 'string concatenation',
  harness: 'run with execution disabled',
};

function renderLayers(layers, input) {
  const commandBlock = el('div', {}, [
    el('h3', { style: 'margin-bottom:8px', text: 'The command exactly as pasted' }),
    el('pre', { class: 'cmd-box', text: str(input.command, 16384) }),
  ]);
  if (layers.length === 0) {
    return [el('p', { class: 'muted', text: 'The command was not encoded or wrapped; what you see is what ran.' }), commandBlock];
  }
  const items = layers.map((l) => {
    const method = str(l.method, 30);
    const markers = obj(l.markers);
    const markerText = [
      arr(markers.exec).length ? `runs code: ${arr(markers.exec).slice(0, 5).map((m) => str(m, 30)).join(', ')}` : '',
      arr(markers.remote).length ? `fetches from the network: ${arr(markers.remote).slice(0, 5).map((m) => str(m, 30)).join(', ')}` : '',
      arr(markers.decode).length ? `decodes more data: ${arr(markers.decode).slice(0, 5).map((m) => str(m, 30)).join(', ')}` : '',
    ].filter(Boolean);
    return el('li', { class: 'layer' }, [
      el('div', { class: 'layer-head' }, [
        el('strong', { text: `Layer ${str(l.index, 4)}` }),
        el('span', { class: 'tag', text: METHOD_LABEL[method] ?? method }),
        l.llm_assisted ? el('span', { class: 'tag', text: 'unwrapped with a language model' }) : null,
        l.status && l.status !== 'ok' ? el('span', { class: 'tag', text: str(l.status, 20) }) : null,
        typeof l.bytes_len === 'number' ? el('span', { class: 'muted small', text: fmtBytes(l.bytes_len) }) : null,
      ]),
      l.text || l.preview ? el('pre', { text: str(l.text ?? l.preview, 4096) + (l.truncated || (l.text ?? '').length > 4096 ? '\n…' : '') }) : el('p', { class: 'muted small', text: str(l.reason, 200) || 'No text for this layer.' }),
      markerText.length ? el('p', { class: 'layer-markers', text: `Signs in this layer: ${markerText.join('; ')}` }) : null,
    ]);
  });
  return [
    el('p', { class: 'muted', text: 'The command hid code behind encoding. Each layer below is what the previous one would have executed; nothing here was run outside the sandbox.' }),
    el('ol', { class: 'layers' }, items),
    el('div', { style: 'margin-top:16px' }, commandBlock),
  ];
}

// Decoys ------------------------------------------------------------------------------------------

function renderDecoys(decoys, events) {
  const leaked = new Set(events.filter((e) => e.kind === 'canary.hit').map((e) => e.decoy_id));
  const read = new Set(events.filter((e) => e.kind === 'file.open' && e.decoy_id).map((e) => e.decoy_id));
  const list = [...decoys.values()];
  if (list.length === 0) return el('p', { class: 'muted', text: 'No decoy manifest was recorded for this run.' });
  const stateOf = (d) => (leaked.has(d.id) ? 'leaked' : read.has(d.id) ? 'read' : 'untouched');
  const order = { leaked: 0, read: 1, untouched: 2 };
  list.sort((a, b) => order[stateOf(a)] - order[stateOf(b)]);
  const touched = list.filter((d) => stateOf(d) !== 'untouched');
  const untouched = list.filter((d) => stateOf(d) === 'untouched');
  const row = (d) => {
    const state = stateOf(d);
    return el('li', { class: `decoy is-${state}` }, [
      el('span', { class: 'path', text: homePath(d.path) || str(d.id, 40) }),
      el('span', { class: 'cat', text: `fake ${categoryLabel(d.category)}` }),
      el('span', { class: 'state', text: state === 'leaked' ? 'sent out' : state === 'read' ? 'opened' : 'untouched' }),
      d.value ? el('span', { class: 'val', text: `token ${str(d.value, 64)}` }) : null,
    ]);
  };
  const touchedText = touched.length === 0 ? 'The command touched none of them.' : `The command touched ${touched.length} of them:`;
  return [
    el('p', { class: 'decoy-intro', text: `Every credential in this sandbox was created for this run: ${plural(list.length, 'decoy file')} with random tokens that are worthless anywhere else. No container ever held a real secret. ${touchedText}` }),
    touched.length ? el('ul', { class: 'decoys' }, touched.map(row)) : null,
    untouched.length
      ? el('details', { class: 'decoys-rest', open: touched.length === 0 ? true : null }, [
          el('summary', { text: touched.length ? `${untouched.length} other fake ${untouched.length === 1 ? 'credential was' : 'credentials were'} not touched` : `All ${untouched.length} fake credentials` }),
          el('ul', { class: 'decoys' }, untouched.map(row)),
        ])
      : null,
  ];
}

// Every event -------------------------------------------------------------------------------------

const FILTERS = [
  ['all', 'All', () => true],
  ['flagged', 'Flagged', (e) => e.classification === 'forbidden' || e.classification === 'unexplained' || e.kind === 'canary.hit'],
  ['network', 'Network', (e) => e.source === 'sinkhole' || e.kind === 'net.connect'],
  ['files', 'Files', (e) => e.kind === 'file.open'],
  ['programs', 'Programs', (e) => e.kind === 'proc.exec' || e.kind === 'shim.call'],
];

function renderEvents(events, bySeq, decoys) {
  if (events.length === 0) return el('p', { class: 'muted', text: 'No events were recorded.' });
  const list = el('ol', { class: 'events' });
  const filters = el('div', { class: 'event-filters', role: 'group', 'aria-label': 'Filter events' });
  const apply = (id) => {
    const [, , pred] = FILTERS.find((f) => f[0] === id) ?? FILTERS[0];
    for (const chip of filters.children) chip.setAttribute('aria-pressed', chip.dataset.id === id ? 'true' : 'false');
    clear(list);
    const shown = events.filter(pred);
    if (shown.length === 0) list.append(el('li', { class: 'muted small', style: 'padding:8px', text: 'Nothing in this group.' }));
    for (const ev of shown.slice(0, 1000)) {
      const d = describeEvent(ev, bySeq, decoys);
      list.append(el('li', { class: `event-row tone-${d.tone}` }, [
        el('span', { class: 'seq', text: `#${str(ev.seq, 6)}` }),
        el('span', { class: 'src', text: SOURCE_LABEL[ev.source] ?? str(ev.source, 12) }),
        el('div', {}, [
          el('div', { class: 'ev-text' }, [d.text, ' ', classChip(ev.classification)]),
          d.detail ? el('div', { class: 'ev-detail', text: d.detail }) : null,
        ]),
      ]));
    }
    if (shown.length > 1000) list.append(el('li', { class: 'muted small', style: 'padding:8px', text: `${shown.length - 1000} more events not shown.` }));
  };
  for (const [id, label] of FILTERS) {
    const chip = el('button', { type: 'button', class: 'chip', 'data-id': id, 'aria-pressed': 'false', text: label });
    chip.addEventListener('click', () => apply(id));
    filters.append(chip);
  }
  apply('all');
  return [filters, list];
}

// Output, timing, models ----------------------------------------------------------------------------

function renderOutput(output) {
  const out = str(output.stdout_preview, 32768);
  const err = str(output.stderr_preview, 32768);
  if (!out && !err) return null;
  return [
    el('p', { class: 'muted', text: 'What the command printed inside the sandbox.' }),
    out ? el('div', {}, [el('h3', { style: 'margin-bottom:8px', text: `Output (${fmtBytes(output.stdout_bytes ?? out.length)})` }), el('pre', { class: 'cmd-box', text: out })]) : null,
    err ? el('div', { style: 'margin-top:12px' }, [el('h3', { style: 'margin-bottom:8px', text: `Errors (${fmtBytes(output.stderr_bytes ?? err.length)})` }), el('pre', { class: 'cmd-box', text: err })]) : null,
    output.truncated ? el('p', { class: 'muted small', style: 'margin-top:8px', text: 'The output was cut at the preview limit.' }) : null,
  ];
}

function renderTiming(timing, models, coverage) {
  const steps = [
    ['queued_ms', 'Queued'], ['setup_ms', 'Setup'], ['unwrap_ms', 'Unwrap'], ['exec_ms', 'Run'], ['rules_ms', 'Rules'], ['explain_ms', 'Explain'], ['upload_ms', 'Save'], ['total_ms', 'Total'],
  ].filter(([k]) => typeof timing[k] === 'number');
  const modelLines = models
    .filter((m) => m && typeof m === 'object')
    .map((m) => `${str(m.role, 20)}: ${str(m.model, 60) || 'no model'}${m.fallback ? ' (fell back to the template)' : ''}${typeof m.calls === 'number' ? `, ${plural(m.calls, 'call')}` : ''}${typeof m.ms === 'number' ? `, ${fmtMs(m.ms)}` : ''}`);
  const cov = [
    coverage.mode ? `evidence mode ${str(coverage.mode, 20)}` : '',
    typeof coverage.gvisor_dropped === 'number' && coverage.gvisor_dropped > 0 ? `${coverage.gvisor_dropped} sandbox events dropped` : '',
    typeof coverage.decode_errors === 'number' && coverage.decode_errors > 0 ? `${coverage.decode_errors} undecodable records` : '',
    coverage.oom_killed ? 'the command ran out of memory' : '',
    coverage.scan_truncated ? 'scan truncated' : '',
    arr(coverage.tls_unreadable).length ? `${arr(coverage.tls_unreadable).length} encrypted connections not inspected` : '',
  ].filter(Boolean);
  if (steps.length === 0 && modelLines.length === 0 && cov.length === 0) return null;
  return [
    steps.length ? el('dl', { class: 'timing' }, steps.map(([k, label]) => el('div', {}, [el('dt', { text: label }), el('dd', { text: fmtMs(timing[k]) })]))) : null,
    modelLines.length ? el('p', { class: 'muted small', style: 'margin-top:14px', text: `Vultr Serverless Inference: ${modelLines.join('; ')}.` }) : null,
    cov.length ? el('p', { class: 'muted small', style: 'margin-top:6px', text: `Coverage: ${cov.join(', ')}.` }) : null,
  ];
}

load();
