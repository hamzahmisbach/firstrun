// Who started what. Turns the flat event list of a report into a tree of programs, one per sandbox
// run. No DOM here, so it can be tested on its own. The tree only arranges what was recorded: it adds
// no findings and has no part in the verdict.
//
// Events from the sandbox carry the process id. Records from the fake internet do not, because they
// come from another machine's point of view, so they go to the program that most recently opened a
// connection to that port. That is a match by time, and the page says so.

/** Clock difference allowed between the sandbox and the fake internet when matching by time. */
const CLOCK_SLACK_MS = 20;
const SINK_KINDS = new Set(['dns.query', 'http.request', 'tls.clienthello', 'tls.failed', 'tcp.connect', 'udp.datagram']);

const timeOf = (ev) => (typeof ev.t_rel_ms === 'number' ? ev.t_rel_ms : Infinity);
const seqOf = (ev) => (typeof ev.seq === 'number' ? ev.seq : Infinity);
const byTime = (a, b) => timeOf(a) - timeOf(b) || seqOf(a) - seqOf(b);
const attemptOf = (ev) => (ev.attempt === 2 ? 2 : 1);

function sinkPort(ev) {
  if (ev.kind === 'dns.query') return 53;
  if (ev.kind === 'tcp.connect' || ev.kind === 'udp.datagram') return ev.orig_dst_port;
  return ev.port;
}

/** The test behind the report's "Flagged" filter. */
export function isFlagged(ev) {
  return ev.classification === 'forbidden' || ev.classification === 'unexplained' || ev.kind === 'canary.hit';
}

/** 2 for something forbidden or a fake key leaving, 1 for something the claim does not explain, else 0. */
export function flagLevel(ev) {
  if (ev.classification === 'forbidden' || ev.kind === 'canary.hit') return 2;
  return isFlagged(ev) ? 1 : 0;
}

/** @returns {{program: string, args: string}} empty strings for a process that ran no program of its own */
export function nodeLabel(node) {
  const first = node.execs[0];
  if (first) {
    const argv = Array.isArray(first.argv) ? first.argv.map((a) => String(a ?? '')) : [];
    const path = typeof first.exe === 'string' && first.exe ? first.exe : argv[0] ?? '';
    return { program: path.split('/').filter(Boolean).pop() ?? '', args: argv.slice(1).join(' ') };
  }
  const shim = node.items.find((i) => i.type === 'event' && i.ev.kind === 'shim.call')?.ev;
  if (!shim) return { program: '', args: '' };
  return { program: String(shim.tool ?? ''), args: (Array.isArray(shim.args) ? shim.args : []).map((a) => String(a ?? '')).join(' ') };
}

function buildRun(attempt, events) {
  const nodes = new Map();
  const nodeFor = (pid) => {
    if (!nodes.has(pid)) nodes.set(pid, { pid, ppid: null, execs: [], items: [], parent: null, flag: 0, time: Infinity, hasProgram: false, isCommand: false, parentUnknown: false });
    return nodes.get(pid);
  };
  const raise = (node, ev) => {
    node.time = Math.min(node.time, timeOf(ev));
    node.flag = Math.max(node.flag, flagLevel(ev));
  };
  const place = (node, ev) => {
    node.items.push({ type: 'event', ev });
    raise(node, ev);
  };
  const unattached = [];
  const homeOfSeq = new Map();
  const connects = new Map();
  const rest = [];

  // First, everything the sandbox itself recorded. `forks` names the parent of a process that never
  // ran a program, which no proc.exec can do.
  for (const ev of events) {
    for (const link of Array.isArray(ev.forks) ? ev.forks : []) {
      if (Array.isArray(link) && Number.isInteger(link[0]) && Number.isInteger(link[1]) && nodeFor(link[0]).ppid === null) nodeFor(link[0]).ppid = link[1];
    }
    if (!Number.isInteger(ev.pid)) {
      rest.push(ev);
      continue;
    }
    const node = nodeFor(ev.pid);
    if (typeof ev.seq === 'number') homeOfSeq.set(ev.seq, node);
    if (node.ppid === null && Number.isInteger(ev.ppid)) node.ppid = ev.ppid;
    if (ev.kind === 'proc.exec') {
      node.execs.push(ev);
      node.hasProgram = true;
      raise(node, ev);
      // The first program is the node's title; a later one is the same process turning into another.
      if (node.execs.length > 1) node.items.push({ type: 'event', ev });
      continue;
    }
    if (ev.kind === 'shim.call') node.hasProgram = true;
    if (ev.kind === 'net.connect' && Number.isInteger(ev.dst_port)) {
      if (!connects.has(ev.dst_port)) connects.set(ev.dst_port, []);
      connects.get(ev.dst_port).push({ t: timeOf(ev), node });
    }
    place(node, ev);
  }

  // Then the fake internet's records, matched by time, and the fake-key alerts, which follow the
  // record they were found in.
  for (const ev of rest.filter((e) => SINK_KINDS.has(e.kind))) {
    const from = (connects.get(sinkPort(ev)) ?? []).filter((c) => c.t <= timeOf(ev) + CLOCK_SLACK_MS).pop();
    if (typeof ev.seq === 'number' && from) homeOfSeq.set(ev.seq, from.node);
    if (from) place(from.node, ev);
    else unattached.push(ev);
  }
  for (const ev of rest.filter((e) => !SINK_KINDS.has(e.kind))) {
    const home = ev.kind === 'canary.hit' ? homeOfSeq.get(ev.event_seq) : null;
    if (home) place(home, ev);
    else unattached.push(ev);
  }

  // A parent the recorder never saw gets an empty node, so its children stay together. In practice
  // that is the shell running the pasted command, whose own start is hidden as sandbox machinery.
  for (const node of [...nodes.values()]) {
    if (node.ppid !== null && node.ppid !== node.pid) nodeFor(node.ppid);
  }

  // Link children to parents. A loop from a reused process id is cut rather than followed.
  const roots = [];
  for (const node of nodes.values()) {
    let parent = node.ppid !== null && node.ppid !== node.pid ? nodes.get(node.ppid) : null;
    for (let up = parent; up; up = up.parent) {
      if (up === node) {
        parent = null;
        break;
      }
    }
    node.parent = parent ?? null;
    if (!parent) roots.push(node);
  }

  // A program marks every program above it, and an empty node takes its time from its children.
  for (const node of nodes.values()) {
    for (let up = node.parent; up && up.flag < node.flag; up = up.parent) up.flag = node.flag;
    for (let up = node.parent; up && up.time > node.time; up = up.parent) up.time = node.time;
  }

  // Everything in the sandbox descends from the pasted command's shell, so the earliest process with
  // no program of its own is that shell, and any other process with no known parent hangs under it,
  // marked as such.
  roots.sort((a, b) => a.time - b.time || a.pid - b.pid);
  const top = roots.find((n) => !n.hasProgram);
  if (top) {
    top.isCommand = true;
    for (const node of roots) {
      if (node === top) continue;
      node.parent = top;
      node.parentUnknown = true;
      top.flag = Math.max(top.flag, node.flag);
    }
  }

  // A fork that never ran a program is still running its parent's program, so what it did and what
  // it started are listed there.
  const merged = (n) => !n.hasProgram && !n.isCommand && !n.parentUnknown && n.parent !== null;
  const homeOf = (n) => {
    let home = n;
    while (merged(home)) home = home.parent;
    return home;
  };
  const shown = [];
  for (const node of nodes.values()) {
    if (!merged(node)) {
      shown.push(node);
      continue;
    }
    const home = homeOf(node);
    for (const item of node.items) home.items.push(item);
  }
  for (const node of shown) {
    if (node.parent) homeOf(node.parent).items.push({ type: 'child', node });
  }

  const itemTime = (item) => (item.type === 'child' ? item.node.time : timeOf(item.ev));
  for (const node of shown) {
    // By time; at the same moment, what the process did itself reads before what it started.
    node.items.sort((a, b) => itemTime(a) - itemTime(b) || (a.type === b.type ? 0 : a.type === 'child' ? 1 : -1) || (a.type === 'event' ? seqOf(a.ev) - seqOf(b.ev) : 0));
  }
  return {
    attempt,
    roots: top ? [top] : roots,
    unattached: unattached.sort(byTime),
    programs: shown.filter((n) => n.hasProgram).length,
  };
}

/**
 * @param {object[]} events report.events
 * @returns {{attempt: number, roots: object[], unattached: object[], programs: number}[]} one per sandbox run, in order
 */
export function buildProcessChains(events) {
  const list = (Array.isArray(events) ? events : []).filter((e) => e && typeof e === 'object').sort(byTime);
  return [...new Set(list.map(attemptOf))]
    .sort((a, b) => a - b)
    .map((attempt) => buildRun(attempt, list.filter((e) => attemptOf(e) === attempt)));
}
