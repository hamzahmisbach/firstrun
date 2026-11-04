// EventSource wrapper for GET /api/runs/:id/events (section 10.1 "Reconnect", 10.2).
// - opens with ?after=<n> so a reload does not replay what the page already has
// - the browser reconnects by itself with Last-Event-ID; we only show "reconnecting"
// - run.done / run.error close the stream (otherwise EventSource would reconnect forever)
// - a 204 (buffer gone) or any non-200 closes the stream; the caller then fetches the report

export const EVENT_NAMES = [
  'run.queued',
  'run.started',
  'unwrap.layer',
  'contract.ready',
  'exec.started',
  'evidence',
  'alert',
  'exec.finished',
  'teardown',
  'verdict',
  'explanation',
  'run.done',
  'run.error',
];

const TERMINAL = new Set(['run.done', 'run.error']);

/**
 * @param {string} runId
 * @param {{after?: number, onEvent: (name: string, data: object, id: number) => void,
 *          onReconnecting?: (on: boolean) => void, onClosed?: (reason: 'done'|'gone') => void}} opts
 * @returns {{close: () => void, lastId: () => number}}
 */
export function openRunStream(runId, opts) {
  let lastId = opts.after ?? 0;
  let closed = false;
  let ended = false;
  const url = `/api/runs/${encodeURIComponent(runId)}/events${lastId > 0 ? `?after=${lastId}` : ''}`;
  const es = new EventSource(url);

  function finish(reason) {
    if (closed) return;
    closed = true;
    es.close();
    opts.onReconnecting?.(false);
    opts.onClosed?.(reason);
  }

  for (const name of EVENT_NAMES) {
    es.addEventListener(name, (msg) => {
      if (closed) return;
      const id = Number(msg.lastEventId);
      if (Number.isFinite(id) && id > 0) {
        if (id <= lastId) return; // replayed duplicate after a reconnect
        lastId = id;
      }
      let data;
      try {
        data = JSON.parse(msg.data);
      } catch {
        return;
      }
      if (!data || typeof data !== 'object') return;
      opts.onReconnecting?.(false);
      opts.onEvent(name, data, id);
      if (TERMINAL.has(name)) {
        ended = true;
        finish('done');
      }
    });
  }

  es.addEventListener('open', () => opts.onReconnecting?.(false));
  es.addEventListener('error', () => {
    if (closed) return;
    if (es.readyState === EventSource.CLOSED) {
      // 204 (run finished, buffer dropped), 404, 429 or a fatal transport error: no automatic retry.
      finish(ended ? 'done' : 'gone');
    } else {
      opts.onReconnecting?.(true);
    }
  });

  return {
    close: () => finish('done'),
    lastId: () => lastId,
  };
}

/** GET /api/runs/:id -> {ok, status, data} with the JSON error body on failure. */
export async function fetchRun(runId) {
  let res;
  try {
    res = await fetch(`/api/runs/${encodeURIComponent(runId)}`, { headers: { accept: 'application/json' } });
  } catch {
    return { ok: false, status: 0, data: { error: 'network', message: '' } };
  }
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  return { ok: res.ok, status: res.status, data: data ?? { error: res.ok ? 'internal' : 'internal', message: '' } };
}
