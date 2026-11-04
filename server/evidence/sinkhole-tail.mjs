// Tail of the sinkhole directory (7.2): events.jsonl and tcp.jsonl are JSON lines written by the
// mitmproxy addon and tcpsink.py; dns.log is dnsmasq's text log, of which only `query[...]` lines
// are events. Every record is handed to `onRecord` as a plain object with a `kind`.
import path from 'node:path';
import { createFileTail } from './sink-reader.mjs';
import { EVIDENCE_LIMITS } from './schema.mjs';

const DNS_QUERY_RE = /query\[([A-Za-z0-9]+)\]\s+(\S+)\s+from\s+(\S+)/;

/** `dnsmasq[15]: query[A] example.test from 10.213.0.18` -> record, or null for other lines. */
export function parseDnsLine(line, now = Date.now()) {
  const m = DNS_QUERY_RE.exec(line);
  if (!m) return null;
  return { kind: 'dns.query', name: m[2], qtype: m[1].toUpperCase(), client: m[3], ts_ms: now, ts_src: 'arrival' };
}

export function createSinkholeTail({ sinkholeDir, onRecord, onError = () => {}, pollMs = EVIDENCE_LIMITS.tail.sinkholePollMs }) {
  let decodeErrors = 0;
  const jsonLine = (line) => {
    let record;
    try {
      record = JSON.parse(line);
    } catch {
      decodeErrors += 1;
      return;
    }
    if (!record || typeof record !== 'object' || typeof record.kind !== 'string') {
      decodeErrors += 1;
      return;
    }
    onRecord(record);
  };
  const tails = [
    createFileTail(path.join(sinkholeDir, 'events.jsonl'), { pollMs, onLine: jsonLine, onError }),
    createFileTail(path.join(sinkholeDir, 'tcp.jsonl'), { pollMs, onLine: jsonLine, onError }),
    createFileTail(path.join(sinkholeDir, 'dns.log'), {
      pollMs,
      onError,
      onLine(line) {
        const record = parseDnsLine(line);
        if (record) onRecord(record);
      },
    }),
  ];
  return {
    start() {
      for (const t of tails) t.start();
    },
    async drain() {
      for (const t of tails) await t.drain();
    },
    async stop() {
      for (const t of tails) await t.stop();
    },
    decodeErrors: () => decodeErrors,
  };
}
