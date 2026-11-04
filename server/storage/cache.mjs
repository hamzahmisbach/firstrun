// In-memory report cache (LRU 200, TTL 1 h) and the local spool /srv/firstrun/spool/<id>.json
// (section 10.4). With no Object Storage credentials the spool is the only report store.
import { mkdir, readdir, readFile, rename, stat, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { LIMITS } from '../config.mjs';
import { RUN_ID_RE } from '../run/ids.mjs';

export class ReportCache {
  #map = new Map(); // insertion order = recency (re-inserted on get)
  #max;
  #ttlMs;
  #now;

  constructor({ max = LIMITS.storage.cacheMaxReports, ttlMs = LIMITS.storage.cacheTtlMs, now = Date.now } = {}) {
    this.#max = max;
    this.#ttlMs = ttlMs;
    this.#now = now;
  }

  get size() {
    return this.#map.size;
  }

  get(id) {
    const entry = this.#map.get(id);
    if (!entry) return null;
    if (entry.expires <= this.#now()) {
      this.#map.delete(id);
      return null;
    }
    this.#map.delete(id);
    this.#map.set(id, entry);
    return entry.report;
  }

  set(id, report) {
    this.#map.delete(id);
    this.#map.set(id, { report, expires: this.#now() + this.#ttlMs });
    while (this.#map.size > this.#max) this.#map.delete(this.#map.keys().next().value);
  }

  delete(id) {
    this.#map.delete(id);
  }
}

function assertId(id) {
  if (typeof id !== 'string' || !RUN_ID_RE.test(id)) throw new TypeError('invalid run id');
  return id;
}

/** Atomic JSON files, one per run; `list()` returns {id, mtimeMs} for the janitor's retries. */
export function createSpool(dir) {
  const file = (id) => path.join(dir, `${assertId(id)}.json`);
  return {
    dir,
    async init() {
      await mkdir(dir, { recursive: true, mode: 0o750 });
    },
    async write(id, report) {
      const target = file(id);
      const tmp = `${target}.${process.pid}.tmp`;
      await writeFile(tmp, JSON.stringify(report), { mode: 0o640 });
      await rename(tmp, target);
    },
    async read(id) {
      try {
        return JSON.parse(await readFile(file(id), 'utf8'));
      } catch (err) {
        if (err.code === 'ENOENT') return null;
        throw err;
      }
    },
    async delete(id) {
      await unlink(file(id)).catch((err) => {
        if (err.code !== 'ENOENT') throw err;
      });
    },
    async list() {
      let entries;
      try {
        entries = await readdir(dir);
      } catch (err) {
        if (err.code === 'ENOENT') return [];
        throw err;
      }
      const out = [];
      for (const name of entries) {
        const m = /^([0-9A-Z]{26})\.json$/.exec(name);
        if (!m) continue;
        try {
          const info = await stat(path.join(dir, name));
          out.push({ id: m[1], mtimeMs: info.mtimeMs });
        } catch {
          // removed between readdir and stat
        }
      }
      return out;
    },
  };
}
