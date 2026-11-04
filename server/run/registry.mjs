// In-memory run state: queued -> running (phase) -> done | error (section 10.1 notes).
// Finished runs stay for LIMITS.runs.retainAfterEndMs, then GET /api/runs/:id answers 404.
// Day 1 keeps the (stub) report here too; storage/cache.mjs + S3 take that over later.
import { LIMITS } from '../config.mjs';

export class RunRegistry {
  #runs = new Map(); // insertion order = creation order
  #opts;
  #now;
  #timer;

  constructor({ now = Date.now, ...opts } = {}) {
    this.#opts = { ...LIMITS.runs, ...opts };
    this.#now = now;
    this.#timer = setInterval(() => this.sweep(), this.#opts.sweepEveryMs);
    this.#timer.unref();
  }

  add(run) {
    if (this.#runs.has(run.run_id)) throw new Error('duplicate run_id');
    this.#runs.set(run.run_id, run);
    return run;
  }

  get(runId) {
    return this.#runs.get(runId);
  }

  has(runId) {
    return this.#runs.has(runId);
  }

  /** Forget finished runs past retention, and the oldest finished ones beyond maxFinished. */
  sweep() {
    const cutoff = this.#now() - this.#opts.retainAfterEndMs;
    const finished = [];
    for (const run of this.#runs.values()) {
      if (run.ended_ms === null) continue;
      if (run.ended_ms <= cutoff) this.#runs.delete(run.run_id);
      else finished.push(run);
    }
    finished.sort((a, b) => a.ended_ms - b.ended_ms);
    for (const run of finished.slice(0, Math.max(0, finished.length - this.#opts.maxFinished))) {
      this.#runs.delete(run.run_id);
    }
  }

  close() {
    clearInterval(this.#timer);
  }
}
