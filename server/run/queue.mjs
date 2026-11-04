// Global semaphore (2 runs in parallel) with a bounded FIFO of waiting runs (8), section 4 step 2.
// Position 0 = running, 1 = next in line. run.queued is emitted on enqueue and again with the new
// position whenever the line moves.
import { LIMITS } from '../config.mjs';

export class QueueFullError extends Error {
  constructor() {
    super('queue full');
    this.code = 'queue_full';
  }
}

export class RunQueue {
  #concurrency;
  #maxWaiting;
  #execute;
  #emit;
  #onCrash;
  #waiting = [];
  #active = new Set();
  #closed = false;
  #idleWaiters = [];

  /**
   * @param {object} opts
   * @param {(run: object) => Promise<void>} opts.execute  runs one run to completion; should not throw
   * @param {(run: object, event: string, fields: object) => void} opts.emit  SSE publish
   * @param {(run: object, err: unknown) => void} [opts.onCrash]  execute() threw anyway
   */
  constructor({ concurrency = LIMITS.queue.concurrency, maxWaiting = LIMITS.queue.maxWaiting, execute, emit, onCrash = () => {} }) {
    this.#concurrency = concurrency;
    this.#maxWaiting = maxWaiting;
    this.#execute = execute;
    this.#emit = emit;
    this.#onCrash = onCrash;
  }

  get active() {
    return this.#active.size;
  }

  get waiting() {
    return this.#waiting.length;
  }

  isFull() {
    return this.#active.size >= this.#concurrency && this.#waiting.length >= this.#maxWaiting;
  }

  /** Returns the position (0 = starts now). Throws QueueFullError, or Error when closed. */
  enqueue(run) {
    if (this.#closed) throw new Error('queue closed');
    if (this.isFull()) throw new QueueFullError();
    this.#waiting.push(run);
    this.#pump(false);
    const position = this.position(run.run_id);
    this.#emit(run, 'run.queued', { position, queue_len: this.#waiting.length });
    return position;
  }

  /** 0 when running, 1.. when waiting, null when unknown or finished. */
  position(runId) {
    for (const run of this.#active) if (run.run_id === runId) return 0;
    const i = this.#waiting.findIndex((r) => r.run_id === runId);
    return i === -1 ? null : i + 1;
  }

  /** Stop accepting runs; returns the runs that were still waiting (the caller fails them). */
  close() {
    this.#closed = true;
    return this.#waiting.splice(0);
  }

  /** Resolves when no run is active. */
  idle() {
    return this.#active.size === 0 ? Promise.resolve() : new Promise((resolve) => this.#idleWaiters.push(resolve));
  }

  #pump(notify) {
    let moved = false;
    while (this.#active.size < this.#concurrency && this.#waiting.length > 0) {
      const run = this.#waiting.shift();
      this.#active.add(run);
      moved = true;
      // Start on a later tick so run.queued is always published before anything the run emits.
      Promise.resolve()
        .then(() => this.#execute(run))
        .catch((err) => this.#onCrash(run, err))
        .finally(() => {
          this.#active.delete(run);
          this.#pump(true);
          if (this.#active.size === 0) for (const resolve of this.#idleWaiters.splice(0)) resolve();
        });
    }
    if (notify && moved) {
      this.#waiting.forEach((run, i) =>
        this.#emit(run, 'run.queued', { position: i + 1, queue_len: this.#waiting.length }),
      );
    }
  }
}
