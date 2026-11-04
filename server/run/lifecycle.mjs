// ============================================================================================
// STUB LIFECYCLE (day 1). NOTHING IS EXECUTED: no Docker, no sandbox, no LLM, no S3.
// It walks the phases with short sleeps, emits the SSE events the UI expects, and hands back an
// in-memory fake report marked `stub: true` so the API and SSE can be exercised end to end.
//
// TODO(day 2): replace with the real lifecycle, docs/ARCHITECTURE.md section 4 steps 3-13:
//   3  run dir /srv/firstrun/runs/<id>/{seed,work,sinkhole}; command -> work/cmd.sh via fs.writeFile
//   4  canary + seed HOME, decoys.json (5.3)
//   5  deterministic decoder (8.2) -> SSE unwrap.layer
//   6  in parallel: network + sinkhole, claim-to-contract LLM (contract.ready), harness loop (8.3)
//   7  docker run sandbox (5.1) via run/docker.mjs only: execFile, shell:false, MINIMAL_ENV
//   8  evidence from sidecar + sinkhole tail -> SSE evidence / alert
//   9  timeout -s KILL 60 inside, watchdog docker kill at 75 s -> SSE exec.finished
//   10 teardown in finally (docker rm -f, network rm, rm seed/ work/) + janitor
//   11 rules (section 9) -> SSE verdict
//   12 explanation LLM or template -> SSE explanation
//   13 report (10.3) -> S3 PUT + cache -> ctx.done(report) emits run.done
// Contract with the caller (http/routes.mjs): call ctx.done(report) once, or throw (a RunError
// for a known failure code); the caller turns anything else into run.error {code: "internal"}.
// ============================================================================================
import { setTimeout as sleep } from 'node:timers/promises';
import { LIMITS } from '../config.mjs';

/** A failure with a run.error code from section 10.2 (sandbox_start_failed, internal, ...). */
export class RunError extends Error {
  constructor(code, message, { stage = null, retryable = false } = {}) {
    super(message);
    this.code = code;
    this.stage = stage;
    this.retryable = retryable;
  }
}

export const STUB_NOTE =
  'STUB: this day-1 build did not execute the command; the verdict below is a placeholder, not an analysis.';

/**
 * @param {{stepMs?: number}} [opts] delay per phase, so the timeline is visible in the UI
 * @returns {(run: object, ctx: object) => Promise<void>}
 */
export function createStubLifecycle({ stepMs = 150 } = {}) {
  return async function runStubLifecycle(run, ctx) {
    const timing = { queued_ms: Date.now() - run.created_ms };
    let mark = Date.now();
    const lap = (key) => {
      const now = Date.now();
      timing[key] = now - mark;
      mark = now;
    };

    ctx.emit('run.started', { sample_id: run.sample_id, command_sha256: run.command_sha256, claim: run.input.claim });

    ctx.phase('setup');
    await sleep(stepMs);
    lap('setup_ms');

    ctx.phase('unwrap');
    await sleep(stepMs);
    lap('unwrap_ms');

    ctx.phase('exec');
    ctx.emit('exec.started', { container_id: null, timeout_s: LIMITS.sandbox.execTimeoutS });
    await sleep(stepMs);
    lap('exec_ms');
    ctx.emit('exec.finished', {
      exit_code: 0,
      timed_out: false,
      killed_by: null,
      duration_ms: timing.exec_ms,
      stdout_bytes: 0,
      stderr_bytes: 0,
    });

    ctx.phase('rules');
    await sleep(stepMs);
    lap('rules_ms');
    const verdict = {
      level: 'CLEAN',
      rule_ids: [],
      coverage_notes: [
        STUB_NOTE,
        'CLEAN means nothing suspicious was observed in this run (Linux sandbox, 60 s, no internet), not proof that the command is safe.',
      ],
    };
    ctx.emit('verdict', { verdict, findings: [] });

    ctx.phase('explain');
    await sleep(stepMs);
    lap('explain_ms');

    ctx.phase('upload');
    await sleep(stepMs);
    lap('upload_ms');
    timing.total_ms = Date.now() - run.created_ms;

    ctx.done(buildStubReport(run, verdict, timing));
  };
}

/** Fake report in the section 10.3 shape, clearly marked as a stub. */
function buildStubReport(run, verdict, timing) {
  return {
    schema_version: 1,
    stub: true,
    run_id: run.run_id,
    created_at: run.created_at,
    input: run.input,
    layers: [],
    contract: {
      summary: '',
      expected_hosts: [],
      expected_write_paths: [],
      expected_processes: [],
      allowed_decoy_categories: [],
      notes: 'stub: no contract was generated',
    },
    contract_meta: { source: 'fallback', prompt_version: 'stub' },
    events: [],
    findings: [],
    verdict,
    explanation: {
      verdict_echo: verdict.level,
      headline: 'Stub run: the command was not executed',
      paragraphs: [STUB_NOTE],
      finding_notes: [],
      next_step: 'Do not rely on this report; it only exercises the API and the timeline.',
    },
    explanation_meta: { source: 'template' },
    decoys: [],
    coverage: {
      timed_out: false,
      tls_unreadable: [],
      notes: [STUB_NOTE],
      mode: 'stub',
      gvisor_dropped: 0,
      decode_errors: 0,
      pre_t0: 0,
      dedup: 0,
      capped: {},
      scan_truncated: false,
      oom_killed: false,
    },
    output: { stdout_preview: '', stderr_preview: '', stdout_bytes: 0, stderr_bytes: 0, truncated: false },
    timing: {
      queued_ms: timing.queued_ms,
      setup_ms: timing.setup_ms,
      unwrap_ms: timing.unwrap_ms,
      exec_ms: timing.exec_ms,
      rules_ms: timing.rules_ms,
      explain_ms: timing.explain_ms,
      upload_ms: timing.upload_ms,
      total_ms: timing.total_ms,
    },
    models_used: [],
  };
}
