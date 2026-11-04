// Report storage facade (section 10.4): memory cache -> local spool -> Object Storage.
// mode "s3": PUT to the bucket, spool on failure (janitor retries for a day).
// mode "local": no FIRSTRUN_S3_* credentials; the spool is the report store and nothing expires.
// Either way a run never fails because of Object Storage unless the spool is unwritable too.
import { LIMITS } from '../config.mjs';
import { ReportCache, createSpool } from './cache.mjs';
import { StorageUnavailable, createS3 } from './s3.mjs';

export { StorageUnavailable };

/**
 * @param {object} opts
 * @param {ReturnType<import('../config.mjs').loadConfig>} opts.config
 * @param {Function} [opts.log]
 * @param {object} [opts.s3]  a pre-built S3 wrapper (tests)
 * @param {() => number} [opts.now]
 */
export async function createStorage({ config, log = () => {}, s3 = undefined, now = Date.now }) {
  const cache = new ReportCache({ now });
  const spool = createSpool(config.spoolDir);
  await spool.init();
  const remote = s3 === undefined ? (config.s3 ? await createS3(config.s3) : null) : s3;
  const mode = remote ? 's3' : 'local';
  let health = { status: null, checkedMs: 0 };

  async function putReport(id, report) {
    cache.set(id, report);
    if (remote) {
      try {
        await remote.putReport(id, report);
        return { where: 's3' };
      } catch (err) {
        log({ level: 'warn', msg: 'storage.put_failed', run_id: id, err: err?.message ?? String(err) });
      }
    }
    await spool.write(id, report); // throws -> the lifecycle reports storage_failed
    return { where: 'spool' };
  }

  async function getReport(id) {
    const cached = cache.get(id);
    if (cached) return cached;
    const spooled = await spool.read(id);
    if (spooled) {
      cache.set(id, spooled);
      return spooled;
    }
    if (!remote) return null;
    const report = await remote.getReport(id); // throws StorageUnavailable
    if (report) cache.set(id, report);
    return report;
  }

  async function deleteReport(id) {
    cache.delete(id);
    await spool.delete(id);
    if (remote) await remote.deleteReport(id);
  }

  /** Janitor (s3 mode): re-upload spooled reports; drop the ones older than a day. */
  async function retrySpool() {
    if (!remote) return { uploaded: 0, dropped: 0, pending: 0 };
    let uploaded = 0;
    let dropped = 0;
    let pending = 0;
    for (const { id, mtimeMs } of await spool.list()) {
      const report = await spool.read(id);
      if (!report) continue;
      try {
        await remote.putReport(id, report);
        await spool.delete(id);
        uploaded += 1;
      } catch (err) {
        if (now() - mtimeMs > LIMITS.storage.spoolMaxAgeMs) {
          await spool.delete(id);
          dropped += 1;
          log({ level: 'warn', msg: 'storage.spool_dropped', run_id: id });
        } else {
          pending += 1;
        }
      }
    }
    return { uploaded, dropped, pending };
  }

  /** Delete reports older than ttlDays (s3 mode; local reports stay until an admin deletes them). */
  async function retention(ttlDays = config.reportTtlDays) {
    if (!remote) return { deleted: 0 };
    const cutoff = now() - ttlDays * 24 * 3600 * 1000;
    let deleted = 0;
    for (const { id, lastModified } of await remote.listReports()) {
      if (lastModified.getTime() >= cutoff) continue;
      await remote.deleteReport(id);
      cache.delete(id);
      deleted += 1;
    }
    return { deleted };
  }

  /** "ok" | "local" | "degraded" for /healthz; HeadBucket cached 5 minutes. */
  async function check() {
    if (!remote) return 'local';
    if (now() - health.checkedMs < LIMITS.storage.headBucketCacheMs && health.status) return health.status;
    let status = 'ok';
    try {
      await remote.headBucket();
    } catch (err) {
      status = 'degraded';
      log({ level: 'warn', msg: 'storage.head_bucket_failed', err: err?.message ?? String(err) });
    }
    health = { status, checkedMs: now() };
    return status;
  }

  return { mode, cache, spool, remote, putReport, getReport, deleteReport, retrySpool, retention, check };
}
