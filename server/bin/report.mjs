#!/usr/bin/env node
// Admin tool for reports on the VM (section 10.4). Run with the service's environment:
//   sudo -u firstrun node --env-file=/etc/firstrun/firstrun.env /opt/firstrun/server/bin/report.mjs <cmd>
//   get <run_id>      print the report JSON (cache -> spool -> Object Storage)
//   delete <run_id>   DeleteObject + remove the spool copy (the running server's cache expires within 1 h)
//   retention         delete objects older than FIRSTRUN_REPORT_TTL_DAYS (s3 mode)
//   selftest          PutObject + GetObject + DeleteObject of selftest/<ts>.json (s3 mode)
import { loadConfig } from '../config.mjs';
import { RUN_ID_RE } from '../run/ids.mjs';
import { createStorage } from '../storage/index.mjs';

const [cmd, arg] = process.argv.slice(2);
const usage = () => {
  process.stderr.write('usage: report.mjs get <run_id> | delete <run_id> | retention | selftest\n');
  process.exit(2);
};
if (!['get', 'delete', 'retention', 'selftest'].includes(cmd)) usage();
if ((cmd === 'get' || cmd === 'delete') && !(typeof arg === 'string' && RUN_ID_RE.test(arg))) usage();

const config = loadConfig(process.env);
const storage = await createStorage({ config, log: (r) => process.stderr.write(`${JSON.stringify(r)}\n`) });

try {
  if (cmd === 'get') {
    const report = await storage.getReport(arg);
    if (!report) {
      process.stderr.write('not found\n');
      process.exit(1);
    }
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else if (cmd === 'delete') {
    await storage.deleteReport(arg);
    process.stdout.write(`deleted ${arg} (${storage.mode})\n`);
  } else if (cmd === 'retention') {
    const r = await storage.retention();
    process.stdout.write(`${JSON.stringify({ mode: storage.mode, ...r })}\n`);
  } else if (cmd === 'selftest') {
    if (!storage.remote) {
      process.stdout.write('mode local: no FIRSTRUN_S3_* credentials, nothing to test; reports live in the spool\n');
    } else {
      const key = await storage.remote.selftest();
      process.stdout.write(`ok: put/get/delete ${key} on bucket ${storage.remote.bucket}\n`);
    }
  }
} catch (err) {
  process.stderr.write(`${cmd} failed: ${err?.message ?? String(err)}\n`);
  process.exit(1);
}
