// Section 11 "Tidak ada shell di host": no child_process.exec*, no shell option other than false,
// and child_process only in run/docker.mjs (the single execFile("/usr/bin/docker") call site).
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const ALLOWED_CHILD_PROCESS = new Set([path.join('run', 'docker.mjs')]);

function sources(dir, rel = '') {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    if (e.name === 'node_modules' || e.name === 'test' || e.name.startsWith('.')) return [];
    const relPath = path.join(rel, e.name);
    if (e.isDirectory()) return sources(path.join(dir, e.name), relPath);
    return /\.(mjs|cjs|js)$/.test(e.name) ? [relPath] : [];
  });
}

test('no shell anywhere in server code', () => {
  const files = sources(ROOT);
  assert.ok(files.includes('main.mjs') && files.length >= 9, `scanned ${files.length} files`);
  for (const file of files) {
    const text = readFileSync(path.join(ROOT, file), 'utf8');
    assert.doesNotMatch(text, /shell\s*:\s*(?!false\b)/, `${file}: shell option must be false`);
    assert.doesNotMatch(text, /\bexecSync\b|\bspawnSync\b/, `${file}: no sync process APIs`);
    assert.doesNotMatch(text, /child_process['"]\s*\)?\s*\.\s*exec\b/, `${file}: child_process.exec`);
    assert.doesNotMatch(text, /\{[^}]*\bexec\b[^}]*\}\s*from\s*['"](node:)?child_process['"]/, `${file}: imports exec`);
    if (/['"](node:)?child_process['"]/.test(text)) {
      assert.ok(ALLOWED_CHILD_PROCESS.has(file), `${file}: only run/docker.mjs may use child_process`);
    }
  }
});
