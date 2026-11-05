// web/ allowlist server: only known files, nothing from the request touches the filesystem.
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { ASSETS, PAGES, REPORT_PAGE, createStatic, FONTS } from '../http/static.mjs';

const RUN_ID = '7K2Q4W5E6R7T8Y9U0I1O2P3A4S';

function writeWeb(dir, { skip = null } = {}) {
  mkdirSync(dir, { recursive: true });
  const files = {
    'index.html': '<!doctype html><link href="/static/style.css?v=dev"><script src="/static/app.js?v=dev"></script>',
    'report.html': '<!doctype html><script src="/static/report.js?v=dev"></script><script src="/static/other.js?v=dev"></script>',
    'robots.txt': 'User-agent: *\nDisallow: /r/\nDisallow: /api/\n',
    'style.css': 'body{margin:0}',
    'ui.js': 'export const ui = 1;',
    'sse.js': 'export const sse = 1;',
    'app.js': 'import { ui } from "./ui.js";\nimport "./sse.js";\nimport "./nope.js";\nconsole.log("app")',
    'report.js': 'console.log("report")',
    'secret.txt': 'must never be served',
  };
  for (const [name, content] of Object.entries(files)) if (name !== skip) writeFileSync(path.join(dir, name), content);
  mkdirSync(path.join(dir, 'fonts'), { recursive: true });
  for (const name of FONTS) writeFileSync(path.join(dir, name), 'font bytes');
  mkdirSync(path.join(dir, 'sub'));
  writeFileSync(path.join(dir, 'sub', 'index.html'), 'nested');
}

describe('createStatic', () => {
  let root;
  let webDir;
  let server;
  let base;

  before(async () => {
    root = mkdtempSync(path.join(tmpdir(), 'firstrun-static-'));
    webDir = path.join(root, 'web');
    writeWeb(webDir);
    const serve = await createStatic(webDir);
    // Everything is in memory now: deleting the folder must not change any response below.
    rmSync(webDir, { recursive: true, force: true });
    server = http.createServer((req, res) => {
      const pathname = req.url.split('?')[0];
      if (serve(req, res, pathname)) return;
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end('{"error":"not_found"}');
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    rmSync(root, { recursive: true, force: true });
  });

  const get = (p, headers = {}, method = 'GET') => fetch(base + p, { method, headers });

  test('allowlist covers exactly the web files the pages need', () => {
    assert.deepEqual(Object.values(PAGES), ['index.html', 'robots.txt']);
    assert.equal(REPORT_PAGE, 'report.html');
    assert.deepEqual([...ASSETS], ['style.css', 'ui.js', 'sse.js', 'app.js', 'report.js']);
  });

  test('/ serves index.html with asset hashes substituted and no-cache', async () => {
    const r = await get('/');
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('content-type'), 'text/html; charset=utf-8');
    assert.equal(r.headers.get('cache-control'), 'no-cache');
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(r.headers.get('x-robots-tag'), null);
    const html = await r.text();
    assert.match(html, /\/static\/style\.css\?v=[0-9a-f]{8}"/);
    assert.match(html, /\/static\/app\.js\?v=[0-9a-f]{8}"/);
    assert.doesNotMatch(html, /\?v=dev/);
  });

  test('/r/<run_id> serves report.html with noindex; unknown assets keep their placeholder', async () => {
    const r = await get(`/r/${RUN_ID}`);
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('content-type'), 'text/html; charset=utf-8');
    assert.equal(r.headers.get('x-robots-tag'), 'noindex');
    assert.equal(r.headers.get('cache-control'), 'no-cache');
    const html = await r.text();
    assert.match(html, /\/static\/report\.js\?v=[0-9a-f]{8}"/);
    assert.match(html, /\/static\/other\.js\?v=dev"/);
  });

  test('/r/ with a bad id is not handled (router answers 404)', async () => {
    for (const p of ['/r/', '/r/abc', `/r/${RUN_ID.toLowerCase()}`, `/r/${RUN_ID}/`, `/r/${RUN_ID}x`, '/r/../index.html']) {
      const r = await get(p);
      assert.equal(r.status, 404, p);
      assert.equal(r.headers.get('content-type'), 'application/json', p);
    }
  });

  test('assets are served from /static/ with a one hour cache and an ETag', async () => {
    const r = await get('/static/app.js?v=whatever');
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('content-type'), 'text/javascript; charset=utf-8');
    assert.equal(r.headers.get('cache-control'), 'public, max-age=3600');
    const js = await r.text();
    assert.match(js, /^import \{ ui \} from "\.\/ui\.js\?v=[0-9a-f]{8}";\n/);
    assert.match(js, /import "\.\/sse\.js\?v=[0-9a-f]{8}";/);
    assert.match(js, /import "\.\/nope\.js";/); // not an asset: left alone
    const etag = r.headers.get('etag');
    assert.match(etag, /^"[0-9a-f]{16}"$/);
    const cached = await get('/static/app.js', { 'if-none-match': etag });
    assert.equal(cached.status, 304);
    assert.equal(await cached.text(), '');

    const css = await get('/static/style.css');
    assert.equal(css.headers.get('content-type'), 'text/css; charset=utf-8');
    const ui = await get('/static/ui.js');
    assert.equal(await ui.text(), 'export const ui = 1;');
    const font = await get('/static/fonts/plex-sans-400.woff2');
    assert.equal(font.status, 200);
    assert.equal(font.headers.get('content-type'), 'font/woff2');
    assert.equal((await get('/static/fonts/other.woff2')).status, 404);
  });

  test('a changed dependency changes the hash of the module that imports it', async () => {
    const dir = path.join(root, 'web-dep');
    writeWeb(dir);
    const before = await createStatic(dir);
    writeFileSync(path.join(dir, 'ui.js'), 'export const ui = 2;');
    const after = await createStatic(dir);
    const etagOf = (serve, p) =>
      new Promise((resolve) => {
        const res = { writeHead: (status, headers) => resolve(headers.ETag), end() {} };
        serve({ method: 'HEAD', headers: {} }, res, p);
      });
    assert.notEqual(await etagOf(before, '/static/ui.js'), await etagOf(after, '/static/ui.js'));
    assert.notEqual(await etagOf(before, '/static/app.js'), await etagOf(after, '/static/app.js'));
    assert.equal(await etagOf(before, '/static/report.js'), await etagOf(after, '/static/report.js'));
  });

  test('robots.txt disallows nothing more than it should and is plain text', async () => {
    const r = await get('/robots.txt');
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('content-type'), 'text/plain; charset=utf-8');
    assert.match(await r.text(), /Disallow: \/r\//);
  });

  test('files outside the allowlist and traversal attempts are never handled', async () => {
    const paths = [
      '/secret.txt',
      '/static/secret.txt',
      '/static/index.html',
      '/static/../secret.txt',
      '/static/..%2Fsecret.txt',
      '/static/sub/index.html',
      '/sub/index.html',
      '/index.html',
      '/report.html',
      '/static/',
      '/static',
      '/static/app.js/',
      '/STATIC/app.js',
      '/favicon.ico',
    ];
    for (const p of paths) {
      const r = await get(p);
      assert.equal(r.status, 404, p);
      assert.equal(r.headers.get('content-type'), 'application/json', p);
    }
  });

  test('HEAD returns headers only; other methods get 405 with Allow', async () => {
    const head = await get('/', {}, 'HEAD');
    assert.equal(head.status, 200);
    assert.equal(await head.text(), '');
    assert.ok(Number(head.headers.get('content-length')) > 0);

    const post = await get('/', {}, 'POST');
    assert.equal(post.status, 405);
    assert.equal(post.headers.get('allow'), 'GET, HEAD');
    const del = await get('/static/app.js', {}, 'DELETE');
    assert.equal(del.status, 405);
  });

  test('a missing allowlisted file fails at startup', async () => {
    const dir = path.join(root, 'web-missing');
    writeWeb(dir, { skip: 'sse.js' });
    await assert.rejects(createStatic(dir), /sse\.js/);
  });
});
