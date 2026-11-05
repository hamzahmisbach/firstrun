// Static files from web/ (section 10.1): an allowlist read into memory once at startup.
// No path from a request ever reaches the filesystem; a request can only select one of the
// entries below. `/` serves index.html, `/r/<run_id>` serves report.html, assets live under
// /static/ and are versioned with ?v=<hash> (the hash is substituted into the HTML at startup).
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { RUN_ID_RE } from '../run/ids.mjs';

const HTML = 'text/html; charset=utf-8';
const ASSET_TYPES = {
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
};

/** Everything the web server can ever hand out. Pages are keyed by URL path, assets by file name. */
export const PAGES = Object.freeze({ '/': 'index.html', '/robots.txt': 'robots.txt' });
export const REPORT_PAGE = 'report.html';
export const ASSETS = Object.freeze(['style.css', 'ui.js', 'sse.js', 'app.js', 'chain.js', 'report.js']);
/** Self-hosted IBM Plex (web/fonts/LICENSE-IBM-Plex.txt), so a page needs no other site. */
export const FONTS = Object.freeze([
  'fonts/plex-sans-400.woff2',
  'fonts/plex-sans-500.woff2',
  'fonts/plex-sans-600.woff2',
  'fonts/plex-sans-700.woff2',
  'fonts/plex-sans-condensed-600.woff2',
  'fonts/plex-sans-condensed-700.woff2',
  'fonts/plex-mono-400.woff2',
  'fonts/plex-mono-500.woff2',
  'fonts/plex-mono-600.woff2',
]);

const CACHE_HTML = 'no-cache';
const CACHE_ASSET = 'public, max-age=3600';
const CACHE_FONT = 'public, max-age=604800';

/**
 * Read the allowlisted files under `webDir`. Throws if one is missing, so a broken deploy fails
 * at startup instead of 404ing in front of a judge.
 * @returns {Promise<(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse, pathname: string) => boolean>}
 */
export async function createStatic(webDir) {
  const assets = new Map(); // url path -> entry
  const versions = new Map(); // file name -> short hash

  // Order matters: a module is hashed after the modules it imports (ui.js and sse.js first), so
  // `import './ui.js'` inside app.js can be rewritten to the versioned URL before app.js is hashed.
  for (const name of ASSETS) {
    const entry = await load(webDir, name, ASSET_TYPES[path.extname(name)], CACHE_ASSET, name.endsWith('.js') ? versions : null);
    assets.set(`/static/${name}`, entry);
    versions.set(name, entry.etag.slice(1, 9));
  }
  for (const name of FONTS) assets.set(`/static/${name}`, await load(webDir, name, ASSET_TYPES['.woff2'], CACHE_FONT));
  const pages = new Map();
  for (const [url, name] of Object.entries(PAGES)) {
    pages.set(url, await load(webDir, name, name.endsWith('.html') ? HTML : ASSET_TYPES['.txt'], CACHE_HTML, versions));
  }
  const report = await load(webDir, REPORT_PAGE, HTML, CACHE_HTML, versions, { 'X-Robots-Tag': 'noindex' });

  function lookup(pathname) {
    const page = pages.get(pathname);
    if (page) return page;
    const asset = assets.get(pathname);
    if (asset) return asset;
    if (pathname.startsWith('/r/') && RUN_ID_RE.test(pathname.slice(3))) return report;
    return null;
  }

  return function serveStatic(req, res, pathname) {
    const entry = lookup(pathname);
    if (!entry) return false;
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { Allow: 'GET, HEAD', 'Content-Length': 0, 'Cache-Control': 'no-store' });
      res.end();
      return true;
    }
    const headers = {
      'Content-Type': entry.type,
      'Cache-Control': entry.cache,
      ETag: entry.etag,
      'X-Content-Type-Options': 'nosniff',
      ...entry.headers,
    };
    if (req.headers['if-none-match'] === entry.etag) {
      res.writeHead(304, headers);
      res.end();
      return true;
    }
    res.writeHead(200, { ...headers, 'Content-Length': entry.body.length });
    res.end(req.method === 'HEAD' ? undefined : entry.body);
    return true;
  };
}

async function load(webDir, name, type, cache, versions = null, headers = {}) {
  let body = await readFile(path.join(webDir, name));
  if (versions) body = Buffer.from(applyVersions(body.toString('utf8'), versions), 'utf8');
  const etag = `"${createHash('sha256').update(body).digest('hex').slice(0, 16)}"`;
  return { body, type, cache, etag, headers };
}

/**
 * `/static/<asset>?v=<anything>` in a page, and `'./<asset>.js'` import specifiers in a module,
 * become URLs carrying `?v=<hash of that asset>`, so a one hour cache never serves a stale pair.
 */
function applyVersions(text, versions) {
  return text
    .replace(/\/static\/([A-Za-z0-9_.-]+)\?v=[A-Za-z0-9]*/g, (match, name) =>
      versions.has(name) ? `/static/${name}?v=${versions.get(name)}` : match,
    )
    .replace(/(['"])\.\/([A-Za-z0-9_-]+\.js)\1/g, (match, quote, name) =>
      versions.has(name) ? `${quote}./${name}?v=${versions.get(name)}${quote}` : match,
    );
}
