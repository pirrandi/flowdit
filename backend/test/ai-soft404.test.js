// Soft-404 classifier: a response is "not found" when it looks like what the
// target serves for a random path that cannot exist under the same prefix.
// Pure rules (matchesBaseline) plus the probing/caching (notFoundReason) with
// the target's HTTP mocked through globalThis.fetch. No DB involved.
const { test, beforeEach, mock } = require('node:test');
const assert = require('node:assert/strict');
const { matchesBaseline, notFoundReason, clearBaselineCache, probePrefix } = require('../src/services/ai/soft404');

beforeEach(() => clearBaselineCache());

const SPA_INDEX = `<!doctype html><html><head><title>App</title><link href="/static/css/main.3f2a91bc.css" rel="stylesheet"></head><body><div id="root"></div>${'<!-- padding -->'.repeat(60)}<script src="/static/js/main.a1b2c3d4.js"></script></body></html>`;

const html = { 'content-type': 'text/html; charset=utf-8' };
const json = { 'content-type': 'application/json' };
const target = { id: 't1', host: 'app.example.test' };

function res(status, body, headers = {}) {
  return new Response(status === 204 || status === 304 ? null : body, { status, headers });
}

// Answers by pathname; `/fd404-` probes are routed through `probe(pathname)`.
function mockTarget(routes, probe) {
  return mock.method(globalThis, 'fetch', async url => {
    const { pathname } = new URL(url);
    if (pathname.includes('/fd404-')) return probe(pathname);
    const r = routes[pathname];
    return r ? r() : res(404, 'not found', { 'content-type': 'text/plain' });
  });
}

async function judge(path) {
  const url = `https://app.example.test${path}`;
  const response = await fetch(url, { redirect: 'manual' });
  const body = await response.text();
  return notFoundReason(target, 'https', url, path, response, body);
}

test('the probe prefix is the first segment, or the root for single-segment paths', () => {
  assert.equal(probePrefix('/api/v1/users'), '/api');
  assert.equal(probePrefix('/api/'), '');
  assert.equal(probePrefix('/admin'), '');
});

test('SPA catch-all: a 200 html identical to the random path is a soft 404', async () => {
  // Every path answers the same index.html — the random one included.
  const http = mock.method(globalThis, 'fetch', async () => res(200, SPA_INDEX, html));
  try {
    assert.equal(await judge('/static/js'), 'soft_404');
    assert.equal(await judge('/a'), 'soft_404', 'a short path stripped from both sides still matches');
  } finally {
    http.mock.restore();
  }
});

test('a catch-all page that echoes the requested path is still a soft 404', () => {
  const page = p => `<html><body><h1>Nothing at ${p}</h1><p>request id 7f3a9c21e4b0</p>${'x'.repeat(100)}</body></html>`;
  const baseline = { status: 200, contentType: 'text/html', location: null, probePath: '/fd404-0a1b2c3d4e5f', body: page('/fd404-0a1b2c3d4e5f').replace('7f3a9c21e4b0', '99aa00bb11cc') };
  assert.equal(matchesBaseline(baseline, { status: 200, contentType: 'text/html; charset=utf-8', location: null, body: page('/admin/backup'), paths: ['/admin/backup'] }), true);
  // URL-encoded echo too.
  const enc = { ...baseline, body: page(encodeURIComponent('/fd404-0a1b2c3d4e5f')) };
  assert.equal(matchesBaseline(enc, { status: 200, contentType: 'text/html', location: null, body: page(encodeURIComponent('/admin/backup')), paths: ['/admin/backup'] }), true);
});

test('JSON 404 under /api: real 404s are http_404, real API answers are kept, and /api gets its own baseline', async () => {
  const probes = [];
  const http = mockTarget(
    { '/api/users': () => res(200, '{"data":[]}', json), '/dashboard': () => res(200, SPA_INDEX, html) },
    pathname => {
      probes.push(pathname);
      // The SPA catch-all serves index.html at the root; /api/* has its own JSON 404.
      return pathname.startsWith('/api/') ? res(404, '{"error":"not found"}', json) : res(200, SPA_INDEX, html);
    }
  );
  try {
    assert.equal(await judge('/api/missing'), 'http_404');
    assert.equal(await judge('/api/users'), null);
    assert.equal(await judge('/dashboard'), 'soft_404');
    assert.equal(await judge('/api/users/1'), 'http_404');
  } finally {
    http.mock.restore();
  }
  // One probe per (target, scheme, prefix): /api once, the root once.
  assert.equal(probes.length, 2);
  assert.ok(probes.some(p => /^\/api\/fd404-[0-9a-f]+$/.test(p)));
  assert.ok(probes.some(p => /^\/fd404-[0-9a-f]+$/.test(p)));
});

test('a 200 JSON catch-all: a small different body is a real endpoint, the same error body is not', async () => {
  const http = mockTarget({ '/api/users': () => res(200, '{"data":[]}', json), '/api/nope': () => res(200, '{"error":"not found"}', json) },
    () => res(200, '{"error":"not found"}', json));
  try {
    assert.equal(await judge('/api/users'), null);
    assert.equal(await judge('/api/nope'), 'soft_404');
  } finally {
    http.mock.restore();
  }
});

test('redirect-to-login catch-all: same Location (minus the path) is a soft 404, another Location is real', () => {
  const baseline = { status: 302, contentType: 'text/html', location: `/login?next=${encodeURIComponent('/admin/fd404-abcdef012345')}`, probePath: '/admin/fd404-abcdef012345', body: '' };
  const login = p => ({ status: 302, contentType: 'text/html', location: `/login?next=${encodeURIComponent(p)}`, body: '', paths: [p] });
  assert.equal(matchesBaseline(baseline, login('/admin/settings')), true);
  assert.equal(matchesBaseline(baseline, { ...login('/admin/settings'), location: '/admin/settings/' }), false);
});

test('a real page that differs from the catch-all is not a soft 404', () => {
  const baseline = { status: 200, contentType: 'text/html', location: null, probePath: '/fd404-abcdef012345', body: SPA_INDEX };
  const cand = body => ({ status: 200, contentType: 'text/html', location: null, body, paths: ['/about'] });
  assert.equal(matchesBaseline(baseline, cand(`<html><body>${'About us. '.repeat(300)}</body></html>`)), false, 'much longer page');
  assert.equal(matchesBaseline(baseline, { ...cand(SPA_INDEX), contentType: 'application/javascript' }), false, 'different content type');
  assert.equal(matchesBaseline(baseline, { ...cand(SPA_INDEX), status: 403 }), false, 'different status');
  // Same page with a per-request nonce of a few bytes: within the ±64-byte tolerance.
  assert.equal(matchesBaseline(baseline, cand(SPA_INDEX.replace('<div id="root">', '<div id="root" data-nonce="Zm9vYmFy">'))), true);
});

test('401/403/5xx are never classified, even when the whole prefix answers the same', async () => {
  const http = mock.method(globalThis, 'fetch', async () => res(403, 'forbidden', { 'content-type': 'text/plain' }));
  try {
    assert.equal(await judge('/admin/panel'), null);
  } finally {
    http.mock.restore();
  }
});

test('a failed baseline fetch skips classification and is retried next time', async () => {
  let probes = 0;
  const http = mock.method(globalThis, 'fetch', async url => {
    if (String(url).includes('/fd404-')) {
      probes++;
      throw new TypeError('fetch failed', { cause: { code: 'ECONNRESET' } });
    }
    return res(200, SPA_INDEX, html);
  });
  try {
    assert.equal(await judge('/static/js'), null);
    assert.equal(await judge('/static/css'), null);
  } finally {
    http.mock.restore();
  }
  assert.equal(probes, 2, 'a failure is not cached');
});
