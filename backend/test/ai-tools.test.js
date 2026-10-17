// AI agent network tools, called directly (no model in the loop). The target's
// HTTP is mocked through globalThis.fetch; scope checks and endpoint recording
// run against the real test DB.
const { test, before, beforeEach, after, mock } = require('node:test');
const assert = require('node:assert/strict');
const { db, resetDb, registerUser, createProject } = require('./helpers');
const { scanToolsLevel1 } = require('../src/services/ai/scanToolsLevel1');
const { scanToolsLevel2 } = require('../src/services/ai/scanToolsLevel2');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

const tool = name => [...scanToolsLevel1, ...scanToolsLevel2].find(t => t.name === name);

async function setupTarget(host = 'app.example.test') {
  const owner = await registerUser();
  const project = await createProject(owner.accessToken);
  const { rows } = await db.query(
    `INSERT INTO targets (project_id, host, type, scope, status) VALUES ($1,$2,'domain','in','active') RETURNING id`,
    [project.id, host]
  );
  return { ctx: { projectId: project.id, startedBy: owner.user.id }, targetId: rows[0].id };
}

// The soft-404 probe (a random /fd404-<hex> path) answers 404, like a target
// without a catch-all; otherwise every mocked path would look like a soft 404.
const isProbe = url => String(url).includes('/fd404-');
const realCalls = http => http.mock.calls.filter(c => !isProbe(c.arguments[0]));

function mockHttp(body = 'ok', init = { status: 200, headers: { 'content-type': 'text/plain' } }) {
  return mock.method(globalThis, 'fetch', async url => (isProbe(url) ? new Response('not found', { status: 404 }) : new Response(body, init)));
}

test('a non-http(s) scheme is refused before any request', async () => {
  const { ctx, targetId } = await setupTarget();
  const http = mockHttp();
  try {
    for (const name of ['fetch_endpoint', 'fetch_page_source', 'search_page_source']) {
      await assert.rejects(
        tool(name).execute({ target_id: targetId, path: '/', scheme: 'file', pattern: 'x' }, ctx),
        /scheme "file" not allowed/
      );
    }
    const res = await tool('send_http_request').execute({ target_id: targetId, method: 'GET', path: '/', scheme: 'gopher' }, ctx);
    assert.match(res.error, /scheme "gopher" not allowed/);
  } finally {
    http.mock.restore();
  }
  assert.equal(http.mock.callCount(), 0);
});

test('a path cannot move the request to another host', async () => {
  const { ctx, targetId } = await setupTarget();
  const http = mockHttp();
  try {
    for (const path of ['@evil.example/x', '//evil.example/x', '\\\\evil.example/x']) {
      await tool('fetch_endpoint').execute({ target_id: targetId, path }, ctx);
      await tool('send_http_request').execute({ target_id: targetId, method: 'POST', path }, ctx);
    }
  } finally {
    http.mock.restore();
  }
  for (const call of http.mock.calls) {
    assert.equal(new URL(call.arguments[0]).host, 'app.example.test');
    assert.equal(call.arguments[1].redirect, 'manual');
  }
});

test('the target port is kept and enforced', async () => {
  const { ctx, targetId } = await setupTarget('https://10.0.0.5:8443/');
  const http = mockHttp();
  try {
    await tool('fetch_endpoint').execute({ target_id: targetId, path: ':9999/x' }, ctx);
  } finally {
    http.mock.restore();
  }
  assert.equal(new URL(http.mock.calls[0].arguments[0]).host, '10.0.0.5:8443');
});

// ── 10. ReDoS in search_page_source ──────────────────────────────────────
test('a catastrophic regex times out with a tool error instead of blocking the process', async () => {
  const { ctx, targetId } = await setupTarget();
  const http = mockHttp(`${'a'.repeat(40)}!`);
  const started = Date.now();
  let res;
  try {
    res = await tool('search_page_source').execute({ target_id: targetId, path: '/app.js', pattern: '^(a+)+$', flags: '' }, ctx);
  } finally {
    http.mock.restore();
  }
  assert.match(res.error, /timed out/);
  assert.ok(Date.now() - started < 10000);
});

test('search_page_source still finds matches, and rejects oversized patterns before fetching', async () => {
  const { ctx, targetId } = await setupTarget();
  const http = mockHttp('const apiKey = "sk-123"; const apiSecret = 1; fetch("/api/internal")');
  try {
    const ok = await tool('search_page_source').execute({ target_id: targetId, path: '/app.js', pattern: 'api[A-Z]\\w+', flags: '' }, ctx);
    assert.equal(ok.match_count, 2);
    assert.equal(ok.matches[0].match, 'apiKey');
    const tooLong = await tool('search_page_source').execute({ target_id: targetId, path: '/app.js', pattern: 'a'.repeat(501) }, ctx);
    assert.match(tooLong.error, /too long/);
  } finally {
    http.mock.restore();
  }
  assert.equal(realCalls(http).length, 1);
});

// ── 15. response size caps ───────────────────────────────────────────────
test('fetch_page_source caps the page size and the bytes read from the target', async () => {
  const { ctx, targetId } = await setupTarget();
  const big = 'x'.repeat(6 * 1024 * 1024);
  const http = mockHttp(big);
  let res;
  try {
    res = await tool('fetch_page_source').execute({ target_id: targetId, path: '/big.js', limit: 10_000_000 }, ctx);
  } finally {
    http.mock.restore();
  }
  assert.equal(res.returned_length, 50000);
  assert.equal(res.total_length, 5 * 1024 * 1024);
  assert.equal(res.body_truncated, true);
});

// ── only endpoints that exist are recorded (404 / soft 404) ──────────────
const recordedPaths = async targetId =>
  (await db.query(`SELECT path, status_code FROM target_endpoints WHERE target_id=$1 ORDER BY path`, [targetId])).rows;

test('a real 404 is not recorded and comes back as not_found http_404', async () => {
  const { ctx, targetId } = await setupTarget();
  const http = mockHttp('{"error":"no"}', { status: 404, headers: { 'content-type': 'application/json' } });
  let res;
  try {
    res = await tool('fetch_endpoint').execute({ target_id: targetId, path: '/backup.zip' }, ctx);
    const src = await tool('fetch_page_source').execute({ target_id: targetId, path: '/old/admin.php' }, ctx);
    assert.equal(src.reason, 'http_404');
  } finally {
    http.mock.restore();
  }
  assert.equal(res.status, 404);
  assert.equal(res.not_found, true);
  assert.equal(res.reason, 'http_404');
  assert.deepEqual(await recordedPaths(targetId), []);
});

test('a soft 404 (SPA answering 200 to everything) is not recorded and the body is withheld', async () => {
  const { ctx, targetId } = await setupTarget();
  const index = `<!doctype html><html><body><div id="root"></div>${'<!-- x -->'.repeat(80)}</body></html>`;
  // No isProbe() branch: the random probe path gets the same index.html.
  const http = mock.method(globalThis, 'fetch', async () => new Response(index, { status: 200, headers: { 'content-type': 'text/html' } }));
  let res, search;
  try {
    res = await tool('fetch_endpoint').execute({ target_id: targetId, path: '/static/js' }, ctx);
    search = await tool('search_page_source').execute({ target_id: targetId, path: '/static/js/app.js', pattern: 'root' }, ctx);
  } finally {
    http.mock.restore();
  }
  assert.equal(res.not_found, true);
  assert.equal(res.reason, 'soft_404');
  assert.match(res.note, /any non-existent path/i);
  assert.equal(res.body_preview, undefined);
  assert.equal(search.reason, 'soft_404');
  assert.equal(search.matches, undefined);
  assert.deepEqual(await recordedPaths(targetId), []);
});

test('a 403 is recorded, and a real new 200 is recorded once', async () => {
  const { ctx, targetId } = await setupTarget();
  const http = mock.method(globalThis, 'fetch', async url => {
    const { pathname } = new URL(url);
    if (isProbe(url)) return new Response('nope', { status: 404 });
    if (pathname === '/admin') return new Response('forbidden', { status: 403, headers: { 'content-type': 'text/plain' } });
    return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
  });
  let forbidden, first, again;
  try {
    forbidden = await tool('fetch_endpoint').execute({ target_id: targetId, path: '/admin' }, ctx);
    first = await tool('fetch_endpoint').execute({ target_id: targetId, path: '/api/health' }, ctx);
    again = await tool('fetch_endpoint').execute({ target_id: targetId, path: '/api/health?x=1' }, ctx);
  } finally {
    http.mock.restore();
  }
  assert.equal(forbidden.not_found, undefined);
  assert.equal(first.not_found, undefined);
  assert.equal(first.already_recorded, undefined);
  assert.equal(first.body_preview, '{"ok":true}');
  assert.equal(again.already_recorded, true);
  assert.deepEqual(await recordedPaths(targetId), [{ path: '/admin', status_code: 403 }, { path: '/api/health', status_code: 200 }]);
});

// ── 13. endpoint normalization and uniqueness ────────────────────────────
test('endpoint paths are normalized, recorded once, and over-long paths do not break the tool', async () => {
  const { ctx, targetId } = await setupTarget();
  const http = mockHttp();
  let long;
  try {
    for (const path of ['/api//users/', 'api/users', '/api/users?page=2']) {
      await tool('fetch_endpoint').execute({ target_id: targetId, path }, ctx);
    }
    await Promise.all([1, 2, 3].map(() => tool('fetch_endpoint').execute({ target_id: targetId, path: '/race' }, ctx)));
    await tool('fetch_endpoint').execute({ target_id: targetId, path: '/Api/Users' }, ctx);
    long = await tool('fetch_endpoint').execute({ target_id: targetId, path: `/${'a'.repeat(1500)}` }, ctx);
  } finally {
    http.mock.restore();
  }
  assert.equal(long.status, 200);
  const { rows } = await db.query(`SELECT path FROM target_endpoints WHERE target_id=$1`, [targetId]);
  assert.deepEqual(rows.map(r => r.path.length > 50 ? String(r.path.length) : r.path).sort(), ['/Api/Users', '/api/users', '/race', '1000']);
});

test('the manual endpoint route normalizes paths and answers 409 on a duplicate', async () => {
  const supertest = require('supertest');
  const { app } = require('./helpers');
  const owner = await registerUser();
  const project = await createProject(owner.accessToken);
  const { rows: [t] } = await db.query(
    `INSERT INTO targets (project_id, host, type, scope, status) VALUES ($1,'h.test','domain','in','active') RETURNING id`, [project.id]
  );
  const post = path => supertest(app).post(`/api/projects/${project.id}/targets/${t.id}/endpoints`)
    .set('Authorization', `Bearer ${owner.accessToken}`).send({ path, method: 'GET' });
  const first = await post('/admin//panel/');
  assert.equal(first.status, 201);
  assert.equal(first.body.path, '/admin/panel');
  assert.equal((await post('/admin/panel')).status, 409);
});

test('the endpoint migration merges existing duplicates and is idempotent', async () => {
  const path = require('node:path');
  const { execFileSync } = require('node:child_process');
  const runMigrate = () => execFileSync(process.execPath, [path.join(__dirname, '..', 'src', 'db', 'migrate.js')], { env: { ...process.env }, stdio: 'pipe' });

  const { targetId } = await setupTarget();
  await db.query(`DROP INDEX IF EXISTS uq_target_endpoints_target_path_method`);
  const ins = (p, method, createdAt, interesting, notes) => db.query(
    `INSERT INTO target_endpoints (target_id, path, method, interesting, notes, created_at) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
    [targetId, p, method, interesting, notes, createdAt]
  );
  await ins('/api/x', 'GET', '2026-01-02', false, 'second');
  const { rows: [oldest] } = await ins('//api//x/?q=1', 'GET', '2026-01-01', false, 'first');
  await ins('api/x#frag', 'GET', '2026-01-03', true, 'second');
  await ins('/api/x', 'POST', '2026-01-04', false, null);
  await ins('/API/x', 'GET', '2026-01-05', false, null);

  runMigrate();
  const snapshot = async () => (await db.query(
    `SELECT id, path, method, interesting, notes, created_at FROM target_endpoints WHERE target_id=$1 ORDER BY path, method`, [targetId]
  )).rows;
  const once = await snapshot();
  assert.deepEqual(once.map(r => `${r.method} ${r.path}`).sort(), ['GET /API/x', 'GET /api/x', 'POST /api/x']);
  const merged = once.find(r => r.method === 'GET' && r.path === '/api/x');
  assert.equal(merged.id, oldest.id);
  assert.equal(merged.interesting, true);
  assert.deepEqual(merged.notes.split('\n').sort(), ['first', 'second']);
  assert.equal(merged.created_at.toISOString().slice(0, 10), '2026-01-01');

  runMigrate();
  assert.deepEqual(await snapshot(), once);
  const { rows: idx } = await db.query(`SELECT 1 FROM pg_indexes WHERE indexname='uq_target_endpoints_target_path_method'`);
  assert.equal(idx.length, 1);
});
