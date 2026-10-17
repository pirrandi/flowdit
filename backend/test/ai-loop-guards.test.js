// AI agent anti-loop guards. Replays the loop seen live on a real engagement:
// the model kept fetching the same API path with a new cache-buster on every
// call (and paging a huge source map), so no two calls were identical and the
// exact-signature guard never fired. The provider and the network are mocked;
// everything else (event log, guards, endpoint recording) runs for real.
const { test, before, beforeEach, after, mock } = require('node:test');
const assert = require('node:assert/strict');
const { db, resetDb, registerUser, createProject } = require('./helpers');
const ai = require('../src/services/ai');
const agentLoop = require('../src/services/ai/agentLoop');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

async function setupSession() {
  const owner = await registerUser();
  const project = await createProject(owner.accessToken);
  const { rows } = await db.query(
    `INSERT INTO targets (project_id, host, type, scope, status) VALUES ($1,'app.example.test','domain','in','active') RETURNING id`,
    [project.id]
  );
  const { session, primaryThread } = await agentLoop.createSessionWithPrimaryThread(
    project.id, rows[0].id, owner.user.id, 'en', 'Recon the target'
  );
  return { session, threadId: primaryThread.id, targetId: rows[0].id };
}

// A model that never concludes: every turn it asks for one more tool call.
function mockEndlessModel(nextCall) {
  let n = 0;
  return mock.method(ai, 'chatWithTools', async () => {
    n++;
    return { text: '', toolCalls: [{ id: `call_${n}`, ...nextCall(n) }], usage: {}, model: 'mock' };
  });
}

// The soft-404 probe (a random /fd404-<hex> path) answers 404, so mocked
// paths count as real endpoints; realCalls() leaves the probes out.
const isProbe = url => String(url).includes('/fd404-');
const realCalls = http => http.mock.calls.filter(c => !isProbe(c.arguments[0])).length;

function mockTargetHttp() {
  return mock.method(globalThis, 'fetch', async url => (isProbe(url)
    ? new Response('{"error":"not found"}', { status: 404, headers: { 'content-type': 'application/json' } })
    : new Response('{"data":[]}', { status: 200, headers: { 'content-type': 'application/json' } })));
}

async function toolResults(sessionId) {
  const { rows } = await db.query(
    `SELECT payload FROM ai_scan_events WHERE session_id=$1 AND type='tool.result' ORDER BY id`,
    [sessionId]
  );
  return rows.map(r => r.payload.result);
}

test('query-string variants of one path are stored as a single endpoint and capped per run', async () => {
  const { session, threadId, targetId } = await setupSession();
  const model = mockEndlessModel(n => ({
    name: 'fetch_endpoint',
    input: { target_id: targetId, path: `/api/news?_=${n}&pagination[pageSize]=${n}` },
  }));
  const http = mockTargetHttp();
  try {
    await agentLoop.advance(session.id, threadId);
  } finally {
    model.mock.restore();
    http.mock.restore();
  }

  const { rows: endpoints } = await db.query(`SELECT path FROM target_endpoints WHERE target_id=$1`, [targetId]);
  assert.deepEqual(endpoints.map(e => e.path), ['/api/news']);

  // 15 real requests, then every further variant is blocked before hitting the network.
  assert.equal(realCalls(http), 15);
  const results = await toolResults(session.id);
  assert.ok(results.length > 15, 'the loop kept going until the checkpoint');
  assert.ok(results.slice(0, 15).every(r => !r.error));
  for (const r of results.slice(15)) assert.match(r.error, /^Blocked: you already read \/api\/news/);
});

test('paging one file by offset hits the same per-path cap', async () => {
  const { session, threadId, targetId } = await setupSession();
  const model = mockEndlessModel(n => ({
    name: 'fetch_page_source',
    input: { target_id: targetId, path: '/static/js/main.js.map', offset: n * 20000 },
  }));
  const http = mockTargetHttp();
  try {
    await agentLoop.advance(session.id, threadId);
  } finally {
    model.mock.restore();
    http.mock.restore();
  }
  assert.equal(realCalls(http), 15);
  const results = await toolResults(session.id);
  assert.match(results[15].error, /use search_page_source/);
});

test('distinct paths are not throttled by the per-path cap', async () => {
  const { session, threadId, targetId } = await setupSession();
  const model = mockEndlessModel(n => ({
    name: 'fetch_endpoint',
    input: { target_id: targetId, path: `/page-${n}` },
  }));
  const http = mockTargetHttp();
  try {
    await agentLoop.advance(session.id, threadId);
  } finally {
    model.mock.restore();
    http.mock.restore();
  }
  const results = await toolResults(session.id);
  assert.ok(results.length >= 20);
  assert.ok(results.every(r => !r.error), 'no call should be blocked');
});

// Found in review: a sub-agent report counted as the start of a new run, so
// the coordinator got a fresh per-path budget every time a sub-agent reported.
test('the coordinator still hits the per-path cap across a sub-agent report', async () => {
  const { session, threadId, targetId } = await setupSession();
  let n = 0;
  const model = mock.method(ai, 'chatWithTools', async () => {
    n++;
    if (n === 8) {
      await db.query(
        `INSERT INTO ai_scan_events (session_id, thread_id, type, payload) VALUES ($1,$2,'subagent.reported',$3)`,
        [session.id, threadId, JSON.stringify({ label: 'sub', summary: 'nothing new' })]
      );
    }
    return { text: '', toolCalls: [{ id: `call_${n}`, name: 'fetch_endpoint', input: { target_id: targetId, path: `/api/news?_=${n}` } }], usage: {}, model: 'mock' };
  });
  const http = mockTargetHttp();
  try {
    await agentLoop.advance(session.id, threadId);
  } finally {
    model.mock.restore();
    http.mock.restore();
  }
  assert.equal(realCalls(http), 15);
});

// ── "no progress" guard: blind brute force ───────────────────────────────
// Replays the guessing streaks seen live: path after path that does not
// exist, each one different, so neither the exact-signature nor the per-path
// guard ever fires.
function mockHttpWithHits(isHit) {
  return mock.method(globalThis, 'fetch', async url => {
    const { pathname } = new URL(url);
    if (!isProbe(url) && isHit(pathname)) {
      return new Response('{"data":[]}', { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response('not found', { status: 404, headers: { 'content-type': 'text/plain' } });
  });
}

async function runGuessing(pathFor, isHit, onModelCall = async () => {}) {
  const { session, threadId, targetId } = await setupSession();
  let n = 0;
  const model = mock.method(ai, 'chatWithTools', async () => {
    n++;
    await onModelCall(n, session, threadId);
    return { text: '', toolCalls: [{ id: `call_${n}`, name: 'fetch_endpoint', input: { target_id: targetId, path: pathFor(n) } }], usage: {}, model: 'mock' };
  });
  const http = mockHttpWithHits(isHit);
  try {
    await agentLoop.advance(session.id, threadId);
  } finally {
    model.mock.restore();
    http.mock.restore();
  }
  return { session, threadId, targetId, http, results: await toolResults(session.id) };
}

const NO_PROGRESS = /^Blocked: your last 20 network reads in a row found nothing new/;

test('20 not-found reads in a row trip the no-progress guard', async () => {
  const { http, results, targetId } = await runGuessing(n => `/guess-${n}`, () => false);
  assert.equal(realCalls(http), 20);
  assert.ok(results.slice(0, 20).every(r => r.not_found && r.reason === 'http_404'));
  assert.match(results[20].error, NO_PROGRESS);
  assert.match(results[20].error, /Stop guessing paths/);
  const { rows } = await db.query(`SELECT 1 FROM target_endpoints WHERE target_id=$1`, [targetId]);
  assert.equal(rows.length, 0);
});

test('ignoring the no-progress block escalates to a paused checkpoint', async () => {
  const { session, threadId, results } = await runGuessing(n => `/guess-${n}`, () => false);
  // 20 real reads, 2 blocked warnings, the 3rd blocked call pauses the thread.
  assert.equal(results.length, 23);
  assert.ok(results.slice(20).every(r => NO_PROGRESS.test(r.error)));
  const { rows: [cp] } = await db.query(`SELECT payload FROM ai_scan_events WHERE session_id=$1 AND type='turn.checkpoint'`, [session.id]);
  assert.equal(cp.payload.reason, 'no_progress');
  assert.equal(cp.payload.auto, false);
  const { rows: [t] } = await db.query(`SELECT status FROM ai_scan_threads WHERE id=$1`, [threadId]);
  assert.equal(t.status, 'idle');
  const { rows: evs } = await db.query(`SELECT * FROM ai_scan_events WHERE session_id=$1 ORDER BY created_at, id`, [session.id]);
  const msgs = agentLoop.eventsToMessages(evs);
  assert.match(msgs[msgs.length - 1].content, /\[system checkpoint\]: you were paused because 20\+ network reads/);
});

test('a newly recorded endpoint resets the streak', async () => {
  const { http, results } = await runGuessing(n => (n === 15 ? '/api-docs' : `/guess-${n}`), p => p === '/api-docs');
  // 14 misses, 1 hit, then 20 more misses before the block.
  assert.equal(realCalls(http), 35);
  assert.ok(results.slice(0, 35).every(r => !r.error));
  assert.match(results[35].error, NO_PROGRESS);
});

test('the coordinator keeps its no-progress streak across a sub-agent report', async () => {
  const { results } = await runGuessing(n => `/guess-${n}`, () => false, async (n, session, threadId) => {
    if (n === 8) {
      await db.query(
        `INSERT INTO ai_scan_events (session_id, thread_id, type, payload) VALUES ($1,$2,'subagent.reported',$3)`,
        [session.id, threadId, JSON.stringify({ label: 'sub', summary: 'nothing new' })]
      );
    }
  });
  assert.match(results[20].error, NO_PROGRESS);
});

test('a pentester message starts a new run and drops the streak', async () => {
  const { results } = await runGuessing(n => `/guess-${n}`, () => false, async (n, session, threadId) => {
    if (n === 15) {
      await db.query(
        `INSERT INTO ai_scan_events (session_id, thread_id, type, payload) VALUES ($1,$2,'chat.message',$3)`,
        [session.id, threadId, JSON.stringify({ role: 'user', text: 'keep going, try the admin area' })]
      );
    }
  });
  // Call 15 was persisted after the message, so the new run counts from it:
  // calls 15..34 are its 20 misses and call 35 is the first one blocked.
  assert.ok(results.slice(0, 34).every(r => !r.error), 'the old streak was dropped at the user message');
  assert.match(results[34].error, NO_PROGRESS);
});
