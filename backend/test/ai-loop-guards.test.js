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

function mockTargetHttp() {
  return mock.method(globalThis, 'fetch', async () => new Response('{"data":[]}', {
    status: 200, headers: { 'content-type': 'application/json' },
  }));
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
  assert.equal(http.mock.callCount(), 15);
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
  assert.equal(http.mock.callCount(), 15);
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
