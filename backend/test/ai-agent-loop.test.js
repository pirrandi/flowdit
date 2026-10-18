// AI agent loop: concurrency, multi-agent state and history invariants. The
// provider (ai.chatWithTools) and the target's HTTP (globalThis.fetch) are
// mocked; the event log, thread/session state machine and tools run for real.
const { test, before, beforeEach, after, mock } = require('node:test');
const assert = require('node:assert/strict');
const supertest = require('supertest');
const { app, db, resetDb, registerUser, createProject } = require('./helpers');
const ai = require('../src/services/ai');
const agentLoop = require('../src/services/ai/agentLoop');
const { chatWithToolsAt, toOpenAIMessages } = require('../src/services/ai/openaiCompatible');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

async function setupSession({ autonomous = true, singleAgent = false, lang = 'en', scoped = false } = {}) {
  const owner = await registerUser();
  const project = await createProject(owner.accessToken);
  const { rows } = await db.query(
    `INSERT INTO targets (project_id, host, type, scope, status) VALUES ($1,'app.example.test','domain','in','active'), ($1,'other.example.test','domain','in','active') RETURNING id`,
    [project.id]
  );
  const [targetId, otherTargetId] = rows.map(r => r.id);
  const { session, primaryThread } = await agentLoop.createSessionWithPrimaryThread(
    project.id, scoped ? targetId : null, owner.user.id, lang, 'Recon the target',
    { ai_autonomous_requests: autonomous, ai_single_agent: singleAgent }
  );
  return { owner, project, session, threadId: primaryThread.id, targetId, otherTargetId };
}

const text = t => ({ type: 'text', text: t, usage: {}, model: 'mock' });
const toolUse = (name, input, extra = {}) => ({ type: 'tool_use', toolCalls: [{ id: 'x', name, input, ...extra }], usage: {}, model: 'mock' });
const isSubAgent = opts => opts.systemPrompt.includes('You are a sub-agent');
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function waitFor(fn, what, timeoutMs = 10000) {
  const start = Date.now();
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() - start > timeoutMs) throw new Error(`timed out waiting for ${what}`);
    await sleep(25);
  }
}

const events = async (sessionId, type) =>
  (await db.query(`SELECT * FROM ai_scan_events WHERE session_id=$1 ${type ? 'AND type=$2' : ''} ORDER BY id`, type ? [sessionId, type] : [sessionId])).rows;
const threadStatus = async id => (await db.query(`SELECT status FROM ai_scan_threads WHERE id=$1`, [id])).rows[0].status;
const sessionStatus = async id => (await db.query(`SELECT status FROM ai_scan_sessions WHERE id=$1`, [id])).rows[0].status;
const noRunningThreads = async sessionId =>
  !(await db.query(`SELECT 1 FROM ai_scan_threads WHERE session_id=$1 AND status='running'`, [sessionId])).rows.length;

function mockHttp(impl) {
  return mock.method(globalThis, 'fetch', impl || (async () => new Response('ok', { status: 200, headers: { 'content-type': 'text/plain' } })));
}

// Every tool_use must be followed right away by its tool_result.
function assertPaired(messages) {
  messages.forEach((m, i) => {
    if (m.toolCalls) {
      assert.equal(messages[i + 1]?.role, 'tool', `tool_use at ${i} not followed by its result`);
      assert.equal(messages[i + 1].toolCallId, m.toolCalls[0].id);
    }
    if (m.role === 'tool') assert.ok(messages[i - 1]?.toolCalls, `tool_result at ${i} without its tool_use`);
  });
}

// ── 3. double approval ───────────────────────────────────────────────────
test('two concurrent approvals of one gated call execute it exactly once', async () => {
  const { session, threadId, targetId, owner } = await setupSession({ autonomous: false });
  let n = 0;
  const model = mock.method(ai, 'chatWithTools', async () => (++n === 1
    ? toolUse('send_http_request', { target_id: targetId, method: 'POST', path: '/login' })
    : text('done')));
  const http = mockHttp();
  try {
    await agentLoop.advance(session.id, threadId);
    assert.equal(await threadStatus(threadId), 'waiting_approval');
    const [called] = await events(session.id, 'tool.called');
    await Promise.all([
      agentLoop.resolveGatedCall(session.id, called.id, 'accepted', owner.user.id),
      agentLoop.resolveGatedCall(session.id, called.id, 'accepted', owner.user.id),
    ]);
    await waitFor(async () => (await threadStatus(threadId)) === 'idle', 'thread idle');
  } finally {
    model.mock.restore();
    http.mock.restore();
  }
  assert.equal(http.mock.callCount(), 1);
  assert.equal((await events(session.id, 'tool.result')).length, 1);
  assert.equal(model.mock.callCount(), 2);
});

// ── 4 + 17. sub-agent error ──────────────────────────────────────────────
test('a sub-agent error reports to the coordinator and does not wedge the session', async () => {
  const { session, threadId } = await setupSession();
  let primaryCalls = 0;
  const model = mock.method(ai, 'chatWithTools', async (_provider, opts) => {
    if (isSubAgent(opts)) throw new Error('provider down');
    primaryCalls++;
    if (primaryCalls === 1) return toolUse('delegate_to_subagent', { task: 'enumerate' });
    return text(`noted ${primaryCalls}`);
  });
  try {
    await agentLoop.advance(session.id, threadId);
    await waitFor(async () => {
      const report = (await events(session.id, 'subagent.reported'))[0];
      if (!report) return false;
      const answers = (await events(session.id, 'chat.message')).filter(e => e.payload.role === 'assistant' && e.thread_id === threadId);
      return answers.some(a => Number(a.id) > Number(report.id)) && await noRunningThreads(session.id);
    }, 'coordinator to answer after the error report');
  } finally {
    model.mock.restore();
  }
  const [report] = await events(session.id, 'subagent.reported');
  assert.match(report.payload.summary, /failed: .*provider down/);
  assert.equal(await threadStatus(threadId), 'idle');
  assert.equal(await sessionStatus(session.id), 'idle');
});

test('retry relaunches every thread that should run, the primary included', async () => {
  const { session, threadId } = await setupSession();
  // The wedge seen before the fix: session `error`, primary flipped to
  // running by a report while advance() refused error sessions, sub errored.
  const { rows: [sub] } = await db.query(
    `INSERT INTO ai_scan_threads (session_id, parent_thread_id, label, status) VALUES ($1,$2,'sub','error') RETURNING id`,
    [session.id, threadId]
  );
  await db.query(`INSERT INTO ai_scan_events (session_id, thread_id, type, payload) VALUES ($1,$2,'thread.started','{"task":"t"}')`, [session.id, sub.id]);
  await db.query(`UPDATE ai_scan_threads SET status='running' WHERE id=$1`, [threadId]);
  await db.query(`UPDATE ai_scan_sessions SET status='error' WHERE id=$1`, [session.id]);

  const seen = { primary: 0, sub: 0 };
  const model = mock.method(ai, 'chatWithTools', async (_provider, opts) => {
    seen[isSubAgent(opts) ? 'sub' : 'primary']++;
    return text('ok');
  });
  try {
    await agentLoop.retry(session.id);
    await waitFor(async () => (await threadStatus(sub.id)) === 'completed' && await noRunningThreads(session.id), 'all threads settled');
  } finally {
    model.mock.restore();
  }
  assert.ok(seen.primary >= 1, 'primary relaunched');
  assert.equal(seen.sub, 1);
  assert.equal(await sessionStatus(session.id), 'idle');
});

// ── 5. tool_use / tool_result pairing ────────────────────────────────────
test('eventsToMessages defers interleaved messages and closes orphaned calls', () => {
  let id = 0;
  const ev = (type, payload) => ({ id: ++id, type, payload });
  const history = [
    ev('chat.message', { role: 'user', text: 'go' }),
    ev('tool.called', { name: 'fetch_endpoint', input: { path: '/a' } }),            // 2
    ev('chat.message', { role: 'user', text: 'also check /b' }),                   // during the tool
    ev('subagent.reported', { label: 's', summary: 'found x' }),
    ev('tool.result', { call_id: 2, name: 'fetch_endpoint', result: { status: 200 } }),
    ev('tool.called', { name: 'fetch_endpoint', input: { path: '/crash' } }),        // 6 — crashed, no result
    ev('tool.called', { name: 'fetch_endpoint', input: { path: '/c' } }),            // 7
    ev('tool.result', { call_id: 7, name: 'fetch_endpoint', result: { status: 200 } }),
    ev('tool.result', { call_id: 6, name: 'fetch_endpoint', result: { status: 500 } }), // late, already closed
    ev('tool.called', { name: 'fetch_endpoint', input: { path: '/d' } }),            // 10 — trailing orphan
    ev('subagent.reported', { label: 's2', summary: 'done' }),
  ];
  const messages = agentLoop.eventsToMessages(history);
  assertPaired(messages);
  assert.deepEqual(messages.map(m => m.role), ['user', 'assistant', 'tool', 'user', 'user', 'assistant', 'tool', 'assistant', 'tool', 'assistant', 'tool', 'user']);
  assert.equal(messages[3].content, 'also check /b');
  assert.match(messages[6].result.error, /^interrupted, no result/);
  assert.equal(messages[8].result.result.status, 200);
  assert.match(messages[10].result.error, /^interrupted/);
});

// ── 6. fire-and-forget errors ────────────────────────────────────────────
test('an unexpected throw inside a launched advance marks the thread as error', async () => {
  const { session, threadId } = await setupSession();
  const model = mock.method(ai, 'chatWithTools', async () => ({ type: 'tool_use', toolCalls: null, usage: {}, model: 'mock' }));
  try {
    agentLoop.launchAdvance(session.id, threadId);
    await waitFor(async () => (await threadStatus(threadId)) === 'error', 'thread error');
  } finally {
    model.mock.restore();
  }
  const [err] = await events(session.id, 'session.error');
  assert.match(err.payload.reason, /^internal error:/);
  assert.equal(await sessionStatus(session.id), 'error');
});

test('DELETE refuses a session while any of its threads is running', async () => {
  const { owner, project, session, threadId } = await setupSession();
  await db.query(`UPDATE ai_scan_threads SET status='idle' WHERE id=$1`, [threadId]);
  await db.query(`INSERT INTO ai_scan_threads (session_id, parent_thread_id, label, status) VALUES ($1,$2,'sub','running')`, [session.id, threadId]);
  await db.query(`UPDATE ai_scan_sessions SET status='waiting_approval' WHERE id=$1`, [session.id]);
  const res = await supertest(app)
    .delete(`/api/projects/${project.id}/ai-scan/sessions/${session.id}`)
    .set('Authorization', `Bearer ${owner.accessToken}`);
  assert.equal(res.status, 409);
});

// ── 7. interrupt during tool execution ───────────────────────────────────
test('an interrupt while a tool runs leaves a single loop on the thread', async () => {
  const { owner, session, threadId, targetId } = await setupSession();
  let release;
  const gate = new Promise(r => { release = r; });
  const calls = [];
  const model = mock.method(ai, 'chatWithTools', async (_provider, opts) => {
    calls.push(opts.messages);
    if (calls.length === 1) return toolUse('fetch_endpoint', { target_id: targetId, path: '/slow' });
    // The old tool finishes while the new loop is still waiting on the model.
    release();
    await sleep(200);
    return text('on it');
  });
  const http = mockHttp(async () => { await gate; return new Response('late', { status: 200 }); });
  let oldLoop;
  try {
    oldLoop = agentLoop.advance(session.id, threadId);
    await waitFor(() => http.mock.callCount() === 1, 'tool to start');
    await agentLoop.interrupt(session.id);
    await agentLoop.sendMessage(session.id, owner.user.id, '[interrupt] do something else');
    await oldLoop;
    await waitFor(async () => (await threadStatus(threadId)) === 'idle', 'new loop to answer');
    await sleep(100);
  } finally {
    release();
    model.mock.restore();
    http.mock.restore();
  }
  assert.equal(calls.length, 2, 'the interrupted loop must not call the model again');
  assertPaired(calls[1]);
  assert.equal(await threadStatus(threadId), 'idle');
});

// ── 8. report arriving while the coordinator is answering ────────────────
test('a sub-agent report that lands mid-call is not lost when the coordinator goes idle', async () => {
  const { session, threadId } = await setupSession();
  const calls = [];
  const model = mock.method(ai, 'chatWithTools', async (_provider, opts) => {
    calls.push(opts.messages);
    if (calls.length === 1) {
      await db.query(
        `INSERT INTO ai_scan_events (session_id, thread_id, type, payload) VALUES ($1,$2,'subagent.reported',$3)`,
        [session.id, threadId, JSON.stringify({ label: 'sub', summary: 'found an admin panel' })]
      );
    }
    return text(`answer ${calls.length}`);
  });
  try {
    await agentLoop.advance(session.id, threadId);
  } finally {
    model.mock.restore();
  }
  assert.equal(calls.length, 2);
  assert.ok(calls[1].some(m => typeof m.content === 'string' && m.content.includes('found an admin panel')));
  assert.equal(await threadStatus(threadId), 'idle');
});

// ── 11. delegation offering and fan-out caps ─────────────────────────────
test('delegate_to_subagent is refused when it was not offered (single-agent mode)', async () => {
  const { session, threadId } = await setupSession({ singleAgent: true });
  let n = 0;
  const model = mock.method(ai, 'chatWithTools', async () => (++n === 1 ? toolUse('delegate_to_subagent', { task: 'x' }) : text('ok')));
  try {
    await agentLoop.advance(session.id, threadId);
  } finally {
    model.mock.restore();
  }
  const [result] = await events(session.id, 'tool.result');
  assert.match(result.payload.result.error, /unknown tool "delegate_to_subagent"/);
  const { rows } = await db.query(`SELECT 1 FROM ai_scan_threads WHERE session_id=$1 AND parent_thread_id IS NOT NULL`, [session.id]);
  assert.equal(rows.length, 0);
});

test('delegate_to_subagent is capped per session', async () => {
  const { session, threadId } = await setupSession();
  for (let i = 0; i < 5; i++) {
    await db.query(`INSERT INTO ai_scan_threads (session_id, parent_thread_id, label, status) VALUES ($1,$2,'busy','waiting_approval')`, [session.id, threadId]);
  }
  let n = 0;
  const model = mock.method(ai, 'chatWithTools', async (_provider, opts) => {
    if (isSubAgent(opts)) return text('sub done');
    return ++n === 1 ? toolUse('delegate_to_subagent', { task: 'one more' }) : text('ok');
  });
  try {
    await agentLoop.advance(session.id, threadId);
  } finally {
    model.mock.restore();
  }
  const [result] = await events(session.id, 'tool.result');
  assert.match(result.payload.result.result?.error || result.payload.result.error, /too many active sub-agents/);
});

// ── 12. unknown tools and invalid arguments ──────────────────────────────
test('an unknown tool is an error result the model can correct, still loop-guarded', async () => {
  const { session, threadId } = await setupSession();
  let n = 0;
  const model = mock.method(ai, 'chatWithTools', async () => (++n <= 3 ? toolUse('nmap_scan', { host: 'x' }) : text('ok')));
  try {
    await agentLoop.advance(session.id, threadId);
  } finally {
    model.mock.restore();
  }
  const results = (await events(session.id, 'tool.result')).map(r => r.payload.result.error);
  assert.match(results[0], /unknown tool "nmap_scan".*Available tools: .*fetch_endpoint/);
  assert.match(results[1], /unknown tool/);
  assert.match(results[2], /^Blocked: you already called nmap_scan/);
  assert.equal((await events(session.id, 'session.error')).length, 0);
  assert.equal(await threadStatus(threadId), 'idle');
});

test('invalid JSON tool arguments become an error result instead of a crash', async () => {
  const fetchMock = mock.method(globalThis, 'fetch', async () => new Response(JSON.stringify({
    choices: [{ message: { tool_calls: [{ id: 'c1', type: 'function', function: { name: 'fetch_endpoint', arguments: '{"path": "/a",' } }] } }],
  }), { status: 200, headers: { 'content-type': 'application/json' } }));
  let parsed;
  try {
    parsed = await chatWithToolsAt({ apiUrl: 'https://provider.test/v1/chat/completions', apiKey: 'k', systemPrompt: 's', messages: [], tools: [], model: 'm' });
  } finally {
    fetchMock.mock.restore();
  }
  assert.equal(parsed.toolCalls[0].invalidArguments, '{"path": "/a",');

  const { session, threadId } = await setupSession();
  let n = 0;
  const model = mock.method(ai, 'chatWithTools', async () => (++n === 1 ? { ...parsed, usage: {} } : text('ok')));
  try {
    await agentLoop.advance(session.id, threadId);
  } finally {
    model.mock.restore();
  }
  const [result] = await events(session.id, 'tool.result');
  assert.match(result.payload.result.error, /invalid JSON arguments for fetch_endpoint/);
  assert.equal(await threadStatus(threadId), 'idle');
});

// ── 14. finding dedupe ───────────────────────────────────────────────────
test('propose_finding returns an existing finding with the same normalized name', async () => {
  for (const autonomous of [true, false]) {
    const { project, session, threadId, targetId, owner } = await setupSession({ autonomous });
    const { rows: [existing] } = await db.query(
      `INSERT INTO custom_vulns (project_id, name, category, severity, target_id, created_by) VALUES ($1,'SQL Injection in Login','SQLi','high',$2,$3) RETURNING id`,
      [project.id, targetId, owner.user.id]
    );
    let n = 0;
    const model = mock.method(ai, 'chatWithTools', async () => (++n === 1
      ? toolUse('propose_finding', { name: '  sql   injection in LOGIN ', category: 'SQLi', severity: 'high', description: 'd', target_id: targetId })
      : text('ok')));
    try {
      await agentLoop.advance(session.id, threadId);
    } finally {
      model.mock.restore();
    }
    const [result] = await events(session.id, 'tool.result');
    assert.match(result.payload.result.error, new RegExp(`already exists .*id ${existing.id}`));
    assert.equal(await threadStatus(threadId), 'idle', 'a duplicate never reaches the approval gate');
    const { rows } = await db.query(`SELECT 1 FROM custom_vulns WHERE project_id=$1`, [project.id]);
    assert.equal(rows.length, 1);
    await resetDb();
  }
});

// ── 16. target scoping ───────────────────────────────────────────────────
test('a session scoped to one target refuses other targets and says so in the prompt', async () => {
  const { session, threadId, targetId, otherTargetId } = await setupSession({ scoped: true });
  const prompts = [];
  let n = 0;
  const model = mock.method(ai, 'chatWithTools', async (_provider, opts) => {
    prompts.push(opts.systemPrompt);
    if (isSubAgent(opts)) return text('sub done');
    n++;
    if (n === 1) return toolUse('fetch_endpoint', { target_id: otherTargetId, path: '/' });
    if (n === 2) return toolUse('delegate_to_subagent', { task: 'other', target_id: otherTargetId });
    return text('ok');
  });
  const http = mockHttp();
  try {
    await agentLoop.advance(session.id, threadId);
  } finally {
    model.mock.restore();
    http.mock.restore();
  }
  assert.equal(http.mock.callCount(), 0);
  const results = (await events(session.id, 'tool.result')).map(r => r.payload.result.error);
  assert.match(results[0], new RegExp(`scoped to target_id "${targetId}"`));
  assert.match(results[1], /cannot be assigned another target/);
  assert.ok(prompts[0].includes(`target_id "${targetId}"`));
});

// ── 18. needs-attention notifications follow the session language ────────
test('the approval notification is written in the session language', async () => {
  const { session, threadId, targetId } = await setupSession({ autonomous: false, lang: 'en' });
  let n = 0;
  const model = mock.method(ai, 'chatWithTools', async () => (++n === 1
    ? toolUse('send_http_request', { target_id: targetId, method: 'GET', path: '/' })
    : text('ok')));
  try {
    await agentLoop.advance(session.id, threadId);
  } finally {
    model.mock.restore();
  }
  const row = await waitFor(async () => (await db.query(
    `SELECT meta FROM activity_log WHERE action='ai_scan_needs_attention' AND entity_id=$1`, [session.id]
  )).rows[0], 'activity row');
  assert.equal(row.meta.message, 'The AI Agent wants to run "send_http_request" and needs your approval.');
});

// ── 19. reasoning_content round trip ─────────────────────────────────────
test('reasoning_content from a thinking model is sent back with its tool call', async () => {
  const { session, threadId } = await setupSession();
  const calls = [];
  const model = mock.method(ai, 'chatWithTools', async (_provider, opts) => {
    calls.push(opts.messages);
    return calls.length === 1
      ? { ...toolUse('get_targets_in_scope', {}), reasoningContent: 'I should list the scope first.' }
      : text('ok');
  });
  try {
    await agentLoop.advance(session.id, threadId);
  } finally {
    model.mock.restore();
  }
  const assistantCall = calls[1].find(m => m.toolCalls);
  assert.equal(assistantCall.reasoningContent, 'I should list the scope first.');
  assert.equal(toOpenAIMessages([assistantCall])[0].reasoning_content, 'I should list the scope first.');
  assert.equal(toOpenAIMessages([{ role: 'assistant', toolCalls: [{ id: '1', name: 'x', input: {} }] }])[0].reasoning_content, undefined);
});

// ── propose_finding en el gate avisa a los writers ───────────────────────
test('a propose_finding waiting for approval notifies the writers, the starter included', async () => {
  const { session, threadId, targetId, owner, project } = await setupSession({ autonomous: false });
  // Un hallazgo solo llega al gate citando una respuesta real de la sesión:
  // primero un fetch exitoso, después la propuesta que lo cita.
  let n = 0;
  const model = mock.method(ai, 'chatWithTools', async () => {
    n++;
    if (n === 1) return toolUse('fetch_endpoint', { target_id: targetId, path: '/api/orders/2' });
    if (n === 2) {
      const [res] = await events(session.id, 'tool.result');
      return toolUse('propose_finding', {
        name: 'IDOR on /api/orders', category: 'Access Control', severity: 'high', description: 'd',
        target_id: targetId, evidence_refs: [`ev_${res.id}`],
      });
    }
    return text('ok');
  });
  const http = mockHttp(async (url) => new URL(String(url)).pathname === '/api/orders/2'
    ? new Response('{"order":2,"owner":"someone-else"}', { status: 200, headers: { 'content-type': 'application/json' } })
    : new Response('Not Found', { status: 404, headers: { 'content-type': 'text/plain' } }));
  try {
    await agentLoop.advance(session.id, threadId);
  } finally {
    model.mock.restore();
    http.mock.restore();
  }
  assert.equal(await threadStatus(threadId), 'waiting_approval');
  const notif = await waitFor(async () => (await db.query(
    `SELECT * FROM notifications WHERE type='ai_finding_gate' AND user_id=$1`, [owner.user.id]
  )).rows[0], 'ai_finding_gate notification');
  assert.equal(notif.entity_type, 'ai_scan_session');
  assert.equal(notif.entity_id, session.id);
  assert.equal(notif.project_id, project.id);
  assert.equal(notif.payload.source, 'ai_agent');
  assert.equal(notif.payload.finding_title, 'IDOR on /api/orders');
  assert.equal(notif.payload.severity, 'high');
});

test('a gated HTTP tool does not raise an ai_finding_gate notification', async () => {
  const { session, threadId, targetId } = await setupSession({ autonomous: false });
  let n = 0;
  const model = mock.method(ai, 'chatWithTools', async () => (++n === 1
    ? toolUse('send_http_request', { target_id: targetId, method: 'POST', path: '/login' })
    : text('ok')));
  try {
    await agentLoop.advance(session.id, threadId);
  } finally {
    model.mock.restore();
  }
  assert.equal(await threadStatus(threadId), 'waiting_approval');
  await sleep(150);
  const { rows } = await db.query(`SELECT 1 FROM notifications WHERE type='ai_finding_gate'`);
  assert.equal(rows.length, 0);
});
