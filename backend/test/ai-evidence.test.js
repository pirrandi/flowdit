// Hallazgos del AI Agent respaldados por evidencia (evidence.js): solo una
// respuesta de red real y exitosa, de esta sesión y de este target, se puede
// citar; nunca un 404, un soft-404 o un error. Al aprobar, lo citado se
// adjunta como http_proofs. El proveedor (ai.chatWithTools) y el HTTP del
// target (globalThis.fetch) están mockeados; el loop y la DB corren de verdad.
const { test, before, beforeEach, after, mock } = require('node:test');
const assert = require('node:assert/strict');
const { db, resetDb, registerUser, createProject } = require('./helpers');
const ai = require('../src/services/ai');
const agentLoop = require('../src/services/ai/agentLoop');
const { clearBaselineCache } = require('../src/services/ai/soft404');
const { validateEvidenceRefs, citability } = require('../src/services/ai/evidence');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); clearBaselineCache(); });
after(async () => { await db.pool.end(); });

async function setupSession({ autonomous = false, lang = 'en' } = {}) {
  const owner = await registerUser();
  const project = await createProject(owner.accessToken);
  const { rows } = await db.query(
    `INSERT INTO targets (project_id, host, type, scope, status) VALUES ($1,'app.example.test','domain','in','active'), ($1,'other.example.test','domain','in','active') RETURNING id`,
    [project.id]
  );
  const [targetId, otherTargetId] = rows.map(r => r.id);
  const { session, primaryThread } = await agentLoop.createSessionWithPrimaryThread(
    project.id, null, owner.user.id, lang, 'Recon the target', { ai_autonomous_requests: autonomous }
  );
  return { owner, project, session, threadId: primaryThread.id, targetId, otherTargetId };
}

const text = t => ({ type: 'text', text: t, usage: {}, model: 'mock' });
const toolUse = (name, input) => ({ type: 'tool_use', toolCalls: [{ id: 'x', name, input }], usage: {}, model: 'mock' });
const events = async (sessionId, type) =>
  (await db.query(`SELECT * FROM ai_scan_events WHERE session_id=$1 AND type=$2 ORDER BY id`, [sessionId, type])).rows;
const threadStatus = async id => (await db.query(`SELECT status FROM ai_scan_threads WHERE id=$1`, [id])).rows[0].status;

// Target de prueba: un SPA con catch-all (200 + la misma página para todo
// path inexistente), un path real, un 404 de verdad y uno que no conecta.
const CATCH_ALL = '<html><body><div id="root"></div></body></html>';
function mockTarget() {
  return mock.method(globalThis, 'fetch', async (url) => {
    const u = new URL(String(url));
    if (u.pathname === '/boom') throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } });
    if (u.pathname === '/gone') return new Response('Not Found', { status: 404, headers: { 'content-type': 'text/plain' } });
    if (u.pathname === '/admin/config') return new Response('{"debug":true,"db_password":"hunter2"}', { status: 200, headers: { 'content-type': 'application/json', server: 'nginx' } });
    return new Response(CATCH_ALL, { status: 200, headers: { 'content-type': 'text/html' } });
  });
}

// Corre una ronda del loop: cada `step` recibe los resultados ya guardados y
// devuelve la próxima respuesta del modelo.
async function runModel(session, threadId, steps) {
  let n = 0;
  const model = mock.method(ai, 'chatWithTools', async () => {
    const step = steps[n++];
    if (!step) return text('done');
    return step(await events(session.id, 'tool.result'));
  });
  try {
    await agentLoop.advance(session.id, threadId);
  } finally {
    model.mock.restore();
  }
}

const refOf = ev => `ev_${ev.id}`;
const fetchStep = (targetId, path) => () => toolUse('fetch_endpoint', { target_id: targetId, path });
const FINDING = { name: 'Exposed debug config', category: 'Information Disclosure', severity: 'high', description: 'The config endpoint leaks a DB password.' };

// Cuatro lecturas: real, soft-404, 404 y error de red.
async function observeAll(session, threadId, targetId) {
  await runModel(session, threadId, [
    fetchStep(targetId, '/admin/config'), fetchStep(targetId, '/ghost'),
    fetchStep(targetId, '/gone'), fetchStep(targetId, '/boom'),
  ]);
  const [real, soft, notFound, failed] = await events(session.id, 'tool.result');
  assert.equal(real.payload.result.status, 200);
  assert.equal(soft.payload.result.reason, 'soft_404');
  assert.equal(notFound.payload.result.reason, 'http_404');
  assert.match(failed.payload.result.error, /request failed/);
  return { real, soft, notFound, failed };
}

test('only real, successful network observations get an evidence_ref in the model history', async () => {
  const { session, threadId, targetId } = await setupSession({ autonomous: true });
  const http = mockTarget();
  try {
    const { real } = await observeAll(session, threadId, targetId);
    const all = (await db.query(`SELECT * FROM ai_scan_events WHERE session_id=$1 ORDER BY id`, [session.id])).rows;
    const toolMsgs = agentLoop.eventsToMessages(all).filter(m => m.role === 'tool');
    assert.equal(toolMsgs.length, 4);
    assert.deepEqual(toolMsgs.map(m => m.result.evidence_ref ?? null), [refOf(real), null, null, null]);
  } finally {
    http.mock.restore();
  }
});

test('propose_finding is rejected before the gate for soft-404, 404, error, missing and malformed refs', async () => {
  const { project, session, threadId, targetId } = await setupSession();
  const http = mockTarget();
  try {
    const { soft, notFound, failed } = await observeAll(session, threadId, targetId);
    const cases = [
      [[refOf(soft)], /is a soft-404 response — the target answers any non-existent path.*you cannot report a finding on it/],
      [[refOf(notFound)], /is a not-found \(404\/410\) response — the path does not exist; you cannot report a finding on it/],
      [[refOf(failed)], /is a failed request .*nothing was observed/],
      [undefined, /propose_finding requires evidence_refs/],
      [[], /propose_finding requires evidence_refs/],
      [['https://app.example.test/admin/config'], /is not a valid evidence_ref/],
      [['ev_999999999'], /does not exist in this session/],
    ];
    for (const [refs, expected] of cases) {
      await db.query(`UPDATE ai_scan_threads SET status='running' WHERE id=$1`, [threadId]);
      const before = (await events(session.id, 'tool.result')).length;
      await runModel(session, threadId, [() => toolUse('propose_finding', { ...FINDING, target_id: targetId, evidence_refs: refs })]);
      const results = await events(session.id, 'tool.result');
      assert.equal(results.length, before + 1, `${JSON.stringify(refs)}: the call got a result instead of waiting for approval`);
      assert.match(results.at(-1).payload.result.error, expected, JSON.stringify(refs));
      assert.match(results.at(-1).payload.result.error, /^Not submitted for review/);
      assert.notEqual(await threadStatus(threadId), 'waiting_approval');
    }
    const { rows } = await db.query(`SELECT 1 FROM custom_vulns WHERE project_id=$1`, [project.id]);
    assert.equal(rows.length, 0);
  } finally {
    http.mock.restore();
  }
});

test('refs from another session or another target are rejected; other threads of the same session are allowed', async () => {
  const a = await setupSession();
  const http = mockTarget();
  try {
    const { real } = await observeAll(a.session, a.threadId, a.targetId);

    // Otra sesión del mismo proyecto: el ref es real, pero no de este trabajo.
    const { session: other } = await agentLoop.createSessionWithPrimaryThread(a.project.id, null, a.owner.user.id, 'en', null, {});
    const foreign = await validateEvidenceRefs({ sessionId: other.id, targetId: a.targetId, refs: [refOf(real)] });
    assert.match(foreign.errors.join('\n'), new RegExp(`${refOf(real)} does not exist in this session`));

    // Mismo ref, hallazgo de otro target.
    const wrongTarget = await validateEvidenceRefs({ sessionId: a.session.id, targetId: a.otherTargetId, refs: [refOf(real)] });
    assert.match(wrongTarget.errors.join('\n'), /was observed on target_id .* but this finding is for target_id/);

    // Sub-agente de la misma sesión: el coordinador puede citar su evidencia.
    const { rows: [sub] } = await db.query(
      `INSERT INTO ai_scan_threads (session_id, parent_thread_id, label, status) VALUES ($1,$2,'sub','completed') RETURNING id`,
      [a.session.id, a.threadId]
    );
    const { rows: [called] } = await db.query(
      `INSERT INTO ai_scan_events (session_id, thread_id, type, payload) VALUES ($1,$2,'tool.called',$3) RETURNING id`,
      [a.session.id, sub.id, { name: 'fetch_endpoint', input: { target_id: a.targetId, path: '/admin/config' }, tier: 1 }]
    );
    const { rows: [subResult] } = await db.query(
      `INSERT INTO ai_scan_events (session_id, thread_id, type, payload) VALUES ($1,$2,'tool.result',$3) RETURNING id`,
      [a.session.id, sub.id, { call_id: called.id, name: 'fetch_endpoint', result: { url: 'https://app.example.test/admin/config', status: 200, headers: {}, body_preview: 'x' } }]
    );
    const ok = await validateEvidenceRefs({ sessionId: a.session.id, targetId: null, refs: [`ev_${subResult.id}`] });
    assert.equal(ok.errors, undefined);
    assert.equal(ok.targetId, a.targetId, 'the finding target is inferred from the evidence');

    // Una lectura de la DB de Flowdit (tier 0) no es una observación del target.
    assert.equal(citability('get_existing_findings', { result: { findings: [] } }).citable, false);
    // Un tier 2 rechazado nunca corrió.
    assert.equal(citability('send_http_request', { decision: 'rejected' }).citable, false);
  } finally {
    http.mock.restore();
  }
});

test('a valid ref reaches the gate with its proofs, and approval attaches them as http_proofs', async () => {
  const { project, session, threadId, targetId, owner } = await setupSession();
  const http = mockTarget();
  try {
    const { real } = await observeAll(session, threadId, targetId);
    await db.query(`UPDATE ai_scan_threads SET status='running' WHERE id=$1`, [threadId]);
    // Sin target_id: se infiere de la evidencia. Lo que el modelo escriba en
    // http_proofs se ignora — solo cuentan las respuestas guardadas.
    await runModel(session, threadId, [() => toolUse('propose_finding', {
      ...FINDING, evidence_refs: [refOf(real)],
      http_proofs: [{ method: 'GET', request: 'GET /invented', response: 'HTTP/1.1 200 OK\n\nflag{fake}' }],
    })]);
    assert.equal(await threadStatus(threadId), 'waiting_approval');
    const called = (await events(session.id, 'tool.called')).at(-1);
    assert.equal(called.payload.name, 'propose_finding');
    assert.equal(called.payload.evidence_target_id, targetId);
    assert.equal(called.payload.evidence_proofs.length, 1);

    const model = mock.method(ai, 'chatWithTools', async () => text('ok'));
    try {
      await agentLoop.resolveGatedCall(session.id, called.id, 'accepted', owner.user.id);
    } finally {
      model.mock.restore();
    }
    const { rows: [vuln] } = await db.query(`SELECT * FROM custom_vulns WHERE project_id=$1`, [project.id]);
    assert.ok(vuln, 'finding created');
    assert.equal(vuln.target_id, targetId);
    assert.equal(vuln.http_proofs.length, 1);
    const [p] = vuln.http_proofs;
    assert.equal(p.method, 'GET');
    assert.equal(p.evidence_ref, refOf(real));
    assert.match(p.request, /^GET \/admin\/config HTTP\/1\.1\nHost: app\.example\.test/);
    assert.match(p.response, /^HTTP\/1\.1 200\n/);
    assert.match(p.response, /"db_password":"hunter2"/);
    assert.match(p.annotation, new RegExp(`Evidence ${refOf(real)} \\(fetch_endpoint\\)`));
    assert.doesNotMatch(JSON.stringify(vuln.http_proofs), /invented|flag\{fake\}/);
  } finally {
    http.mock.restore();
  }
});

test('"edit and add" keeps the cited evidence on the finding the pentester created', async () => {
  const { project, session, threadId, targetId, owner } = await setupSession();
  const http = mockTarget();
  try {
    const { real } = await observeAll(session, threadId, targetId);
    await db.query(`UPDATE ai_scan_threads SET status='running' WHERE id=$1`, [threadId]);
    await runModel(session, threadId, [() => toolUse('propose_finding', { ...FINDING, target_id: targetId, evidence_refs: [refOf(real)] })]);
    const called = (await events(session.id, 'tool.called')).at(-1);
    const { rows: [manual] } = await db.query(
      `INSERT INTO custom_vulns (project_id, name, severity, target_id, created_by) VALUES ($1,'Edited by hand','medium',$2,$3) RETURNING id`,
      [project.id, targetId, owner.user.id]
    );
    const model = mock.method(ai, 'chatWithTools', async () => text('ok'));
    try {
      await agentLoop.resolveGatedCall(session.id, called.id, 'accepted', owner.user.id, { created_vuln_id: manual.id });
    } finally {
      model.mock.restore();
    }
    const { rows: [vuln] } = await db.query(`SELECT http_proofs FROM custom_vulns WHERE id=$1`, [manual.id]);
    assert.deepEqual(vuln.http_proofs.map(p => p.evidence_ref), [refOf(real)]);
  } finally {
    http.mock.restore();
  }
});

test('update_finding needs evidence only for new technical claims, and never re-attaches a ref', async () => {
  const { project, session, threadId, targetId, owner } = await setupSession({ autonomous: true });
  const http = mockTarget();
  try {
    const { real, soft } = await observeAll(session, threadId, targetId);
    const { rows: [vuln] } = await db.query(
      `INSERT INTO custom_vulns (project_id, name, severity, target_id, created_by) VALUES ($1,'Debug config','low',$2,$3) RETURNING id`,
      [project.id, targetId, owner.user.id]
    );
    const update = input => () => toolUse('update_finding', { finding_id: vuln.id, ...input });
    await db.query(`UPDATE ai_scan_threads SET status='running' WHERE id=$1`, [threadId]);
    await runModel(session, threadId, [
      update({ description: 'Reworded.' }),                                   // editorial: sin refs
      update({ severity: 'critical' }),                                       // sube severidad: exige refs
      update({ remediation_status: 'not_remediated', evidence_refs: [refOf(soft)] }), // ref no citable
      update({ severity: 'critical', evidence_refs: [refOf(real)] }),
      update({ remediation_status: 'not_remediated', evidence_refs: [refOf(real)] }), // mismo ref otra vez
    ]);
    const results = (await events(session.id, 'tool.result')).slice(-5).map(e => e.payload.result);
    assert.ok(results[0].created_vuln_id, JSON.stringify(results[0]));
    assert.match(results[1].error, /raises the severity/);
    assert.match(results[1].error, /update_finding requires evidence_refs/);
    assert.match(results[2].error, /soft-404/);
    assert.ok(results[3].created_vuln_id, JSON.stringify(results[3]));
    assert.ok(results[4].created_vuln_id, JSON.stringify(results[4]));
    const { rows: [after] } = await db.query(`SELECT * FROM custom_vulns WHERE id=$1`, [vuln.id]);
    assert.equal(after.description, 'Reworded.');
    assert.equal(after.severity, 'critical');
    assert.equal(after.remediation_status, 'not_remediated');
    assert.deepEqual(after.http_proofs.map(p => p.evidence_ref), [refOf(real)]);
  } finally {
    http.mock.restore();
  }
});

test('tier 2 GETs to a soft-404 are marked not_found and cannot be cited', async () => {
  const { session, threadId, targetId } = await setupSession({ autonomous: true });
  const http = mockTarget();
  try {
    await runModel(session, threadId, [
      () => toolUse('send_http_request', { target_id: targetId, method: 'GET', path: '/ghost' }),
      () => toolUse('send_http_request', { target_id: targetId, method: 'POST', path: '/gone' }),
      () => toolUse('send_http_request', { target_id: targetId, method: 'GET', path: '/admin/config' }),
    ]);
    const [soft, gone, real] = await events(session.id, 'tool.result');
    assert.equal(soft.payload.result.reason, 'soft_404');
    assert.equal(soft.payload.result.body_preview, undefined, 'the catch-all body is not handed to the model');
    assert.equal(gone.payload.result.reason, 'http_404');
    assert.equal(real.payload.result.not_found, undefined);
    const v = await validateEvidenceRefs({ sessionId: session.id, targetId, refs: [refOf(soft), refOf(gone)] });
    assert.equal(v.errors.length, 2);
    const ok = await validateEvidenceRefs({ sessionId: session.id, targetId, refs: [refOf(real)] });
    assert.equal(ok.errors, undefined);
  } finally {
    http.mock.restore();
  }
});
