// Datos de la vista cliente (client.html) del lado del servidor. "Cliente" es
// tanto un link del portal como una cuenta con rol viewer: los dos reciben la
// misma proyección fija (WSTG, targets, actividad, hallazgos) y quedan afuera
// de las rutas internas (puertos, endpoints, labs, AI, whiteboard...). Estos
// tests fijan que nada de eso sale de la API, haga lo que haga el frontend.
const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const request = require('supertest');
const { WebSocket } = require('ws');
const { app, db, resetDb, registerUser, createProject } = require('./helpers');
const activity = require('../src/services/activity');
const wsService = require('../src/services/ws');

let server, port;
before(async () => {
  await resetDb();
  server = http.createServer(app);
  wsService.setup(server);
  await new Promise(resolve => server.listen(0, resolve));
  port = server.address().port;
});
beforeEach(async () => { await resetDb(); });
after(async () => {
  await new Promise(resolve => server.close(resolve));
  await db.pool.end();
});

const auth = t => ({ Authorization: `Bearer ${t}` });
const sleep = ms => new Promise(r => setTimeout(r, ms));

// Textos internos sembrados: ninguno puede aparecer en una respuesta al cliente.
const SECRETS = ['INTERNAL-WSTG-NOTE', 'INTERNAL-WSTG-DESC', 'INTERNAL-WSTG-FIX', 'INTERNAL-TARGET-NOTE', 'Draft SQLi'];

async function addViewer(ownerToken, projectId) {
  const user = await registerUser();
  const inv = await request(app).post(`/api/projects/${projectId}/invites`).set(auth(ownerToken)).send({ role: 'viewer' });
  assert.equal(inv.status, 201);
  const join = await request(app).post('/api/projects/join').set(auth(user.accessToken)).send({ token: inv.body.token });
  assert.equal(join.status, 200);
  return user;
}

// Proyecto con portal, un link de portal, una cuenta viewer y datos internos:
// un target con notas, un hallazgo publicado y un borrador, y WSTG con nota,
// descripción/remediación internas y vínculos a ambos hallazgos.
async function setup(flags = {}) {
  const owner = await registerUser();
  const project = await createProject(owner.accessToken);
  const patch = await request(app).patch(`/api/projects/${project.id}`).set(auth(owner.accessToken))
    .send({ client_view_enabled: true, show_findings: true, ...flags });
  assert.equal(patch.status, 200);
  const link = await request(app).post(`/api/projects/${project.id}/portal/links`).set(auth(owner.accessToken)).send({ label: 'Client Contact' });
  assert.equal(link.status, 201);
  const sess = await request(app).post('/api/portal/auth').send({ token: link.body.token });
  assert.equal(sess.status, 200);
  const viewer = await addViewer(owner.accessToken, project.id);

  const base = `/api/projects/${project.id}`;
  const o = auth(owner.accessToken);
  const target = await request(app).post(`${base}/targets`).set(o).send({ host: 'app.client.example', type: 'domain', scope: 'in', notes: 'INTERNAL-TARGET-NOTE' });
  assert.equal(target.status, 201);
  const pub = await request(app).post(`${base}/vulns`).set(o).send({ name: 'Published XSS', severity: 'critical', target_id: target.body.id });
  const draft = await request(app).post(`${base}/vulns`).set(o).send({ name: 'Draft SQLi', severity: 'critical', notes: 'internal' });
  assert.equal(pub.status, 201);
  assert.equal(draft.status, 201);
  assert.equal((await request(app).patch(`${base}/vulns/${pub.body.id}`).set(o).send({ client_visible: true })).status, 200);
  await db.query('UPDATE custom_vulns SET ai_generated=true WHERE id=$1', [draft.body.id]);

  const w = `${base}/wstg`;
  for (const [path, body] of [
    ['WSTG-INFO-01/status', { status: 'done' }],
    ['WSTG-INFO-01/note',   { note: 'INTERNAL-WSTG-NOTE' }],
    ['WSTG-INFO-01/report', { description: 'INTERNAL-WSTG-DESC', remediation: 'INTERNAL-WSTG-FIX' }],
    ['WSTG-INFO-01/link',   { linked_vuln_id: draft.body.id }],
    ['WSTG-INPV-05/status', { status: 'fail' }],
    ['WSTG-INPV-05/link',   { linked_vuln_id: pub.body.id }],
    ['WSTG-FAKE-99/status', { status: 'done' }],
  ]) {
    const r = await request(app).patch(`${w}/${path}`).set(o).send(body);
    assert.equal(r.status, 200, `${path}: ${JSON.stringify(r.body)}`);
  }
  return {
    owner, viewer, project, base, target: target.body, pub: pub.body, draft: draft.body,
    portalToken: sess.body.accessToken,
  };
}

const assertNoSecrets = (body, who) => {
  const json = JSON.stringify(body);
  for (const s of SECRETS) assert.ok(!json.includes(s), `${who} must not receive "${s}"`);
};

// ── WSTG ────────────────────────────────────────────────────────────────

test('WSTG is refused to portal and viewer when show_wstg_progress is off', async () => {
  const { base, portalToken, viewer, owner } = await setup();
  for (const [who, tok] of [['portal', portalToken], ['viewer', viewer.accessToken]]) {
    const r = await request(app).get(`${base}/wstg`).set(auth(tok));
    assert.equal(r.status, 403, who);
  }
  const own = await request(app).get(`${base}/wstg`).set(auth(owner.accessToken));
  assert.equal(own.status, 200);
});

test('client WSTG is a fixed projection: no notes (switch off), editor, internal text or draft links', async () => {
  const { base, portalToken, viewer, pub } = await setup({ show_wstg_progress: true });
  const portal = await request(app).get(`${base}/wstg`).set(auth(portalToken));
  assert.equal(portal.status, 200);
  const p = portal.body;
  assert.deepEqual(Object.keys(p).sort(), ['WSTG-INFO-01', 'WSTG-INPV-05'], 'only catalog tests');
  assert.deepEqual(p['WSTG-INFO-01'], {
    test_id: 'WSTG-INFO-01', name: 'Search Engine Discovery & Recon', category: 'Information Gathering',
    status: 'done', linked_finding: null, // vinculado a un borrador
  });
  assert.deepEqual(p['WSTG-INPV-05'].linked_finding, { id: pub.id, name: 'Published XSS' });
  assert.equal(p['WSTG-INPV-05'].category, 'Input Validation');
  assertNoSecrets(p, 'portal');

  // La cuenta viewer recibe exactamente lo mismo que el portal.
  const v = await request(app).get(`${base}/wstg`).set(auth(viewer.accessToken));
  assert.equal(v.status, 200);
  assert.deepEqual(v.body, p);
});

test('client WSTG carries the note only when show_wstg_notes is on; the team keeps the full shape', async () => {
  const { base, portalToken, viewer, owner, draft } = await setup({ show_wstg_progress: true, show_wstg_notes: true });
  for (const tok of [portalToken, viewer.accessToken]) {
    const r = await request(app).get(`${base}/wstg`).set(auth(tok));
    assert.equal(r.status, 200);
    const t = r.body['WSTG-INFO-01'];
    assert.deepEqual(Object.keys(t).sort(), ['category', 'linked_finding', 'name', 'note', 'status', 'test_id']);
    assert.equal(t.note, 'INTERNAL-WSTG-NOTE');
    assert.equal(r.body['WSTG-INPV-05'].note, null);
    const json = JSON.stringify(r.body);
    for (const leak of ['INTERNAL-WSTG-DESC', 'INTERNAL-WSTG-FIX', 'last_editor', 'editor', 'description', 'remediation', 'target_id', draft.id]) {
      assert.ok(!json.includes(leak), `client WSTG must not include ${leak}`);
    }
  }
  const own = await request(app).get(`${base}/wstg`).set(auth(owner.accessToken));
  const t = own.body['WSTG-INFO-01'];
  assert.equal(t.description, 'INTERNAL-WSTG-DESC');
  assert.equal(t.linked_vuln_id, draft.id);
  assert.ok(t.last_editor?.username);
});

// ── Targets, ports, endpoints, labs ─────────────────────────────────────

test('targets are refused to portal and viewer when show_targets is off', async () => {
  const { base, portalToken, viewer } = await setup();
  for (const tok of [portalToken, viewer.accessToken]) {
    assert.equal((await request(app).get(`${base}/targets`).set(auth(tok))).status, 403);
  }
});

test('client targets are a fixed projection without notes or who added them', async () => {
  const { base, portalToken, viewer, owner, target } = await setup({ show_targets: true });
  for (const [who, tok] of [['portal', portalToken], ['viewer', viewer.accessToken]]) {
    const r = await request(app).get(`${base}/targets`).set(auth(tok));
    assert.equal(r.status, 200, who);
    assert.deepEqual(r.body, [{ id: target.id, host: 'app.client.example', type: 'domain', scope: 'in', status: target.status }]);
    assertNoSecrets(r.body, who);
  }
  const own = await request(app).get(`${base}/targets`).set(auth(owner.accessToken));
  assert.equal(own.body[0].notes, 'INTERNAL-TARGET-NOTE');
  assert.ok(own.body[0].added_by_username);
});

test('ports, endpoints and PortSwigger labs are internal: 403 for portal and viewer even with every switch on', async () => {
  const { base, portalToken, viewer, owner, target } = await setup({ show_targets: true, show_wstg_progress: true, show_wstg_notes: true });
  const paths = [`targets/${target.id}/ports`, `targets/${target.id}/endpoints`, 'ps'];
  for (const p of paths) {
    for (const [who, tok] of [['portal', portalToken], ['viewer', viewer.accessToken]]) {
      const r = await request(app).get(`${base}/${p}`).set(auth(tok));
      assert.equal(r.status, 403, `${p} must be 403 for ${who}`);
    }
    assert.equal((await request(app).get(`${base}/${p}`).set(auth(owner.accessToken))).status, 200, `${p} owner`);
  }
});

// ── Cuentas viewer (el cliente con cuenta) ───────────────────────────────

test('viewer account gets the client activity feed: allowlist, no AI provenance, no internal events', async () => {
  const { base, portalToken, viewer, owner, project, pub, draft } = await setup({ show_activity: true });
  const { rows } = await db.query('SELECT id, username, display_name, avatar_color FROM users WHERE id=$1', [owner.user.id]);
  const actor = rows[0];
  await activity.log({ projectId: project.id, user: actor, action: 'vuln_created', entityType: 'custom_vuln',
    entityId: pub.id, entityName: 'XSS (IA)', meta: { severity: 'critical', ai_generated: true, via: 'claude-code' } });
  await activity.log({ projectId: project.id, user: actor, action: 'ai_scan_started', entityType: 'ai_scan_session', entityName: 'AI Agent' });
  await activity.log({ projectId: project.id, user: actor, action: 'invite_created', entityType: 'member', meta: { token: 'secret-invite-token' } });

  const feed = await request(app).get(`${base}/activity`).set(auth(viewer.accessToken));
  assert.equal(feed.status, 200);
  const portalFeed = await request(app).get(`${base}/activity`).set(auth(portalToken));
  assert.deepEqual(feed.body, portalFeed.body, 'viewer and portal see the same feed');
  assert.ok(feed.body.length >= 1);
  for (const e of feed.body) {
    assert.equal(e.entity_type, 'custom_vuln');
    assert.equal(e.entity_id, pub.id, 'only the published finding');
    assert.equal(e.user_id, undefined);
    assert.ok(!e.meta || !('ai_generated' in e.meta || 'via' in e.meta));
  }
  const json = JSON.stringify(feed.body);
  assert.ok(!json.includes('secret-invite-token') && !json.includes(draft.id) && !json.includes('ai_scan'));

  // El equipo sigue viendo todo, con la procedencia IA.
  const own = await request(app).get(`${base}/activity`).set(auth(owner.accessToken));
  assert.ok(own.body.some(e => e.action === 'ai_scan_started'));
  assert.ok(own.body.some(e => e.meta?.ai_generated === true));
});

test('viewer account activity respects show_activity', async () => {
  const { base, viewer } = await setup();
  assert.equal((await request(app).get(`${base}/activity`).set(auth(viewer.accessToken))).status, 403);
});

test('viewer account findings: published only, portal projection, no AI provenance', async () => {
  const { base, viewer, pub } = await setup();
  const r = await request(app).get(`${base}/vulns`).set(auth(viewer.accessToken));
  assert.equal(r.status, 200);
  assert.deepEqual(r.body.map(f => f.id), [pub.id]);
  for (const leak of ['notes', 'ai_generated', 'client_visible', 'editor_username', 'created_by', 'origin']) {
    assert.equal(r.body[0][leak], undefined, leak);
  }
});

test('viewer account is refused on internal-only routes', async () => {
  const { base, viewer, project } = await setup({ show_wstg_progress: true });
  const paths = [
    `${base}/whiteboard`, `${base}/ai-scan/sessions`, `${base}/mcp-proposals`, `${base}/report-config`,
    `${base}/ai/usage`, `/api/methodologies/project-progress/${project.id}`,
  ];
  for (const p of paths) {
    const r = await request(app).get(p).set(auth(viewer.accessToken));
    assert.equal(r.status, 403, `${p} must be 403 for a viewer`);
  }
});

test('viewer account gets members, project and tickets without internal data', async () => {
  const { base, viewer, owner, project, draft } = await setup({ tickets_enabled: true });

  const m = await request(app).get(`${base}/members`).set(auth(viewer.accessToken));
  assert.equal(m.status, 200);
  for (const row of m.body) {
    assert.deepEqual(Object.keys(row).sort(), ['avatar_color', 'avatar_url', 'display_name', 'role', 'username']);
  }

  const one = await request(app).get(base).set(auth(viewer.accessToken));
  assert.equal(one.status, 200);
  assert.equal(one.body.member_role, 'viewer');
  for (const leak of ['ai_provider', 'github_repo', 'owner_id', 'organization_id', 'description']) {
    assert.equal(one.body[leak], undefined, leak);
  }
  const list = await request(app).get('/api/projects').set(auth(viewer.accessToken));
  const row = list.body.find(p => p.id === project.id);
  assert.equal(row.crit_count, 1, 'counts only the published critical, not the draft');
  assert.equal(row.ai_provider, undefined);
  const ownRow = (await request(app).get('/api/projects').set(auth(owner.accessToken))).body.find(p => p.id === project.id);
  assert.equal(ownRow.crit_count, 2);

  // Ticket del equipo vinculado al borrador: el viewer no ve su nombre.
  const t = await request(app).post(`${base}/tickets`).set(auth(owner.accessToken)).send({ title: 'Q', vuln_id: draft.id });
  assert.equal(t.status, 201);
  const tl = await request(app).get(`${base}/tickets`).set(auth(viewer.accessToken));
  assert.equal(tl.body[0].vuln_name, null);
  assert.ok(!('github_url' in tl.body[0]));
  const td = await request(app).get(`${base}/tickets/${t.body.id}`).set(auth(viewer.accessToken));
  assert.equal(td.body.vuln_name, null);
  assert.ok(!('github_url' in td.body));
  // Ni puede vincular un borrador al abrir una consulta.
  const bad = await request(app).post(`${base}/tickets`).set(auth(viewer.accessToken)).send({ title: 'Q2', vuln_id: draft.id });
  assert.equal(bad.status, 400);
});

// ── WebSocket ───────────────────────────────────────────────────────────

async function connect(projectId, token) {
  const socket = new WebSocket(`ws://127.0.0.1:${port}/ws?projectId=${projectId}`);
  socket.received = [];
  socket.on('message', d => socket.received.push(JSON.parse(d)));
  await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
  socket.send(JSON.stringify({ type: 'auth', token }));
  for (let i = 0; i < 50 && !socket.received.some(m => m.type === 'auth_ok'); i++) await sleep(20);
  assert.ok(socket.received.some(m => m.type === 'auth_ok'));
  return socket;
}

test('viewer socket only gets a bare activity ping: no event payload, AI stream or team presence', async () => {
  const { owner, viewer, project } = await setup();
  const viewerSocket = await connect(project.id, viewer.accessToken);
  const ownerSocket  = await connect(project.id, owner.accessToken);
  const { rows } = await db.query('SELECT id, username, display_name, avatar_color FROM users WHERE id=$1', [owner.user.id]);
  await activity.log({ projectId: project.id, user: rows[0], action: 'invite_created', entityType: 'member', meta: { token: 'secret-invite-token', ai_generated: true } });
  wsService.broadcastScanEvent(project.id, { session_id: 'x', event: { type: 'chat.message', text: 'AI internal' } });
  ownerSocket.send(JSON.stringify({ type: 'wb:patch', patch: { secret: 'wb' } }));
  await sleep(300);

  const vMsgs = viewerSocket.received.filter(m => m.type !== 'auth_ok');
  assert.deepEqual(vMsgs, [{ type: 'activity' }], JSON.stringify(vMsgs));
  const oMsgs = ownerSocket.received;
  assert.ok(oMsgs.some(m => m.type === 'activity' && m.meta?.token === 'secret-invite-token'));
  assert.ok(oMsgs.some(m => m.type === 'ai_scan:event'));
  assert.ok(oMsgs.some(m => m.type === 'presence'));
  viewerSocket.close();
  ownerSocket.close();
});
