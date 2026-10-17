// Feed de actividad del portal del cliente: allowlist de pares (entity_type,
// action) en routes/activity.js. Estos tests fijan que cualquier evento que no
// esté explícitamente pensado para el cliente (uno nuevo, los del AI Agent, las
// propuestas de Claude Code, invitaciones...) queda afuera por defecto, y que
// ni el feed ni los hallazgos del portal exponen procedencia IA.
const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { app, db, resetDb, registerUser, createProject } = require('./helpers');
const activity = require('../src/services/activity');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

const auth = t => ({ Authorization: `Bearer ${t}` });

const AI_KEYS = ['ai_generated', 'origin', 'session_id', 'via', 'message'];
const AI_WORDING = /\b(IA|AI|AI Agent|Claude|Claude Code|claude-code|ai_agent)\b/i;

async function setupPortal(flags = {}) {
  const owner = await registerUser();
  const project = await createProject(owner.accessToken);
  const patch = await request(app)
    .patch(`/api/projects/${project.id}`)
    .set(auth(owner.accessToken))
    .send({ client_view_enabled: true, show_findings: true, show_activity: true, ...flags });
  assert.equal(patch.status, 200);
  const link = await request(app)
    .post(`/api/projects/${project.id}/portal/links`)
    .set(auth(owner.accessToken))
    .send({ label: 'Client Contact' });
  assert.equal(link.status, 201);
  const sess = await request(app).post('/api/portal/auth').send({ token: link.body.token });
  assert.equal(sess.status, 200);
  // activity.log necesita la fila del usuario como actor.
  const { rows } = await db.query('SELECT id, username, display_name, avatar_color FROM users WHERE id=$1', [owner.user.id]);
  return { owner, actor: rows[0], project, portalToken: sess.body.accessToken };
}

async function createFinding(ownerToken, projectId, body) {
  const res = await request(app).post(`/api/projects/${projectId}/vulns`).set(auth(ownerToken)).send(body);
  assert.equal(res.status, 201);
  return res.body;
}

async function publish(ownerToken, projectId, vulnId) {
  const res = await request(app)
    .patch(`/api/projects/${projectId}/vulns/${vulnId}`)
    .set(auth(ownerToken))
    .send({ client_visible: true });
  assert.equal(res.status, 200);
}

const portalFeed = async (project, portalToken) => {
  const res = await request(app).get(`/api/projects/${project.id}/activity`).set(auth(portalToken));
  assert.equal(res.status, 200);
  return res.body;
};

test('portal feed hides an unknown/new action type (allowlist, not denylist)', async () => {
  const { owner, actor, project, portalToken } = await setupPortal();
  const f = await createFinding(owner.accessToken, project.id, { name: 'SQLi', severity: 'high' });
  await publish(owner.accessToken, project.id, f.id);
  // Un evento que nadie dio de alta para el cliente: ni entity_type ni action
  // conocidos, y también una acción nueva sobre un entity_type permitido.
  await activity.log({ projectId: project.id, user: actor, action: 'brand_new_event', entityType: 'brand_new_entity', entityName: 'internal thing' });
  await activity.log({ projectId: project.id, user: actor, action: 'vuln_internal_retriaged', entityType: 'custom_vuln', entityId: f.id, entityName: 'SQLi' });

  const feed = await portalFeed(project, portalToken);
  assert.ok(!feed.some(e => e.action === 'brand_new_event'));
  assert.ok(!feed.some(e => e.action === 'vuln_internal_retriaged'));
  // Lo permitido sigue apareciendo.
  assert.ok(feed.some(e => e.action === 'vuln_created' && e.entity_id === f.id));

  // El equipo interno ve todo.
  const team = await request(app).get(`/api/projects/${project.id}/activity`).set(auth(owner.accessToken));
  assert.ok(team.body.some(e => e.action === 'brand_new_event'));
  assert.ok(team.body.some(e => e.action === 'vuln_internal_retriaged'));
});

test('portal feed never shows AI agent, Claude Code proposal or invite events', async () => {
  const { owner, actor, project, portalToken } = await setupPortal({ show_targets: true, show_wstg_progress: true });
  const { rows: s } = await db.query(
    `INSERT INTO ai_scan_sessions (project_id, started_by) VALUES ($1,$2) RETURNING id`, [project.id, actor.id]
  );
  const sid = s[0].id;
  const aiEvents = [
    ['ai_scan_started',         'ai_scan_session', {}],
    ['ai_scan_deleted',         'ai_scan_session', {}],
    ['ai_scan_needs_attention', 'ai_scan_session', { message: 'El AI Agent agotó el presupuesto de auto-continues' }],
    ['ai_scan_limit_reached',   'ai_scan_session', { cost_usd: 1.23 }],
    ['ai_scan_checkpoint',      'ai_scan_session', {}],
    ['ai_scan_no_progress',     'ai_scan_session', {}],
    ['claude_code_proposed',    'mcp_proposal',    { via: 'claude-code', kind: 'finding' }],
    ['claude_code_proposal_approved', 'mcp_proposal', { via: 'claude-code', kind: 'note' }],
    ['invite_created',          'member',          { role: 'editor', token: 'secret-invite-token' }],
    ['port_added',              'port',            { state: 'open' }],
  ];
  for (const [action, entityType, meta] of aiEvents) {
    await activity.log({ projectId: project.id, user: actor, action, entityType, entityId: sid, entityName: 'Proyecto (AI Agent)', meta });
  }
  // Allowed control events, so the feed is not trivially empty.
  const t = await request(app).post(`/api/projects/${project.id}/targets`).set(auth(owner.accessToken)).send({ host: 'client.example.com', type: 'domain' });
  assert.equal(t.status, 201);

  const feed = await portalFeed(project, portalToken);
  for (const [action] of aiEvents) assert.ok(!feed.some(e => e.action === action), `${action} must not reach the portal`);
  assert.ok(feed.every(e => !e.entity_type.startsWith('ai_') && e.entity_type !== 'mcp_proposal'));
  assert.ok(!JSON.stringify(feed).includes('secret-invite-token'));
  assert.ok(feed.some(e => e.action === 'target_added' && e.entity_name === 'client.example.com'));
});

test('portal feed hides events about unpublished findings and gated sections', async () => {
  const { owner, project, portalToken } = await setupPortal(); // show_targets off
  const draft = await createFinding(owner.accessToken, project.id, { name: 'Draft finding', severity: 'high' });
  await request(app).patch(`/api/projects/${project.id}/vulns/${draft.id}/remediation`)
    .set(auth(owner.accessToken)).send({ remediation_status: 'remediated' });
  const hid = await request(app).post(`/api/projects/${project.id}/targets`).set(auth(owner.accessToken)).send({ host: 'hidden.example.com', type: 'domain' });
  assert.equal(hid.status, 201);

  let feed = await portalFeed(project, portalToken);
  assert.equal(feed.length, 0, JSON.stringify(feed));

  // Al publicarlo, su historia (alta + remediación) pasa a ser del cliente.
  await publish(owner.accessToken, project.id, draft.id);
  feed = await portalFeed(project, portalToken);
  assert.deepEqual(feed.map(e => e.action).sort(), ['remediation_status_changed', 'vuln_created']);
  assert.ok(feed.every(e => e.entity_name === 'Draft finding'));
});

test('published AI-generated finding: portal finding and activity carry no AI provenance', async () => {
  const { owner, actor, project, portalToken } = await setupPortal();
  const { rows: s } = await db.query(
    `INSERT INTO ai_scan_sessions (project_id, started_by) VALUES ($1,$2) RETURNING id`, [project.id, actor.id]
  );
  // Así guardan el hallazgo el AI Agent / la aprobación de Claude Code.
  const { rows } = await db.query(
    `INSERT INTO custom_vulns (project_id, name, severity, description, remediation, created_by, updated_by, ai_generated, origin, session_id)
     VALUES ($1, 'XSS (encontrado con IA)', 'high', 'desc', 'fix', $2, $2, true, 'claude_code', $3) RETURNING id`,
    [project.id, actor.id, s[0].id]
  );
  const vulnId = rows[0].id;
  await activity.log({
    projectId: project.id, user: actor, action: 'vuln_created', entityType: 'custom_vuln',
    entityId: vulnId, entityName: 'XSS (encontrado con IA)',
    meta: { severity: 'high', ai_generated: true, via: 'claude-code' },
  });
  await activity.log({
    projectId: project.id, user: actor, action: 'remediation_status_changed', entityType: 'custom_vuln',
    entityId: vulnId, entityName: 'XSS (encontrado con IA)',
    meta: { remediation_status: 'remediated', ai_generated: true },
  });
  // El lead corrige el título antes de publicar: el feed debe mostrar este.
  const upd = await request(app).patch(`/api/projects/${project.id}/vulns/${vulnId}`)
    .set(auth(owner.accessToken)).send({ name: 'Reflected XSS', client_visible: true });
  assert.equal(upd.status, 200);

  const vulns = await request(app).get(`/api/projects/${project.id}/vulns`).set(auth(portalToken));
  assert.equal(vulns.status, 200);
  assert.equal(vulns.body.length, 1);
  for (const k of AI_KEYS) assert.equal(vulns.body[0][k], undefined, `finding must not expose ${k}`);

  const feed = await portalFeed(project, portalToken);
  assert.equal(feed.length, 2);
  for (const e of feed) {
    assert.equal(e.entity_name, 'Reflected XSS');
    assert.doesNotMatch(e.entity_name, AI_WORDING);
    for (const k of AI_KEYS) {
      assert.equal(e[k], undefined, `event must not expose ${k}`);
      assert.equal(e.meta?.[k], undefined, `event meta must not expose ${k}`);
    }
    assert.equal(e.user_id, undefined);
  }
  assert.equal(feed.find(e => e.action === 'vuln_created').meta.severity, 'high');
  assert.equal(feed.find(e => e.action === 'remediation_status_changed').meta.remediation_status, 'remediated');

  // Internamente la procedencia se conserva.
  const team = await request(app).get(`/api/projects/${project.id}/activity`).set(auth(owner.accessToken));
  assert.ok(team.body.some(e => e.meta?.ai_generated === true && e.meta?.via === 'claude-code'));
});
