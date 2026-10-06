// Project role tiers: owner > editor (the lead) > pentester > viewer.
// A pentester does all the technical work but must never take a CLIENT-FACING
// action: publishing findings to the portal, answering/triaging client tickets,
// exporting the report or editing the report builder. These tests pin that
// boundary server-side — hiding the buttons in the UI is cosmetic.
const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const request = require('supertest');
const { app, db, resetDb, registerUser, createProject } = require('./helpers');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

const auth = t => ({ Authorization: `Bearer ${t}` });

// Joins `role` members through the real invite flow, so the owner-assigns-role
// path is exercised on every test that uses it.
async function addMember(ownerToken, projectId, role) {
  const user = await registerUser();
  const inv = await request(app)
    .post(`/api/projects/${projectId}/invites`)
    .set(auth(ownerToken))
    .send({ role });
  assert.equal(inv.status, 201, `invite for ${role}: ${JSON.stringify(inv.body)}`);
  const join = await request(app)
    .post('/api/projects/join')
    .set(auth(user.accessToken))
    .send({ token: inv.body.token });
  assert.equal(join.status, 200);
  assert.equal(join.body.role, role);
  return user;
}

async function setup() {
  const owner = await registerUser();
  const project = await createProject(owner.accessToken);
  const res = await request(app)
    .patch(`/api/projects/${project.id}`)
    .set(auth(owner.accessToken))
    .send({ tickets_enabled: true });
  assert.equal(res.status, 200);
  const editor    = await addMember(owner.accessToken, project.id, 'editor');
  const pentester = await addMember(owner.accessToken, project.id, 'pentester');
  const viewer    = await addMember(owner.accessToken, project.id, 'viewer');
  return { owner, project, editor, pentester, viewer };
}

async function createFinding(token, projectId, body = {}) {
  return request(app)
    .post(`/api/projects/${projectId}/vulns`)
    .set(auth(token))
    .send({ name: 'SQLi', severity: 'high', ...body });
}

async function createTicket(token, projectId) {
  const res = await request(app)
    .post(`/api/projects/${projectId}/tickets`)
    .set(auth(token))
    .send({ title: 'Client question' });
  assert.equal(res.status, 201);
  return res.body;
}

test('owner can assign the pentester role to an existing member', async () => {
  const { owner, project, editor } = await setup();
  const res = await request(app)
    .patch(`/api/projects/${project.id}/members/${editor.user.id}`)
    .set(auth(owner.accessToken))
    .send({ role: 'pentester' });
  assert.equal(res.status, 200);
  const { rows } = await db.query(
    `SELECT role FROM project_members WHERE project_id=$1 AND user_id=$2`,
    [project.id, editor.user.id]
  );
  assert.equal(rows[0].role, 'pentester');
});

test('pentester can create and edit findings and targets', async () => {
  const { project, pentester } = await setup();
  const f = await createFinding(pentester.accessToken, project.id);
  assert.equal(f.status, 201);

  const patch = await request(app)
    .patch(`/api/projects/${project.id}/vulns/${f.body.id}`)
    .set(auth(pentester.accessToken))
    .send({ description: 'Blind, time-based' });
  assert.equal(patch.status, 200);
  assert.equal(patch.body.description, 'Blind, time-based');

  const t = await request(app)
    .post(`/api/projects/${project.id}/targets`)
    .set(auth(pentester.accessToken))
    .send({ host: 'app.example.com', type: 'domain' });
  assert.equal(t.status, 201);
  const tp = await request(app)
    .patch(`/api/projects/${project.id}/targets/${t.body.id}`)
    .set(auth(pentester.accessToken))
    .send({ notes: 'login at /auth' });
  assert.equal(tp.status, 200);
});

test('pentester cannot publish a finding on create or patch', async () => {
  const { project, pentester } = await setup();
  const f = await createFinding(pentester.accessToken, project.id, { client_visible: true });
  assert.equal(f.status, 201);
  assert.equal(f.body.client_visible, false, 'create always yields a draft');

  const pub = await request(app)
    .patch(`/api/projects/${project.id}/vulns/${f.body.id}`)
    .set(auth(pentester.accessToken))
    .send({ client_visible: true });
  assert.equal(pub.status, 403);

  // Sending the current value back unchanged (full-row round-trip) is fine.
  const same = await request(app)
    .patch(`/api/projects/${project.id}/vulns/${f.body.id}`)
    .set(auth(pentester.accessToken))
    .send({ client_visible: false, name: 'SQLi (login)' });
  assert.equal(same.status, 200);

  const { rows } = await db.query(`SELECT client_visible FROM custom_vulns WHERE id=$1`, [f.body.id]);
  assert.equal(rows[0].client_visible, false);
});

test('pentester cannot hide a finding the lead already published', async () => {
  const { project, editor, pentester } = await setup();
  const f = await createFinding(editor.accessToken, project.id);
  const pub = await request(app)
    .patch(`/api/projects/${project.id}/vulns/${f.body.id}`)
    .set(auth(editor.accessToken))
    .send({ client_visible: true });
  assert.equal(pub.status, 200);
  assert.equal(pub.body.client_visible, true);

  const hide = await request(app)
    .patch(`/api/projects/${project.id}/vulns/${f.body.id}`)
    .set(auth(pentester.accessToken))
    .send({ client_visible: false });
  assert.equal(hide.status, 403);
});

test('AI agent finding writes never set client_visible', async () => {
  const { project, pentester } = await setup();
  const { createFindingFromProposal, updateFindingFromProposal } = require('../src/services/ai/agentLoop');
  const id = await createFindingFromProposal(
    project.id, { name: 'Agent XSS', severity: 'medium', client_visible: true }, pentester.user.id
  );
  await updateFindingFromProposal(
    project.id, { finding_id: id, description: 'reflected', client_visible: true }, pentester.user.id
  );
  const { rows } = await db.query(`SELECT client_visible, description FROM custom_vulns WHERE id=$1`, [id]);
  assert.equal(rows[0].description, 'reflected');
  assert.equal(rows[0].client_visible, false);
});

test('pentester can read tickets but cannot reply, triage, delete or push them', async () => {
  const { owner, project, pentester } = await setup();
  const ticket = await createTicket(owner.accessToken, project.id);
  const base = `/api/projects/${project.id}/tickets`;

  const list = await request(app).get(base).set(auth(pentester.accessToken));
  assert.equal(list.status, 200);
  assert.equal(list.body.length, 1);
  const one = await request(app).get(`${base}/${ticket.id}`).set(auth(pentester.accessToken));
  assert.equal(one.status, 200);

  const reply = await request(app).post(`${base}/${ticket.id}/replies`)
    .set(auth(pentester.accessToken)).send({ body: 'We are on it' });
  assert.equal(reply.status, 403);
  const status = await request(app).patch(`${base}/${ticket.id}`)
    .set(auth(pentester.accessToken)).send({ status: 'closed' });
  assert.equal(status.status, 403);
  const gh = await request(app).post(`${base}/${ticket.id}/github`).set(auth(pentester.accessToken));
  assert.equal(gh.status, 403);
  const del = await request(app).delete(`${base}/${ticket.id}`).set(auth(pentester.accessToken));
  assert.equal(del.status, 403);
});

test('only the owner can delete a ticket, replies included', async () => {
  const { owner, project, editor } = await setup();
  const ticket = await createTicket(owner.accessToken, project.id);
  const base = `/api/projects/${project.id}/tickets`;
  const reply = await request(app).post(`${base}/${ticket.id}/replies`)
    .set(auth(editor.accessToken)).send({ body: 'Looking into it' });
  assert.equal(reply.status, 201);

  const byEditor = await request(app).delete(`${base}/${ticket.id}`).set(auth(editor.accessToken));
  assert.equal(byEditor.status, 403);

  const byOwner = await request(app).delete(`${base}/${ticket.id}`).set(auth(owner.accessToken));
  assert.equal(byOwner.status, 200);
  const gone = await request(app).get(`${base}/${ticket.id}`).set(auth(owner.accessToken));
  assert.equal(gone.status, 404);
  const { rows } = await db.query('SELECT 1 FROM ticket_replies WHERE ticket_id=$1', [ticket.id]);
  assert.equal(rows.length, 0);
});

test('editor can reply to and triage tickets; a viewer (client account) can still reply', async () => {
  const { owner, project, editor, viewer } = await setup();
  const ticket = await createTicket(owner.accessToken, project.id);
  const base = `/api/projects/${project.id}/tickets`;

  const reply = await request(app).post(`${base}/${ticket.id}/replies`)
    .set(auth(editor.accessToken)).send({ body: 'Fixed in 1.2' });
  assert.equal(reply.status, 201);
  const status = await request(app).patch(`${base}/${ticket.id}`)
    .set(auth(editor.accessToken)).send({ status: 'closed' });
  assert.equal(status.status, 200);

  const clientReply = await request(app).post(`${base}/${ticket.id}/replies`)
    .set(auth(viewer.accessToken)).send({ body: 'Thanks' });
  assert.equal(clientReply.status, 201);
});

test('pentester cannot change the report config or export the report; editor can', async () => {
  const { project, editor, pentester } = await setup();
  const cfgUrl = `/api/projects/${project.id}/report-config`;

  const read = await request(app).get(cfgUrl).set(auth(pentester.accessToken));
  assert.equal(read.status, 200);
  const put = await request(app).put(cfgUrl).set(auth(pentester.accessToken)).send({ data: { meta: {} } });
  assert.equal(put.status, 403);
  const putEd = await request(app).put(cfgUrl).set(auth(editor.accessToken)).send({ data: { meta: {} } });
  assert.equal(putEd.status, 200);

  const rptData = JSON.stringify({ meta: {}, sections: [] });
  const docx = await request(app).post('/api/export/docx')
    .set(auth(pentester.accessToken)).send({ projectId: project.id, rptData });
  assert.equal(docx.status, 403);
  const retest = await request(app).post('/api/export/docx')
    .set(auth(pentester.accessToken)).send({ projectId: project.id, type: 'retest', rptData });
  assert.equal(retest.status, 403);
  const docxEd = await request(app).post('/api/export/docx')
    .set(auth(editor.accessToken)).send({ projectId: project.id, rptData });
  assert.equal(docxEd.status, 200);

  // PDF: the role gate runs before the browser launches, so this never needs Chrome.
  const prev = process.env.FRONTEND_URL;
  process.env.FRONTEND_URL = 'http://localhost';
  try {
    const pdf = await request(app).post('/api/export/pdf')
      .set(auth(pentester.accessToken))
      .send({ pageUrl: 'http://localhost/export', projectId: project.id });
    assert.equal(pdf.status, 403);
    const noPid = await request(app).post('/api/export/pdf')
      .set(auth(editor.accessToken))
      .send({ pageUrl: 'http://localhost/export' });
    assert.equal(noPid.status, 400);
  } finally {
    if (prev === undefined) delete process.env.FRONTEND_URL;
    else process.env.FRONTEND_URL = prev;
  }
});

test('viewer still cannot write', async () => {
  const { project, viewer } = await setup();
  const f = await createFinding(viewer.accessToken, project.id);
  assert.equal(f.status, 403);
  const t = await request(app)
    .post(`/api/projects/${project.id}/targets`)
    .set(auth(viewer.accessToken))
    .send({ host: 'x.example.com', type: 'domain' });
  assert.equal(t.status, 403);
});

test('pentester cannot manage members', async () => {
  const { project, pentester, viewer } = await setup();
  const res = await request(app)
    .patch(`/api/projects/${project.id}/members/${viewer.user.id}`)
    .set(auth(pentester.accessToken))
    .send({ role: 'editor' });
  assert.equal(res.status, 403);
});

test('re-running migrations keeps a single role CHECK that allows pentester', async () => {
  const MIGRATE = path.join(__dirname, '..', 'src', 'db', 'migrate.js');
  const run = () => execFileSync(process.execPath, [MIGRATE], {
    env: { ...process.env, DB_NAME: process.env.DB_NAME }, stdio: 'pipe',
  });
  run(); run();
  const { rows } = await db.query(
    `SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
     WHERE conrelid = 'project_members'::regclass AND contype = 'c'`
  );
  assert.equal(rows.length, 1, JSON.stringify(rows));
  assert.equal(rows[0].conname, 'project_members_role_check');
  assert.match(rows[0].def, /pentester/);
});
