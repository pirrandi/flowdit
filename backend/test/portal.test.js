// Client-portal hardening: a portal link token is an EXTERNAL client, not an
// internal viewer. These tests pin the server-side enforcement so a portal
// session can never read internal data by hitting the API directly, regardless
// of what the client frontend does or doesn't request.
const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { app, db, resetDb, registerUser, createProject } = require('./helpers');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

const auth = t => ({ Authorization: `Bearer ${t}` });

// Spin up a project with the portal enabled and return both the owner token and
// a minted portal session token. `flags` overrides the visibility switches.
async function setupPortal(flags = {}) {
  const owner = await registerUser();
  const project = await createProject(owner.accessToken);

  const patch = await request(app)
    .patch(`/api/projects/${project.id}`)
    .set(auth(owner.accessToken))
    .send({ client_view_enabled: true, show_findings: true, ...flags });
  assert.equal(patch.status, 200);

  const tok = await request(app)
    .post(`/api/projects/${project.id}/portal/token`)
    .set(auth(owner.accessToken));
  assert.equal(tok.status, 200);

  const sess = await request(app)
    .post('/api/portal/auth')
    .send({ token: tok.body.portal_token });
  assert.equal(sess.status, 200);

  return { owner, project, portalToken: sess.body.accessToken };
}

async function createFinding(ownerToken, projectId, body) {
  const res = await request(app)
    .post(`/api/projects/${projectId}/vulns`)
    .set(auth(ownerToken))
    .send(body);
  assert.equal(res.status, 201);
  return res.body;
}

test('portal session is blocked from internal-only routes', async () => {
  const { project, portalToken } = await setupPortal();
  for (const path of ['ai-scan/sessions', 'whiteboard', 'members']) {
    const res = await request(app)
      .get(`/api/projects/${project.id}/${path}`)
      .set(auth(portalToken));
    assert.equal(res.status, 403, `${path} should be 403 for portal`);
  }
});

test('portal findings are filtered to published and stripped of internal fields', async () => {
  const { owner, project, portalToken } = await setupPortal();

  await createFinding(owner.accessToken, project.id, { name: 'Hidden draft', severity: 'high', description: 'secret', notes: 'internal note' });
  const shown  = await createFinding(owner.accessToken, project.id, { name: 'Published XSS', severity: 'critical', description: 'client-facing', notes: 'internal note' });

  // Publish only the second one.
  await request(app)
    .patch(`/api/projects/${project.id}/vulns/${shown.id}`)
    .set(auth(owner.accessToken))
    .send({ client_visible: true });

  const res = await request(app)
    .get(`/api/projects/${project.id}/vulns`)
    .set(auth(portalToken));
  assert.equal(res.status, 200);
  assert.equal(res.body.length, 1, 'portal sees only the published finding');
  const f = res.body[0];
  assert.equal(f.id, shown.id);
  // Internal fields must not leak.
  for (const leak of ['notes', 'evidence', 'editor_username', 'editor_avatar_url', 'verifier_username', 'updated_by', 'created_by', 'ai_generated', 'client_visible']) {
    assert.equal(f[leak], undefined, `portal finding must not expose ${leak}`);
  }
  // Client-facing fields must be present.
  assert.equal(f.name, 'Published XSS');
  assert.equal(f.description, 'client-facing');

  // The owner (internal) still sees both findings with full fields.
  const ownerRes = await request(app)
    .get(`/api/projects/${project.id}/vulns`)
    .set(auth(owner.accessToken));
  assert.equal(ownerRes.body.length, 2);
  assert.ok('notes' in ownerRes.body[0]);
});

test('portal findings route is refused when show_findings is off', async () => {
  const { project, portalToken } = await setupPortal({ show_findings: false });
  const res = await request(app)
    .get(`/api/projects/${project.id}/vulns`)
    .set(auth(portalToken));
  assert.equal(res.status, 403);
});

test('portal activity strips avatars and timestamps when switches are on', async () => {
  const { owner, project, portalToken } = await setupPortal({ show_activity: true, portal_hide_team_avatars: true, portal_hide_log_times: true });
  // Generate an activity entry.
  await createFinding(owner.accessToken, project.id, { name: 'Logged finding', severity: 'low' });

  const res = await request(app)
    .get(`/api/projects/${project.id}/activity`)
    .set(auth(portalToken));
  assert.equal(res.status, 200);
  assert.ok(res.body.length >= 1);
  for (const row of res.body) {
    assert.equal(row.created_at, null, 'log time must be hidden');
    assert.equal(row.avatar_url, null, 'team avatar must be hidden');
  }
});

test('portal activity keeps timestamps when the switch is off', async () => {
  const { owner, project, portalToken } = await setupPortal({ show_activity: true, portal_hide_log_times: false });
  await createFinding(owner.accessToken, project.id, { name: 'Logged finding', severity: 'low' });

  const res = await request(app)
    .get(`/api/projects/${project.id}/activity`)
    .set(auth(portalToken));
  assert.equal(res.status, 200);
  assert.ok(res.body[0].created_at, 'log time should be present when not hidden');
});

test('portal project projection excludes internal config', async () => {
  const { project, portalToken } = await setupPortal();
  const res = await request(app)
    .get(`/api/projects/${project.id}`)
    .set(auth(portalToken));
  assert.equal(res.status, 200);
  assert.equal(res.body.show_findings, true);           // presentation flag kept
  assert.equal(res.body.ai_provider, undefined);        // internal config dropped
  assert.equal(res.body.portal_token, undefined);       // link token never echoed back
  assert.equal(res.body.organization_id, undefined);
});

test('portal targets route is refused when show_targets is off (default)', async () => {
  const { project, portalToken } = await setupPortal();   // show_targets defaults false
  const res = await request(app)
    .get(`/api/projects/${project.id}/targets`)
    .set(auth(portalToken));
  assert.equal(res.status, 403);
});

test('portal client can open a query without linking a finding', async () => {
  const { project, portalToken } = await setupPortal({ tickets_enabled: true });
  // The client form sends vuln_id: null when no finding is selected.
  for (const vuln_id of [null, '', undefined]) {
    const res = await request(app)
      .post(`/api/projects/${project.id}/tickets`)
      .set(auth(portalToken))
      .send({ title: 'General question', description: 'About the scope', vuln_id });
    assert.equal(res.status, 201, `vuln_id=${JSON.stringify(vuln_id)} should be accepted`);
    assert.equal(res.body.vuln_id, null);
  }
});

// Add a registered user to the project with the given role via an invite code.
async function addMember(ownerToken, projectId, role) {
  const user = await registerUser();
  const invite = await request(app)
    .post(`/api/projects/${projectId}/invites`)
    .set(auth(ownerToken))
    .send({ role });
  assert.equal(invite.status, 201);
  const join = await request(app)
    .post('/api/projects/join')
    .set(auth(user.accessToken))
    .send({ token: invite.body.token });
  assert.equal(join.status, 200);
  return user;
}

async function createTicket(token, projectId, body) {
  const res = await request(app)
    .post(`/api/projects/${projectId}/tickets`)
    .set(auth(token))
    .send(body);
  assert.equal(res.status, 201);
  return res.body;
}

test('portal session is refused on every methodology route and on report-config', async () => {
  const { owner, project, portalToken } = await setupPortal({ show_wstg_progress: true, show_wstg_notes: true, show_targets: true });

  const method = await request(app)
    .post('/api/methodologies')
    .set(auth(owner.accessToken))
    .send({ name: 'Internal checklist', tests: [{ name: 'Check A' }] });
  assert.equal(method.status, 201);
  const mid = method.body.id;
  await request(app)
    .patch(`/api/methodologies/${mid}/progress/${project.id}/0`)
    .set(auth(owner.accessToken))
    .send({ status: 'fail', note: 'internal pentester note' });
  await request(app)
    .patch(`/api/methodologies/${mid}/activate/${project.id}`)
    .set(auth(owner.accessToken))
    .send({ active: true });

  const paths = [
    '/api/methodologies',
    `/api/methodologies/${mid}/progress/${project.id}`,
    `/api/methodologies/project-progress/${project.id}`,
    `/api/projects/${project.id}/report-config`,
  ];
  for (const path of paths) {
    const portal = await request(app).get(path).set(auth(portalToken));
    assert.equal(portal.status, 403, `${path} should be 403 for portal`);
    const team = await request(app).get(path).set(auth(owner.accessToken));
    assert.equal(team.status, 200, `${path} should stay 200 for the owner`);
  }

  // The dead (and broken) active-methodologies route is gone.
  const dead = await request(app)
    .get(`/api/methodologies/project/${project.id}`)
    .set(auth(owner.accessToken));
  assert.equal(dead.status, 404);
});

test('only the owner receives portal_token in project get and list', async () => {
  const { owner, project } = await setupPortal();

  const own = await request(app).get(`/api/projects/${project.id}`).set(auth(owner.accessToken));
  assert.ok(own.body.portal_token, 'owner gets the portal token');
  const ownList = await request(app).get('/api/projects').set(auth(owner.accessToken));
  assert.ok(ownList.body.find(p => p.id === project.id).portal_token);

  for (const role of ['viewer', 'pentester', 'editor']) {
    const member = await addMember(owner.accessToken, project.id, role);
    const one = await request(app).get(`/api/projects/${project.id}`).set(auth(member.accessToken));
    assert.equal(one.status, 200);
    assert.equal(one.body.member_role, role);
    assert.equal(one.body.portal_token, undefined, `${role} must not get portal_token (get)`);
    const list = await request(app).get('/api/projects').set(auth(member.accessToken));
    const row = list.body.find(p => p.id === project.id);
    assert.ok(row);
    assert.equal(row.portal_token, undefined, `${role} must not get portal_token (list)`);
  }
});

test('portal does not see the name of an unpublished finding linked to a ticket', async () => {
  const { owner, project, portalToken } = await setupPortal({ tickets_enabled: true });
  const draft = await createFinding(owner.accessToken, project.id, { name: 'Secret draft finding', severity: 'high' });
  const ticket = await createTicket(owner.accessToken, project.id, { title: 'About the draft', vuln_id: draft.id });

  const list = await request(app).get(`/api/projects/${project.id}/tickets`).set(auth(portalToken));
  assert.equal(list.status, 200);
  assert.equal(list.body[0].vuln_name, null);
  assert.equal(list.body[0].vuln_id, null);
  const one = await request(app).get(`/api/projects/${project.id}/tickets/${ticket.id}`).set(auth(portalToken));
  assert.equal(one.status, 200);
  assert.equal(one.body.vuln_name, null);

  // Team still sees it.
  const team = await request(app).get(`/api/projects/${project.id}/tickets/${ticket.id}`).set(auth(owner.accessToken));
  assert.equal(team.body.vuln_name, 'Secret draft finding');

  // Once published, the portal sees the name too.
  await request(app)
    .patch(`/api/projects/${project.id}/vulns/${draft.id}`)
    .set(auth(owner.accessToken))
    .send({ client_visible: true });
  const after = await request(app).get(`/api/projects/${project.id}/tickets/${ticket.id}`).set(auth(portalToken));
  assert.equal(after.body.vuln_name, 'Secret draft finding');
  assert.equal(after.body.vuln_id, draft.id);
});

test('portal cannot link a ticket to an unpublished finding', async () => {
  const { owner, project, portalToken } = await setupPortal({ tickets_enabled: true });
  const draft = await createFinding(owner.accessToken, project.id, { name: 'Draft', severity: 'low' });
  const res = await request(app)
    .post(`/api/projects/${project.id}/tickets`)
    .set(auth(portalToken))
    .send({ title: 'Question', vuln_id: draft.id });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'Finding not available');

  await request(app)
    .patch(`/api/projects/${project.id}/vulns/${draft.id}`)
    .set(auth(owner.accessToken))
    .send({ client_visible: true });
  const ok = await request(app)
    .post(`/api/projects/${project.id}/tickets`)
    .set(auth(portalToken))
    .send({ title: 'Question', vuln_id: draft.id });
  assert.equal(ok.status, 201);
  assert.equal(ok.body.vuln_id, draft.id);
});

test('portal cannot reply to a closed query; the team still can', async () => {
  const { owner, project, portalToken } = await setupPortal({ tickets_enabled: true });
  const ticket = await createTicket(portalToken, project.id, { title: 'Done question' });
  const close = await request(app)
    .patch(`/api/projects/${project.id}/tickets/${ticket.id}`)
    .set(auth(owner.accessToken))
    .send({ status: 'closed' });
  assert.equal(close.status, 200);

  const portal = await request(app)
    .post(`/api/projects/${project.id}/tickets/${ticket.id}/replies`)
    .set(auth(portalToken))
    .send({ body: 'one more thing' });
  assert.equal(portal.status, 409);

  const team = await request(app)
    .post(`/api/projects/${project.id}/tickets/${ticket.id}/replies`)
    .set(auth(owner.accessToken))
    .send({ body: 'closing note' });
  assert.equal(team.status, 201);
});

test('ticket description and reply body are capped at 10000 characters', async () => {
  const { owner, project, portalToken } = await setupPortal({ tickets_enabled: true });
  const long = 'x'.repeat(10001);

  for (const token of [portalToken, owner.accessToken]) {
    const res = await request(app)
      .post(`/api/projects/${project.id}/tickets`)
      .set(auth(token))
      .send({ title: 'Long', description: long });
    assert.equal(res.status, 400);
  }

  const ticket = await createTicket(portalToken, project.id, { title: 'Short', description: 'x'.repeat(10000) });
  for (const token of [portalToken, owner.accessToken]) {
    const res = await request(app)
      .post(`/api/projects/${project.id}/tickets/${ticket.id}/replies`)
      .set(auth(token))
      .send({ body: long });
    assert.equal(res.status, 400);
  }
});

test('portal ticket chat hides team identity and, when switched on, timestamps', async () => {
  const { owner, project, portalToken } = await setupPortal({ tickets_enabled: true, portal_hide_log_times: true });
  const ticket = await createTicket(owner.accessToken, project.id, { title: 'Team question' });
  await request(app)
    .post(`/api/projects/${project.id}/tickets/${ticket.id}/replies`)
    .set(auth(owner.accessToken))
    .send({ body: 'team answer' });
  await request(app)
    .post(`/api/projects/${project.id}/tickets/${ticket.id}/replies`)
    .set(auth(portalToken))
    .send({ body: 'client answer', client_name: 'Alice' });

  const internal = ['author_id', 'author_username', 'author_display_name', 'author_color',
    'opened_by', 'opened_by_username', 'opened_by_display_name', 'opened_by_color', 'github_url'];

  const res = await request(app).get(`/api/projects/${project.id}/tickets/${ticket.id}`).set(auth(portalToken));
  assert.equal(res.status, 200);
  assert.equal(res.body.created_at, null);
  assert.equal(res.body.updated_at, null);
  assert.equal(res.body.is_team, true);
  assert.equal(res.body.opened_by_name, owner.user.username);
  for (const f of internal) assert.equal(res.body[f], undefined, `ticket must not expose ${f}`);
  assert.equal(res.body.replies.length, 2);
  const [team, client] = res.body.replies;
  assert.deepEqual([team.is_team, team.author_name], [true, owner.user.username]);
  assert.deepEqual([client.is_team, client.author_name], [false, 'Alice']);
  for (const r of res.body.replies) {
    assert.equal(r.created_at, null, 'reply time must be hidden');
    for (const f of internal) assert.equal(r[f], undefined, `reply must not expose ${f}`);
  }

  const list = await request(app).get(`/api/projects/${project.id}/tickets`).set(auth(portalToken));
  for (const f of internal) assert.equal(list.body[0][f], undefined, `ticket list must not expose ${f}`);
  assert.equal(list.body[0].updated_at, null);

  // The team keeps the full view.
  const teamRes = await request(app).get(`/api/projects/${project.id}/tickets/${ticket.id}`).set(auth(owner.accessToken));
  assert.ok(teamRes.body.opened_by_username);
  assert.ok(teamRes.body.replies[0].author_id);
  assert.ok(teamRes.body.replies[0].author_username);
  assert.ok(teamRes.body.replies[0].created_at);
});

test('portal ticket chat keeps timestamps when the switch is off', async () => {
  const { owner, project, portalToken } = await setupPortal({ tickets_enabled: true, portal_hide_log_times: false });
  const ticket = await createTicket(owner.accessToken, project.id, { title: 'Q' });
  await request(app)
    .post(`/api/projects/${project.id}/tickets/${ticket.id}/replies`)
    .set(auth(owner.accessToken))
    .send({ body: 'answer' });
  const res = await request(app).get(`/api/projects/${project.id}/tickets/${ticket.id}`).set(auth(portalToken));
  assert.ok(res.body.created_at);
  assert.ok(res.body.replies[0].created_at);
  assert.equal(res.body.replies[0].author_id, undefined);
});

test('generating and rotating the portal link is audited and hidden from the portal feed', async () => {
  const { owner, project, portalToken } = await setupPortal({ show_activity: true });
  // setupPortal generated the first link; rotate it once.
  const rot = await request(app)
    .post(`/api/projects/${project.id}/portal/token`)
    .set(auth(owner.accessToken));
  assert.equal(rot.status, 200);

  const { rows } = await db.query(
    `SELECT meta FROM activity_log WHERE project_id=$1 AND action='portal_link_generated' ORDER BY created_at`,
    [project.id]
  );
  assert.deepEqual(rows.map(r => r.meta.regenerated), [false, true]);

  const team = await request(app).get(`/api/projects/${project.id}/activity`).set(auth(owner.accessToken));
  assert.ok(team.body.some(e => e.action === 'portal_link_generated'));

  // The old portal session is revoked by the rotation; mint a fresh one.
  const sess = await request(app).post('/api/portal/auth').send({ token: rot.body.portal_token });
  assert.equal(sess.status, 200);
  assert.notEqual(sess.body.accessToken, portalToken);
  const feed = await request(app).get(`/api/projects/${project.id}/activity`).set(auth(sess.body.accessToken));
  assert.equal(feed.status, 200);
  assert.ok(!feed.body.some(e => e.action === 'portal_link_generated'));
});
