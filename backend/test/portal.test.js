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
