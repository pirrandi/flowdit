// Regression tests for the cross-project data isolation (IDOR) fixes in a582e20.
const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { app, db, resetDb, registerUser, createProject } = require('./helpers');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

async function addTarget(accessToken, projectId, host = 'example.com') {
  const res = await request(app)
    .post(`/api/projects/${projectId}/targets`)
    .set('Authorization', `Bearer ${accessToken}`)
    .send({ host, type: 'domain' });
  assert.equal(res.status, 201);
  return res.body;
}

test('a project owner can read their own project', async () => {
  const owner = await registerUser({ username: 'owner1', email: 'owner1@example.com' });
  const project = await createProject(owner.accessToken);

  const res = await request(app)
    .get(`/api/projects/${project.id}`)
    .set('Authorization', `Bearer ${owner.accessToken}`);
  assert.equal(res.status, 200);
  assert.equal(res.body.id, project.id);
});

test('a non-member cannot read another user\'s project', async () => {
  const owner = await registerUser({ username: 'owner2', email: 'owner2@example.com' });
  const stranger = await registerUser({ username: 'stranger2', email: 'stranger2@example.com' });
  const project = await createProject(owner.accessToken);

  const res = await request(app)
    .get(`/api/projects/${project.id}`)
    .set('Authorization', `Bearer ${stranger.accessToken}`);
  assert.equal(res.status, 404);
});

test('a non-member cannot list another project\'s members', async () => {
  const owner = await registerUser({ username: 'owner3', email: 'owner3@example.com' });
  const stranger = await registerUser({ username: 'stranger3', email: 'stranger3@example.com' });
  const project = await createProject(owner.accessToken);

  const res = await request(app)
    .get(`/api/projects/${project.id}/members`)
    .set('Authorization', `Bearer ${stranger.accessToken}`);
  assert.equal(res.status, 404);
});

test('a non-member cannot create a target on another user\'s project', async () => {
  const owner = await registerUser({ username: 'owner4', email: 'owner4@example.com' });
  const stranger = await registerUser({ username: 'stranger4', email: 'stranger4@example.com' });
  const project = await createProject(owner.accessToken);

  const res = await request(app)
    .post(`/api/projects/${project.id}/targets`)
    .set('Authorization', `Bearer ${stranger.accessToken}`)
    .send({ host: 'evil.example.com', type: 'domain' });
  assert.equal(res.status, 404);
});

// Regression for the ports.js/endpoints.js fix: nested under :targetId, but
// nothing verified :targetId actually belonged to :projectId. A project member
// could previously CRUD another project's ports by supplying a foreign targetId.
test('a project member cannot read another project\'s target ports via their own projectId', async () => {
  const ownerA = await registerUser({ username: 'ownerA', email: 'ownerA@example.com' });
  const ownerB = await registerUser({ username: 'ownerB', email: 'ownerB@example.com' });
  const projectA = await createProject(ownerA.accessToken, { name: 'Project A' });
  const projectB = await createProject(ownerB.accessToken, { name: 'Project B' });
  const targetA = await addTarget(ownerA.accessToken, projectA.id);

  // ownerB tries to reach targetA's ports by pairing it with their OWN projectId
  const res = await request(app)
    .get(`/api/projects/${projectB.id}/targets/${targetA.id}/ports`)
    .set('Authorization', `Bearer ${ownerB.accessToken}`);
  assert.equal(res.status, 404);
});

test('a project member cannot create a port on another project\'s target', async () => {
  const ownerA = await registerUser({ username: 'ownerA2', email: 'ownerA2@example.com' });
  const ownerB = await registerUser({ username: 'ownerB2', email: 'ownerB2@example.com' });
  const projectA = await createProject(ownerA.accessToken, { name: 'Project A2' });
  const projectB = await createProject(ownerB.accessToken, { name: 'Project B2' });
  const targetA = await addTarget(ownerA.accessToken, projectA.id);

  const res = await request(app)
    .post(`/api/projects/${projectB.id}/targets/${targetA.id}/ports`)
    .set('Authorization', `Bearer ${ownerB.accessToken}`)
    .send({ port: 443, protocol: 'tcp' });
  assert.equal(res.status, 404);

  const check = await db.query('SELECT * FROM target_ports WHERE target_id=$1', [targetA.id]);
  assert.equal(check.rows.length, 0);
});

// Regression for services/ownership.js: a vuln's target_id was accepted from the
// request body with no check that the target belonged to the same project,
// letting another project's target host leak back out through the join.
test('creating a vuln with a foreign target_id does not link to the other project\'s target', async () => {
  const ownerA = await registerUser({ username: 'ownerA3', email: 'ownerA3@example.com' });
  const ownerB = await registerUser({ username: 'ownerB3', email: 'ownerB3@example.com' });
  const projectA = await createProject(ownerA.accessToken, { name: 'Project A3' });
  const projectB = await createProject(ownerB.accessToken, { name: 'Project B3' });
  const targetA = await addTarget(ownerA.accessToken, projectA.id, 'secret-internal-host.example.com');

  const res = await request(app)
    .post(`/api/projects/${projectB.id}/vulns`)
    .set('Authorization', `Bearer ${ownerB.accessToken}`)
    .send({ name: 'Test finding', severity: 'medium', target_id: targetA.id });

  assert.equal(res.status, 201);
  assert.equal(res.body.target_id, null);
});

test('a viewer cannot modify project data', async () => {
  const owner = await registerUser({ username: 'ownerV', email: 'ownerV@example.com' });
  const viewer = await registerUser({ username: 'viewerV', email: 'viewerV@example.com' });
  const project = await createProject(owner.accessToken, { name: 'Viewer test' });

  await db.query(
    `INSERT INTO project_members (project_id, user_id, role) VALUES ($1,$2,'viewer')`,
    [project.id, viewer.user.id]
  );

  const res = await request(app)
    .post(`/api/projects/${project.id}/targets`)
    .set('Authorization', `Bearer ${viewer.accessToken}`)
    .send({ host: 'blocked.example.com', type: 'domain' });
  assert.equal(res.status, 403);
});

test('GET on a project with a nonexistent id returns 404, not 500', async () => {
  const owner = await registerUser({ username: 'owner5', email: 'owner5@example.com' });
  const res = await request(app)
    .get('/api/projects/00000000-0000-0000-0000-000000000000')
    .set('Authorization', `Bearer ${owner.accessToken}`);
  assert.equal(res.status, 404);
});
