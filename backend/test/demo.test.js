const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { app, db, resetDb } = require('./helpers');
const { seedDemo } = require('../src/db/seed-demo');

before(async () => { await resetDb(); });
beforeEach(async () => { delete process.env.DEMO_MODE; await resetDb(); await seedDemo(); });
after(async () => { delete process.env.DEMO_MODE; await db.pool.end(); });

async function loginAsDemo() {
  const res = await request(app).post('/api/auth/login').send({ login: 'demo', password: 'demo' });
  return res.body.accessToken;
}

test('seedDemo creates a login-ready demo account with a populated project', async () => {
  const access = await loginAsDemo();
  assert.ok(access);

  const projects = await request(app).get('/api/projects').set('Authorization', `Bearer ${access}`);
  assert.equal(projects.body.length, 1);
  const pid = projects.body[0].id;

  const vulns = await request(app).get(`/api/projects/${pid}/vulns`).set('Authorization', `Bearer ${access}`);
  assert.equal(vulns.body.length, 10);

  const targets = await request(app).get(`/api/projects/${pid}/targets`).set('Authorization', `Bearer ${access}`);
  assert.equal(targets.body.length, 5);

  const tickets = await request(app).get(`/api/projects/${pid}/tickets`).set('Authorization', `Bearer ${access}`);
  assert.equal(tickets.body.length, 3);
});

test('seedDemo is idempotent — re-running it does not error or duplicate the project', async () => {
  await seedDemo();
  await seedDemo();
  const access = await loginAsDemo();
  const projects = await request(app).get('/api/projects').set('Authorization', `Bearer ${access}`);
  assert.equal(projects.body.length, 1);
});

test('with DEMO_MODE=true, the demo account cannot delete its project or organization', async () => {
  process.env.DEMO_MODE = 'true';
  const access = await loginAsDemo();

  const projects = await request(app).get('/api/projects').set('Authorization', `Bearer ${access}`);
  const pid = projects.body[0].id;
  const delProject = await request(app).delete(`/api/projects/${pid}`).set('Authorization', `Bearer ${access}`);
  assert.equal(delProject.status, 403);

  const orgs = await request(app).get('/api/organizations').set('Authorization', `Bearer ${access}`);
  const oid = orgs.body[0].id;
  const delOrg = await request(app).delete(`/api/organizations/${oid}`).set('Authorization', `Bearer ${access}`);
  assert.equal(delOrg.status, 403);
});

test('with DEMO_MODE=true, the demo account cannot enable 2FA (would lock out other visitors)', async () => {
  process.env.DEMO_MODE = 'true';
  const access = await loginAsDemo();

  const setup = await request(app).post('/api/auth/mfa/setup').set('Authorization', `Bearer ${access}`);
  assert.equal(setup.status, 200); // setup alone is harmless — only /enable is blocked

  const enable = await request(app)
    .post('/api/auth/mfa/enable')
    .set('Authorization', `Bearer ${access}`)
    .send({ code: '123456' });
  assert.equal(enable.status, 403);
});

test('with DEMO_MODE=true, editing findings/targets is still allowed (demo stays hands-on)', async () => {
  process.env.DEMO_MODE = 'true';
  const access = await loginAsDemo();

  const projects = await request(app).get('/api/projects').set('Authorization', `Bearer ${access}`);
  const pid = projects.body[0].id;
  const vulns = await request(app).get(`/api/projects/${pid}/vulns`).set('Authorization', `Bearer ${access}`);
  const vid = vulns.body[0].id;

  const patch = await request(app)
    .patch(`/api/projects/${pid}/vulns/${vid}`)
    .set('Authorization', `Bearer ${access}`)
    .send({ notes: 'edited by a demo visitor' });
  assert.equal(patch.status, 200);
});

test('without DEMO_MODE, the demo account is not restricted (guard is a no-op outside the demo deploy)', async () => {
  const access = await loginAsDemo();
  const projects = await request(app).get('/api/projects').set('Authorization', `Bearer ${access}`);
  const pid = projects.body[0].id;
  const delProject = await request(app).delete(`/api/projects/${pid}`).set('Authorization', `Bearer ${access}`);
  assert.equal(delProject.status, 200);
});
