const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { app, db, resetDb, registerUser, createProject } = require('./helpers');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

const auth = (token) => ({ Authorization: `Bearer ${token}` });

test('display_name accepts spaces and accents and is returned by PATCH and GET /auth/me', async () => {
  const { accessToken, credentials } = await registerUser({ username: 'juanp' });

  const res = await request(app).patch('/api/auth/me').set(auth(accessToken))
    .send({ display_name: 'Juan Pérez' });
  assert.equal(res.status, 200);
  assert.equal(res.body.display_name, 'Juan Pérez');
  assert.equal(res.body.username, 'juanp');

  const me = await request(app).get('/api/auth/me').set(auth(accessToken));
  assert.equal(me.body.display_name, 'Juan Pérez');
  assert.equal(me.body.username, 'juanp');

  // Username is still the login identifier, unchanged by the display name.
  const login = await request(app).post('/api/auth/login')
    .send({ login: 'juanp', password: credentials.password });
  assert.equal(login.status, 200);
  assert.equal(login.body.user.username, 'juanp');
  assert.equal(login.body.user.display_name, 'Juan Pérez');
});

test('display_name is normalised: trimmed, whitespace collapsed, control chars stripped', async () => {
  const { accessToken } = await registerUser();
  const res = await request(app).patch('/api/auth/me').set(auth(accessToken))
    .send({ display_name: '  Ana \t\n  María\u0000 ‮López  ' });
  assert.equal(res.status, 200);
  assert.equal(res.body.display_name, 'Ana María López');
});

test('empty display_name clears it to null', async () => {
  const { accessToken } = await registerUser();
  await request(app).patch('/api/auth/me').set(auth(accessToken)).send({ display_name: 'Someone' });
  const res = await request(app).patch('/api/auth/me').set(auth(accessToken)).send({ display_name: '   ' });
  assert.equal(res.status, 200);
  assert.equal(res.body.display_name, null);
});

test('display_name longer than 50 characters is rejected', async () => {
  const { accessToken } = await registerUser();
  const res = await request(app).patch('/api/auth/me').set(auth(accessToken))
    .send({ display_name: 'é'.repeat(51) });
  assert.equal(res.status, 400);

  const ok = await request(app).patch('/api/auth/me').set(auth(accessToken))
    .send({ display_name: 'é'.repeat(50) });
  assert.equal(ok.status, 200);
});

test('display_name must be a string', async () => {
  const { accessToken } = await registerUser();
  const res = await request(app).patch('/api/auth/me').set(auth(accessToken))
    .send({ display_name: { nope: 1 } });
  assert.equal(res.status, 400);
});

test('display_name is not unique', async () => {
  const a = await registerUser();
  const b = await registerUser();
  const r1 = await request(app).patch('/api/auth/me').set(auth(a.accessToken)).send({ display_name: 'Same Name' });
  const r2 = await request(app).patch('/api/auth/me').set(auth(b.accessToken)).send({ display_name: 'Same Name' });
  assert.equal(r1.status, 200);
  assert.equal(r2.status, 200);
});

test('username validation is unchanged: spaces/accents rejected, valid change works and logs in', async () => {
  const { accessToken, credentials } = await registerUser();
  const bad = await request(app).patch('/api/auth/me').set(auth(accessToken)).send({ username: 'Juan Pérez' });
  assert.equal(bad.status, 400);

  const good = await request(app).patch('/api/auth/me').set(auth(accessToken)).send({ username: 'juan_perez' });
  assert.equal(good.status, 200);
  assert.equal(good.body.username, 'juan_perez');

  const login = await request(app).post('/api/auth/login')
    .send({ login: 'juan_perez', password: credentials.password });
  assert.equal(login.status, 200);
});

test('project members, org members and activity feed include display_name', async () => {
  const { accessToken, user } = await registerUser();
  await request(app).patch('/api/auth/me').set(auth(accessToken)).send({ display_name: 'Juan Pérez' });
  const project = await createProject(accessToken);

  const members = await request(app).get(`/api/projects/${project.id}/members`).set(auth(accessToken));
  assert.equal(members.status, 200);
  const me = members.body.find(m => m.id === user.id);
  assert.equal(me.display_name, 'Juan Pérez');
  assert.ok(me.username);

  const orgs = await request(app).get('/api/organizations').set(auth(accessToken));
  const orgMembers = await request(app).get(`/api/organizations/${orgs.body[0].id}/members`).set(auth(accessToken));
  assert.equal(orgMembers.status, 200);
  assert.equal(orgMembers.body.find(m => m.id === user.id).display_name, 'Juan Pérez');

  const target = await request(app).post(`/api/projects/${project.id}/targets`).set(auth(accessToken))
    .send({ host: 'example.com', type: 'domain' });
  assert.equal(target.status, 201);

  const activity = await request(app).get(`/api/projects/${project.id}/activity`).set(auth(accessToken));
  assert.equal(activity.status, 200);
  assert.ok(activity.body.length > 0);
  assert.equal(activity.body[0].display_name, 'Juan Pérez');
  assert.ok(activity.body[0].username);
});
