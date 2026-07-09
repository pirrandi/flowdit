const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { app, db, resetDb, registerUser } = require('./helpers');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

test('register creates a user with a personal organization and returns tokens', async () => {
  const res = await request(app).post('/api/auth/register').send({
    username: 'alice',
    email: 'alice@example.com',
    password: 'correct-horse-battery-staple',
  });

  assert.equal(res.status, 201);
  assert.ok(res.body.accessToken);
  assert.ok(res.body.refreshToken);
  assert.equal(res.body.user.username, 'alice');

  const orgs = await request(app)
    .get('/api/organizations')
    .set('Authorization', `Bearer ${res.body.accessToken}`);
  assert.equal(orgs.status, 200);
  assert.equal(orgs.body.length, 1);
  assert.equal(orgs.body[0].name, "alice's Organization");
});

test('register rejects a duplicate username', async () => {
  await registerUser({ username: 'bob', email: 'bob@example.com' });
  const res = await request(app).post('/api/auth/register').send({
    username: 'bob',
    email: 'bob-different@example.com',
    password: 'correct-horse-battery-staple',
  });
  assert.equal(res.status, 409);
});

test('register rejects a password shorter than 8 characters', async () => {
  const res = await request(app).post('/api/auth/register').send({
    username: 'shortpw',
    email: 'shortpw@example.com',
    password: 'short',
  });
  assert.equal(res.status, 400);
});

test('login succeeds with correct username and password', async () => {
  const { credentials } = await registerUser({ username: 'carol', email: 'carol@example.com' });
  const res = await request(app).post('/api/auth/login').send({
    login: 'carol',
    password: credentials.password,
  });
  assert.equal(res.status, 200);
  assert.ok(res.body.accessToken);
});

test('login succeeds using email instead of username', async () => {
  const { credentials } = await registerUser({ username: 'dave', email: 'dave@example.com' });
  const res = await request(app).post('/api/auth/login').send({
    login: 'dave@example.com',
    password: credentials.password,
  });
  assert.equal(res.status, 200);
});

test('login fails with wrong password', async () => {
  await registerUser({ username: 'erin', email: 'erin@example.com' });
  const res = await request(app).post('/api/auth/login').send({
    login: 'erin',
    password: 'totally-wrong-password',
  });
  assert.equal(res.status, 401);
});

test('login fails for a nonexistent user', async () => {
  const res = await request(app).post('/api/auth/login').send({
    login: 'nobody-here',
    password: 'whatever12345',
  });
  assert.equal(res.status, 401);
});

test('GET /auth/me requires a bearer token', async () => {
  const res = await request(app).get('/api/auth/me');
  assert.equal(res.status, 401);
});

test('GET /auth/me rejects a malformed token', async () => {
  const res = await request(app).get('/api/auth/me').set('Authorization', 'Bearer not-a-real-token');
  assert.equal(res.status, 401);
});

test('GET /auth/me returns the authenticated user with a valid token', async () => {
  const user = await registerUser({ username: 'frank', email: 'frank@example.com' });
  const res = await request(app)
    .get('/api/auth/me')
    .set('Authorization', `Bearer ${user.accessToken}`);
  assert.equal(res.status, 200);
  assert.equal(res.body.username, 'frank');
});
