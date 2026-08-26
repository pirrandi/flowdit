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

// ── Refresh token lifetime is configurable ───────────────────────────────
// JWT_REFRESH_EXPIRES_IN used to be documented but ignored: every insert site
// hardcoded 30 days, so an operator tightening the window saw no effect.

test('refreshExpiryDays honours JWT_REFRESH_EXPIRES_IN and falls back safely', () => {
  const { refreshExpiryDays } = require('../src/utils/tokens');
  const prev = process.env.JWT_REFRESH_EXPIRES_IN;
  try {
    process.env.JWT_REFRESH_EXPIRES_IN = '7d';
    assert.equal(refreshExpiryDays(), 7);
    process.env.JWT_REFRESH_EXPIRES_IN = '14';
    assert.equal(refreshExpiryDays(), 14);
    // Unparseable values must not reach SQL as a broken interval.
    process.env.JWT_REFRESH_EXPIRES_IN = 'not-a-duration';
    assert.equal(refreshExpiryDays(), 30);
    delete process.env.JWT_REFRESH_EXPIRES_IN;
    assert.equal(refreshExpiryDays(), 30);
  } finally {
    if (prev === undefined) delete process.env.JWT_REFRESH_EXPIRES_IN;
    else process.env.JWT_REFRESH_EXPIRES_IN = prev;
  }
});

test('a configured refresh window is actually applied to the persisted token', async () => {
  const prev = process.env.JWT_REFRESH_EXPIRES_IN;
  process.env.JWT_REFRESH_EXPIRES_IN = '3d';
  try {
    const user = await registerUser({ username: 'refreshwin', email: 'refreshwin@example.com' });
    const { rows } = await db.query(
      `SELECT EXTRACT(DAY FROM (expires_at - NOW())) AS days
       FROM refresh_tokens WHERE token=$1`,
      [user.refreshToken]
    );
    assert.equal(rows.length, 1);
    // 3 days out, minus the sub-second the insert took, floors to 2.
    assert.ok(Number(rows[0].days) >= 2 && Number(rows[0].days) <= 3, `got ${rows[0].days} days`);
  } finally {
    if (prev === undefined) delete process.env.JWT_REFRESH_EXPIRES_IN;
    else process.env.JWT_REFRESH_EXPIRES_IN = prev;
  }
});
