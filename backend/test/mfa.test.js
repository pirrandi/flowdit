const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const otplib = require('otplib');
const { app, db, resetDb, registerUser } = require('./helpers');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

async function enrollMfa(accessToken) {
  const setup = await request(app)
    .post('/api/auth/mfa/setup')
    .set('Authorization', `Bearer ${accessToken}`);
  const code = await otplib.generate({ secret: setup.body.secret });
  const enable = await request(app)
    .post('/api/auth/mfa/enable')
    .set('Authorization', `Bearer ${accessToken}`)
    .send({ code });
  return { secret: setup.body.secret, backupCodes: enable.body.backupCodes };
}

test('mfa status defaults to disabled', async () => {
  const user = await registerUser({ username: 'mfa1', email: 'mfa1@example.com' });
  const res = await request(app).get('/api/auth/mfa/status').set('Authorization', `Bearer ${user.accessToken}`);
  assert.equal(res.status, 200);
  assert.equal(res.body.enabled, false);
});

test('setup returns a base32 secret and a QR data URL, but does not enable 2FA yet', async () => {
  const user = await registerUser({ username: 'mfa2', email: 'mfa2@example.com' });
  const res = await request(app).post('/api/auth/mfa/setup').set('Authorization', `Bearer ${user.accessToken}`);
  assert.equal(res.status, 200);
  assert.ok(res.body.secret);
  assert.ok(res.body.qrCodeDataUrl.startsWith('data:image'));

  const status = await request(app).get('/api/auth/mfa/status').set('Authorization', `Bearer ${user.accessToken}`);
  assert.equal(status.body.enabled, false);
});

test('enable rejects a wrong 6-digit code', async () => {
  const user = await registerUser({ username: 'mfa3', email: 'mfa3@example.com' });
  await request(app).post('/api/auth/mfa/setup').set('Authorization', `Bearer ${user.accessToken}`);
  const res = await request(app)
    .post('/api/auth/mfa/enable')
    .set('Authorization', `Bearer ${user.accessToken}`)
    .send({ code: '000000' });
  assert.equal(res.status, 400);
});

test('enable with the correct code turns 2FA on and returns 10 backup codes', async () => {
  const user = await registerUser({ username: 'mfa4', email: 'mfa4@example.com' });
  const { backupCodes } = await enrollMfa(user.accessToken);
  assert.equal(backupCodes.length, 10);

  const status = await request(app).get('/api/auth/mfa/status').set('Authorization', `Bearer ${user.accessToken}`);
  assert.equal(status.body.enabled, true);
});

test('login for a 2FA-enabled account returns a challenge instead of tokens', async () => {
  const user = await registerUser({ username: 'mfa5', email: 'mfa5@example.com' });
  await enrollMfa(user.accessToken);

  const res = await request(app).post('/api/auth/login').send({ login: 'mfa5', password: user.credentials.password });
  assert.equal(res.status, 200);
  assert.equal(res.body.mfaRequired, true);
  assert.ok(res.body.challengeToken);
  assert.equal(res.body.accessToken, undefined);
});

test('mfa/verify with a valid TOTP code completes the login', async () => {
  const user = await registerUser({ username: 'mfa6', email: 'mfa6@example.com' });
  const { secret } = await enrollMfa(user.accessToken);

  const login = await request(app).post('/api/auth/login').send({ login: 'mfa6', password: user.credentials.password });
  const code = await otplib.generate({ secret });
  const res = await request(app).post('/api/auth/mfa/verify').send({ challengeToken: login.body.challengeToken, code });
  assert.equal(res.status, 200);
  assert.ok(res.body.accessToken);
});

test('mfa/verify rejects an invalid code', async () => {
  const user = await registerUser({ username: 'mfa7', email: 'mfa7@example.com' });
  await enrollMfa(user.accessToken);

  const login = await request(app).post('/api/auth/login').send({ login: 'mfa7', password: user.credentials.password });
  const res = await request(app).post('/api/auth/mfa/verify').send({ challengeToken: login.body.challengeToken, code: '000000' });
  assert.equal(res.status, 401);
});

test('mfa/verify rejects an unknown or expired challenge token', async () => {
  const res = await request(app).post('/api/auth/mfa/verify').send({ challengeToken: 'not-a-real-token', code: '123456' });
  assert.equal(res.status, 401);
});

test('a backup code completes login and is single-use', async () => {
  const user = await registerUser({ username: 'mfa8', email: 'mfa8@example.com' });
  const { backupCodes } = await enrollMfa(user.accessToken);
  const backupCode = backupCodes[0];

  const login1 = await request(app).post('/api/auth/login').send({ login: 'mfa8', password: user.credentials.password });
  const first = await request(app).post('/api/auth/mfa/verify').send({ challengeToken: login1.body.challengeToken, code: backupCode });
  assert.equal(first.status, 200);
  assert.ok(first.body.accessToken);

  const login2 = await request(app).post('/api/auth/login').send({ login: 'mfa8', password: user.credentials.password });
  const second = await request(app).post('/api/auth/mfa/verify').send({ challengeToken: login2.body.challengeToken, code: backupCode });
  assert.equal(second.status, 401);
});

test('disable requires the correct account password', async () => {
  const user = await registerUser({ username: 'mfa9', email: 'mfa9@example.com' });
  await enrollMfa(user.accessToken);

  const wrong = await request(app)
    .post('/api/auth/mfa/disable')
    .set('Authorization', `Bearer ${user.accessToken}`)
    .send({ password: 'not-the-password' });
  assert.equal(wrong.status, 401);

  const status = await request(app).get('/api/auth/mfa/status').set('Authorization', `Bearer ${user.accessToken}`);
  assert.equal(status.body.enabled, true);
});

test('disable with the correct password turns 2FA off and login no longer challenges', async () => {
  const user = await registerUser({ username: 'mfa10', email: 'mfa10@example.com' });
  await enrollMfa(user.accessToken);

  const disable = await request(app)
    .post('/api/auth/mfa/disable')
    .set('Authorization', `Bearer ${user.accessToken}`)
    .send({ password: user.credentials.password });
  assert.equal(disable.status, 200);

  const login = await request(app).post('/api/auth/login').send({ login: 'mfa10', password: user.credentials.password });
  assert.equal(login.status, 200);
  assert.ok(login.body.accessToken);
  assert.equal(login.body.mfaRequired, undefined);
});
