// Coverage for the OIDC/Entra ID SSO surface: src/routes/sso.js (check /
// callback / exchange) and src/services/sso.js (flow/exchange stores,
// provisioning). A live Entra ID tenant isn't available in this test
// environment, so the full authorization-code exchange (routes/sso.js
// GET /start success path and the back half of GET /callback, both of which
// call out to services/sso.js's getOidcConfig -> openid-client discovery())
// is NOT covered here — see the note above the callback tests below.
process.env.SSO_ENCRYPTION_KEY = process.env.SSO_ENCRYPTION_KEY || 'test_only_sso_key_do_not_use_in_prod';

const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { app, db, resetDb, registerUser } = require('./helpers');
const { encrypt, decrypt } = require('../src/utils/crypto');
const {
  saveFlow, takeFlow, saveExchange, takeExchange, provisionSsoUser,
} = require('../src/services/sso');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

async function createOrg(accessToken, name = 'SSO Corp') {
  const res = await request(app)
    .post('/api/organizations')
    .set('Authorization', `Bearer ${accessToken}`)
    .send({ name });
  assert.equal(res.status, 201);
  return res.body;
}

async function configureSso(accessToken, orgId, overrides = {}) {
  const res = await request(app)
    .put(`/api/organizations/${orgId}/sso`)
    .set('Authorization', `Bearer ${accessToken}`)
    .send({
      issuer_url: 'https://login.microsoftonline.com/tenant-id/v2.0',
      client_id: 'client-123',
      client_secret: 'super-secret-value',
      email_domain: 'acme-corp.test',
      enforce: false,
      enabled: true,
      ...overrides,
    });
  assert.equal(res.status, 200);
  return res.body;
}

// ── utils/crypto.js: AES-256-GCM round trip ──────────────────────────

test('encrypt/decrypt round-trips a plaintext secret', () => {
  const plaintext = 'my-oidc-client-secret';
  const enc = encrypt(plaintext);
  assert.equal(decrypt(enc), plaintext);
});

test('encrypt produces a different ciphertext each time (random IV)', () => {
  const a = encrypt('same-value');
  const b = encrypt('same-value');
  assert.notEqual(a, b);
  assert.equal(decrypt(a), 'same-value');
  assert.equal(decrypt(b), 'same-value');
});

test('decrypt rejects a tampered payload', () => {
  const enc = encrypt('tamper-me');
  const [iv, tag, cipher] = enc.split(':');
  const tampered = `${iv}:${tag}:${cipher.slice(0, -2)}00`;
  assert.throws(() => decrypt(tampered));
});

// ── services/sso.js: flow / exchange stores ──────────────────────────

test('saveFlow/takeFlow round-trips state and is single-use', () => {
  saveFlow('state-abc', { codeVerifier: 'v', nonce: 'n', orgId: 'org-1' });
  const first = takeFlow('state-abc');
  assert.deepEqual(first, { codeVerifier: 'v', nonce: 'n', orgId: 'org-1', expiresAt: first.expiresAt });

  const second = takeFlow('state-abc');
  assert.equal(second, null);
});

test('takeFlow returns null for an unknown state', () => {
  assert.equal(takeFlow('never-saved-state'), null);
});

test('saveExchange/takeExchange round-trips the session and is single-use', () => {
  const session = { accessToken: 'a', refreshToken: 'b', user: { id: '1' } };
  saveExchange('code-xyz', session);
  const first = takeExchange('code-xyz');
  assert.equal(first.accessToken, 'a');

  const second = takeExchange('code-xyz');
  assert.equal(second, null);
});

test('takeExchange returns null for an unknown code', () => {
  assert.equal(takeExchange('never-saved-code'), null);
});

// ── services/sso.js: provisionSsoUser (pure w.r.t. network) ──────────

test('provisionSsoUser creates a new user and adds them to the org on domain match', async () => {
  const owner = await registerUser({ username: 'ssoowner1', email: 'ssoowner1@example.com' });
  const org = await createOrg(owner.accessToken, 'Provision Co');

  const claims = { email: 'newhire@acme-corp.test', name: 'New Hire' };
  const user = await provisionSsoUser(claims, { id: org.id, email_domain: 'acme-corp.test' });

  assert.equal(user.email, 'newhire@acme-corp.test');
  assert.ok(user.id);

  const membership = await db.query(
    'SELECT role FROM organization_members WHERE organization_id=$1 AND user_id=$2',
    [org.id, user.id]
  );
  assert.equal(membership.rows.length, 1);
  assert.equal(membership.rows[0].role, 'member');
});

test('provisionSsoUser rejects a claims email whose domain does not match the org\'s configured domain', async () => {
  const owner = await registerUser({ username: 'ssoowner2', email: 'ssoowner2@example.com' });
  const org = await createOrg(owner.accessToken, 'Provision Co 2');

  const claims = { email: 'attacker@evil.example.com' };
  await assert.rejects(
    () => provisionSsoUser(claims, { id: org.id, email_domain: 'acme-corp.test' }),
    /does not match/
  );
});

test('provisionSsoUser reuses an existing user by email instead of creating a duplicate', async () => {
  const owner = await registerUser({ username: 'ssoowner3', email: 'ssoowner3@example.com' });
  const existing = await registerUser({ username: 'existinguser3', email: 'existinguser3@acme-corp.test' });
  const org = await createOrg(owner.accessToken, 'Provision Co 3');

  const claims = { email: 'existinguser3@acme-corp.test', name: 'Existing User' };
  const user = await provisionSsoUser(claims, { id: org.id, email_domain: 'acme-corp.test' });

  assert.equal(user.id, existing.user.id);
  const count = await db.query('SELECT COUNT(*)::int AS c FROM users WHERE email=$1', ['existinguser3@acme-corp.test']);
  assert.equal(count.rows[0].c, 1);
});

test('provisionSsoUser does not duplicate membership for a user already in the org', async () => {
  const owner = await registerUser({ username: 'ssoowner4', email: 'ssoowner4@example.com' });
  const org = await createOrg(owner.accessToken, 'Provision Co 4');

  const claims = { email: 'repeat@acme-corp.test', name: 'Repeat User' };
  const first = await provisionSsoUser(claims, { id: org.id, email_domain: 'acme-corp.test' });
  const second = await provisionSsoUser(claims, { id: org.id, email_domain: 'acme-corp.test' });

  assert.equal(first.id, second.id);
  const membership = await db.query(
    'SELECT COUNT(*)::int AS c FROM organization_members WHERE organization_id=$1 AND user_id=$2',
    [org.id, first.id]
  );
  assert.equal(membership.rows[0].c, 1);
});

test('provisionSsoUser resolves a username collision deterministically', async () => {
  const owner = await registerUser({ username: 'ssoowner5', email: 'ssoowner5@example.com' });
  await registerUser({ username: 'jsmith', email: 'jsmith-preexisting@example.com' });
  const org = await createOrg(owner.accessToken, 'Provision Co 5');

  const claims = { email: 'jsmith@acme-corp.test', name: 'jsmith' };
  const user = await provisionSsoUser(claims, { id: org.id, email_domain: 'acme-corp.test' });

  assert.notEqual(user.username, 'jsmith');
  assert.ok(user.username.startsWith('jsmith'));
});

// ── routes/sso.js: POST /auth/sso/check ──────────────────────────────

test('/sso/check reports available:true with a startUrl for a domain with enabled SSO', async () => {
  const owner = await registerUser({ username: 'checkowner1', email: 'checkowner1@example.com' });
  const org = await createOrg(owner.accessToken, 'Check Co');
  await configureSso(owner.accessToken, org.id, { email_domain: 'checkco.test' });

  const res = await request(app).post('/api/auth/sso/check').send({ email: 'someone@checkco.test' });
  assert.equal(res.status, 200);
  assert.equal(res.body.available, true);
  assert.equal(res.body.organizationName, 'Check Co');
  assert.equal(res.body.startUrl, `/auth/sso/start?oid=${org.id}`);
});

test('/sso/check reports available:false for a domain with no SSO configured', async () => {
  const res = await request(app).post('/api/auth/sso/check').send({ email: 'someone@no-sso-here.test' });
  assert.equal(res.status, 200);
  assert.equal(res.body.available, false);
});

test('/sso/check reports available:false for a domain whose config exists but is disabled', async () => {
  const owner = await registerUser({ username: 'checkowner2', email: 'checkowner2@example.com' });
  const org = await createOrg(owner.accessToken, 'Check Co 2');
  await configureSso(owner.accessToken, org.id, { email_domain: 'disabledco.test', enabled: false });

  const res = await request(app).post('/api/auth/sso/check').send({ email: 'someone@disabledco.test' });
  assert.equal(res.status, 200);
  assert.equal(res.body.available, false);
});

test('/sso/check handles a malformed email without a domain', async () => {
  const res = await request(app).post('/api/auth/sso/check').send({ email: 'not-an-email' });
  assert.equal(res.status, 200);
  assert.equal(res.body.available, false);
});

// ── routes/sso.js: GET /auth/sso/callback (only the network-free paths) ──
// The success path (state found -> decrypt secret -> discovery() ->
// authorizationCodeGrant()) requires a real IdP round trip and is
// intentionally not covered here.

test('/sso/callback redirects with an error when state is missing', async () => {
  const res = await request(app).get('/api/auth/sso/callback');
  assert.equal(res.status, 302);
  assert.match(res.headers.location, /ssoError=/);
});

test('/sso/callback redirects with an error for an unknown/expired state', async () => {
  const res = await request(app).get('/api/auth/sso/callback').query({ state: 'never-issued-state', code: 'abc' });
  assert.equal(res.status, 302);
  assert.match(res.headers.location, /ssoError=/);
  assert.match(res.headers.location, /expired/);
});

// ── routes/sso.js: POST /auth/sso/exchange ───────────────────────────

test('/sso/exchange trades a valid one-time code for the saved session, then invalidates it', async () => {
  const session = { accessToken: 'access-tok', refreshToken: 'refresh-tok', user: { id: 'u1', username: 'bob' } };
  saveExchange('exchange-code-1', session);

  const first = await request(app).post('/api/auth/sso/exchange').send({ code: 'exchange-code-1' });
  assert.equal(first.status, 200);
  assert.equal(first.body.accessToken, 'access-tok');

  const second = await request(app).post('/api/auth/sso/exchange').send({ code: 'exchange-code-1' });
  assert.equal(second.status, 400);
});

test('/sso/exchange rejects a missing code', async () => {
  const res = await request(app).post('/api/auth/sso/exchange').send({});
  assert.equal(res.status, 400);
});

test('/sso/exchange rejects an unknown code', async () => {
  const res = await request(app).post('/api/auth/sso/exchange').send({ code: 'not-a-real-code' });
  assert.equal(res.status, 400);
});

// ── enforcement guard on auth.js login/register ──────────────────────

test('an enforced SSO domain blocks password login even with the correct password', async () => {
  // Register the victim BEFORE enforcement is turned on: once enforce=true
  // is set for this domain, /auth/register itself also refuses that domain
  // (see the dedicated registration-blocking test below), so an account that
  // predates the SSO enforcement is the only way to reach a login attempt.
  const victim = await registerUser({ username: 'enforcevictim1', email: 'victim1@enforced.test' });

  const owner = await registerUser({ username: 'enforceowner1', email: 'enforceowner1@example.com' });
  const org = await createOrg(owner.accessToken, 'Enforce Co');
  await configureSso(owner.accessToken, org.id, { email_domain: 'enforced.test', enforce: true });

  const res = await request(app)
    .post('/api/auth/login')
    .send({ login: 'enforcevictim1', password: victim.credentials.password });
  assert.equal(res.status, 403);
  assert.equal(res.body.ssoRequired, true);
  assert.equal(res.body.accessToken, undefined);
});

test('a non-enforced (SSO-available but optional) domain still allows password login', async () => {
  const owner = await registerUser({ username: 'enforceowner2', email: 'enforceowner2@example.com' });
  const org = await createOrg(owner.accessToken, 'Optional Co');
  await configureSso(owner.accessToken, org.id, { email_domain: 'optional.test', enforce: false });

  const user = await registerUser({ username: 'optionaluser2', email: 'user2@optional.test' });

  const res = await request(app)
    .post('/api/auth/login')
    .send({ login: 'optionaluser2', password: user.credentials.password });
  assert.equal(res.status, 200);
  assert.ok(res.body.accessToken);
});

test('an enforced SSO domain also blocks new password registration for that domain', async () => {
  const owner = await registerUser({ username: 'enforceowner3', email: 'enforceowner3@example.com' });
  const org = await createOrg(owner.accessToken, 'Enforce Co 3');
  await configureSso(owner.accessToken, org.id, { email_domain: 'enforcedreg.test', enforce: true });

  const res = await request(app)
    .post('/api/auth/register')
    .send({ username: 'newbypassuser', email: 'newbypassuser@enforcedreg.test', password: 'correct-horse-battery-staple' });
  assert.equal(res.status, 403);
  assert.equal(res.body.ssoRequired, true);
});
