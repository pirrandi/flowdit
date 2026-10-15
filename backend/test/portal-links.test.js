// Per-contact client portal links: one revocable, optionally expiring link per
// client contact. Pins owner-only management, the auth contract (same 401 for
// unknown/revoked/expired), per-link session revocation, the legacy backfill
// of the old shared projects.portal_token, server-side ticket attribution and
// the link used in reply emails.
const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const { app, db, resetDb, registerUser, createProject } = require('./helpers');
const mailer = require('../src/services/mailer');
const { backfillLegacyPortalLinks, hashToken } = require('../src/services/portalLinks');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

const auth = t => ({ Authorization: `Bearer ${t}` });

async function setupProject(flags = {}) {
  const owner = await registerUser();
  const project = await createProject(owner.accessToken);
  const patch = await request(app)
    .patch(`/api/projects/${project.id}`)
    .set(auth(owner.accessToken))
    .send({ client_view_enabled: true, tickets_enabled: true, show_activity: true, ...flags });
  assert.equal(patch.status, 200);
  return { owner, project };
}

async function createLink(ownerToken, projectId, body = { label: 'Alice Contact' }) {
  const res = await request(app)
    .post(`/api/projects/${projectId}/portal/links`)
    .set(auth(ownerToken))
    .send(body);
  assert.equal(res.status, 201, JSON.stringify(res.body));
  return res.body;
}

async function portalSession(token) {
  const res = await request(app).post('/api/portal/auth').send({ token });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return res.body;
}

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

test('owner creates, lists and revokes portal links', async () => {
  const { owner, project } = await setupProject();
  const created = await createLink(owner.accessToken, project.id,
    { label: 'Alice Contact', email: 'alice@client.example', expires_in_days: 90 });

  assert.equal(created.label, 'Alice Contact');
  assert.equal(created.email, 'alice@client.example');
  assert.equal(created.status, 'active');
  assert.equal(created.is_legacy, false);
  assert.match(created.token, /^[0-9a-f]{48}$/);
  assert.equal(created.created_by_name, owner.user.username);
  const days = (new Date(created.expires_at) - Date.now()) / 86400000;
  assert.ok(days > 89.9 && days <= 90, `expires in ~90 days, got ${days}`);
  assert.equal(created.token_enc, undefined);
  assert.equal(created.token_hash, undefined);

  const never = await createLink(owner.accessToken, project.id, { label: 'Bob', expires_in_days: null });
  assert.equal(never.expires_at, null);

  const list = await request(app)
    .get(`/api/projects/${project.id}/portal/links`)
    .set(auth(owner.accessToken));
  assert.equal(list.status, 200);
  assert.equal(list.body.length, 2);
  const alice = list.body.find(l => l.id === created.id);
  assert.equal(alice.token, created.token, 'active link token is re-copyable');
  assert.equal(alice.use_count, 0);
  assert.equal(alice.last_used_at, null);
  for (const l of list.body) {
    assert.equal(l.token_enc, undefined);
    assert.equal(l.token_hash, undefined);
  }

  const rev = await request(app)
    .post(`/api/projects/${project.id}/portal/links/${created.id}/revoke`)
    .set(auth(owner.accessToken));
  assert.equal(rev.status, 200);
  assert.equal(rev.body.status, 'revoked');
  assert.equal(rev.body.token, null, 'revoked link no longer hands out its token');
  assert.ok(rev.body.revoked_at);

  // Idempotent: a second revoke is a 200 no-op.
  const again = await request(app)
    .post(`/api/projects/${project.id}/portal/links/${created.id}/revoke`)
    .set(auth(owner.accessToken));
  assert.equal(again.status, 200);
  assert.equal(again.body.revoked_at, rev.body.revoked_at);
});

test('portal link creation validates its input', async () => {
  const { owner, project } = await setupProject();
  const bad = [
    {},
    { label: '' },
    { label: '   ' },
    { label: 'x'.repeat(201) },
    { label: 'Ok', email: 'not-an-email' },
    { label: 'Ok', expires_in_days: 0 },
    { label: 'Ok', expires_in_days: 3651 },
    { label: 'Ok', expires_in_days: 'soon' },
  ];
  for (const body of bad) {
    const res = await request(app)
      .post(`/api/projects/${project.id}/portal/links`)
      .set(auth(owner.accessToken))
      .send(body);
    assert.equal(res.status, 400, `should reject ${JSON.stringify(body)}`);
  }
});

test('revoking an unknown or foreign link is a 404', async () => {
  const { owner, project } = await setupProject();
  const other = await setupProject();
  const foreign = await createLink(other.owner.accessToken, other.project.id);

  for (const id of [foreign.id, '00000000-0000-0000-0000-000000000000', 'not-a-uuid']) {
    const res = await request(app)
      .post(`/api/projects/${project.id}/portal/links/${id}/revoke`)
      .set(auth(owner.accessToken));
    assert.equal(res.status, 404, id);
  }
  const { rows } = await db.query('SELECT revoked_at FROM portal_links WHERE id=$1', [foreign.id]);
  assert.equal(rows[0].revoked_at, null, 'foreign link untouched');
});

test('only the owner can manage portal links; editor, pentester, viewer and portal get 403', async () => {
  const { owner, project } = await setupProject();
  const link = await createLink(owner.accessToken, project.id);
  const sess = await portalSession(link.token);

  const tokens = { portal: sess.accessToken };
  for (const role of ['editor', 'pentester', 'viewer']) {
    tokens[role] = (await addMember(owner.accessToken, project.id, role)).accessToken;
  }

  for (const [who, token] of Object.entries(tokens)) {
    const list = await request(app).get(`/api/projects/${project.id}/portal/links`).set(auth(token));
    assert.equal(list.status, 403, `${who} list`);
    const create = await request(app)
      .post(`/api/projects/${project.id}/portal/links`)
      .set(auth(token))
      .send({ label: 'Sneaky' });
    assert.equal(create.status, 403, `${who} create`);
    const revoke = await request(app)
      .post(`/api/projects/${project.id}/portal/links/${link.id}/revoke`)
      .set(auth(token));
    assert.equal(revoke.status, 403, `${who} revoke`);
  }

  const { rows } = await db.query('SELECT COUNT(*)::int AS n, bool_and(revoked_at IS NULL) AS live FROM portal_links WHERE project_id=$1', [project.id]);
  assert.deepEqual(rows[0], { n: 1, live: true });

  // The removed single-link endpoint is gone.
  const old = await request(app)
    .post(`/api/projects/${project.id}/portal/token`)
    .set(auth(owner.accessToken));
  assert.equal(old.status, 404);
});

test('auth with an active link returns the contact and bumps usage', async () => {
  const { owner, project } = await setupProject();
  const link = await createLink(owner.accessToken, project.id, { label: 'Alice Contact', email: 'alice@client.example' });

  const first = await portalSession(link.token);
  assert.equal(first.projectId, project.id);
  assert.equal(first.contactName, 'Alice Contact');
  assert.equal(first.contactEmail, 'alice@client.example');
  assert.equal(jwt.decode(first.accessToken).linkId, link.id);
  assert.equal(jwt.decode(first.accessToken).tok, undefined);
  await portalSession(link.token);

  const { rows } = await db.query('SELECT use_count, last_used_at FROM portal_links WHERE id=$1', [link.id]);
  assert.equal(rows[0].use_count, 2);
  assert.ok(rows[0].last_used_at);

  const noEmail = await createLink(owner.accessToken, project.id, { label: 'Bob' });
  assert.equal((await portalSession(noEmail.token)).contactEmail, null);
});

test('unknown, revoked and expired links get the identical 401', async () => {
  const { owner, project } = await setupProject();
  const revoked = await createLink(owner.accessToken, project.id, { label: 'Revoked' });
  const expired = await createLink(owner.accessToken, project.id, { label: 'Expired', expires_in_days: 1 });
  await request(app)
    .post(`/api/projects/${project.id}/portal/links/${revoked.id}/revoke`)
    .set(auth(owner.accessToken));
  await db.query(`UPDATE portal_links SET expires_at = NOW() - INTERVAL '1 minute' WHERE id=$1`, [expired.id]);

  const bodies = [];
  for (const token of [revoked.token, expired.token, 'f'.repeat(48)]) {
    const res = await request(app).post('/api/portal/auth').send({ token });
    assert.equal(res.status, 401);
    bodies.push(res.body);
  }
  assert.deepEqual(bodies[0], { error: 'Invalid or expired link' });
  assert.deepEqual(bodies[1], bodies[0]);
  assert.deepEqual(bodies[2], bodies[0]);

  const list = await request(app).get(`/api/projects/${project.id}/portal/links`).set(auth(owner.accessToken));
  const byLabel = Object.fromEntries(list.body.map(l => [l.label, l]));
  assert.equal(byLabel.Expired.status, 'expired');
  assert.equal(byLabel.Expired.token, null);
  assert.equal(byLabel.Revoked.status, 'revoked');
});

test('password-protected portal still works with per-contact links', async () => {
  const { owner, project } = await setupProject();
  await request(app)
    .patch(`/api/projects/${project.id}`)
    .set(auth(owner.accessToken))
    .send({ portal_require_password: true, portal_password: 's3cret-portal' });
  const link = await createLink(owner.accessToken, project.id);

  const probe = await request(app).post('/api/portal/auth').send({ token: link.token });
  assert.equal(probe.status, 401);
  assert.equal(probe.body.passwordRequired, true);
  assert.equal(probe.body.contactName, undefined, 'no contact data before the password');
  const wrong = await request(app).post('/api/portal/auth').send({ token: link.token, password: 'nope' });
  assert.equal(wrong.status, 401);
  const ok = await request(app).post('/api/portal/auth').send({ token: link.token, password: 's3cret-portal' });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.contactName, 'Alice Contact');

  const { rows } = await db.query('SELECT use_count FROM portal_links WHERE id=$1', [link.id]);
  assert.equal(rows[0].use_count, 1, 'only the successful auth counts as a use');
});

test('revoking a link ends its session on the next request; other contacts keep working', async () => {
  const { owner, project } = await setupProject();
  const alice = await createLink(owner.accessToken, project.id, { label: 'Alice' });
  const bob   = await createLink(owner.accessToken, project.id, { label: 'Bob' });
  const aliceSess = await portalSession(alice.token);
  const bobSess   = await portalSession(bob.token);

  const url = `/api/projects/${project.id}`;
  assert.equal((await request(app).get(url).set(auth(aliceSess.accessToken))).status, 200);

  await request(app)
    .post(`/api/projects/${project.id}/portal/links/${alice.id}/revoke`)
    .set(auth(owner.accessToken));

  const dead = await request(app).get(url).set(auth(aliceSess.accessToken));
  assert.equal(dead.status, 401);
  assert.equal(dead.body.error, 'Portal link has changed. Please use the new link.');
  assert.equal((await request(app).get(url).set(auth(bobSess.accessToken))).status, 200);

  // Expiry ends a live session the same way.
  await db.query(`UPDATE portal_links SET expires_at = NOW() - INTERVAL '1 second' WHERE id=$1`, [bob.id]);
  assert.equal((await request(app).get(url).set(auth(bobSess.accessToken))).status, 401);
});

test('a portal session issued before per-contact links (no linkId) is rejected', async () => {
  const { project } = await setupProject();
  const legacyJwt = jwt.sign(
    { sub: 'portal', projectId: project.id, type: 'portal', tok: 'whatever' },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
  const res = await request(app).get(`/api/projects/${project.id}`).set(auth(legacyJwt));
  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'Portal link has changed. Please use the new link.');
});

test('a link only opens its own project', async () => {
  const { owner, project } = await setupProject();
  const other = await setupProject();
  const link = await createLink(owner.accessToken, project.id);
  const sess = await portalSession(link.token);
  const res = await request(app).get(`/api/projects/${other.project.id}`).set(auth(sess.accessToken));
  assert.equal(res.status, 403);
  // A forged JWT pointing the link at another project is refused too.
  const forged = jwt.sign(
    { sub: 'portal', type: 'portal', projectId: other.project.id, linkId: link.id },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
  assert.equal((await request(app).get(`/api/projects/${other.project.id}`).set(auth(forged))).status, 401);
});

test('legacy backfill turns an existing portal_token into a working, idempotent legacy link', async () => {
  const { owner, project } = await setupProject();
  const legacyToken = 'a'.repeat(48);
  await db.query('UPDATE projects SET portal_token=$1 WHERE id=$2', [legacyToken, project.id]);

  assert.equal(await backfillLegacyPortalLinks(db), 1);
  assert.equal(await backfillLegacyPortalLinks(db), 0, 'second run is a no-op');

  const { rows } = await db.query('SELECT * FROM portal_links WHERE project_id=$1', [project.id]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].is_legacy, true);
  assert.equal(rows[0].label, 'Shared link (legacy)');
  assert.equal(rows[0].expires_at, null);
  assert.equal(rows[0].token_hash, hashToken(legacyToken));
  assert.ok(!rows[0].token_enc.includes(legacyToken), 'token stored encrypted');

  const sess = await portalSession(legacyToken);
  assert.equal(sess.contactName, null);
  assert.equal(sess.contactEmail, null);

  // Legacy keeps the self-declared client name.
  const ticket = await request(app)
    .post(`/api/projects/${project.id}/tickets`)
    .set(auth(sess.accessToken))
    .send({ title: 'Legacy question', client_name: 'Carol' });
  assert.equal(ticket.status, 201);
  assert.equal(ticket.body.client_name, 'Carol');
  const anon = await request(app)
    .post(`/api/projects/${project.id}/tickets`)
    .set(auth(sess.accessToken))
    .send({ title: 'Anonymous question' });
  assert.equal(anon.body.client_name, 'Client');

  // Once revoked, the backfill does not resurrect it.
  const list = await request(app).get(`/api/projects/${project.id}/portal/links`).set(auth(owner.accessToken));
  assert.equal(list.body[0].token, legacyToken);
  await request(app)
    .post(`/api/projects/${project.id}/portal/links/${rows[0].id}/revoke`)
    .set(auth(owner.accessToken));
  assert.equal(await backfillLegacyPortalLinks(db), 0);
  assert.equal((await request(app).post('/api/portal/auth').send({ token: legacyToken })).status, 401);
});

test('tickets and replies through a contact link are attributed to that contact', async () => {
  const { owner, project } = await setupProject();
  const link = await createLink(owner.accessToken, project.id, { label: 'Alice Contact', email: 'alice@client.example' });
  const sess = await portalSession(link.token);

  const res = await request(app)
    .post(`/api/projects/${project.id}/tickets`)
    .set(auth(sess.accessToken))
    .send({ title: 'Question', client_name: 'Mallory' });
  assert.equal(res.status, 201);
  assert.equal(res.body.client_name, 'Alice Contact', 'body client_name is ignored');
  assert.equal(res.body.client_email, 'alice@client.example', 'falls back to the link email');
  assert.equal(res.body.portal_link_id, undefined, 'portal projection hides the link id');

  const { rows } = await db.query('SELECT client_name, portal_link_id FROM tickets WHERE id=$1', [res.body.id]);
  assert.deepEqual(rows[0], { client_name: 'Alice Contact', portal_link_id: link.id });

  // An explicit email from the client is kept.
  const withEmail = await request(app)
    .post(`/api/projects/${project.id}/tickets`)
    .set(auth(sess.accessToken))
    .send({ title: 'Other', client_email: 'alice.personal@client.example' });
  assert.equal(withEmail.body.client_email, 'alice.personal@client.example');

  const reply = await request(app)
    .post(`/api/projects/${project.id}/tickets/${res.body.id}/replies`)
    .set(auth(sess.accessToken))
    .send({ body: 'More detail', client_name: 'Mallory' });
  assert.equal(reply.status, 201);
  assert.equal(reply.body.author_name, 'Alice Contact');
});

test('reply emails link the ticket contact, then the legacy link, never a dead one', async (t) => {
  const { owner, project } = await setupProject();
  const sent = [];
  t.mock.method(mailer, 'sendTicketReplyNotification', async (opts) => { sent.push(opts); });

  const alice = await createLink(owner.accessToken, project.id, { label: 'Alice', email: 'alice@client.example' });
  const sess = await portalSession(alice.token);
  const ticket = await request(app)
    .post(`/api/projects/${project.id}/tickets`)
    .set(auth(sess.accessToken))
    .send({ title: 'Question' });
  assert.equal(ticket.status, 201);

  const teamReply = async () => {
    const r = await request(app)
      .post(`/api/projects/${project.id}/tickets/${ticket.body.id}/replies`)
      .set(auth(owner.accessToken))
      .send({ body: 'Answer' });
    assert.equal(r.status, 201);
    return sent.at(-1);
  };

  const first = await teamReply();
  assert.equal(first.toEmail, 'alice@client.example');
  assert.ok(first.portalUrl.endsWith(`/client-login#token=${alice.token}`));

  // Alice's link revoked: fall back to the project's active legacy link.
  const legacyToken = 'b'.repeat(48);
  await db.query('UPDATE projects SET portal_token=$1 WHERE id=$2', [legacyToken, project.id]);
  await backfillLegacyPortalLinks(db);
  await request(app)
    .post(`/api/projects/${project.id}/portal/links/${alice.id}/revoke`)
    .set(auth(owner.accessToken));
  assert.ok((await teamReply()).portalUrl.endsWith(`#token=${legacyToken}`));

  // No active link left: the email goes out without one.
  const { rows } = await db.query('SELECT id FROM portal_links WHERE project_id=$1 AND is_legacy', [project.id]);
  await request(app)
    .post(`/api/projects/${project.id}/portal/links/${rows[0].id}/revoke`)
    .set(auth(owner.accessToken));
  assert.equal((await teamReply()).portalUrl, null);
});

test('link activity is logged for create and revoke (once) and hidden from the portal', async () => {
  const { owner, project } = await setupProject();
  const link = await createLink(owner.accessToken, project.id, { label: 'Alice', expires_in_days: 30 });
  const other = await createLink(owner.accessToken, project.id, { label: 'Viewer of the feed' });
  for (let i = 0; i < 2; i++) {
    await request(app)
      .post(`/api/projects/${project.id}/portal/links/${link.id}/revoke`)
      .set(auth(owner.accessToken));
  }

  const { rows } = await db.query(
    `SELECT action, entity_type, entity_id, entity_name, meta FROM activity_log
     WHERE project_id=$1 AND entity_type='portal' ORDER BY created_at, action`,
    [project.id]
  );
  const forAlice = rows.filter(r => r.entity_id === link.id);
  assert.deepEqual(forAlice.map(r => r.action), ['portal_link_created', 'portal_link_revoked']);
  assert.equal(forAlice[0].entity_name, 'Alice');
  assert.equal(new Date(forAlice[0].meta.expires_at).toISOString(), new Date(link.expires_at).toISOString());
  assert.equal(forAlice[1].entity_name, 'Alice');

  const sess = await portalSession(other.token);
  const feed = await request(app).get(`/api/projects/${project.id}/activity`).set(auth(sess.accessToken));
  assert.equal(feed.status, 200);
  assert.ok(!feed.body.some(e => e.entity_type === 'portal'));
});

test('a portal session never receives any link token or its ciphertext', async () => {
  const { owner, project } = await setupProject({ show_findings: true });
  const alice = await createLink(owner.accessToken, project.id, { label: 'Alice', email: 'alice@client.example' });
  const bob   = await createLink(owner.accessToken, project.id, { label: 'Bob' });
  const auth0 = await request(app).post('/api/portal/auth').send({ token: alice.token });
  const sess  = auth0.body;

  const ticket = await request(app)
    .post(`/api/projects/${project.id}/tickets`)
    .set(auth(sess.accessToken))
    .send({ title: 'Q' });
  await request(app)
    .post(`/api/projects/${project.id}/tickets/${ticket.body.id}/replies`)
    .set(auth(owner.accessToken))
    .send({ body: 'A' });

  const { rows } = await db.query('SELECT token_enc, token_hash FROM portal_links WHERE project_id=$1', [project.id]);
  const secrets = [alice.token, bob.token, ...rows.flatMap(r => [r.token_enc, r.token_hash.trim()])];

  const bodies = [JSON.stringify(auth0.body)];
  for (const path of ['', '/tickets', `/tickets/${ticket.body.id}`, '/activity', '/vulns']) {
    const res = await request(app).get(`/api/projects/${project.id}${path}`).set(auth(sess.accessToken));
    assert.equal(res.status, 200, path);
    bodies.push(JSON.stringify(res.body));
  }
  for (const body of bodies) {
    for (const secret of secrets) assert.ok(!body.includes(secret), 'portal response leaks a link secret');
    assert.ok(!body.includes('token_enc') && !body.includes('token_hash'));
  }
});
