// Coverage for backend/src/routes/organizations.js: multi-tenant org CRUD,
// role-gated member management, token-based invites, and — most importantly —
// that org boundaries hold up the same way project boundaries do in
// isolation.test.js (regression class: a582e20's cross-project IDOR).
const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { app, db, resetDb, registerUser, createProject } = require('./helpers');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

async function createOrg(accessToken, name = 'Acme Corp') {
  const res = await request(app)
    .post('/api/organizations')
    .set('Authorization', `Bearer ${accessToken}`)
    .send({ name });
  assert.equal(res.status, 201);
  return res.body;
}

async function createInvite(accessToken, orgId, overrides = {}) {
  const res = await request(app)
    .post(`/api/organizations/${orgId}/invites`)
    .set('Authorization', `Bearer ${accessToken}`)
    .send(overrides);
  assert.equal(res.status, 201);
  return res.body;
}

async function joinOrg(accessToken, token) {
  return request(app)
    .post('/api/organizations/join')
    .set('Authorization', `Bearer ${accessToken}`)
    .send({ token });
}

// ── creation / ownership ─────────────────────────────────────────────

test('creating an organization makes the creator its owner', async () => {
  const owner = await registerUser({ username: 'orgowner1', email: 'orgowner1@example.com' });
  const org = await createOrg(owner.accessToken, 'Owner Co');

  assert.equal(org.member_role, 'owner');
  assert.equal(org.is_personal, false);
  assert.equal(org.name, 'Owner Co');

  const list = await request(app)
    .get('/api/organizations')
    .set('Authorization', `Bearer ${owner.accessToken}`);
  assert.equal(list.status, 200);
  const found = list.body.find(o => o.id === org.id);
  assert.ok(found, 'created org should appear in the caller\'s org list');
  assert.equal(found.member_role, 'owner');
  assert.equal(Number(found.member_count), 1);
});

test('org name requires a non-empty value', async () => {
  const owner = await registerUser({ username: 'orgowner2', email: 'orgowner2@example.com' });
  const res = await request(app)
    .post('/api/organizations')
    .set('Authorization', `Bearer ${owner.accessToken}`)
    .send({ name: '' });
  assert.equal(res.status, 400);
});

// ── role-gated management ────────────────────────────────────────────

test('a member cannot invite others or rename the org; an admin can invite but still cannot rename', async () => {
  const owner  = await registerUser({ username: 'roleowner1', email: 'roleowner1@example.com' });
  const member = await registerUser({ username: 'rolemember1', email: 'rolemember1@example.com' });
  const org = await createOrg(owner.accessToken, 'Role Co');

  const invite = await createInvite(owner.accessToken, org.id, { role: 'member' });
  const joined = await joinOrg(member.accessToken, invite.token);
  assert.equal(joined.status, 200);
  assert.equal(joined.body.role, 'member');

  // member cannot invite
  const memberInvite = await request(app)
    .post(`/api/organizations/${org.id}/invites`)
    .set('Authorization', `Bearer ${member.accessToken}`)
    .send({ role: 'member' });
  assert.equal(memberInvite.status, 403);

  // member cannot rename the org
  const memberRename = await request(app)
    .patch(`/api/organizations/${org.id}`)
    .set('Authorization', `Bearer ${member.accessToken}`)
    .send({ name: 'Hijacked Name' });
  assert.equal(memberRename.status, 403);

  // owner promotes member to admin
  const promote = await request(app)
    .patch(`/api/organizations/${org.id}/members/${member.user.id}`)
    .set('Authorization', `Bearer ${owner.accessToken}`)
    .send({ role: 'admin' });
  assert.equal(promote.status, 200);

  // admin CAN invite ...
  const adminInvite = await request(app)
    .post(`/api/organizations/${org.id}/invites`)
    .set('Authorization', `Bearer ${member.accessToken}`)
    .send({ role: 'member' });
  assert.equal(adminInvite.status, 201);

  // ... but still cannot rename (owner-only action)
  const adminRename = await request(app)
    .patch(`/api/organizations/${org.id}`)
    .set('Authorization', `Bearer ${member.accessToken}`)
    .send({ name: 'Still Hijacked' });
  assert.equal(adminRename.status, 403);
});

test('a member cannot change roles or remove members; that is owner-only', async () => {
  const owner  = await registerUser({ username: 'roleowner2', email: 'roleowner2@example.com' });
  const member = await registerUser({ username: 'rolemember2', email: 'rolemember2@example.com' });
  const other  = await registerUser({ username: 'roleother2', email: 'roleother2@example.com' });
  const org = await createOrg(owner.accessToken, 'Role Co 2');

  await joinOrg(member.accessToken, (await createInvite(owner.accessToken, org.id)).token);
  await joinOrg(other.accessToken, (await createInvite(owner.accessToken, org.id)).token);

  const res = await request(app)
    .patch(`/api/organizations/${org.id}/members/${other.user.id}`)
    .set('Authorization', `Bearer ${member.accessToken}`)
    .send({ role: 'admin' });
  assert.equal(res.status, 403);

  const del = await request(app)
    .delete(`/api/organizations/${org.id}/members/${other.user.id}`)
    .set('Authorization', `Bearer ${member.accessToken}`);
  assert.equal(del.status, 403);
});

test('owner cannot change their own role or remove themselves', async () => {
  const owner = await registerUser({ username: 'selfowner1', email: 'selfowner1@example.com' });
  const org = await createOrg(owner.accessToken, 'Self Co');

  const roleRes = await request(app)
    .patch(`/api/organizations/${org.id}/members/${owner.user.id}`)
    .set('Authorization', `Bearer ${owner.accessToken}`)
    .send({ role: 'admin' });
  assert.equal(roleRes.status, 400);

  const delRes = await request(app)
    .delete(`/api/organizations/${org.id}/members/${owner.user.id}`)
    .set('Authorization', `Bearer ${owner.accessToken}`);
  assert.equal(delRes.status, 400);
});

test('PATCH member role rejects an invalid role value', async () => {
  const owner  = await registerUser({ username: 'roleowner3', email: 'roleowner3@example.com' });
  const member = await registerUser({ username: 'rolemember3', email: 'rolemember3@example.com' });
  const org = await createOrg(owner.accessToken, 'Role Co 3');
  await joinOrg(member.accessToken, (await createInvite(owner.accessToken, org.id)).token);

  const res = await request(app)
    .patch(`/api/organizations/${org.id}/members/${member.user.id}`)
    .set('Authorization', `Bearer ${owner.accessToken}`)
    .send({ role: 'owner' });
  assert.equal(res.status, 400);
});

// ── invite flow ───────────────────────────────────────────────────────

test('invite create -> accept flow adds the invited user with the invited role', async () => {
  const owner = await registerUser({ username: 'invowner1', email: 'invowner1@example.com' });
  const invitee = await registerUser({ username: 'invitee1', email: 'invitee1@example.com' });
  const org = await createOrg(owner.accessToken, 'Invite Co');

  const invite = await createInvite(owner.accessToken, org.id, { role: 'admin', label: 'ops team' });
  assert.ok(invite.token.startsWith('FO-'));

  const join = await joinOrg(invitee.accessToken, invite.token);
  assert.equal(join.status, 200);
  assert.equal(join.body.organizationId, org.id);
  assert.equal(join.body.role, 'admin');

  const members = await request(app)
    .get(`/api/organizations/${org.id}/members`)
    .set('Authorization', `Bearer ${invitee.accessToken}`);
  assert.equal(members.status, 200);
  const invited = members.body.find(m => m.id === invitee.user.id);
  assert.ok(invited);
  assert.equal(invited.role, 'admin');
});

test('joining with an unknown invite token is rejected', async () => {
  const user = await registerUser({ username: 'badtoken1', email: 'badtoken1@example.com' });
  const res = await joinOrg(user.accessToken, 'FO-DEADBEEF0000');
  assert.equal(res.status, 404);
});

test('an expired invite token is rejected', async () => {
  const owner = await registerUser({ username: 'expowner1', email: 'expowner1@example.com' });
  const invitee = await registerUser({ username: 'expinvitee1', email: 'expinvitee1@example.com' });
  const org = await createOrg(owner.accessToken, 'Expire Co');
  const invite = await createInvite(owner.accessToken, org.id);

  await db.query(`UPDATE organization_invites SET expires_at = NOW() - INTERVAL '1 day' WHERE id=$1`, [invite.id]);

  const res = await joinOrg(invitee.accessToken, invite.token);
  assert.equal(res.status, 404);
});

test('an already-accepted invite token cannot be reused', async () => {
  const owner = await registerUser({ username: 'reuseowner1', email: 'reuseowner1@example.com' });
  const first = await registerUser({ username: 'reusefirst1', email: 'reusefirst1@example.com' });
  const second = await registerUser({ username: 'reusesecond1', email: 'reusesecond1@example.com' });
  const org = await createOrg(owner.accessToken, 'Reuse Co');
  const invite = await createInvite(owner.accessToken, org.id);

  const firstJoin = await joinOrg(first.accessToken, invite.token);
  assert.equal(firstJoin.status, 200);

  const secondJoin = await joinOrg(second.accessToken, invite.token);
  assert.equal(secondJoin.status, 404);
});

test('a user already in the org gets a conflict when reusing a valid invite', async () => {
  const owner = await registerUser({ username: 'dupowner1', email: 'dupowner1@example.com' });
  const org = await createOrg(owner.accessToken, 'Dup Co');
  const invite = await createInvite(owner.accessToken, org.id);

  // owner is already a member of their own org
  const res = await joinOrg(owner.accessToken, invite.token);
  assert.equal(res.status, 409);
});

test('only owner/admin can list or delete invites', async () => {
  const owner  = await registerUser({ username: 'invlistowner1', email: 'invlistowner1@example.com' });
  const member = await registerUser({ username: 'invlistmember1', email: 'invlistmember1@example.com' });
  const org = await createOrg(owner.accessToken, 'Invite List Co');
  const invite = await createInvite(owner.accessToken, org.id);
  await joinOrg(member.accessToken, (await createInvite(owner.accessToken, org.id)).token);

  const listAsMember = await request(app)
    .get(`/api/organizations/${org.id}/invites`)
    .set('Authorization', `Bearer ${member.accessToken}`);
  assert.equal(listAsMember.status, 403);

  const deleteAsMember = await request(app)
    .delete(`/api/organizations/${org.id}/invites/${invite.id}`)
    .set('Authorization', `Bearer ${member.accessToken}`);
  assert.equal(deleteAsMember.status, 403);

  const listAsOwner = await request(app)
    .get(`/api/organizations/${org.id}/invites`)
    .set('Authorization', `Bearer ${owner.accessToken}`);
  assert.equal(listAsOwner.status, 200);
  assert.ok(listAsOwner.body.some(i => i.id === invite.id));
});

// ── isolation (the important ones) ───────────────────────────────────

test('a stranger cannot read an org they are not a member of, even knowing its id', async () => {
  const ownerA = await registerUser({ username: 'isoOwnerA1', email: 'isoOwnerA1@example.com' });
  const stranger = await registerUser({ username: 'isoStranger1', email: 'isoStranger1@example.com' });
  const orgA = await createOrg(ownerA.accessToken, 'Org A');

  const res = await request(app)
    .get(`/api/organizations/${orgA.id}`)
    .set('Authorization', `Bearer ${stranger.accessToken}`);
  assert.equal(res.status, 404);
});

test('a stranger cannot list an org\'s members they do not belong to', async () => {
  const ownerA = await registerUser({ username: 'isoOwnerA2', email: 'isoOwnerA2@example.com' });
  const stranger = await registerUser({ username: 'isoStranger2', email: 'isoStranger2@example.com' });
  const orgA = await createOrg(ownerA.accessToken, 'Org A2');

  const res = await request(app)
    .get(`/api/organizations/${orgA.id}/members`)
    .set('Authorization', `Bearer ${stranger.accessToken}`);
  assert.equal(res.status, 404);
});

test('a non-member org\'s data (rollup counts) never appears in a stranger\'s org list', async () => {
  const ownerA = await registerUser({ username: 'isoOwnerA3', email: 'isoOwnerA3@example.com' });
  const stranger = await registerUser({ username: 'isoStranger3', email: 'isoStranger3@example.com' });
  const orgA = await createOrg(ownerA.accessToken, 'Org A3');

  const res = await request(app)
    .get('/api/organizations')
    .set('Authorization', `Bearer ${stranger.accessToken}`);
  assert.equal(res.status, 200);
  assert.ok(!res.body.some(o => o.id === orgA.id), 'stranger must not see org A in their own org list');
});

test('a member of org B cannot invite members into org A', async () => {
  const ownerA = await registerUser({ username: 'isoOwnerA4', email: 'isoOwnerA4@example.com' });
  const ownerB = await registerUser({ username: 'isoOwnerB4', email: 'isoOwnerB4@example.com' });
  const orgA = await createOrg(ownerA.accessToken, 'Org A4');
  const orgB = await createOrg(ownerB.accessToken, 'Org B4');
  void orgB;

  const res = await request(app)
    .post(`/api/organizations/${orgA.id}/invites`)
    .set('Authorization', `Bearer ${ownerB.accessToken}`)
    .send({ role: 'member' });
  assert.equal(res.status, 404);
});

test('an owner of org B cannot rename org A or touch its SSO config', async () => {
  const ownerA = await registerUser({ username: 'isoOwnerA5', email: 'isoOwnerA5@example.com' });
  const ownerB = await registerUser({ username: 'isoOwnerB5', email: 'isoOwnerB5@example.com' });
  const orgA = await createOrg(ownerA.accessToken, 'Org A5');
  await createOrg(ownerB.accessToken, 'Org B5');

  const renameRes = await request(app)
    .patch(`/api/organizations/${orgA.id}`)
    .set('Authorization', `Bearer ${ownerB.accessToken}`)
    .send({ name: 'Pwned' });
  assert.equal(renameRes.status, 404);

  const ssoRes = await request(app)
    .get(`/api/organizations/${orgA.id}/sso`)
    .set('Authorization', `Bearer ${ownerB.accessToken}`);
  assert.equal(ssoRes.status, 404);

  const ssoWriteRes = await request(app)
    .put(`/api/organizations/${orgA.id}/sso`)
    .set('Authorization', `Bearer ${ownerB.accessToken}`)
    .send({ issuer_url: 'https://evil.example.com', client_id: 'x', client_secret: 'y', email_domain: 'evil.example.com' });
  assert.equal(ssoWriteRes.status, 404);
});

test('a member of org A cannot delete an invite belonging to org B by guessing ids', async () => {
  const ownerA = await registerUser({ username: 'isoOwnerA6', email: 'isoOwnerA6@example.com' });
  const ownerB = await registerUser({ username: 'isoOwnerB6', email: 'isoOwnerB6@example.com' });
  const orgA = await createOrg(ownerA.accessToken, 'Org A6');
  const orgB = await createOrg(ownerB.accessToken, 'Org B6');
  const inviteB = await createInvite(ownerB.accessToken, orgB.id);

  // ownerA tries to delete org B's invite by pairing its id with org A's orgId.
  // The route scopes the DELETE by `id=$1 AND organization_id=$2`, so this is
  // a no-op (matches the same idempotent-delete convention as
  // projects.js's DELETE /:projectId/invites/:inviteId) — it still answers
  // 200 {ok:true} even though nothing matched, but the row itself is proven
  // untouched below, which is the actual isolation guarantee we care about.
  const res = await request(app)
    .delete(`/api/organizations/${orgA.id}/invites/${inviteB.id}`)
    .set('Authorization', `Bearer ${ownerA.accessToken}`);
  assert.equal(res.status, 200);

  const stillThere = await db.query('SELECT * FROM organization_invites WHERE id=$1', [inviteB.id]);
  assert.equal(stillThere.rows.length, 1);
});

test('GET on a nonexistent org id returns 404, not 500', async () => {
  const user = await registerUser({ username: 'nonexistorg1', email: 'nonexistorg1@example.com' });
  const res = await request(app)
    .get('/api/organizations/00000000-0000-0000-0000-000000000000')
    .set('Authorization', `Bearer ${user.accessToken}`);
  assert.equal(res.status, 404);
});

// ── deletion ──────────────────────────────────────────────────────────

test('owner can delete their org; a non-owner member cannot', async () => {
  const owner  = await registerUser({ username: 'delowner1', email: 'delowner1@example.com' });
  const member = await registerUser({ username: 'delmember1', email: 'delmember1@example.com' });
  const org = await createOrg(owner.accessToken, 'Delete Co');
  await joinOrg(member.accessToken, (await createInvite(owner.accessToken, org.id)).token);

  const memberDelete = await request(app)
    .delete(`/api/organizations/${org.id}`)
    .set('Authorization', `Bearer ${member.accessToken}`);
  assert.equal(memberDelete.status, 403);

  const ownerDelete = await request(app)
    .delete(`/api/organizations/${org.id}`)
    .set('Authorization', `Bearer ${owner.accessToken}`);
  assert.equal(ownerDelete.status, 200);

  const check = await db.query('SELECT * FROM organizations WHERE id=$1', [org.id]);
  assert.equal(check.rows.length, 0);
});

// ── moving a project between orgs ────────────────────────────────────

async function addOrgMember(ownerToken, orgId, role) {
  const user = await registerUser();
  const invite = await createInvite(ownerToken, orgId, { role });
  const joined = await joinOrg(user.accessToken, invite.token);
  assert.equal(joined.status, 200);
  return user;
}

const moveProject = (token, projectId, organization_id) => request(app)
  .post(`/api/projects/${projectId}/move`)
  .set('Authorization', `Bearer ${token}`)
  .send({ organization_id });

test('project owner who is admin of the destination org can move the project there', async () => {
  const destOwner = await registerUser();
  const dest = await createOrg(destOwner.accessToken, 'Dest Co');
  const mover = await addOrgMember(destOwner.accessToken, dest.id, 'admin');
  const project = await createProject(mover.accessToken);

  // Before the move the destination org owner has no access at all.
  const before = await request(app).get(`/api/projects/${project.id}`)
    .set('Authorization', `Bearer ${destOwner.accessToken}`);
  assert.equal(before.status, 404);

  const res = await moveProject(mover.accessToken, project.id, dest.id);
  assert.equal(res.status, 200);
  assert.equal(res.body.organization_name, 'Dest Co');

  // The mover keeps their direct ownership; the dest org owner gains implicit access.
  const mine = await request(app).get(`/api/projects/${project.id}`)
    .set('Authorization', `Bearer ${mover.accessToken}`);
  assert.equal(mine.status, 200);
  assert.equal(mine.body.member_role, 'owner');
  assert.equal(mine.body.organization_id, dest.id);
  const after = await request(app).get(`/api/projects/${project.id}`)
    .set('Authorization', `Bearer ${destOwner.accessToken}`);
  assert.equal(after.status, 200);

  const { rows } = await db.query(
    `SELECT meta FROM activity_log WHERE project_id=$1 AND action='project_moved'`, [project.id]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].meta.to, 'Dest Co');
});

test('cannot move a project into an org where the caller is only a member, or not a member', async () => {
  const destOwner = await registerUser();
  const dest = await createOrg(destOwner.accessToken, 'Dest Co');
  const mover = await addOrgMember(destOwner.accessToken, dest.id, 'member');
  const stranger = await registerUser();
  const foreign = await createOrg(stranger.accessToken, 'Foreign Co');
  const project = await createProject(mover.accessToken);

  assert.equal((await moveProject(mover.accessToken, project.id, dest.id)).status, 403);
  assert.equal((await moveProject(mover.accessToken, project.id, foreign.id)).status, 403);
  const { rows } = await db.query('SELECT organization_id FROM projects WHERE id=$1', [project.id]);
  assert.equal(rows[0].organization_id, project.organization_id);
});

test('a project editor cannot move the project even when they own the destination org', async () => {
  const owner = await registerUser();
  const project = await createProject(owner.accessToken);
  const editor = await registerUser();
  const inv = await request(app).post(`/api/projects/${project.id}/invites`)
    .set('Authorization', `Bearer ${owner.accessToken}`).send({ role: 'editor' });
  assert.equal(inv.status, 201);
  const join = await request(app).post('/api/projects/join')
    .set('Authorization', `Bearer ${editor.accessToken}`).send({ token: inv.body.token });
  assert.equal(join.status, 200);
  const editorsOrg = await createOrg(editor.accessToken, 'Editor Co');

  assert.equal((await moveProject(editor.accessToken, project.id, editorsOrg.id)).status, 403);
});

test('moving a project to the org it already belongs to is rejected', async () => {
  const owner = await registerUser();
  const project = await createProject(owner.accessToken);
  const res = await moveProject(owner.accessToken, project.id, project.organization_id);
  assert.equal(res.status, 400);
});
