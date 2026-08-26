const { test, before, beforeEach, after, mock } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { app, db, resetDb, registerUser, createProject } = require('./helpers');
const github = require('../src/services/github');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

async function setup() {
  const user = await registerUser({ username: 'ghuser', email: 'ghuser@example.com' });
  const project = await createProject(user.accessToken);
  await request(app)
    .patch(`/api/projects/${project.id}`)
    .set('Authorization', `Bearer ${user.accessToken}`)
    .send({ tickets_enabled: true });
  const ticket = await request(app)
    .post(`/api/projects/${project.id}/tickets`)
    .set('Authorization', `Bearer ${user.accessToken}`)
    .send({ title: 'SQLi needs a fix', description: 'Confirmed on /search' });
  return { access: user.accessToken, pid: project.id, tid: ticket.body.id };
}

test('sending to GitHub fails with a clear error when the project has no repo/token configured', async () => {
  const { access, pid, tid } = await setup();
  const res = await request(app)
    .post(`/api/projects/${pid}/tickets/${tid}/github`)
    .set('Authorization', `Bearer ${access}`);
  assert.equal(res.status, 400);
  assert.match(res.body.error, /not configured/i);
});

test('configuring a repo and PAT never echoes the token back, only a boolean flag', async () => {
  const { access, pid } = await setup();
  const updated = await request(app)
    .patch(`/api/projects/${pid}`)
    .set('Authorization', `Bearer ${access}`)
    .send({ github_repo: 'acme/webapp', github_pat: 'ghp_supersecret' });
  assert.equal(updated.status, 200);
  assert.equal(updated.body.github_repo, 'acme/webapp');
  assert.equal(updated.body.has_github_pat, true);
  assert.equal(updated.body.github_pat_enc, undefined);
  assert.equal(JSON.stringify(updated.body).includes('supersecret'), false);
});

test('sending a configured ticket to GitHub creates an issue and stores the link', async () => {
  const { access, pid, tid } = await setup();
  await request(app)
    .patch(`/api/projects/${pid}`)
    .set('Authorization', `Bearer ${access}`)
    .send({ github_repo: 'acme/webapp', github_pat: 'ghp_supersecret' });

  const createIssue = mock.method(github, 'createIssue', async (repo, pat) => {
    assert.equal(repo, 'acme/webapp');
    assert.equal(pat, 'ghp_supersecret');
    return { id: '42', url: 'https://github.com/acme/webapp/issues/42' };
  });

  try {
    const res = await request(app)
      .post(`/api/projects/${pid}/tickets/${tid}/github`)
      .set('Authorization', `Bearer ${access}`);
    assert.equal(res.status, 201);
    assert.equal(res.body.external_url, 'https://github.com/acme/webapp/issues/42');
    assert.equal(createIssue.mock.callCount(), 1);

    const ticket = await request(app)
      .get(`/api/projects/${pid}/tickets/${tid}`)
      .set('Authorization', `Bearer ${access}`);
    assert.equal(ticket.body.github_url, 'https://github.com/acme/webapp/issues/42');
  } finally {
    createIssue.mock.restore();
  }
});

test('sending an already-linked ticket to GitHub again is rejected with the existing link', async () => {
  const { access, pid, tid } = await setup();
  await request(app)
    .patch(`/api/projects/${pid}`)
    .set('Authorization', `Bearer ${access}`)
    .send({ github_repo: 'acme/webapp', github_pat: 'ghp_supersecret' });

  const createIssue = mock.method(github, 'createIssue', async () => (
    { id: '7', url: 'https://github.com/acme/webapp/issues/7' }
  ));
  try {
    const first = await request(app)
      .post(`/api/projects/${pid}/tickets/${tid}/github`)
      .set('Authorization', `Bearer ${access}`);
    assert.equal(first.status, 201);

    const second = await request(app)
      .post(`/api/projects/${pid}/tickets/${tid}/github`)
      .set('Authorization', `Bearer ${access}`);
    assert.equal(second.status, 409);
    assert.equal(second.body.external_url, 'https://github.com/acme/webapp/issues/7');
    assert.equal(createIssue.mock.callCount(), 1); // second attempt never calls the API
  } finally {
    createIssue.mock.restore();
  }
});

test('a GitHub API failure surfaces as a clean 502, not a 500', async () => {
  const { access, pid, tid } = await setup();
  await request(app)
    .patch(`/api/projects/${pid}`)
    .set('Authorization', `Bearer ${access}`)
    .send({ github_repo: 'acme/webapp', github_pat: 'ghp_bad' });

  const createIssue = mock.method(github, 'createIssue', async () => {
    throw new Error('GitHub token is invalid or expired');
  });
  try {
    const res = await request(app)
      .post(`/api/projects/${pid}/tickets/${tid}/github`)
      .set('Authorization', `Bearer ${access}`);
    assert.equal(res.status, 502);
    assert.match(res.body.error, /invalid or expired/);
  } finally {
    createIssue.mock.restore();
  }
});

test('a viewer cannot send a ticket to GitHub (matches the editor bar for other ticket mutations)', async () => {
  const owner = await registerUser({ username: 'ghowner', email: 'ghowner@example.com' });
  const project = await createProject(owner.accessToken);
  await request(app)
    .patch(`/api/projects/${project.id}`)
    .set('Authorization', `Bearer ${owner.accessToken}`)
    .send({ tickets_enabled: true });
  await request(app)
    .patch(`/api/projects/${project.id}`)
    .set('Authorization', `Bearer ${owner.accessToken}`)
    .send({ github_repo: 'acme/webapp', github_pat: 'ghp_x' });
  const ticket = await request(app)
    .post(`/api/projects/${project.id}/tickets`)
    .set('Authorization', `Bearer ${owner.accessToken}`)
    .send({ title: 'Some finding' });

  const viewer = await registerUser({ username: 'ghviewer', email: 'ghviewer@example.com' });
  const invite = await request(app)
    .post(`/api/projects/${project.id}/invites`)
    .set('Authorization', `Bearer ${owner.accessToken}`)
    .send({ role: 'viewer' });
  await request(app)
    .post(`/api/projects/join`)
    .set('Authorization', `Bearer ${viewer.accessToken}`)
    .send({ token: invite.body.token });

  const res = await request(app)
    .post(`/api/projects/${project.id}/tickets/${ticket.body.id}/github`)
    .set('Authorization', `Bearer ${viewer.accessToken}`);
  assert.equal(res.status, 403);
});
