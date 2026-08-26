// The export page used to keep the whole report builder state in the
// browser's localStorage — risk-matrix probabilities, the executive
// impact/roadmap texts, the rewritten finding bodies and the saved
// templates. These cover the server-side storage that replaced it.
const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { app, db, resetDb, registerUser, createProject } = require('./helpers');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

const SAMPLE = {
  meta: { preparedBy: 'Diego', accentColor: '#7c3aed', coverFields: { date: true } },
  sections: [{ id: 'risk-matrix', visible: true }],
  vulnEdits: {
    'ffffffff-ffff-4fff-8fff-ffffffffffff': {
      probability: 5,
      remediationPriority: 'immediate',
      businessImpact: 'Full customer database exposure.',
      execAction: 'Rotate credentials and patch within 48h.',
      description: '<p>rewritten</p>',
      remediation: '<p>patched</p>',
    },
  },
  freeEditMd: '# manual edit',
};

// ── report config ────────────────────────────────────────────────────

test('report config starts empty and survives a round trip intact', async () => {
  const owner = await registerUser();
  const project = await createProject(owner.accessToken);
  const auth = { Authorization: `Bearer ${owner.accessToken}` };

  const empty = await request(app).get(`/api/projects/${project.id}/report-config`).set(auth);
  assert.equal(empty.status, 200);
  assert.equal(empty.body.data, null);

  const put = await request(app)
    .put(`/api/projects/${project.id}/report-config`).set(auth).send({ data: SAMPLE });
  assert.equal(put.status, 200);

  const got = await request(app).get(`/api/projects/${project.id}/report-config`).set(auth);
  assert.equal(got.status, 200);
  assert.deepEqual(got.body.data, SAMPLE);
});

test('saving report config twice overwrites instead of erroring on the project key', async () => {
  const owner = await registerUser();
  const project = await createProject(owner.accessToken);
  const auth = { Authorization: `Bearer ${owner.accessToken}` };

  await request(app).put(`/api/projects/${project.id}/report-config`).set(auth).send({ data: SAMPLE });
  const second = await request(app)
    .put(`/api/projects/${project.id}/report-config`).set(auth)
    .send({ data: { ...SAMPLE, meta: { preparedBy: 'Someone else' } } });
  assert.equal(second.status, 200);
  assert.equal(second.body.data.meta.preparedBy, 'Someone else');
});

test('report config rejects a non-object payload', async () => {
  const owner = await registerUser();
  const project = await createProject(owner.accessToken);
  const auth = { Authorization: `Bearer ${owner.accessToken}` };

  for (const data of ['nope', 42, null, ['a']]) {
    const res = await request(app)
      .put(`/api/projects/${project.id}/report-config`).set(auth).send({ data });
    assert.equal(res.status, 400, `expected 400 for ${JSON.stringify(data)}`);
  }
});

test('a non-member cannot read or write another project\'s report config', async () => {
  const owner = await registerUser();
  const stranger = await registerUser();
  const project = await createProject(owner.accessToken);
  const intruder = { Authorization: `Bearer ${stranger.accessToken}` };

  const read = await request(app).get(`/api/projects/${project.id}/report-config`).set(intruder);
  assert.equal(read.status, 404);

  const write = await request(app)
    .put(`/api/projects/${project.id}/report-config`).set(intruder).send({ data: SAMPLE });
  assert.equal(write.status, 404);
});

test('deleting the user who last saved the report keeps the report config', async () => {
  const owner = await registerUser();
  const editor = await registerUser();
  const project = await createProject(owner.accessToken);

  await db.query(
    `INSERT INTO project_members (project_id, user_id, role) VALUES ($1,$2,'editor')`,
    [project.id, editor.user.id]
  );
  await request(app)
    .put(`/api/projects/${project.id}/report-config`)
    .set({ Authorization: `Bearer ${editor.accessToken}` })
    .send({ data: SAMPLE });

  await db.query(`DELETE FROM users WHERE id=$1`, [editor.user.id]);

  const got = await request(app)
    .get(`/api/projects/${project.id}/report-config`)
    .set({ Authorization: `Bearer ${owner.accessToken}` });
  assert.equal(got.status, 200);
  assert.deepEqual(got.body.data, SAMPLE);
  assert.equal(got.body.updated_by, null);
});

// ── report templates ─────────────────────────────────────────────────

test('a saved report template comes back on the next session', async () => {
  const user = await registerUser();
  const auth = { Authorization: `Bearer ${user.accessToken}` };
  const payload = { meta: SAMPLE.meta, sections: SAMPLE.sections };

  const created = await request(app)
    .post('/api/report-templates').set(auth).send({ name: 'Pentest ES', data: payload });
  assert.equal(created.status, 201);

  const list = await request(app).get('/api/report-templates').set(auth);
  assert.equal(list.status, 200);
  assert.equal(list.body.length, 1);
  assert.equal(list.body[0].name, 'Pentest ES');
  assert.deepEqual(list.body[0].data, payload);
});

test('report templates are private to their owner', async () => {
  const mine = await registerUser();
  const theirs = await registerUser();
  const payload = { meta: {}, sections: [] };

  const created = await request(app)
    .post('/api/report-templates')
    .set({ Authorization: `Bearer ${mine.accessToken}` })
    .send({ name: 'Mine', data: payload });
  assert.equal(created.status, 201);

  const list = await request(app)
    .get('/api/report-templates')
    .set({ Authorization: `Bearer ${theirs.accessToken}` });
  assert.deepEqual(list.body, []);

  const del = await request(app)
    .delete(`/api/report-templates/${created.body.id}`)
    .set({ Authorization: `Bearer ${theirs.accessToken}` });
  assert.equal(del.status, 404);
});

test('report template payload must carry meta and sections', async () => {
  const user = await registerUser();
  const auth = { Authorization: `Bearer ${user.accessToken}` };

  const noName = await request(app)
    .post('/api/report-templates').set(auth).send({ name: '  ', data: { meta: {}, sections: [] } });
  assert.equal(noName.status, 400);

  const noSections = await request(app)
    .post('/api/report-templates').set(auth).send({ name: 'x', data: { meta: {} } });
  assert.equal(noSections.status, 400);
});

test('a malformed template id is a 404, not a 500', async () => {
  const user = await registerUser();
  const res = await request(app)
    .delete('/api/report-templates/not-a-uuid')
    .set({ Authorization: `Bearer ${user.accessToken}` });
  assert.equal(res.status, 404);
});

test('a template can be updated and deleted by its owner', async () => {
  const user = await registerUser();
  const auth = { Authorization: `Bearer ${user.accessToken}` };

  const created = await request(app)
    .post('/api/report-templates').set(auth).send({ name: 'v1', data: { meta: {}, sections: [] } });

  const updated = await request(app)
    .put(`/api/report-templates/${created.body.id}`).set(auth)
    .send({ name: 'v2', data: { meta: { font: 'georgia' }, sections: [{ id: 'cover' }] } });
  assert.equal(updated.status, 200);
  assert.equal(updated.body.name, 'v2');
  assert.equal(updated.body.data.meta.font, 'georgia');

  const del = await request(app).delete(`/api/report-templates/${created.body.id}`).set(auth);
  assert.equal(del.status, 200);

  const list = await request(app).get('/api/report-templates').set(auth);
  assert.deepEqual(list.body, []);
});

test('report templates require authentication', async () => {
  const res = await request(app).get('/api/report-templates');
  assert.equal(res.status, 401);
});
