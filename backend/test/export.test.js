const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { app, db, resetDb, registerUser, createProject } = require('./helpers');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

test('POST /export/pdf requires authentication', async () => {
  const res = await request(app).post('/api/export/pdf').send({ pageUrl: 'http://localhost/export.html' });
  assert.equal(res.status, 401);
});

test('POST /export/pdf rejects a request with no pageUrl', async () => {
  const user = await registerUser({ username: 'exportpdf1', email: 'exportpdf1@example.com' });
  const res = await request(app)
    .post('/api/export/pdf')
    .set('Authorization', `Bearer ${user.accessToken}`)
    .send({});
  assert.equal(res.status, 400);
});

test('POST /export/docx requires authentication', async () => {
  const res = await request(app).post('/api/export/docx').send({ projectId: 'x' });
  assert.equal(res.status, 401);
});

test('POST /export/docx rejects a request with no projectId', async () => {
  const user = await registerUser({ username: 'exportdocx1', email: 'exportdocx1@example.com' });
  const res = await request(app)
    .post('/api/export/docx')
    .set('Authorization', `Bearer ${user.accessToken}`)
    .send({});
  assert.equal(res.status, 400);
});

test('POST /export/docx returns 404 for a project the caller is not a member of', async () => {
  const owner = await registerUser({ username: 'docxowner', email: 'docxowner@example.com' });
  const stranger = await registerUser({ username: 'docxstranger', email: 'docxstranger@example.com' });
  const project = await createProject(owner.accessToken, { name: 'DOCX isolation test' });

  const res = await request(app)
    .post('/api/export/docx')
    .set('Authorization', `Bearer ${stranger.accessToken}`)
    .send({ projectId: project.id });
  assert.equal(res.status, 404);
});

test('POST /export/docx generates a valid DOCX file for an empty project', async () => {
  const owner = await registerUser({ username: 'docxgen', email: 'docxgen@example.com' });
  const project = await createProject(owner.accessToken, { name: 'DOCX generation test' });

  const res = await request(app)
    .post('/api/export/docx')
    .set('Authorization', `Bearer ${owner.accessToken}`)
    .send({ projectId: project.id, rptData: JSON.stringify({ meta: {}, sections: [] }) });

  assert.equal(res.status, 200);
  assert.equal(
    res.headers['content-type'],
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  );
  // supertest has no binary parser registered for the docx mimetype, so it falls
  // back to reading the response as latin1 text — decoding that back to a buffer
  // reconstructs the original bytes losslessly.
  const buf = Buffer.from(res.text, 'binary');
  assert.ok(buf.length > 0);
  // DOCX files are zip archives — the first two bytes are the "PK" zip signature.
  assert.equal(buf[0], 0x50); // 'P'
  assert.equal(buf[1], 0x4b); // 'K'
});
