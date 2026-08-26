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

// ── SSRF guard on the PDF renderer ───────────────────────────────────────
// pageUrl arrives from the browser, so it is attacker-controlled. Puppeteer
// returns the rendered page to the caller as a PDF, which would make an
// unvalidated goto() a full-read SSRF. Every case below must be rejected
// before the browser is ever launched.

// Each test sets the trusted origin explicitly so a rejection proves the guard
// fired, rather than just proving the environment had no origin configured.
function withTrustedOrigin(origin, fn) {
  const prevInternal = process.env.INTERNAL_APP_URL;
  const prevFrontend = process.env.FRONTEND_URL;
  delete process.env.INTERNAL_APP_URL;
  if (origin === undefined) delete process.env.FRONTEND_URL;
  else process.env.FRONTEND_URL = origin;
  return (async () => {
    try { return await fn(); }
    finally {
      if (prevInternal === undefined) delete process.env.INTERNAL_APP_URL;
      else process.env.INTERNAL_APP_URL = prevInternal;
      if (prevFrontend === undefined) delete process.env.FRONTEND_URL;
      else process.env.FRONTEND_URL = prevFrontend;
    }
  })();
}

async function postPdf(accessToken, pageUrl) {
  return request(app)
    .post('/api/export/pdf')
    .set('Authorization', `Bearer ${accessToken}`)
    .send({ pageUrl });
}

test('the PDF renderer discards the caller origin and rebuilds against the configured one', async () => {
  const { resolveInternalPageUrl } = require('../src/routes/export');
  await withTrustedOrigin('http://localhost', async () => {
    // A valid export path on a hostile host is rewritten, not rejected — the
    // point is that the hostile host never survives into the URL Puppeteer opens.
    const out = resolveInternalPageUrl('http://evil.example.com/export?pid=abc#frag');
    assert.equal(new URL(out).host, 'localhost');
    assert.equal(new URL(out).pathname, '/export');
    assert.equal(new URL(out).search, '?pid=abc');
    assert.equal(new URL(out).hash, '');
    assert.ok(!out.includes('evil.example.com'));
  });
});

test('the PDF renderer prefers INTERNAL_APP_URL over FRONTEND_URL', async () => {
  const { resolveInternalPageUrl } = require('../src/routes/export');
  const prevInternal = process.env.INTERNAL_APP_URL;
  const prevFrontend = process.env.FRONTEND_URL;
  process.env.INTERNAL_APP_URL = 'http://nginx';
  process.env.FRONTEND_URL     = 'http://localhost';
  try {
    // Docker puts Puppeteer inside the backend container, where only the
    // internal hostname reaches the frontend — it has to win.
    assert.equal(new URL(resolveInternalPageUrl('http://localhost/export')).host, 'nginx');
  } finally {
    if (prevInternal === undefined) delete process.env.INTERNAL_APP_URL;
    else process.env.INTERNAL_APP_URL = prevInternal;
    if (prevFrontend === undefined) delete process.env.FRONTEND_URL;
    else process.env.FRONTEND_URL = prevFrontend;
  }
});

test('POST /export/pdf refuses to render cloud metadata endpoints', async () => {
  const user = await registerUser({ username: 'ssrf2', email: 'ssrf2@example.com' });
  await withTrustedOrigin('http://localhost', async () => {
    const res = await postPdf(user.accessToken, 'http://169.254.169.254/latest/meta-data/');
    assert.equal(res.status, 400);
    assert.match(res.body.error, /only the export page/i);
  });
});

test('POST /export/pdf refuses to render an internal page that is not the export page', async () => {
  const user = await registerUser({ username: 'ssrf3', email: 'ssrf3@example.com' });
  await withTrustedOrigin('http://localhost', async () => {
    const res = await postPdf(user.accessToken, 'http://localhost/settings.html');
    assert.equal(res.status, 400);
    assert.match(res.body.error, /only the export page/i);
  });
});

test('POST /export/pdf refuses a path that tries to traverse out of the export page', async () => {
  const user = await registerUser({ username: 'ssrf4', email: 'ssrf4@example.com' });
  await withTrustedOrigin('http://localhost', async () => {
    // new URL() normalises "..", so this resolves to /admin, not /export/../admin.
    const res = await postPdf(user.accessToken, 'http://localhost/export/../admin');
    assert.equal(res.status, 400);
    assert.match(res.body.error, /only the export page/i);
  });
});

test('POST /export/pdf rejects a malformed pageUrl', async () => {
  const user = await registerUser({ username: 'ssrf5', email: 'ssrf5@example.com' });
  await withTrustedOrigin('http://localhost', async () => {
    const res = await postPdf(user.accessToken, 'not-a-url');
    assert.equal(res.status, 400);
    assert.match(res.body.error, /valid URL/i);
  });
});

test('POST /export/pdf fails closed when no trusted origin is configured', async () => {
  const user = await registerUser({ username: 'ssrf6', email: 'ssrf6@example.com' });
  await withTrustedOrigin(undefined, async () => {
    const res = await postPdf(user.accessToken, 'http://localhost/export');
    assert.equal(res.status, 400);
    assert.match(res.body.error, /INTERNAL_APP_URL|FRONTEND_URL/);
  });
});
