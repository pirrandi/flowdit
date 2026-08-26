// PCI-DSS compliance tagging: catalog endpoint + custom_vulns.compliance_tags CRUD.
const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { app, db, resetDb, registerUser, createProject } = require('./helpers');
const { PCI_DSS_CONTROLS } = require('../src/db/compliance-frameworks');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

test('GET /api/compliance/frameworks/pci-dss returns the PCI-DSS catalog', async () => {
  const user = await registerUser({ username: 'complianceuser1', email: 'complianceuser1@example.com' });

  const res = await request(app)
    .get('/api/compliance/frameworks/pci-dss')
    .set('Authorization', `Bearer ${user.accessToken}`);

  assert.equal(res.status, 200);
  assert.equal(res.body.length, PCI_DSS_CONTROLS.length);
  assert.ok(res.body.some(c => c.control_id === '6.5.1' && c.title === 'Injection flaws (SQL, OS command, LDAP, XPath, etc.)'));
});

test('GET /api/compliance/frameworks/pci-dss requires authentication', async () => {
  const res = await request(app).get('/api/compliance/frameworks/pci-dss');
  assert.equal(res.status, 401);
});

test('a finding can be created with compliance_tags and reads back correctly', async () => {
  const user = await registerUser({ username: 'complianceuser2', email: 'complianceuser2@example.com' });
  const project = await createProject(user.accessToken);

  const tags = [
    { control_id: '6.5.1', title: 'Injection flaws (SQL, OS command, LDAP, XPath, etc.)' },
    { control_id: '6.5.10', title: 'Broken authentication and session management' },
  ];

  const res = await request(app)
    .post(`/api/projects/${project.id}/vulns`)
    .set('Authorization', `Bearer ${user.accessToken}`)
    .send({ name: 'SQL Injection in login form', severity: 'critical', compliance_tags: tags });

  assert.equal(res.status, 201);
  assert.deepEqual(res.body.compliance_tags, tags);

  const listRes = await request(app)
    .get(`/api/projects/${project.id}/vulns`)
    .set('Authorization', `Bearer ${user.accessToken}`);
  assert.equal(listRes.status, 200);
  const found = listRes.body.find(v => v.id === res.body.id);
  assert.deepEqual(found.compliance_tags, tags);
});

test('a finding created without compliance_tags defaults to an empty array', async () => {
  const user = await registerUser({ username: 'complianceuser3', email: 'complianceuser3@example.com' });
  const project = await createProject(user.accessToken);

  const res = await request(app)
    .post(`/api/projects/${project.id}/vulns`)
    .set('Authorization', `Bearer ${user.accessToken}`)
    .send({ name: 'Finding with no tags', severity: 'low' });

  assert.equal(res.status, 201);
  assert.deepEqual(res.body.compliance_tags, []);
});

test('a finding\'s compliance_tags can be updated via PATCH', async () => {
  const user = await registerUser({ username: 'complianceuser4', email: 'complianceuser4@example.com' });
  const project = await createProject(user.accessToken);

  const created = await request(app)
    .post(`/api/projects/${project.id}/vulns`)
    .set('Authorization', `Bearer ${user.accessToken}`)
    .send({ name: 'Missing security headers', severity: 'low' });
  assert.equal(created.status, 201);

  const newTags = [{ control_id: '2', title: 'Apply secure configurations to all system components' }];
  const patched = await request(app)
    .patch(`/api/projects/${project.id}/vulns/${created.body.id}`)
    .set('Authorization', `Bearer ${user.accessToken}`)
    .send({ compliance_tags: newTags });

  assert.equal(patched.status, 200);
  assert.deepEqual(patched.body.compliance_tags, newTags);
});
