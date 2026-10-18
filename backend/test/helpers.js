process.env.NODE_ENV = process.env.NODE_ENV || 'test';

if (!process.env.DB_NAME || !process.env.DB_NAME.includes('test')) {
  throw new Error(
    'Refusing to run tests: DB_NAME must point at a database whose name contains ' +
    '"test" (e.g. flowdit_test), to avoid truncating real data. ' +
    'See CONTRIBUTING.md for local test DB setup.'
  );
}
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test_only_jwt_secret_do_not_use_in_prod';
// Portal links store an encrypted copy of their token (utils/crypto.js).
process.env.SSO_ENCRYPTION_KEY = process.env.SSO_ENCRYPTION_KEY || 'test_only_sso_key_do_not_use_in_prod';
// Public registration is disabled by default in prod (pentest platform: accounts
// are provisioned by an operator). Tests still exercise the register/SSO paths
// and provision their fixtures through the endpoint, so enable it here.
process.env.ALLOW_PUBLIC_REGISTRATION = 'true';

const app = require('../src/app');
const db  = require('../src/db');
const { seedTemplates } = require('../src/db/vuln-templates');

const TABLES = [
  'mcp_uploads', 'mcp_proposals', 'api_tokens',
  'organization_sso_configs', 'organization_invites', 'organization_members',
  'ai_usage', 'whiteboard_images', 'whiteboard_state', 'report_config', 'report_templates',
  'ticket_replies', 'tickets', 'portal_links',
  'target_endpoints', 'target_ports', 'activity_log', 'project_methodologies',
  'methodology_progress', 'methodologies', 'custom_vulns', 'ps_progress',
  'wstg_item_checks', 'wstg_progress', 'project_invites', 'project_members',
  'targets', 'projects', 'refresh_tokens', 'organizations', 'users',
];

// vuln_templates is meant to be permanent seed data (50 built-in templates),
// but vuln_templates.created_by REFERENCES users(id) — TRUNCATE CASCADE
// truncates the *entire* dependent table regardless of which rows would
// actually be orphaned, so truncating `users` above wipes it too even though
// every built-in row has created_by=NULL. Reseed it every time to compensate.
async function resetDb() {
  await db.query(`TRUNCATE ${TABLES.join(', ')} RESTART IDENTITY CASCADE`);
  await seedTemplates(db);
}

let userCounter = 0;
async function registerUser(overrides = {}) {
  userCounter += 1;
  const body = {
    username: `testuser${userCounter}${Math.random().toString(36).slice(2, 6)}`,
    email: `testuser${userCounter}${Math.random().toString(36).slice(2, 6)}@example.com`,
    password: 'correct-horse-battery-staple',
    ...overrides,
  };
  const supertest = require('supertest');
  const res = await supertest(app).post('/api/auth/register').send(body);
  if (res.status !== 201) throw new Error('registerUser failed: ' + JSON.stringify(res.body));
  return { ...res.body, credentials: body };
}

async function createProject(accessToken, overrides = {}) {
  const supertest = require('supertest');
  const orgsRes = await supertest(app)
    .get('/api/organizations')
    .set('Authorization', `Bearer ${accessToken}`);
  const orgId = orgsRes.body[0].id;

  const res = await supertest(app)
    .post('/api/projects')
    .set('Authorization', `Bearer ${accessToken}`)
    .send({ name: 'Test Project', organization_id: orgId, ...overrides });
  if (res.status !== 201) throw new Error('createProject failed: ' + JSON.stringify(res.body));
  return res.body;
}

module.exports = { app, db, resetDb, registerUser, createProject };
