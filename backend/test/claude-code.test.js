// Integración con Claude Code (servidor MCP en /mcp). Lo que se fija acá es la
// frontera de seguridad: los tokens fdt_ solo abren /mcp (nunca /api), un
// proyecto sin opt-in es invisible, un viewer (cuenta cliente) no accede, el scope
// de targets se respeta, y aprobar una propuesta crea el hallazgo como
// borrador (client_visible=false) una sola vez.
const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { app, db, resetDb, registerUser, createProject } = require('./helpers');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

const auth = t => ({ Authorization: `Bearer ${t}` });

async function addMember(ownerToken, projectId, role) {
  const user = await registerUser();
  const inv = await request(app).post(`/api/projects/${projectId}/invites`).set(auth(ownerToken)).send({ role });
  assert.equal(inv.status, 201);
  const join = await request(app).post('/api/projects/join').set(auth(user.accessToken)).send({ token: inv.body.token });
  assert.equal(join.status, 200);
  return user;
}

async function createToken(accessToken, body = {}) {
  const res = await request(app).post('/api/me/api-tokens').set(auth(accessToken))
    .send({ name: 'laptop', scopes: 'read_propose', ...body });
  assert.equal(res.status, 201, JSON.stringify(res.body));
  return res.body;
}

async function enableClaudeCode(ownerToken, projectId, value = true) {
  const res = await request(app).patch(`/api/projects/${projectId}`).set(auth(ownerToken)).send({ claude_code_enabled: value });
  assert.equal(res.status, 200);
  assert.equal(res.body.claude_code_enabled, value);
}

async function createTarget(token, projectId, body = {}) {
  const res = await request(app).post(`/api/projects/${projectId}/targets`).set(auth(token))
    .send({ host: 'app.example.com', type: 'domain', ...body });
  assert.equal(res.status, 201, JSON.stringify(res.body));
  return res.body;
}

let rpcId = 0;
function mcp(token, method, params = {}) {
  return request(app).post('/mcp')
    .set('Authorization', `Bearer ${token}`)
    .set('Accept', 'application/json, text/event-stream')
    .set('Content-Type', 'application/json')
    .send({ jsonrpc: '2.0', id: ++rpcId, method, params });
}

// tools/call → { isError, data } con el JSON de la tool ya parseado.
async function callTool(token, name, args = {}) {
  const res = await mcp(token, 'tools/call', { name, arguments: args });
  assert.equal(res.status, 200, `HTTP ${res.status}: ${res.text}`);
  const result = res.body.result;
  assert.ok(result, `no result: ${res.text}`);
  const text = result.content[0].text;
  return { isError: !!result.isError, text, data: result.isError ? null : JSON.parse(text) };
}

async function setup() {
  const owner = await registerUser();
  const project = await createProject(owner.accessToken);
  await enableClaudeCode(owner.accessToken, project.id);
  const target = await createTarget(owner.accessToken, project.id);
  const ownerToken = await createToken(owner.accessToken);
  return { owner, project, target, ownerToken };
}

const FINDING = {
  title: 'Reflected XSS in search', severity: 'high',
  description: 'The q parameter is reflected unescaped.', remediation: 'Encode output.',
  cwe: 'CWE-79', cvss_score: 6.1, cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
  evidence: 'curl "https://app.example.com/?q=<script>alert(1)</script>"',
};

// ── Tokens ──────────────────────────────────────────────────────────────

test('token is shown once, stored hashed, and listed without secret', async () => {
  const owner = await registerUser();
  const created = await createToken(owner.accessToken);
  assert.match(created.token, /^fdt_[A-Za-z0-9_-]{43}$/);
  assert.ok(created.token.startsWith(created.token_prefix));

  const { rows } = await db.query('SELECT token_hash FROM api_tokens WHERE id=$1', [created.id]);
  assert.equal(rows[0].token_hash.length, 64);
  assert.notEqual(rows[0].token_hash, created.token);

  const list = await request(app).get('/api/me/api-tokens').set(auth(owner.accessToken));
  assert.equal(list.status, 200);
  assert.equal(list.body.length, 1);
  assert.equal(list.body[0].token, undefined);
  assert.equal(list.body[0].token_hash, undefined);
  assert.equal(list.body[0].status, 'active');
});

test('valid token authenticates /mcp and initialize works', async () => {
  const { ownerToken } = await setup();
  const res = await mcp(ownerToken.token, 'initialize', {
    protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '0' },
  });
  assert.equal(res.status, 200, res.text);
  assert.equal(res.body.result.serverInfo.name, 'flowdit');

  const tools = await mcp(ownerToken.token, 'tools/list');
  const names = tools.body.result.tools.map(t => t.name).sort();
  assert.deepEqual(names, [
    'add_endpoints', 'add_ports', 'add_whiteboard_items', 'connect_whiteboard_items',
    'get_finding', 'get_project', 'get_report_sections', 'get_upload_instructions', 'get_whiteboard', 'list_endpoints', 'list_findings',
    'list_my_proposals', 'list_ports', 'list_projects', 'list_targets', 'move_whiteboard_items', 'propose_finding',
    'propose_finding_update', 'propose_note', 'propose_report_section', 'propose_target', 'update_proposal', 'withdraw_proposal',
  ]);
});

test('missing, unknown, revoked and expired tokens are rejected on /mcp', async () => {
  const { owner, ownerToken } = await setup();

  const none = await request(app).post('/mcp').send({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  assert.equal(none.status, 401);
  assert.equal((await mcp('fdt_doesnotexist', 'tools/list')).status, 401);

  // Un JWT válido de sesión tampoco sirve para /mcp.
  assert.equal((await mcp(owner.accessToken, 'tools/list')).status, 401);

  const rev = await request(app).post(`/api/me/api-tokens/${ownerToken.id}/revoke`).set(auth(owner.accessToken));
  assert.equal(rev.status, 200);
  assert.equal(rev.body.status, 'revoked');
  const revoked = await mcp(ownerToken.token, 'tools/list');
  assert.equal(revoked.status, 401);
  assert.match(revoked.body.error, /revoked/);

  const exp = await createToken(owner.accessToken, { expires_in_days: 1 });
  await db.query(`UPDATE api_tokens SET expires_at = NOW() - INTERVAL '1 minute' WHERE id=$1`, [exp.id]);
  const expired = await mcp(exp.token, 'tools/list');
  assert.equal(expired.status, 401);
  assert.match(expired.body.error, /expired/);
});

test('/mcp is rate limited per IP before authenticating', async () => {
  // Un token inventado no llega al límite por token (corre después de
  // autenticar); lo frena el límite por IP propio de /mcp.
  const res = await mcp('fdt_doesnotexist', 'tools/list');
  assert.equal(res.status, 401);
  assert.equal(res.headers['ratelimit-limit'], '1000');
});

test('fdt_ tokens do not authenticate REST /api routes', async () => {
  const { project, ownerToken } = await setup();
  for (const path of ['/api/projects', `/api/projects/${project.id}`, `/api/projects/${project.id}/vulns`, '/api/me/api-tokens']) {
    const res = await request(app).get(path).set(auth(ownerToken.token));
    assert.equal(res.status, 401, `${path} accepted an API token`);
  }
});

test('a user cannot revoke someone else\'s token', async () => {
  const { ownerToken } = await setup();
  const other = await registerUser();
  const res = await request(app).post(`/api/me/api-tokens/${ownerToken.id}/revoke`).set(auth(other.accessToken));
  assert.equal(res.status, 404);
  const { rows } = await db.query('SELECT revoked_at FROM api_tokens WHERE id=$1', [ownerToken.id]);
  assert.equal(rows[0].revoked_at, null);
});

// ── claude_code_enabled ─────────────────────────────────────────────────

test('projects without claude_code_enabled are invisible to MCP', async () => {
  const { owner, project, ownerToken } = await setup();
  const hidden = await createProject(owner.accessToken, { name: 'NDA project' });

  const list = await callTool(ownerToken.token, 'list_projects');
  assert.deepEqual(list.data.projects.map(p => p.id), [project.id]);

  const get = await callTool(ownerToken.token, 'get_project', { project_id: hidden.id });
  assert.equal(get.isError, true);
  assert.match(get.text, /not found or Claude Code access is not enabled/);

  // Apagarlo a mitad de sesión corta el acceso en la siguiente llamada.
  await enableClaudeCode(owner.accessToken, project.id, false);
  const after = await callTool(ownerToken.token, 'list_targets', { project_id: project.id });
  assert.equal(after.isError, true);
  assert.equal((await callTool(ownerToken.token, 'list_projects')).data.projects.length, 0);
});

test('only the project owner can toggle claude_code_enabled', async () => {
  const { owner, project } = await setup();
  const editor = await addMember(owner.accessToken, project.id, 'editor');
  const res = await request(app).patch(`/api/projects/${project.id}`).set(auth(editor.accessToken)).send({ claude_code_enabled: false });
  assert.equal(res.status, 403);
});

test('non-members cannot read a project through MCP', async () => {
  const { project } = await setup();
  const stranger = await registerUser();
  const tok = await createToken(stranger.accessToken);
  const res = await callTool(tok.token, 'list_findings', { project_id: project.id });
  assert.equal(res.isError, true);
});

// ── Roles y scopes ──────────────────────────────────────────────────────

// Un viewer es la cuenta del cliente (26fe968): por MCP leería borradores,
// así que el proyecto le resulta inexistente, igual que a un no-miembro.
test('viewer (client account) cannot read or propose through MCP', async () => {
  const { owner, project, target } = await setup();
  const viewer = await addMember(owner.accessToken, project.id, 'viewer');
  const tok = await createToken(viewer.accessToken);

  const stranger = await registerUser();
  const strangerTok = await createToken(stranger.accessToken);
  const strangerRes = await callTool(strangerTok.token, 'list_targets', { project_id: project.id });

  for (const [name, args] of [
    ['get_project',   { project_id: project.id }],
    ['list_targets',  { project_id: project.id }],
    ['list_findings', { project_id: project.id }],
    ['list_my_proposals', { project_id: project.id }],
  ]) {
    const res = await callTool(tok.token, name, args);
    assert.equal(res.isError, true, name);
    assert.match(res.text, /not found or Claude Code access is not enabled/, name);
  }
  // Mismo mensaje que para un no-miembro: no se filtra que el proyecto existe.
  const viewerRes = await callTool(tok.token, 'list_targets', { project_id: project.id });
  assert.equal(viewerRes.text, strangerRes.text);

  const prop = await callTool(tok.token, 'propose_finding', { project_id: project.id, target_id: target.id, ...FINDING });
  assert.equal(prop.isError, true);
  assert.match(prop.text, /not found or Claude Code access is not enabled/);
  const { rows } = await db.query('SELECT COUNT(*)::int AS n FROM mcp_proposals');
  assert.equal(rows[0].n, 0);
});

test('list_projects excludes projects where the user is a viewer', async () => {
  const { owner, project } = await setup();
  const viewer = await addMember(owner.accessToken, project.id, 'viewer');
  const tok = await createToken(viewer.accessToken);
  const res = await callTool(tok.token, 'list_projects');
  assert.equal(res.isError, false);
  assert.deepEqual(res.data.projects.filter(p => p.id === project.id), []);
  assert.equal(res.data.projects.length, 0);

  // Control: un pentester del mismo proyecto sí lo ve.
  const pentester = await addMember(owner.accessToken, project.id, 'pentester');
  const ptok = await createToken(pentester.accessToken);
  const pres = await callTool(ptok.token, 'list_projects');
  assert.deepEqual(pres.data.projects.map(p => p.id), [project.id]);
});

test('a read-scoped token cannot propose even for a writer', async () => {
  const { owner, project, target } = await setup();
  const tok = await createToken(owner.accessToken, { scopes: 'read' });
  const prop = await callTool(tok.token, 'propose_finding', { project_id: project.id, target_id: target.id, ...FINDING });
  assert.equal(prop.isError, true);
  assert.match(prop.text, /read-only/);
});

test('propose_finding rejects out-of-scope and foreign targets', async () => {
  const { owner, project, ownerToken } = await setup();
  const out = await createTarget(owner.accessToken, project.id, { host: 'thirdparty.example.net', scope: 'out' });
  const res = await callTool(ownerToken.token, 'propose_finding', { project_id: project.id, target_id: out.id, ...FINDING });
  assert.equal(res.isError, true);
  assert.match(res.text, /out of scope/);

  const other = await createProject(owner.accessToken, { name: 'Other' });
  const foreign = await createTarget(owner.accessToken, other.id);
  const res2 = await callTool(ownerToken.token, 'propose_finding', { project_id: project.id, target_id: foreign.id, ...FINDING });
  assert.equal(res2.isError, true);
  assert.match(res2.text, /does not belong to this project/);

  const { rows } = await db.query('SELECT COUNT(*)::int AS n FROM mcp_proposals');
  assert.equal(rows[0].n, 0);
});

test('a proposal never touches custom_vulns until approved, and duplicates are refused', async () => {
  const { project, target, ownerToken } = await setup();
  const prop = await callTool(ownerToken.token, 'propose_finding', { project_id: project.id, target_id: target.id, ...FINDING });
  assert.equal(prop.isError, false, prop.text);
  assert.equal(prop.data.status, 'pending');

  const { rows } = await db.query('SELECT COUNT(*)::int AS n FROM custom_vulns');
  assert.equal(rows[0].n, 0);

  const dup = await callTool(ownerToken.token, 'propose_finding', { project_id: project.id, target_id: target.id, ...FINDING, title: '  reflected xss IN search ' });
  assert.equal(dup.isError, true);
  assert.match(dup.text, /already pending/);

  const mine = await callTool(ownerToken.token, 'list_my_proposals', { project_id: project.id });
  assert.equal(mine.data.proposals.length, 1);
  assert.equal(mine.data.proposals[0].status, 'pending');

  const activity = await db.query(`SELECT action, meta FROM activity_log WHERE entity_type='mcp_proposal'`);
  assert.equal(activity.rows.length, 1);
  assert.equal(activity.rows[0].meta.via, 'claude-code');
});

// ── Aprobación ──────────────────────────────────────────────────────────

test('approving a finding creates an unpublished custom_vuln with origin claude_code', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const pentester = await addMember(owner.accessToken, project.id, 'pentester');
  const prop = await callTool(ownerToken.token, 'propose_finding', { project_id: project.id, target_id: target.id, ...FINDING });

  const inbox = await request(app).get(`/api/projects/${project.id}/mcp-proposals`).set(auth(pentester.accessToken));
  assert.equal(inbox.status, 200);
  assert.equal(inbox.body.length, 1);
  assert.equal(inbox.body[0].payload.title, FINDING.title);

  const res = await request(app).post(`/api/projects/${project.id}/mcp-proposals/${prop.data.proposal_id}/approve`).set(auth(pentester.accessToken));
  assert.equal(res.status, 200, JSON.stringify(res.body));
  assert.ok(res.body.resulting_vuln_id);

  const { rows } = await db.query('SELECT * FROM custom_vulns WHERE id=$1', [res.body.resulting_vuln_id]);
  const v = rows[0];
  assert.equal(v.origin, 'claude_code');
  assert.equal(v.client_visible, false);
  assert.equal(v.ai_generated, true);
  assert.equal(v.created_by, pentester.user.id);
  assert.equal(v.target_id, target.id);
  assert.equal(v.name, FINDING.title);
  assert.equal(v.severity, 'high');
  assert.equal(v.cwe, 'CWE-79');
  assert.equal(Number(v.cvss_score), 6.1);
  assert.equal(v.notes, FINDING.evidence);

  const { rows: [p] } = await db.query('SELECT status, reviewed_by, resulting_vuln_id FROM mcp_proposals WHERE id=$1', [prop.data.proposal_id]);
  assert.equal(p.status, 'approved');
  assert.equal(p.reviewed_by, pentester.user.id);
  assert.equal(p.resulting_vuln_id, v.id);

  // Ya no figura como pendiente en el inbox.
  const pending = await request(app).get(`/api/projects/${project.id}/mcp-proposals`).set(auth(owner.accessToken));
  assert.equal(pending.body.length, 0);
});

test('double approve is rejected and creates only one finding', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const prop = await callTool(ownerToken.token, 'propose_finding', { project_id: project.id, target_id: target.id, ...FINDING });
  const url = `/api/projects/${project.id}/mcp-proposals/${prop.data.proposal_id}/approve`;

  const [a, b] = await Promise.all([
    request(app).post(url).set(auth(owner.accessToken)),
    request(app).post(url).set(auth(owner.accessToken)),
  ]);
  assert.deepEqual([a.status, b.status].sort(), [200, 409]);
  const again = await request(app).post(url).set(auth(owner.accessToken));
  assert.equal(again.status, 409);
  const rej = await request(app).post(`/api/projects/${project.id}/mcp-proposals/${prop.data.proposal_id}/reject`).set(auth(owner.accessToken));
  assert.equal(rej.status, 409);

  const { rows } = await db.query('SELECT COUNT(*)::int AS n FROM custom_vulns');
  assert.equal(rows[0].n, 1);
});

test('viewers cannot approve or reject proposals', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const viewer = await addMember(owner.accessToken, project.id, 'viewer');
  const prop = await callTool(ownerToken.token, 'propose_finding', { project_id: project.id, target_id: target.id, ...FINDING });
  for (const action of ['approve', 'reject']) {
    const res = await request(app).post(`/api/projects/${project.id}/mcp-proposals/${prop.data.proposal_id}/${action}`).set(auth(viewer.accessToken));
    assert.equal(res.status, 403);
  }
});

test('a proposal cannot be approved through another project', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const other = await createProject(owner.accessToken, { name: 'Other' });
  const prop = await callTool(ownerToken.token, 'propose_finding', { project_id: project.id, target_id: target.id, ...FINDING });
  const res = await request(app).post(`/api/projects/${other.id}/mcp-proposals/${prop.data.proposal_id}/approve`).set(auth(owner.accessToken));
  assert.equal(res.status, 404);
});

test('approving a note appends it to the entity notes; rejecting leaves notes untouched', async () => {
  const { owner, project, target, ownerToken } = await setup();
  await db.query(`UPDATE targets SET notes='existing' WHERE id=$1`, [target.id]);

  const n1 = await callTool(ownerToken.token, 'propose_note', { project_id: project.id, entity_type: 'target', entity_id: target.id, text: 'WAF detected' });
  assert.equal(n1.isError, false, n1.text);
  const ok = await request(app).post(`/api/projects/${project.id}/mcp-proposals/${n1.data.proposal_id}/approve`).set(auth(owner.accessToken));
  assert.equal(ok.status, 200);

  const n2 = await callTool(ownerToken.token, 'propose_note', { project_id: project.id, entity_type: 'target', entity_id: target.id, text: 'nope' });
  const rej = await request(app).post(`/api/projects/${project.id}/mcp-proposals/${n2.data.proposal_id}/reject`).set(auth(owner.accessToken));
  assert.equal(rej.status, 200);

  const { rows } = await db.query('SELECT notes FROM targets WHERE id=$1', [target.id]);
  assert.equal(rows[0].notes, 'existing\n\n[Claude Code] WAF detected');
});

test('propose_note validates that the entity belongs to the project', async () => {
  const { owner, project, ownerToken } = await setup();
  const other = await createProject(owner.accessToken, { name: 'Other' });
  const foreign = await createTarget(owner.accessToken, other.id);
  const res = await callTool(ownerToken.token, 'propose_note', { project_id: project.id, entity_type: 'target', entity_id: foreign.id, text: 'x' });
  assert.equal(res.isError, true);
  assert.match(res.text, /does not belong to this project/);
});

test('Claude Code proposals and approved drafts stay out of the client portal', async () => {
  const { owner, project, target, ownerToken } = await setup();
  await request(app).patch(`/api/projects/${project.id}`).set(auth(owner.accessToken))
    .send({ client_view_enabled: true, show_findings: true, show_activity: true });
  const link = await request(app).post(`/api/projects/${project.id}/portal/links`).set(auth(owner.accessToken)).send({ label: 'Client' });
  const sess = await request(app).post('/api/portal/auth').send({ token: link.body.token });
  assert.equal(sess.status, 200);
  const portal = auth(sess.body.accessToken);

  const prop = await callTool(ownerToken.token, 'propose_finding', { project_id: project.id, target_id: target.id, ...FINDING });
  await request(app).post(`/api/projects/${project.id}/mcp-proposals/${prop.data.proposal_id}/approve`).set(auth(owner.accessToken));

  const feed = await request(app).get(`/api/projects/${project.id}/activity`).set(portal);
  assert.equal(feed.status, 200);
  assert.ok(feed.body.every(e => e.entity_type !== 'mcp_proposal'));
  const vulns = await request(app).get(`/api/projects/${project.id}/vulns`).set(portal);
  assert.equal(vulns.status, 200);
  assert.equal(vulns.body.length, 0);
  const inbox = await request(app).get(`/api/projects/${project.id}/mcp-proposals`).set(portal);
  assert.equal(inbox.status, 403);
});

// ── Editar y retirar propuestas ─────────────────────────────────────────

async function propose(tok, project, target, extra = {}) {
  const r = await callTool(tok, 'propose_finding', { project_id: project.id, target_id: target.id, ...FINDING, ...extra });
  assert.equal(r.isError, false, r.text);
  return r.data.proposal_id;
}

test('update_proposal edits only provided fields of your own pending proposal', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const id = await propose(ownerToken.token, project, target);
  const upd = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: id, severity: 'critical', title: 'Stored XSS in search' });
  assert.equal(upd.isError, false, upd.text);
  assert.deepEqual(upd.data.updated_fields.sort(), ['severity', 'title']);

  const { rows: [p] } = await db.query('SELECT payload, status, updated_at FROM mcp_proposals WHERE id=$1', [id]);
  assert.equal(p.status, 'pending');
  assert.equal(p.payload.severity, 'critical');
  assert.equal(p.payload.title, 'Stored XSS in search');
  assert.equal(p.payload.description, FINDING.description);
  assert.ok(p.updated_at);

  const act = await db.query(`SELECT meta FROM activity_log WHERE action='claude_code_proposal_updated'`);
  assert.equal(act.rows.length, 1);
  assert.equal(act.rows[0].meta.via, 'claude-code');

  // Campos de nota en una propuesta de hallazgo: rechazado.
  const bad = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: id, text: 'x' });
  assert.equal(bad.isError, true);
  assert.match(bad.text, /cannot be set on a finding proposal/);

  // Moverla a un target fuera de scope: rechazado.
  const out = await createTarget(owner.accessToken, project.id, { host: 'thirdparty.example.net', scope: 'out' });
  const moved = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: id, target_id: out.id });
  assert.equal(moved.isError, true);
  assert.match(moved.text, /out of scope/);
});

test('update_proposal applies the duplicate rule against other proposals, not itself', async () => {
  const { project, target, ownerToken } = await setup();
  const a = await propose(ownerToken.token, project, target);
  await propose(ownerToken.token, project, target, { title: 'Open redirect' });
  const self = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: a, title: ' reflected XSS in SEARCH' });
  assert.equal(self.isError, false, self.text);
  const dup = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: a, title: 'open redirect' });
  assert.equal(dup.isError, true);
  assert.match(dup.text, /already pending/);
});

test('update_proposal re-validates note entities', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const n = await callTool(ownerToken.token, 'propose_note', { project_id: project.id, entity_type: 'target', entity_id: target.id, text: 'a' });
  const other = await createProject(owner.accessToken, { name: 'Other' });
  const foreign = await createTarget(owner.accessToken, other.id);
  const bad = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: n.data.proposal_id, entity_id: foreign.id });
  assert.equal(bad.isError, true);
  assert.match(bad.text, /does not belong to this project/);
  const ok = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: n.data.proposal_id, text: 'b' });
  assert.equal(ok.isError, false, ok.text);
  const { rows: [p] } = await db.query('SELECT payload FROM mcp_proposals WHERE id=$1', [n.data.proposal_id]);
  assert.equal(p.payload.text, 'b');
});

test('editing and withdrawing are refused for others\' proposals and for non-pending ones', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const pentester = await addMember(owner.accessToken, project.id, 'pentester');
  const pTok = await createToken(pentester.accessToken);
  const id = await propose(ownerToken.token, project, target);

  for (const tool of ['update_proposal', 'withdraw_proposal']) {
    const args = { project_id: project.id, proposal_id: id, ...(tool === 'update_proposal' ? { severity: 'low' } : {}) };
    const r = await callTool(pTok.token, tool, args);
    assert.equal(r.isError, true, tool);
    assert.match(r.text, /not one of your proposals/);
  }

  // Aprobada: ya no se edita ni se retira.
  const approved = await request(app).post(`/api/projects/${project.id}/mcp-proposals/${id}/approve`).set(auth(owner.accessToken));
  assert.equal(approved.status, 200);
  const e1 = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: id, severity: 'low' });
  assert.equal(e1.isError, true);
  assert.match(e1.text, /already approved/);
  const w1 = await callTool(ownerToken.token, 'withdraw_proposal', { project_id: project.id, proposal_id: id });
  assert.equal(w1.isError, true);
  assert.match(w1.text, /already approved/);

  // Retirada: tampoco se edita ni se vuelve a retirar.
  const id2 = await propose(ownerToken.token, project, target, { title: 'Open redirect' });
  const w2 = await callTool(ownerToken.token, 'withdraw_proposal', { project_id: project.id, proposal_id: id2 });
  assert.equal(w2.isError, false, w2.text);
  assert.equal(w2.data.status, 'withdrawn');
  const e2 = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: id2, severity: 'low' });
  assert.equal(e2.isError, true);
  assert.match(e2.text, /already withdrawn/);
  const w3 = await callTool(ownerToken.token, 'withdraw_proposal', { project_id: project.id, proposal_id: id2 });
  assert.equal(w3.isError, true);
  assert.match(w3.text, /already withdrawn/);

  // Un token read-only no edita aunque la propuesta sea suya.
  const ro = await createToken(owner.accessToken, { scopes: 'read' });
  const id3 = await propose(ownerToken.token, project, target, { title: 'Clickjacking' });
  const r3 = await callTool(ro.token, 'withdraw_proposal', { project_id: project.id, proposal_id: id3 });
  assert.equal(r3.isError, true);
  assert.match(r3.text, /read-only/);
});

test('withdrawn proposals are kept, leave the inbox, show in list_my_proposals and cannot be approved', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const id = await propose(ownerToken.token, project, target);
  const w = await callTool(ownerToken.token, 'withdraw_proposal', { project_id: project.id, proposal_id: id });
  assert.equal(w.isError, false, w.text);

  const { rows } = await db.query('SELECT status FROM mcp_proposals WHERE id=$1', [id]);
  assert.equal(rows[0].status, 'withdrawn');

  const inbox = await request(app).get(`/api/projects/${project.id}/mcp-proposals`).set(auth(owner.accessToken));
  assert.equal(inbox.body.length, 0);
  const withdrawnList = await request(app).get(`/api/projects/${project.id}/mcp-proposals?status=withdrawn`).set(auth(owner.accessToken));
  assert.equal(withdrawnList.status, 200);
  assert.equal(withdrawnList.body.length, 1);

  const mine = await callTool(ownerToken.token, 'list_my_proposals', { project_id: project.id });
  assert.equal(mine.data.proposals[0].status, 'withdrawn');
  const onlyW = await callTool(ownerToken.token, 'list_my_proposals', { status: 'withdrawn' });
  assert.equal(onlyW.data.proposals.length, 1);

  const ap = await request(app).post(`/api/projects/${project.id}/mcp-proposals/${id}/approve`).set(auth(owner.accessToken));
  assert.equal(ap.status, 409);
  assert.match(ap.body.error, /withdrawn/);
  const { rows: v } = await db.query('SELECT COUNT(*)::int AS n FROM custom_vulns');
  assert.equal(v[0].n, 0);

  const act = await db.query(`SELECT meta FROM activity_log WHERE action='claude_code_proposal_withdrawn'`);
  assert.equal(act.rows.length, 1);
  assert.equal(act.rows[0].meta.via, 'claude-code');
});

// ── Capturas (POST /mcp/uploads) ────────────────────────────────────────

const PNG  = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.from('fake-png-body-bytes')]);
const JPEG = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.from('fake-jpeg-body-bytes')]);
const WEBP = Buffer.concat([Buffer.from('RIFF'), Buffer.from([0, 0, 0, 0]), Buffer.from('WEBPVP8 fake')]);

function uploadFile(token, buf, name = 'shot.png', contentType = 'image/png') {
  return request(app).post('/mcp/uploads').set(auth(token)).attach('file', buf, { filename: name, contentType });
}

async function uploadOk(token, buf = PNG, name) {
  const res = await uploadFile(token, buf, name);
  assert.equal(res.status, 201, JSON.stringify(res.body));
  return res.body;
}

test('uploads accept PNG/JPEG/WebP by magic bytes and sanitize the name', async () => {
  const { ownerToken } = await setup();
  const png = await uploadOk(ownerToken.token, PNG, '../../etc/<evil>.png');
  assert.equal(png.mime, 'image/png');
  assert.equal(png.size, PNG.length);
  assert.equal(png.name, '_evil_.png');
  assert.ok(png.upload_id);
  // El content-type del cliente no importa: manda el contenido.
  const jpg = await uploadFile(ownerToken.token, JPEG, 'a.png', 'image/png');
  assert.equal(jpg.body.mime, 'image/jpeg');
  assert.equal((await uploadOk(ownerToken.token, WEBP, 'x.webp')).mime, 'image/webp');
});

test('uploads reject wrong magic bytes, oversize files, missing auth and read-only tokens', async () => {
  const { owner, ownerToken } = await setup();
  const html = await uploadFile(ownerToken.token, Buffer.from('<html><script>alert(1)</script></html>'), 'shot.png', 'image/png');
  assert.equal(html.status, 415);

  const big = Buffer.concat([PNG, Buffer.alloc(4 * 1024 * 1024)]);
  const tooBig = await uploadFile(ownerToken.token, big);
  assert.equal(tooBig.status, 413);

  const ro = await createToken(owner.accessToken, { scopes: 'read' });
  const roRes = await uploadFile(ro.token, PNG);
  assert.equal(roRes.status, 403);
  assert.match(roRes.body.error, /read-only/);

  const anon = await request(app).post('/mcp/uploads').attach('file', PNG, 'shot.png');
  assert.equal(anon.status, 401);
  // Un JWT de sesión tampoco sirve.
  assert.equal((await uploadFile(owner.accessToken, PNG)).status, 401);

  const noFile = await request(app).post('/mcp/uploads').set(auth(ownerToken.token)).field('x', '1');
  assert.equal(noFile.status, 400);

  const { rows } = await db.query('SELECT COUNT(*)::int AS n FROM mcp_uploads');
  assert.equal(rows[0].n, 0);
});

test('unused uploads per user are capped', async () => {
  const { owner, ownerToken } = await setup();
  await db.query(
    `INSERT INTO mcp_uploads (user_id, mime, name, size, data)
     SELECT $1, 'image/png', 'x.png', 1, '\\x00'::bytea FROM generate_series(1, 50)`,
    [owner.user.id]
  );
  const res = await uploadFile(ownerToken.token, PNG);
  assert.equal(res.status, 429);
});

test('expired unused uploads are rejected and swept on the next upload', async () => {
  const { project, target, ownerToken } = await setup();
  const old = await uploadOk(ownerToken.token);
  await db.query(`UPDATE mcp_uploads SET created_at = NOW() - INTERVAL '25 hours' WHERE id=$1`, [old.upload_id]);

  const r = await callTool(ownerToken.token, 'propose_finding', { project_id: project.id, target_id: target.id, ...FINDING, evidence_upload_ids: [old.upload_id] });
  assert.equal(r.isError, true);
  assert.match(r.text, /expired/);
  // La propuesta no quedó creada a medias.
  const { rows } = await db.query('SELECT COUNT(*)::int AS n FROM mcp_proposals');
  assert.equal(rows[0].n, 0);

  await uploadOk(ownerToken.token);
  const { rows: left } = await db.query('SELECT id FROM mcp_uploads WHERE id=$1', [old.upload_id]);
  assert.equal(left.length, 0);
});

test('a foreign upload cannot be attached, and an upload cannot be reused on another proposal', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const pentester = await addMember(owner.accessToken, project.id, 'pentester');
  const pTok = await createToken(pentester.accessToken);
  const theirs = await uploadOk(pTok.token);

  const foreign = await callTool(ownerToken.token, 'propose_finding', { project_id: project.id, target_id: target.id, ...FINDING, evidence_upload_ids: [theirs.upload_id] });
  assert.equal(foreign.isError, true);
  assert.match(foreign.text, /not found/);

  const mine = await uploadOk(ownerToken.token);
  const a = await propose(ownerToken.token, project, target, { evidence_upload_ids: [mine.upload_id] });
  const b = await callTool(ownerToken.token, 'propose_finding', { project_id: project.id, target_id: target.id, ...FINDING, title: 'Other', evidence_upload_ids: [mine.upload_id] });
  assert.equal(b.isError, true);
  assert.match(b.text, /already attached to another proposal/);

  const second = await propose(ownerToken.token, project, target, { title: 'Second' });
  const reuse = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: second, evidence_upload_ids: [mine.upload_id] });
  assert.equal(reuse.isError, true);
  assert.match(reuse.text, /already attached to another proposal/);

  // La propia propuesta sí puede re-listar la suya, y [] la suelta.
  const same = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: a, evidence_upload_ids: [mine.upload_id] });
  assert.equal(same.isError, false, same.text);
  const cleared = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: a, evidence_upload_ids: [] });
  assert.equal(cleared.isError, false, cleared.text);
  const { rows } = await db.query('SELECT used_by_proposal_id FROM mcp_uploads WHERE id=$1', [mine.upload_id]);
  assert.equal(rows[0].used_by_proposal_id, null);
});

test('approval copies uploaded screenshots into evidence with phase original', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const u1 = await uploadOk(ownerToken.token, PNG, 'one.png');
  const u2 = await uploadOk(ownerToken.token, JPEG, 'two.jpg');
  const id = await propose(ownerToken.token, project, target, { evidence_upload_ids: [u1.upload_id, u2.upload_id] });

  const inbox = await request(app).get(`/api/projects/${project.id}/mcp-proposals`).set(auth(owner.accessToken));
  assert.equal(inbox.body[0].evidence_uploads.length, 2);
  assert.equal(inbox.body[0].evidence_uploads[0].data, undefined);

  const ev = await request(app).get(`/api/projects/${project.id}/mcp-proposals/${id}/evidence`).set(auth(owner.accessToken));
  assert.equal(ev.status, 200);
  assert.equal(ev.body.length, 2);
  assert.equal(ev.body[0].data, `data:image/png;base64,${PNG.toString('base64')}`);
  // Sin acceso al proyecto no se ven.
  const stranger = await registerUser();
  const denied = await request(app).get(`/api/projects/${project.id}/mcp-proposals/${id}/evidence`).set(auth(stranger.accessToken));
  assert.equal(denied.status, 404);

  const res = await request(app).post(`/api/projects/${project.id}/mcp-proposals/${id}/approve`).set(auth(owner.accessToken));
  assert.equal(res.status, 200, JSON.stringify(res.body));
  const { rows: [v] } = await db.query('SELECT evidence FROM custom_vulns WHERE id=$1', [res.body.resulting_vuln_id]);
  assert.deepEqual(v.evidence, [
    { data: `data:image/png;base64,${PNG.toString('base64')}`, name: 'one.png', phase: 'original' },
    { data: `data:image/jpeg;base64,${JPEG.toString('base64')}`, name: 'two.jpg', phase: 'original' },
  ]);
});

test('get_upload_instructions returns the public URL and never the token', async () => {
  const { ownerToken } = await setup();
  const res = await request(app).post('/mcp')
    .set('Authorization', `Bearer ${ownerToken.token}`)
    .set('Accept', 'application/json, text/event-stream')
    .set('X-Forwarded-Proto', 'https')
    .set('X-Forwarded-Host', 'flowdit.example.com')
    .send({ jsonrpc: '2.0', id: ++rpcId, method: 'tools/call', params: { name: 'get_upload_instructions', arguments: {} } });
  assert.equal(res.status, 200, res.text);
  const text = res.body.result.content[0].text;
  assert.ok(!text.includes(ownerToken.token));
  const data = JSON.parse(text);
  assert.equal(data.upload_url, 'https://flowdit.example.com/mcp/uploads');
  assert.match(data.command, /\$FLOWDIT_TOKEN/);

  const tools = await mcp(ownerToken.token, 'tools/list');
  const pf = tools.body.result.tools.find(t => t.name === 'propose_finding');
  assert.match(pf.description, /mcp\/uploads/);
});

// El aviso se manda sin await (no debe demorar la respuesta a Claude Code):
// se espera a que aparezca en vez de leerlo al toque.
async function waitForRows(sql, params, min, timeoutMs = 5000) {
  const start = Date.now();
  for (;;) {
    const { rows } = await db.query(sql, params);
    if (rows.length >= min || Date.now() - start > timeoutMs) return rows;
    await new Promise(r => setTimeout(r, 25));
  }
}

test('a finding proposal notifies every writer, the proposer included, but never a viewer', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const pentester = await addMember(owner.accessToken, project.id, 'pentester');
  const viewer    = await addMember(owner.accessToken, project.id, 'viewer');

  const prop = await callTool(ownerToken.token, 'propose_finding', { project_id: project.id, target_id: target.id, ...FINDING });
  assert.equal(prop.isError, false, prop.text);

  const rows = await waitForRows(
    `SELECT * FROM notifications WHERE type = 'ai_finding_proposed' AND project_id = $1`, [project.id], 2
  );
  // Un margen para que un aviso de más (al viewer) también llegue a escribirse.
  await new Promise(r => setTimeout(r, 100));
  const all = (await db.query(`SELECT * FROM notifications WHERE type = 'ai_finding_proposed'`)).rows;
  const to = new Set(all.map(n => n.user_id));
  assert.ok(to.has(owner.user.id), 'the proposer (token owner) is notified');
  assert.ok(to.has(pentester.user.id), 'another writer is notified');
  assert.ok(!to.has(viewer.user.id), 'a viewer (client account) is never notified');
  assert.equal(all.length, 2);
  const n = rows[0];
  assert.equal(n.entity_type, 'mcp_proposal');
  const { rows: [proposal] } = await db.query(`SELECT id FROM mcp_proposals WHERE project_id = $1`, [project.id]);
  assert.equal(n.entity_id, proposal.id);
  assert.equal(n.actor_id, null);
  assert.equal(n.payload.source, 'claude_code');
  assert.equal(n.payload.finding_title, FINDING.title);
  assert.equal(n.payload.severity, FINDING.severity);
  assert.equal(n.payload.project_name, project.name);
});


// ── Targets propuestos, puertos/endpoints directos, whiteboard add-only ──

test('propose_target needs a human approval that explicitly picks the scope', async () => {
  const { owner, project, ownerToken } = await setup();
  const pentester = await addMember(owner.accessToken, project.id, 'pentester');

  const prop = await callTool(ownerToken.token, 'propose_target', {
    project_id: project.id, host: 'api.example.com', type: 'domain', notes: 'Visto en el bundle JS',
  });
  assert.equal(prop.isError, false, prop.text);
  // Nada en targets hasta aprobar.
  const before = await db.query(`SELECT 1 FROM targets WHERE project_id = $1 AND host = 'api.example.com'`, [project.id]);
  assert.equal(before.rows.length, 0);

  const url = `/api/projects/${project.id}/mcp-proposals/${prop.data.proposal_id}/approve`;
  // Sin scope (o con uno inválido) no se aprueba y la propuesta sigue pendiente.
  for (const body of [{}, { scope: 'maybe' }]) {
    const res = await request(app).post(url).set(auth(pentester.accessToken)).send(body);
    assert.equal(res.status, 400, JSON.stringify(res.body));
  }
  const pending = await db.query(`SELECT status FROM mcp_proposals WHERE id = $1`, [prop.data.proposal_id]);
  assert.equal(pending.rows[0].status, 'pending');

  const ok = await request(app).post(url).set(auth(pentester.accessToken)).send({ scope: 'out' });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  const { rows: [t] } = await db.query(`SELECT * FROM targets WHERE id = $1`, [ok.body.resulting_target_id]);
  assert.equal(t.host, 'api.example.com');
  assert.equal(t.scope, 'out');
  assert.equal(t.added_by, pentester.user.id, 'added_by is the approver');
  assert.equal(t.source, 'claude_code');
  const act = await db.query(`SELECT meta FROM activity_log WHERE action = 'target_added' AND entity_id = $1`, [t.id]);
  assert.equal(act.rows.length, 1);
  assert.equal(act.rows[0].meta.via, 'claude-code');
  const { rows: [mp] } = await db.query(`SELECT status, resulting_target_id FROM mcp_proposals WHERE id = $1`, [prop.data.proposal_id]);
  assert.equal(mp.status, 'approved');
  assert.equal(mp.resulting_target_id, t.id);

  // La propuesta avisó a los writers (incluido quien propuso).
  const notif = await waitForRows(`SELECT user_id FROM notifications WHERE type = 'ai_target_proposed'`, [], 2);
  assert.deepEqual(new Set(notif.map(n => n.user_id)), new Set([owner.user.id, pentester.user.id]));
});

test('propose_target refuses hosts already in the project, ignoring scheme, case and trailing slash', async () => {
  const { project, ownerToken } = await setup(); // setup() crea app.example.com
  const dup = await callTool(ownerToken.token, 'propose_target', { project_id: project.id, host: 'https://APP.example.com/', type: 'url' });
  assert.equal(dup.isError, true);
  assert.match(dup.text, /already exists/);
  const first = await callTool(ownerToken.token, 'propose_target', { project_id: project.id, host: 'new.example.com', type: 'domain' });
  assert.equal(first.isError, false, first.text);
  const again = await callTool(ownerToken.token, 'propose_target', { project_id: project.id, host: 'NEW.example.com', type: 'domain' });
  assert.equal(again.isError, true);
  assert.match(again.text, /already pending/);

  // update_proposal no acepta scope ni campos de otro tipo, y sí host.
  const upd = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: first.data.proposal_id, host: 'new2.example.com' });
  assert.equal(upd.isError, false, upd.text);
  const wrong = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: first.data.proposal_id, title: 'x x x' });
  assert.equal(wrong.isError, true);
  const mine = await callTool(ownerToken.token, 'list_my_proposals', { project_id: project.id });
  assert.equal(mine.data.proposals[0].host, 'new2.example.com');
});

test('add_ports / add_endpoints write directly only to in-scope active targets and skip duplicates', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const out = await createTarget(owner.accessToken, project.id, { host: 'out.example.com', scope: 'out' });
  const other = await createProject(owner.accessToken);
  const foreign = await createTarget(owner.accessToken, other.id, { host: 'foreign.example.com' });

  for (const tid of [out.id, foreign.id]) {
    const r = await callTool(ownerToken.token, 'add_ports', { project_id: project.id, target_id: tid, ports: [{ port: 22 }] });
    assert.equal(r.isError, true, r.text);
    const e = await callTool(ownerToken.token, 'add_endpoints', { project_id: project.id, target_id: tid, endpoints: [{ path: '/x' }] });
    assert.equal(e.isError, true, e.text);
  }
  assert.equal((await db.query(`SELECT 1 FROM target_ports`)).rows.length, 0);
  assert.equal((await db.query(`SELECT 1 FROM target_endpoints`)).rows.length, 0);

  const ports = await callTool(ownerToken.token, 'add_ports', {
    project_id: project.id, target_id: target.id,
    ports: [{ port: 443, service: 'https' }, { port: 22, service: 'ssh' }, { port: 443 }],
  });
  assert.equal(ports.isError, false, ports.text);
  assert.equal(ports.data.added.length, 2);
  assert.equal(ports.data.skipped.length, 1);
  const again = await callTool(ownerToken.token, 'add_ports', { project_id: project.id, target_id: target.id, ports: [{ port: 22 }, { port: 22, protocol: 'udp' }] });
  assert.deepEqual(again.data.added.map(p => `${p.port}/${p.protocol}`), ['22/udp']);
  assert.equal(again.data.skipped[0].reason, 'already recorded');
  const { rows: pr } = await db.query(`SELECT added_by, source FROM target_ports WHERE target_id = $1`, [target.id]);
  assert.equal(pr.length, 3);
  assert.ok(pr.every(p => p.added_by === owner.user.id && p.source === 'claude_code'));

  const eps = await callTool(ownerToken.token, 'add_endpoints', {
    project_id: project.id, target_id: target.id,
    endpoints: [{ path: '/api//users/?page=2' }, { path: 'api/users' }, { path: '/api/users', method: 'POST' }],
  });
  assert.equal(eps.isError, false, eps.text);
  assert.deepEqual(eps.data.added.map(e => `${e.method} ${e.path}`), ['GET /api/users', 'POST /api/users']);
  assert.equal(eps.data.skipped.length, 1);
  const eps2 = await callTool(ownerToken.token, 'add_endpoints', { project_id: project.id, target_id: target.id, endpoints: [{ path: '/api/users/' }] });
  assert.equal(eps2.data.added.length, 0);
  assert.equal(eps2.data.skipped[0].reason, 'already recorded');

  // Un evento de Activity por lote, como entity 'target'.
  const act = await db.query(`SELECT action, entity_type, entity_id FROM activity_log WHERE action LIKE 'claude_code_%_added' ORDER BY created_at`);
  assert.deepEqual(act.rows.map(r => r.action), ['claude_code_ports_added', 'claude_code_ports_added', 'claude_code_endpoints_added']);
  assert.ok(act.rows.every(r => r.entity_type === 'target' && r.entity_id === target.id));

  // Un token de solo lectura no escribe.
  const ro = await createToken(owner.accessToken, { scopes: 'read' });
  const roRes = await callTool(ro.token, 'add_ports', { project_id: project.id, target_id: target.id, ports: [{ port: 8080 }] });
  assert.equal(roRes.isError, true);
  assert.match(roRes.text, /read-only/);
});

test('viewers cannot add ports, endpoints, whiteboard items or propose targets', async () => {
  const { owner, project, target } = await setup();
  const viewer = await addMember(owner.accessToken, project.id, 'viewer');
  const tok = await createToken(viewer.accessToken);
  for (const [name, args] of [
    ['add_ports', { target_id: target.id, ports: [{ port: 80 }] }],
    ['add_endpoints', { target_id: target.id, endpoints: [{ path: '/' }] }],
    ['add_whiteboard_items', { notes: [{ text: 'hola' }] }],
    ['move_whiteboard_items', { moves: [{ id: target.id, x: 0, y: 0 }] }],
    ['get_whiteboard', {}],
    ['propose_target', { host: 'x.example.com', type: 'domain' }],
  ]) {
    const r = await callTool(tok.token, name, { project_id: project.id, ...args });
    assert.equal(r.isError, true, name);
    assert.match(r.text, /not found or Claude Code access is not enabled/, name);
  }
  assert.equal((await db.query(`SELECT 1 FROM target_ports`)).rows.length, 0);
  assert.equal((await db.query(`SELECT 1 FROM whiteboard_state`)).rows.length, 0);
});

test('whiteboard additions keep existing items intact and consecutive batches do not overlap', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const existing = {
    nodes: [{ id: target.id, x: 80, y: 80, collapsed: false }],
    notes: [{ id: '11111111-1111-4111-8111-111111111111', x: 500, y: 100, text: 'humano', color: '#ffd96a' }],
    cards: [{ id: '22222222-2222-4222-8222-222222222222', x: 100, y: 600, title: 'Card humana', body: 'b', color: '#1e3a5f' }],
    edges: [], strokes: [{ id: 's1', d: 'M 900 50 L 950 60', color: '#e94141', width: 2 }],
    view: { panX: 0, panY: 0, zoom: 1 },
  };
  const put = await request(app).put(`/api/projects/${project.id}/whiteboard`).set(auth(owner.accessToken)).send({ data: existing });
  assert.equal(put.status, 200);
  const portRes = await callTool(ownerToken.token, 'add_ports', { project_id: project.id, target_id: target.id, ports: [{ port: 443 }] });
  const portId = portRes.data.added[0].id;

  const a = await callTool(ownerToken.token, 'add_whiteboard_items', {
    project_id: project.id,
    nodes: [{ target_id: target.id }], // ya está: se saltea
    cards: [{ title: 'TLS', body: 'Revisar cifrados', link: { type: 'port', id: portId } }],
    notes: [{ text: 'Probar IDOR' }, { text: 'Revisar CORS' }],
  });
  assert.equal(a.isError, false, a.text);
  assert.equal(a.data.skipped.length, 1);
  assert.equal(a.data.added.cards.length, 1);
  assert.equal(a.data.added.notes.length, 2);
  assert.equal(a.data.added.edges.length, 1, 'linked card is connected to its target node');

  const b = await callTool(ownerToken.token, 'add_whiteboard_items', { project_id: project.id, notes: [{ text: 'Segundo lote' }] });
  assert.equal(b.isError, false, b.text);

  const { rows: [wb] } = await db.query(`SELECT data FROM whiteboard_state WHERE project_id = $1`, [project.id]);
  const d = wb.data;
  // Lo existente, intacto.
  assert.deepEqual(d.nodes, existing.nodes);
  assert.deepEqual(d.strokes, existing.strokes);
  assert.deepEqual(d.notes.find(n => n.id === '11111111-1111-4111-8111-111111111111'), existing.notes[0]);
  assert.deepEqual(d.cards.find(c => c.id === '22222222-2222-4222-8222-222222222222'), existing.cards[0]);
  // Lo nuevo, marcado y a la derecha de todo lo que había (sin solaparse).
  const ai = [...d.notes, ...d.cards].filter(i => i.created_by === 'claude_code');
  assert.equal(ai.length, 4);
  const card = d.cards.find(c => c.created_by === 'claude_code');
  assert.equal(card.ref.type, 'port');
  assert.match(card.ref.label, /:443\/tcp$/);
  const existingRight = Math.max(80 + 290, 500 + 170, 100 + 240, 950);
  const firstBatch = [...a.data.added.cards, ...a.data.added.notes];
  assert.ok(firstBatch.every(i => i.x >= existingRight), 'first batch starts right of the existing board');
  const firstRight = Math.max(...a.data.added.cards.map(c => c.x + 240), ...a.data.added.notes.map(n => n.x + 170));
  assert.ok(b.data.added.notes[0].x >= firstRight, 'second batch starts right of the first');

  // Flechas: entre nodo y tarjeta sí, también a una nota; repetida (en
  // cualquier sentido) se saltea.
  const humanCard = '22222222-2222-4222-8222-222222222222';
  const c1 = await callTool(ownerToken.token, 'connect_whiteboard_items', {
    project_id: project.id, edges: [{ from_id: card.id, to_id: target.id }, { from_id: target.id, to_id: humanCard, label: 'expone' }],
  });
  assert.equal(c1.isError, false, c1.text);
  assert.equal(c1.data.skipped.length, 1, 'card→target already existed (auto-linked)');
  assert.equal(c1.data.added.length, 1);
  const reverse = await callTool(ownerToken.token, 'connect_whiteboard_items', {
    project_id: project.id, edges: [{ from_id: target.id, to_id: card.id }, { from_id: humanCard, to_id: target.id }],
  });
  assert.equal(reverse.isError, false, reverse.text);
  assert.equal(reverse.data.added.length, 0, 'B→A is the same connection as A→B');
  assert.deepEqual(reverse.data.skipped.map(x => x.reason), ['connection already exists', 'connection already exists']);
  const noteId = a.data.added.notes[0].id;
  const toNote = await callTool(ownerToken.token, 'connect_whiteboard_items', {
    project_id: project.id, edges: [{ from_id: humanCard, to_id: noteId, style: 'dashed', arrow: 'both', color: '#43a047' }],
  });
  assert.equal(toNote.isError, false, toNote.text);
  assert.deepEqual(
    [toNote.data.added[0].to_id, toNote.data.added[0].style, toNote.data.added[0].arrow, toNote.data.added[0].color],
    [noteId, 'dashed', 'both', '#43a047']
  );

  const summary = await callTool(ownerToken.token, 'get_whiteboard', { project_id: project.id });
  assert.equal(summary.data.nodes[0].host, 'app.example.com');
  assert.equal(summary.data.notes.length, 4);
  assert.equal(summary.data.edges.length, 3);
  const noteEdge = summary.data.edges.find(e => e.to_id === noteId);
  assert.deepEqual([noteEdge.style, noteEdge.arrow, noteEdge.color], ['dashed', 'both', '#43a047']);
  const plain = summary.data.edges.find(e => e.from_id === card.id);
  assert.deepEqual([plain.style, plain.arrow, plain.color, plain.from_endpoint_id], ['solid', 'end', null, null]);
});

test('whiteboard items can be moved: only x/y change, revisions advance, unknown ids are refused', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const note = { id: '11111111-1111-4111-8111-111111111111', x: 500, y: 100, w: 300, text: 'humano', color: '#ffd96a' };
  const card = { id: '22222222-2222-4222-8222-222222222222', x: 100, y: 600, title: 'Card', body: 'b', color: '#1e3a5f' };
  const put = await request(app).put(`/api/projects/${project.id}/whiteboard`).set(auth(owner.accessToken))
    .send({ data: { nodes: [{ id: target.id, x: 80, y: 80, collapsed: true }], notes: [note], cards: [card], edges: [], strokes: [] } });
  assert.equal(put.status, 200);
  const before = await request(app).get(`/api/projects/${project.id}/whiteboard`).set(auth(owner.accessToken));
  const rev = before.body.revision;

  const r = await callTool(ownerToken.token, 'move_whiteboard_items', {
    project_id: project.id,
    moves: [{ id: target.id, x: 1000.4, y: -20 }, { id: note.id, x: 999999, y: 10 }, { id: card.id, x: 100, y: 600 }],
  });
  assert.equal(r.isError, false, r.text);
  assert.deepEqual(r.data.moved.map(m => [m.id, m.x, m.y]), [[target.id, 1000, -20], [note.id, 50000, 10]]);
  assert.equal(r.data.moved[1].w, 300, 'reports the real size');
  assert.deepEqual(r.data.unchanged, [card.id]);

  const { rows: [wb] } = await db.query(`SELECT data FROM whiteboard_state WHERE project_id = $1`, [project.id]);
  assert.deepEqual(wb.data.nodes[0], { id: target.id, x: 1000, y: -20, collapsed: true });
  assert.deepEqual(wb.data.notes[0], { ...note, x: 50000, y: 10 });
  assert.deepEqual(wb.data.cards[0], card);

  // Las pestañas traen solo lo movido con ?since.
  const delta = await request(app).get(`/api/projects/${project.id}/whiteboard?since=${rev}`).set(auth(owner.accessToken));
  assert.equal(delta.body.full, false);
  assert.deepEqual(delta.body.changes.nodes.map(n => n.id), [target.id]);
  assert.deepEqual(delta.body.changes.notes.map(n => n.id), [note.id]);
  assert.deepEqual(delta.body.changes.cards, []);

  const unknown = await callTool(ownerToken.token, 'move_whiteboard_items', {
    project_id: project.id, moves: [{ id: note.id, x: 0, y: 0 }, { id: '33333333-3333-4333-8333-333333333333', x: 0, y: 0 }],
  });
  assert.equal(unknown.isError, true);
  assert.match(unknown.text, /is not a target node, card, note or image/);
  const dup = await callTool(ownerToken.token, 'move_whiteboard_items', {
    project_id: project.id, moves: [{ id: note.id, x: 0, y: 0 }, { id: note.id, x: 1, y: 1 }],
  });
  assert.equal(dup.isError, true);
  const { rows: [after] } = await db.query(`SELECT data FROM whiteboard_state WHERE project_id = $1`, [project.id]);
  assert.deepEqual([after.data.notes[0].x, after.data.notes[0].y], [50000, 10], 'a refused call moves nothing');
});

test('whiteboard items can be sized on creation, sizes are clamped and reported, and sized batches do not overlap', async () => {
  const { owner, project, target, ownerToken } = await setup();
  // Tablero existente con una nota humana redimensionada: el lote nuevo
  // tiene que arrancar a la derecha de su ancho real, no del default.
  const human = { id: '11111111-1111-4111-8111-111111111111', x: 100, y: 100, w: 900, h: 500, text: 'humana', color: '#ffd96a' };
  const put = await request(app).put(`/api/projects/${project.id}/whiteboard`).set(auth(owner.accessToken))
    .send({ data: { notes: [human], nodes: [], cards: [], edges: [], strokes: [] } });
  assert.equal(put.status, 200);

  const a = await callTool(ownerToken.token, 'add_whiteboard_items', {
    project_id: project.id,
    nodes: [{ target_id: target.id, w: 500, h: 600 }],
    cards: [{ title: 'Grande', w: 700, h: 400 }, { title: 'Chica', w: 10, h: 99999 }],
    notes: [{ text: 'Default' }],
  });
  assert.equal(a.isError, false, a.text);
  const [big, small] = a.data.added.cards;
  assert.deepEqual([big.w, big.h], [700, 400]);
  assert.deepEqual([small.w, small.h], [160, 4000], 'clamped to the card min width and the max height');
  assert.deepEqual([a.data.added.nodes[0].w, a.data.added.nodes[0].h], [500, 600]);
  const note = a.data.added.notes[0];
  assert.deepEqual([note.w, note.h], [170, 100], 'unsized note reports the default size');

  const { rows: [wb] } = await db.query(`SELECT data FROM whiteboard_state WHERE project_id = $1`, [project.id]);
  assert.deepEqual(wb.data.notes.find(n => n.id === human.id), human, 'existing note untouched');
  const stored = wb.data.notes.find(n => n.created_by === 'claude_code');
  assert.equal(stored.w, undefined, 'no size is stored unless one was given');
  assert.equal(wb.data.cards.find(c => c.title === 'Grande').w, 700);

  // Nada del lote se pisa entre sí ni con lo existente.
  const boxes = [
    { ...human },
    ...a.data.added.nodes, ...a.data.added.cards, ...a.data.added.notes,
  ];
  const overlaps = (p, q) => p.x < q.x + q.w && q.x < p.x + p.w && p.y < q.y + q.h && q.y < p.y + p.h;
  for (let i = 0; i < boxes.length; i++) {
    for (let j = i + 1; j < boxes.length; j++) {
      assert.ok(!overlaps(boxes[i], boxes[j]), `items ${i} and ${j} overlap: ${JSON.stringify([boxes[i], boxes[j]])}`);
    }
  }
  assert.ok(boxes.slice(1).every(b => b.x >= human.x + human.w), 'batch starts right of the resized note');

  // Un segundo lote arranca pasado el borde derecho real del primero.
  const b = await callTool(ownerToken.token, 'add_whiteboard_items', { project_id: project.id, notes: [{ text: 'Otro', w: 300, h: 300 }] });
  assert.equal(b.isError, false, b.text);
  const firstRight = Math.max(...boxes.map(x => x.x + x.w));
  assert.ok(b.data.added.notes[0].x >= firstRight);

  // get_whiteboard expone la geometría (con defaults si no hay w/h).
  const summary = await callTool(ownerToken.token, 'get_whiteboard', { project_id: project.id });
  const sNote = summary.data.notes.find(n => n.id === human.id);
  assert.deepEqual([sNote.x, sNote.y, sNote.w, sNote.h], [100, 100, 900, 500]);
  const sDefault = summary.data.notes.find(n => n.id === note.id);
  assert.deepEqual([sDefault.x, sDefault.y, sDefault.w, sDefault.h], [note.x, note.y, 170, 100]);
  const sNode = summary.data.nodes[0];
  assert.deepEqual([sNode.w, sNode.h], [500, 600]);
  assert.ok(summary.data.cards.every(c => ['x', 'y', 'w', 'h'].every(k => Number.isFinite(c[k]))));
});

test('whiteboard additions on a project without a board create it, and foreign links are refused', async () => {
  const { owner, project, ownerToken } = await setup();
  const other = await createProject(owner.accessToken);
  const foreign = await createTarget(owner.accessToken, other.id, { host: 'foreign.example.com' });
  const bad = await callTool(ownerToken.token, 'add_whiteboard_items', { project_id: project.id, cards: [{ title: 'x', link: { type: 'target', id: foreign.id } }] });
  assert.equal(bad.isError, true);
  const badNode = await callTool(ownerToken.token, 'add_whiteboard_items', { project_id: project.id, nodes: [{ target_id: foreign.id }] });
  assert.equal(badNode.isError, true);
  assert.equal((await db.query(`SELECT 1 FROM whiteboard_state`)).rows.length, 0);

  const okRes = await callTool(ownerToken.token, 'add_whiteboard_items', { project_id: project.id, notes: [{ text: 'primera' }] });
  assert.equal(okRes.isError, false, okRes.text);
  const { rows: [wb] } = await db.query(`SELECT data FROM whiteboard_state WHERE project_id = $1`, [project.id]);
  assert.equal(wb.data.notes.length, 1);
  assert.deepEqual(wb.data.nodes, []);
});

test('whiteboard cards can link a finding of the project (live in get_whiteboard); foreign findings are refused', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const insertVuln = async (projectId, name, targetId = null) => (await db.query(
    `INSERT INTO custom_vulns (project_id, name, severity, target_id, created_by) VALUES ($1,$2,'high',$3,$4) RETURNING id`,
    [projectId, name, targetId, owner.user.id]
  )).rows[0].id;
  const own = await insertVuln(project.id, 'XSS reflejado', target.id);
  const other = await createProject(owner.accessToken);
  const foreign = await insertVuln(other.id, 'Ajeno');

  const bad = await callTool(ownerToken.token, 'add_whiteboard_items', {
    project_id: project.id, cards: [{ title: 'x', link: { type: 'finding', id: foreign } }],
  });
  assert.equal(bad.isError, true);
  assert.match(bad.text, /does not belong to this project/);
  assert.equal((await db.query(`SELECT 1 FROM whiteboard_state`)).rows.length, 0);

  const a = await callTool(ownerToken.token, 'add_whiteboard_items', {
    project_id: project.id,
    nodes: [{ target_id: target.id }],
    cards: [{ title: 'Hallazgo', body: 'Notas', link: { type: 'finding', id: own } }],
  });
  assert.equal(a.isError, false, a.text);
  assert.equal(a.data.added.edges.length, 1, 'a finding card is connected to its target node');
  const { rows: [wb] } = await db.query(`SELECT data FROM whiteboard_state WHERE project_id = $1`, [project.id]);
  assert.deepEqual(wb.data.cards[0].ref, { type: 'finding', id: own, target_id: target.id, label: 'XSS reflejado' });

  // get_whiteboard shows the CURRENT finding, and deleted once it is gone.
  await db.query(`UPDATE custom_vulns SET name = 'XSS almacenado', remediation_status = 'remediated' WHERE id = $1`, [own]);
  let summary = await callTool(ownerToken.token, 'get_whiteboard', { project_id: project.id });
  assert.deepEqual(summary.data.cards[0].finding, { id: own, title: 'XSS almacenado', severity: 'high', remediation_status: 'remediated' });
  assert.equal(summary.data.cards[0].link.type, 'finding');
  await db.query(`DELETE FROM custom_vulns WHERE id = $1`, [own]);
  summary = await callTool(ownerToken.token, 'get_whiteboard', { project_id: project.id });
  assert.deepEqual(summary.data.cards[0].finding, { id: own, deleted: true });
});

test('whiteboard arrows can anchor on a target endpoint or port; foreign or mismatched ones and bad styles are refused', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const t2 = await createTarget(owner.accessToken, project.id, { host: 'api.example.com' });
  const other = await createProject(owner.accessToken);
  await enableClaudeCode(owner.accessToken, other.id);
  const foreignT = await createTarget(owner.accessToken, other.id, { host: 'foreign.example.com' });

  const ep = (await callTool(ownerToken.token, 'add_endpoints', { project_id: project.id, target_id: target.id, endpoints: [{ path: '/login', method: 'POST' }] })).data.added[0].id;
  const ep2 = (await callTool(ownerToken.token, 'add_endpoints', { project_id: project.id, target_id: t2.id, endpoints: [{ path: '/v1' }] })).data.added[0].id;
  const port = (await callTool(ownerToken.token, 'add_ports', { project_id: project.id, target_id: t2.id, ports: [{ port: 443 }] })).data.added[0].id;
  const foreignEp = (await callTool(ownerToken.token, 'add_endpoints', { project_id: other.id, target_id: foreignT.id, endpoints: [{ path: '/x' }] })).data.added[0].id;

  const added = await callTool(ownerToken.token, 'add_whiteboard_items', {
    project_id: project.id, nodes: [{ target_id: target.id }, { target_id: t2.id }], notes: [{ text: 'Credenciales' }],
  });
  assert.equal(added.isError, false, added.text);
  const noteId = added.data.added.notes[0].id;
  const { rows: [before] } = await db.query(`SELECT data FROM whiteboard_state WHERE project_id = $1`, [project.id]);

  const connect = edges => callTool(ownerToken.token, 'connect_whiteboard_items', { project_id: project.id, edges });
  // Endpoint de otro proyecto, endpoint de otro target, endpoint en una nota.
  for (const edges of [
    [{ from_id: target.id, from_endpoint_id: foreignEp, to_id: noteId }],
    [{ from_id: target.id, from_endpoint_id: ep2, to_id: noteId }],
    [{ from_id: noteId, from_endpoint_id: ep, to_id: target.id }],
    [{ from_id: target.id, from_endpoint_id: ep, from_port_id: port, to_id: noteId }],
  ]) {
    const r = await connect(edges);
    assert.equal(r.isError, true, JSON.stringify(edges));
  }
  // Un style fuera de la lista lo rechaza el schema, sin escribir nada.
  const badStyle = await connect([{ from_id: target.id, to_id: noteId, style: 'wavy' }]);
  assert.equal(badStyle.isError, true);
  const badColor = await connect([{ from_id: target.id, to_id: noteId, color: 'red;x' }]);
  assert.equal(badColor.isError, true);
  const { rows: [unchanged] } = await db.query(`SELECT data FROM whiteboard_state WHERE project_id = $1`, [project.id]);
  assert.deepEqual(unchanged.data.edges, before.data.edges);

  const ok = await connect([
    { from_id: target.id, from_endpoint_id: ep, to_id: t2.id, to_port_id: port, label: 'pivot' },
    { from_id: noteId, to_id: target.id, to_endpoint_id: ep },
    // Mismo par sin endpoint: es otra conexión (al nodo, no a la fila).
    { from_id: noteId, to_id: target.id },
  ]);
  assert.equal(ok.isError, false, ok.text);
  assert.equal(ok.data.added.length, 3);
  assert.equal(ok.data.added[0].from_endpoint_id, ep);
  assert.equal(ok.data.added[0].to_port_id, port);

  // Al revés y con los mismos endpoints: duplicada.
  const dup = await connect([
    { from_id: t2.id, from_port_id: port, to_id: target.id, to_endpoint_id: ep },
    { from_id: target.id, from_endpoint_id: ep, to_id: noteId },
  ]);
  assert.equal(dup.data.added.length, 0);
  assert.equal(dup.data.skipped.length, 2);

  const { rows: [wb] } = await db.query(`SELECT data FROM whiteboard_state WHERE project_id = $1`, [project.id]);
  const stored = wb.data.edges.find(e => e.label === 'pivot');
  assert.deepEqual([stored.fromId, stored.fromEp, stored.toId, stored.toPort], [target.id, ep, t2.id, port]);
  const summary = await callTool(ownerToken.token, 'get_whiteboard', { project_id: project.id });
  const s = summary.data.edges.find(e => e.label === 'pivot');
  assert.deepEqual([s.from_endpoint_id, s.to_port_id, s.to_endpoint_id], [ep, port, null]);
});

test('whiteboard images come from your own upload, consume it, and show in get_whiteboard', async () => {
  const { project, ownerToken } = await setup();
  const up = await uploadOk(ownerToken.token);
  const res = await callTool(ownerToken.token, 'add_whiteboard_items', {
    project_id: project.id, images: [{ upload_id: up.upload_id, caption: 'Panel de login' }], notes: [{ text: 'contexto' }],
  });
  assert.equal(res.isError, false, res.text);
  const img = res.data.added.images[0];
  assert.deepEqual([img.w, img.h], [320, 240]);

  // La subida se consumió: no queda en mcp_uploads y no se puede reusar.
  assert.equal((await db.query('SELECT 1 FROM mcp_uploads WHERE id=$1', [up.upload_id])).rows.length, 0);
  const { rows: [row] } = await db.query('SELECT id, project_id, source, mime, bytes FROM whiteboard_images');
  assert.equal(row.project_id, project.id);
  assert.equal(row.source, 'claude_code');
  assert.ok(row.bytes.equals(PNG));
  const { rows: [wb] } = await db.query('SELECT data FROM whiteboard_state WHERE project_id=$1', [project.id]);
  assert.equal(wb.data.images[0].imageId, row.id);
  assert.equal(wb.data.images[0].created_by, 'claude_code');

  const again = await callTool(ownerToken.token, 'add_whiteboard_items', { project_id: project.id, images: [{ upload_id: up.upload_id }] });
  assert.equal(again.isError, true);
  assert.match(again.text, /not found/);

  const summary = await callTool(ownerToken.token, 'get_whiteboard', { project_id: project.id });
  assert.deepEqual(summary.data.images.map(i => [i.id, i.caption]), [[img.id, 'Panel de login']]);
  const note = res.data.added.notes[0];
  const edge = await callTool(ownerToken.token, 'connect_whiteboard_items', { project_id: project.id, edges: [{ from_id: note.id, to_id: img.id }] });
  assert.equal(edge.isError, false, edge.text);
  assert.equal(edge.data.added.length, 1);
});

test('whiteboard images refuse foreign, attached and expired uploads without consuming anything', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const pentester = await addMember(owner.accessToken, project.id, 'pentester');
  const pTok = await createToken(pentester.accessToken);
  const theirs = await uploadOk(pTok.token);
  const mine = await uploadOk(ownerToken.token);

  const foreign = await callTool(ownerToken.token, 'add_whiteboard_items', {
    project_id: project.id, images: [{ upload_id: mine.upload_id }, { upload_id: theirs.upload_id }],
  });
  assert.equal(foreign.isError, true);
  assert.match(foreign.text, /not found/);
  // Rollback: la subida válida del mismo lote sigue disponible.
  assert.equal((await db.query('SELECT 1 FROM mcp_uploads WHERE id=$1', [mine.upload_id])).rows.length, 1);

  const attached = await uploadOk(ownerToken.token);
  await propose(ownerToken.token, project, target, { evidence_upload_ids: [attached.upload_id] });
  const used = await callTool(ownerToken.token, 'add_whiteboard_items', { project_id: project.id, images: [{ upload_id: attached.upload_id }] });
  assert.equal(used.isError, true);
  assert.match(used.text, /already attached/);

  await db.query(`UPDATE mcp_uploads SET created_at = NOW() - INTERVAL '25 hours' WHERE id=$1`, [mine.upload_id]);
  const expired = await callTool(ownerToken.token, 'add_whiteboard_items', { project_id: project.id, images: [{ upload_id: mine.upload_id }] });
  assert.equal(expired.isError, true);
  assert.match(expired.text, /expired/);

  // Todo se revirtió: ni imágenes ni tablero.
  assert.equal((await db.query('SELECT 1 FROM whiteboard_images')).rows.length, 0);
  assert.equal((await db.query('SELECT 1 FROM whiteboard_state')).rows.length, 0);
});

// ── Cambios propuestos a hallazgos existentes (finding_update) ───────────

// Hallazgo real del proyecto creado a mano, publicado y con evidencia, para
// verificar que aprobar un cambio no toca lo que no venía en la propuesta.
async function createFinding(ownerToken, projectId, targetId, body = {}) {
  const res = await request(app).post(`/api/projects/${projectId}/vulns`).set(auth(ownerToken)).send({
    name: 'SQL injection en login', severity: 'medium', category: 'Injection',
    description: 'Original description', remediation: 'Original remediation', cwe: 'CWE-89',
    target_id: targetId, evidence: [{ data: 'data:image/png;base64,AAAA', name: 'a.png', phase: 'original' }],
    ...body,
  });
  assert.equal(res.status, 201, JSON.stringify(res.body));
  await db.query(`UPDATE custom_vulns SET client_visible = true, origin = 'manual' WHERE id = $1`, [res.body.id]);
  return res.body;
}

test('propose_finding_update leaves the finding untouched and approval applies only the changed fields', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const pentester = await addMember(owner.accessToken, project.id, 'pentester');
  const finding = await createFinding(owner.accessToken, project.id, target.id);

  const prop = await callTool(ownerToken.token, 'propose_finding_update', {
    project_id: project.id, finding_id: finding.id,
    severity: 'critical', description: 'Nueva descripción', cwe: 'CWE-89', // cwe igual al actual: se ignora
  });
  assert.equal(prop.isError, false, prop.text);
  assert.deepEqual(prop.data.proposed_fields.sort(), ['description', 'severity']);

  const { rows: [stored] } = await db.query('SELECT kind, entity_type, entity_id, target_id, payload FROM mcp_proposals WHERE id=$1', [prop.data.proposal_id]);
  assert.equal(stored.kind, 'finding_update');
  assert.equal(stored.entity_type, 'finding');
  assert.equal(stored.entity_id, finding.id);
  assert.equal(stored.target_id, target.id);
  assert.deepEqual(stored.payload, { severity: 'critical', description: 'Nueva descripción', entity_name: finding.name });

  // Hasta aprobar, el hallazgo sigue igual.
  const { rows: [before] } = await db.query('SELECT severity, description FROM custom_vulns WHERE id=$1', [finding.id]);
  assert.equal(before.severity, 'medium');
  assert.equal(before.description, 'Original description');

  const act = await db.query(`SELECT meta FROM activity_log WHERE action='claude_code_proposed'`);
  assert.equal(act.rows[0].meta.kind, 'finding_update');
  assert.deepEqual(act.rows[0].meta.fields.sort(), ['description', 'severity']);

  // El inbox trae los valores actuales para el antes/después.
  const inbox = await request(app).get(`/api/projects/${project.id}/mcp-proposals`).set(auth(pentester.accessToken));
  assert.equal(inbox.status, 200);
  assert.equal(inbox.body[0].kind, 'finding_update');
  assert.equal(inbox.body[0].current_finding.severity, 'medium');
  assert.equal(inbox.body[0].current_finding.title, finding.name);

  const res = await request(app).post(`/api/projects/${project.id}/mcp-proposals/${prop.data.proposal_id}/approve`).set(auth(pentester.accessToken));
  assert.equal(res.status, 200, JSON.stringify(res.body));
  assert.equal(res.body.resulting_vuln_id, finding.id);

  const { rows: [v] } = await db.query('SELECT * FROM custom_vulns WHERE id=$1', [finding.id]);
  assert.equal(v.severity, 'critical');
  assert.equal(v.description, 'Nueva descripción');
  assert.equal(v.name, finding.name);
  assert.equal(v.remediation, 'Original remediation');
  assert.equal(v.category, 'Injection');
  assert.equal(v.updated_by, pentester.user.id);
  assert.equal(v.client_visible, true);
  assert.equal(v.origin, 'manual');
  assert.equal(v.evidence.length, 1);
  assert.equal((await db.query('SELECT COUNT(*)::int AS n FROM custom_vulns')).rows[0].n, 1);

  const { rows: [p] } = await db.query('SELECT status, resulting_vuln_id FROM mcp_proposals WHERE id=$1', [prop.data.proposal_id]);
  assert.equal(p.status, 'approved');
  assert.equal(p.resulting_vuln_id, finding.id);
  const approved = await db.query(`SELECT meta FROM activity_log WHERE action='claude_code_proposal_approved'`);
  assert.equal(approved.rows[0].meta.via, 'claude-code');
  assert.equal(approved.rows[0].meta.kind, 'finding_update');
});

test('propose_finding_update works on a finding that came from an approved proposal', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const id = await propose(ownerToken.token, project, target);
  const ok = await request(app).post(`/api/projects/${project.id}/mcp-proposals/${id}/approve`).set(auth(owner.accessToken));
  const vulnId = ok.body.resulting_vuln_id;

  const prop = await callTool(ownerToken.token, 'propose_finding_update', { project_id: project.id, finding_id: vulnId, title: 'XSS reflejado en búsqueda', remediation: 'Codificar la salida' });
  assert.equal(prop.isError, false, prop.text);
  const res = await request(app).post(`/api/projects/${project.id}/mcp-proposals/${prop.data.proposal_id}/approve`).set(auth(owner.accessToken));
  assert.equal(res.status, 200, JSON.stringify(res.body));
  const { rows: [v] } = await db.query('SELECT name, remediation, severity, client_visible, origin FROM custom_vulns WHERE id=$1', [vulnId]);
  assert.equal(v.name, 'XSS reflejado en búsqueda');
  assert.equal(v.remediation, 'Codificar la salida');
  assert.equal(v.severity, FINDING.severity);
  assert.equal(v.client_visible, false);
  assert.equal(v.origin, 'claude_code');
});

test('a second pending change for the same finding is refused; update_proposal edits it instead', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const finding = await createFinding(owner.accessToken, project.id, target.id);
  const first = await callTool(ownerToken.token, 'propose_finding_update', { project_id: project.id, finding_id: finding.id, severity: 'high' });
  assert.equal(first.isError, false, first.text);

  const again = await callTool(ownerToken.token, 'propose_finding_update', { project_id: project.id, finding_id: finding.id, severity: 'low' });
  assert.equal(again.isError, true);
  assert.match(again.text, /already pending review/);
  assert.match(again.text, new RegExp(first.data.proposal_id));
  assert.match(again.text, /update_proposal/);

  const upd = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: first.data.proposal_id, severity: 'low', cwe: 'CWE-90' });
  assert.equal(upd.isError, false, upd.text);
  const { rows: [p] } = await db.query('SELECT payload FROM mcp_proposals WHERE id=$1', [first.data.proposal_id]);
  assert.deepEqual(p.payload, { severity: 'low', cwe: 'CWE-90', entity_name: finding.name });

  // El hallazgo al que aplica no se puede cambiar, ni otros campos ajenos.
  const moved = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: first.data.proposal_id, entity_id: target.id });
  assert.equal(moved.isError, true);
  assert.match(moved.text, /cannot be set on a finding_update proposal/);
  const ev = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: first.data.proposal_id, evidence: 'x' });
  assert.equal(ev.isError, true);

  // Sin campos, o con valores iguales a los actuales: nada que proponer.
  const other = await createFinding(owner.accessToken, project.id, target.id, { name: 'Otro hallazgo' });
  const empty = await callTool(ownerToken.token, 'propose_finding_update', { project_id: project.id, finding_id: other.id });
  assert.equal(empty.isError, true);
  assert.match(empty.text, /nothing to change/);
  const same = await callTool(ownerToken.token, 'propose_finding_update', { project_id: project.id, finding_id: other.id, severity: 'medium' });
  assert.equal(same.isError, true);
  assert.match(same.text, /already has that value/);
});

test('propose_finding_update refuses findings of other projects and duplicate titles', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const otherProject = await createProject(owner.accessToken, { name: 'Other' });
  const otherTarget = await createTarget(owner.accessToken, otherProject.id);
  const foreign = await createFinding(owner.accessToken, otherProject.id, otherTarget.id);

  const res = await callTool(ownerToken.token, 'propose_finding_update', { project_id: project.id, finding_id: foreign.id, severity: 'low' });
  assert.equal(res.isError, true);
  assert.match(res.text, /does not belong to this project/);

  const a = await createFinding(owner.accessToken, project.id, target.id, { name: 'Open redirect' });
  const b = await createFinding(owner.accessToken, project.id, target.id, { name: 'CSRF en perfil' });
  const dup = await callTool(ownerToken.token, 'propose_finding_update', { project_id: project.id, finding_id: b.id, title: ' open REDIRECT' });
  assert.equal(dup.isError, true);
  assert.match(dup.text, /already exists for this target/);
  // Renombrarse a sí mismo (otro casing) no choca consigo mismo.
  const self = await callTool(ownerToken.token, 'propose_finding_update', { project_id: project.id, finding_id: a.id, title: 'Open Redirect' });
  assert.equal(self.isError, false, self.text);

  // Un hallazgo creado con ese título mientras la propuesta esperaba bloquea la aprobación.
  const pending = await callTool(ownerToken.token, 'propose_finding_update', { project_id: project.id, finding_id: b.id, title: 'IDOR en facturas' });
  assert.equal(pending.isError, false, pending.text);
  await createFinding(owner.accessToken, project.id, target.id, { name: 'IDOR en facturas' });
  const blocked = await request(app).post(`/api/projects/${project.id}/mcp-proposals/${pending.data.proposal_id}/approve`).set(auth(owner.accessToken));
  assert.equal(blocked.status, 409);
  const { rows: [bv] } = await db.query('SELECT name FROM custom_vulns WHERE id=$1', [b.id]);
  assert.equal(bv.name, 'CSRF en perfil');
  const { rows: [bp] } = await db.query('SELECT status FROM mcp_proposals WHERE id=$1', [pending.data.proposal_id]);
  assert.equal(bp.status, 'pending');
});

test('rejecting a finding change leaves the finding unchanged; a deleted finding cannot be updated', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const finding = await createFinding(owner.accessToken, project.id, target.id);
  const prop = await callTool(ownerToken.token, 'propose_finding_update', { project_id: project.id, finding_id: finding.id, severity: 'info', remediation: 'Otra' });
  const rej = await request(app).post(`/api/projects/${project.id}/mcp-proposals/${prop.data.proposal_id}/reject`).set(auth(owner.accessToken));
  assert.equal(rej.status, 200);
  const { rows: [v] } = await db.query('SELECT severity, remediation, updated_by FROM custom_vulns WHERE id=$1', [finding.id]);
  assert.equal(v.severity, 'medium');
  assert.equal(v.remediation, 'Original remediation');

  // Rechazada, ya no bloquea una nueva propuesta para el mismo hallazgo.
  const again = await callTool(ownerToken.token, 'propose_finding_update', { project_id: project.id, finding_id: finding.id, severity: 'high' });
  assert.equal(again.isError, false, again.text);
  await db.query('DELETE FROM custom_vulns WHERE id=$1', [finding.id]);
  const gone = await request(app).post(`/api/projects/${project.id}/mcp-proposals/${again.data.proposal_id}/approve`).set(auth(owner.accessToken));
  assert.equal(gone.status, 409);
  assert.match(gone.body.error, /no longer exists/);
});

test('a read-only token or a viewer cannot propose finding changes', async () => {
  const { owner, project, target } = await setup();
  const finding = await createFinding(owner.accessToken, project.id, target.id);
  const readOnly = await createToken(owner.accessToken, { scopes: 'read' });
  const r = await callTool(readOnly.token, 'propose_finding_update', { project_id: project.id, finding_id: finding.id, severity: 'low' });
  assert.equal(r.isError, true);
  assert.match(r.text, /read-only/);
  const viewer = await addMember(owner.accessToken, project.id, 'viewer');
  const vt = await createToken(viewer.accessToken);
  const v = await callTool(vt.token, 'propose_finding_update', { project_id: project.id, finding_id: finding.id, severity: 'low' });
  assert.equal(v.isError, true);
  assert.equal((await db.query('SELECT COUNT(*)::int AS n FROM mcp_proposals')).rows[0].n, 0);
});

// ── Capturas en cambios a hallazgos existentes ─────────────────────────

const pngUrl = buf => `data:image/png;base64,${buf.toString('base64')}`;

test('propose_finding_update can carry only screenshots; approval appends them to the evidence', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const finding = await createFinding(owner.accessToken, project.id, target.id);
  const u = await uploadOk(ownerToken.token, PNG, 'nueva.png');

  const prop = await callTool(ownerToken.token, 'propose_finding_update', {
    project_id: project.id, finding_id: finding.id, evidence_upload_ids: [u.upload_id],
  });
  assert.equal(prop.isError, false, prop.text);
  assert.deepEqual(prop.data.proposed_fields, ['evidence']);
  assert.equal(prop.data.evidence_images, 1);
  const { rows: [stored] } = await db.query('SELECT payload FROM mcp_proposals WHERE id=$1', [prop.data.proposal_id]);
  assert.deepEqual(stored.payload, { entity_name: finding.name, evidence_mode: 'append' });

  // Hasta aprobar, la evidencia sigue igual.
  assert.equal((await db.query('SELECT evidence FROM custom_vulns WHERE id=$1', [finding.id])).rows[0].evidence.length, 1);
  const inbox = await request(app).get(`/api/projects/${project.id}/mcp-proposals`).set(auth(owner.accessToken));
  assert.equal(inbox.body[0].evidence_uploads.length, 1);
  assert.equal(inbox.body[0].current_finding.evidence_count, 1);
  assert.equal(inbox.body[0].current_finding.original_evidence_count, 1);

  const res = await request(app).post(`/api/projects/${project.id}/mcp-proposals/${prop.data.proposal_id}/approve`).set(auth(owner.accessToken));
  assert.equal(res.status, 200, JSON.stringify(res.body));
  const { rows: [v] } = await db.query('SELECT evidence, severity, client_visible FROM custom_vulns WHERE id=$1', [finding.id]);
  assert.deepEqual(v.evidence, [
    { data: 'data:image/png;base64,AAAA', name: 'a.png', phase: 'original' },
    { data: pngUrl(PNG), name: 'nueva.png', phase: 'original' },
  ]);
  assert.equal(v.severity, 'medium');
  assert.equal(v.client_visible, true);
  const approved = await db.query(`SELECT meta FROM activity_log WHERE action='claude_code_proposal_approved'`);
  assert.deepEqual(approved.rows[0].meta.fields, ['evidence']);
  assert.equal(approved.rows[0].meta.evidence_images, 1);
});

test('evidence_mode replace swaps the original screenshots and keeps retest ones', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const finding = await createFinding(owner.accessToken, project.id, target.id, {
    evidence: [
      { data: 'data:image/png;base64,AAAA', name: 'a.png', phase: 'original' },
      { data: 'data:image/png;base64,BBBB', name: 'b.png' },
      { data: 'data:image/png;base64,CCCC', name: 'retest.png', phase: 'retest' },
    ],
  });
  const u = await uploadOk(ownerToken.token, PNG, 'real.png');
  const prop = await callTool(ownerToken.token, 'propose_finding_update', {
    project_id: project.id, finding_id: finding.id, severity: 'high',
    evidence_upload_ids: [u.upload_id], evidence_mode: 'replace',
  });
  assert.equal(prop.isError, false, prop.text);
  assert.deepEqual(prop.data.proposed_fields.sort(), ['evidence', 'severity']);

  const res = await request(app).post(`/api/projects/${project.id}/mcp-proposals/${prop.data.proposal_id}/approve`).set(auth(owner.accessToken));
  assert.equal(res.status, 200, JSON.stringify(res.body));
  const { rows: [v] } = await db.query('SELECT evidence, severity FROM custom_vulns WHERE id=$1', [finding.id]);
  assert.equal(v.severity, 'high');
  assert.deepEqual(v.evidence, [
    { data: 'data:image/png;base64,CCCC', name: 'retest.png', phase: 'retest' },
    { data: pngUrl(PNG), name: 'real.png', phase: 'original' },
  ]);
});

test('finding change screenshots: evidence_mode needs uploads, and removing the only change is refused', async () => {
  const { owner, project, target, ownerToken } = await setup();
  const finding = await createFinding(owner.accessToken, project.id, target.id);

  const noUploads = await callTool(ownerToken.token, 'propose_finding_update', {
    project_id: project.id, finding_id: finding.id, severity: 'high', evidence_mode: 'replace',
  });
  assert.equal(noUploads.isError, true);
  assert.match(noUploads.text, /evidence_mode only applies/);

  const u = await uploadOk(ownerToken.token, PNG, 'x.png');
  const prop = await callTool(ownerToken.token, 'propose_finding_update', {
    project_id: project.id, finding_id: finding.id, evidence_upload_ids: [u.upload_id],
  });
  assert.equal(prop.isError, false, prop.text);
  const id = prop.data.proposal_id;

  // Cambiar el modo sin tocar las capturas: siguen vinculadas.
  const mode = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: id, evidence_mode: 'replace' });
  assert.equal(mode.isError, false, mode.text);
  assert.equal((await db.query('SELECT payload FROM mcp_proposals WHERE id=$1', [id])).rows[0].payload.evidence_mode, 'replace');

  // Sacar las capturas dejaría la propuesta sin cambios.
  const empty = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: id, evidence_upload_ids: [] });
  assert.equal(empty.isError, true);
  assert.match(empty.text, /would not change anything/);
  assert.equal((await db.query('SELECT COUNT(*)::int AS n FROM mcp_uploads WHERE used_by_proposal_id=$1', [id])).rows[0].n, 1);

  // Con otro cambio sí se pueden sacar, y evidence_mode desaparece del payload.
  const swap = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: id, evidence_upload_ids: [], severity: 'low' });
  assert.equal(swap.isError, false, swap.text);
  assert.deepEqual((await db.query('SELECT payload FROM mcp_proposals WHERE id=$1', [id])).rows[0].payload, { severity: 'low', entity_name: finding.name });
  assert.equal((await db.query('SELECT COUNT(*)::int AS n FROM mcp_uploads WHERE used_by_proposal_id=$1', [id])).rows[0].n, 0);
});

// ── Report sections (report_section) ─────────────────────────────────────
// Claude Code only PROPOSES the HTML of one prose field; a lead approves it
// and only that field of report_config changes.

const REPORT = {
  meta: { preparedBy: 'Diego', coverFields: { date: true } },
  sections: [
    { id: 'exec-summary', type: 'exec-summary', title: 'Resumen Ejecutivo', visible: true, description: '<p>Resumen viejo</p>' },
    { id: 'detailed-findings', type: 'detailed-findings', title: 'Hallazgos Detallados', visible: true },
    { id: 'custom-1', type: 'custom', title: 'Introduccion', visible: true, content: '<p>Intro vieja</p>' },
    {
      id: 'custom-2', type: 'custom', title: 'Clasificación de Riesgo', visible: true, content: '<p>Riesgo</p>',
      children: [
        { id: 'sub-1', title: 'Estimación', content: '<p>Estimación vieja</p>', visible: true },
        { id: 'sub-2', title: 'Factores de Amenaza', content: '<p>Factores</p>', visible: false },
      ],
    },
  ],
  vulnEdits: { 'ffffffff-ffff-4fff-8fff-ffffffffffff': { probability: 4 } },
};
const clone = o => JSON.parse(JSON.stringify(o));

async function enableReportProposals(ownerToken, projectId, value = true) {
  const res = await request(app).patch(`/api/projects/${projectId}`).set(auth(ownerToken)).send({ claude_code_report_enabled: value });
  assert.equal(res.status, 200);
  assert.equal(res.body.claude_code_report_enabled, value);
}

async function saveReport(accessToken, projectId, data = REPORT) {
  const res = await request(app).put(`/api/projects/${projectId}/report-config`).set(auth(accessToken)).send({ data });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return res.body;
}

async function reportSetup() {
  const s = await setup();
  await enableReportProposals(s.owner.accessToken, s.project.id);
  const saved = await saveReport(s.owner.accessToken, s.project.id);
  return { ...s, saved };
}

async function storedReport(projectId) {
  return (await db.query('SELECT data, updated_by, updated_at FROM report_config WHERE project_id=$1', [projectId])).rows[0];
}

function approveProposal(accessToken, projectId, id) {
  return request(app).post(`/api/projects/${projectId}/mcp-proposals/${id}/approve`).set(auth(accessToken));
}

async function proposalStatus(id) {
  return (await db.query('SELECT status FROM mcp_proposals WHERE id=$1', [id])).rows[0].status;
}

test('report tools refuse projects without claude_code_report_enabled', async () => {
  const { owner, project, ownerToken } = await setup();
  await saveReport(owner.accessToken, project.id);
  assert.equal((await db.query('SELECT claude_code_report_enabled FROM projects WHERE id=$1', [project.id])).rows[0].claude_code_report_enabled, false);

  const info = await callTool(ownerToken.token, 'get_project', { project_id: project.id });
  assert.equal(info.data.can_propose, true);
  assert.equal(info.data.can_write_report, false);

  const read = await callTool(ownerToken.token, 'get_report_sections', { project_id: project.id });
  assert.equal(read.isError, true);
  assert.match(read.text, /report proposals are not enabled/);
  const prop = await callTool(ownerToken.token, 'propose_report_section', { project_id: project.id, section_id: 'custom-1', content: '<p>x</p>' });
  assert.equal(prop.isError, true);
  assert.match(prop.text, /report proposals are not enabled/);
  assert.equal((await db.query('SELECT COUNT(*)::int AS n FROM mcp_proposals')).rows[0].n, 0);

  await enableReportProposals(owner.accessToken, project.id);
  assert.equal((await callTool(ownerToken.token, 'get_project', { project_id: project.id })).data.can_write_report, true);
  // Apagar Claude Code entero también apaga las tools del informe.
  await enableClaudeCode(owner.accessToken, project.id, false);
  assert.equal((await callTool(ownerToken.token, 'get_report_sections', { project_id: project.id })).isError, true);
});

test('only the project owner can toggle claude_code_report_enabled', async () => {
  const { owner, project } = await setup();
  const editor = await addMember(owner.accessToken, project.id, 'editor');
  const res = await request(app).patch(`/api/projects/${project.id}`).set(auth(editor.accessToken)).send({ claude_code_report_enabled: true });
  assert.equal(res.status, 403);
  assert.equal((await db.query('SELECT claude_code_report_enabled FROM projects WHERE id=$1', [project.id])).rows[0].claude_code_report_enabled, false);
  await enableReportProposals(owner.accessToken, project.id);
});

test('get_report_sections returns every section with editability and current HTML, or a hint when there is no report', async () => {
  const { owner, project, ownerToken } = await setup();
  await enableReportProposals(owner.accessToken, project.id);

  const empty = await callTool(ownerToken.token, 'get_report_sections', { project_id: project.id });
  assert.equal(empty.isError, false, empty.text);
  assert.deepEqual(empty.data.sections, []);
  assert.match(empty.data.hint, /no saved report/);

  await saveReport(owner.accessToken, project.id);
  const r = await callTool(ownerToken.token, 'get_report_sections', { project_id: project.id });
  assert.equal(r.isError, false, r.text);
  assert.deepEqual(r.data.sections.map(s => [s.id, s.type, s.editable]), [
    ['exec-summary', 'exec-summary', true], ['detailed-findings', 'detailed-findings', false],
    ['custom-1', 'custom', true], ['custom-2', 'custom', true],
  ]);
  const exec = r.data.sections[0];
  assert.equal(exec.field, 'description');
  assert.equal(exec.content, '<p>Resumen viejo</p>');
  assert.equal(r.data.sections[2].content, '<p>Intro vieja</p>');
  assert.deepEqual(r.data.sections[3].children, [
    { id: 'sub-1', title: 'Estimación', visible: true, editable: true, content: '<p>Estimación vieja</p>' },
    { id: 'sub-2', title: 'Factores de Amenaza', visible: false, editable: true, content: '<p>Factores</p>' },
  ]);
});

test('approving a subsection proposal writes only that field and refuses stale report saves', async () => {
  const { owner, project, ownerToken, saved } = await reportSetup();
  const prop = await callTool(ownerToken.token, 'propose_report_section', {
    project_id: project.id, section_id: 'custom-2', subsection_id: 'sub-1',
    content: '<p>Estimación <strong>nueva</strong></p>', rationale: 'Basado en los 3 hallazgos altos.',
  });
  assert.equal(prop.isError, false, prop.text);
  assert.equal(prop.data.section, 'Clasificación de Riesgo');
  assert.equal(prop.data.subsection, 'Estimación');

  const { rows: [row] } = await db.query('SELECT kind, payload FROM mcp_proposals WHERE id=$1', [prop.data.proposal_id]);
  assert.equal(row.kind, 'report_section');
  assert.equal(row.payload.base_content, '<p>Estimación vieja</p>');
  assert.equal(row.payload.section_title, 'Clasificación de Riesgo');
  // Proponer no toca el informe.
  assert.deepEqual((await storedReport(project.id)).data, REPORT);

  const res = await approveProposal(owner.accessToken, project.id, prop.data.proposal_id);
  assert.equal(res.status, 200, JSON.stringify(res.body));
  const after = await storedReport(project.id);
  const expected = clone(REPORT);
  expected.sections[3].children[0].content = '<p>Estimación <strong>nueva</strong></p>';
  assert.deepEqual(after.data, expected);
  assert.equal(after.updated_by, owner.user.id);
  assert.ok(new Date(after.updated_at) > new Date(saved.updated_at));
  assert.equal(await proposalStatus(prop.data.proposal_id), 'approved');

  // Una pestaña abierta con la copia anterior no pisa lo aprobado.
  const stale = await request(app).put(`/api/projects/${project.id}/report-config`).set(auth(owner.accessToken))
    .send({ data: REPORT, base_updated_at: saved.updated_at });
  assert.equal(stale.status, 409);
  assert.deepEqual(stale.body.current.data, expected);
  assert.deepEqual((await storedReport(project.id)).data, expected);
});

test('the proposals list filters by kind: the Findings inbox excludes report_section, the report builder asks only for it', async () => {
  const { owner, project, ownerToken, target } = await reportSetup();
  const finding = await propose(ownerToken.token, project, target);
  const section = await callTool(ownerToken.token, 'propose_report_section', { project_id: project.id, section_id: 'custom-1', content: '<p>Intro nueva</p>' });
  assert.equal(section.isError, false, section.text);
  const base = `/api/projects/${project.id}/mcp-proposals`;
  const ids = res => res.body.map(p => p.id);

  const all = await request(app).get(base).set(auth(owner.accessToken));
  assert.equal(all.status, 200);
  assert.deepEqual(ids(all).sort(), [finding, section.data.proposal_id].sort());

  const inbox = await request(app).get(`${base}?exclude_kind=report_section`).set(auth(owner.accessToken));
  assert.equal(inbox.status, 200);
  assert.deepEqual(ids(inbox), [finding]);

  const report = await request(app).get(`${base}?kind=report_section`).set(auth(owner.accessToken));
  assert.equal(report.status, 200);
  assert.deepEqual(ids(report), [section.data.proposal_id]);
  assert.equal(report.body[0].payload.section_title, 'Introduccion');

  // Combined with status: nothing approved yet.
  const approved = await request(app).get(`${base}?status=approved&kind=report_section`).set(auth(owner.accessToken));
  assert.deepEqual(approved.body, []);

  for (const q of ['kind=bogus', 'exclude_kind=bogus', 'kind=finding&kind=note', "kind=report_section'--"]) {
    const bad = await request(app).get(`${base}?${q}`).set(auth(owner.accessToken));
    assert.equal(bad.status, 400, q);
  }
});

test('an exec-summary proposal writes the section description', async () => {
  const { owner, project, ownerToken } = await reportSetup();
  const prop = await callTool(ownerToken.token, 'propose_report_section', {
    project_id: project.id, section_id: 'exec-summary', content: '<p>Resumen nuevo</p>',
  });
  assert.equal(prop.isError, false, prop.text);
  assert.equal(prop.data.field, 'description');
  const res = await approveProposal(owner.accessToken, project.id, prop.data.proposal_id);
  assert.equal(res.status, 200, JSON.stringify(res.body));
  const expected = clone(REPORT);
  expected.sections[0].description = '<p>Resumen nuevo</p>';
  assert.deepEqual((await storedReport(project.id)).data, expected);
});

test('propose_report_section refuses built-in, unknown and non-existent targets', async () => {
  const { project, ownerToken } = await reportSetup();
  const cases = [
    [{ section_id: 'detailed-findings' }, /generated from project data/],
    [{ section_id: 'nope' }, /does not exist/],
    [{ section_id: 'custom-2', subsection_id: 'nope' }, /does not exist/],
    [{ section_id: 'exec-summary', subsection_id: 'sub-1' }, /no editable subsections/],
  ];
  for (const [target, re] of cases) {
    const r = await callTool(ownerToken.token, 'propose_report_section', { project_id: project.id, content: '<p>x</p>', ...target });
    assert.equal(r.isError, true, JSON.stringify(target));
    assert.match(r.text, re);
  }
  assert.equal((await db.query('SELECT COUNT(*)::int AS n FROM mcp_proposals')).rows[0].n, 0);
});

test('proposed report HTML is sanitized server-side', async () => {
  const { project, ownerToken } = await reportSetup();
  const prop = await callTool(ownerToken.token, 'propose_report_section', {
    project_id: project.id, section_id: 'custom-1',
    content: '<p onclick="steal()">Hola<script>alert(1)</script> <img src=x onerror=alert(1)>' +
      '<a href="javascript:alert(1)">mal</a> <a href="https://example.com" onmouseover="x()">bien</a></p><iframe src="https://x"></iframe>',
  });
  assert.equal(prop.isError, false, prop.text);
  const { rows: [row] } = await db.query('SELECT payload FROM mcp_proposals WHERE id=$1', [prop.data.proposal_id]);
  const html = row.payload.content;
  assert.doesNotMatch(html, /<script|alert\(1\)|onerror|onclick|onmouseover|javascript:|<img|<iframe/i);
  assert.equal(html, '<p>Hola mal <a href="https://example.com" rel="noopener noreferrer">bien</a></p>');

  const blank = await callTool(ownerToken.token, 'propose_report_section', {
    project_id: project.id, section_id: 'exec-summary', content: '<script>alert(1)</script>',
  });
  assert.equal(blank.isError, true);
  assert.match(blank.text, /empty after sanitizing/);
});

test('one pending report proposal per section: duplicates refused, update_proposal and withdraw work', async () => {
  const { project, ownerToken } = await reportSetup();
  const args = { project_id: project.id, section_id: 'custom-1', content: '<p>v1</p>' };
  const first = await callTool(ownerToken.token, 'propose_report_section', args);
  assert.equal(first.isError, false, first.text);
  const id = first.data.proposal_id;

  const dup = await callTool(ownerToken.token, 'propose_report_section', { ...args, content: '<p>otra</p>' });
  assert.equal(dup.isError, true);
  assert.match(dup.text, new RegExp(`already pending review \\(proposal_id ${id}\\)`));
  // Otra sección (o subsección) no choca.
  const other = await callTool(ownerToken.token, 'propose_report_section', { project_id: project.id, section_id: 'custom-2', subsection_id: 'sub-2', content: '<p>x</p>' });
  assert.equal(other.isError, false, other.text);

  const upd = await callTool(ownerToken.token, 'update_proposal', {
    project_id: project.id, proposal_id: id, content: '<p>v2<script>x</script></p>', rationale: 'Más corto',
  });
  assert.equal(upd.isError, false, upd.text);
  assert.deepEqual(upd.data.updated_fields.sort(), ['content', 'rationale']);
  const { rows: [row] } = await db.query('SELECT payload FROM mcp_proposals WHERE id=$1', [id]);
  assert.equal(row.payload.content, '<p>v2</p>');
  assert.equal(row.payload.rationale, 'Más corto');
  assert.equal(row.payload.section_id, 'custom-1');

  const foreign = await callTool(ownerToken.token, 'update_proposal', { project_id: project.id, proposal_id: id, title: 'Otro título' });
  assert.equal(foreign.isError, true);
  assert.match(foreign.text, /cannot be set on a report_section proposal/);

  const wd = await callTool(ownerToken.token, 'withdraw_proposal', { project_id: project.id, proposal_id: id });
  assert.equal(wd.isError, false, wd.text);
  assert.equal(await proposalStatus(id), 'withdrawn');
  const again = await callTool(ownerToken.token, 'propose_report_section', args);
  assert.equal(again.isError, false, again.text);
});

test('a pentester cannot approve report content; the proposal stays pending', async () => {
  const { owner, project, ownerToken } = await reportSetup();
  const pentester = await addMember(owner.accessToken, project.id, 'pentester');
  const prop = await callTool(ownerToken.token, 'propose_report_section', { project_id: project.id, section_id: 'custom-1', content: '<p>nuevo</p>' });
  assert.equal(prop.isError, false, prop.text);

  const res = await approveProposal(pentester.accessToken, project.id, prop.data.proposal_id);
  assert.equal(res.status, 403);
  assert.equal(await proposalStatus(prop.data.proposal_id), 'pending');
  assert.deepEqual((await storedReport(project.id)).data, REPORT);

  // Un pentester con token sí puede PROPONER (es writer).
  const pTok = await createToken(pentester.accessToken);
  const pp = await callTool(pTok.token, 'propose_report_section', { project_id: project.id, section_id: 'exec-summary', content: '<p>x</p>' });
  assert.equal(pp.isError, false, pp.text);
});

test('approving after the target section was deleted fails with 409 and leaves the proposal pending', async () => {
  const { owner, project, ownerToken, saved } = await reportSetup();
  const sec = await callTool(ownerToken.token, 'propose_report_section', { project_id: project.id, section_id: 'custom-1', content: '<p>nuevo</p>' });
  const sub = await callTool(ownerToken.token, 'propose_report_section', { project_id: project.id, section_id: 'custom-2', subsection_id: 'sub-1', content: '<p>nuevo</p>' });
  assert.equal(sec.isError, false, sec.text);
  assert.equal(sub.isError, false, sub.text);

  const edited = clone(REPORT);
  edited.sections = edited.sections.filter(s => s.id !== 'custom-1');
  edited.sections.find(s => s.id === 'custom-2').children = [];
  const put = await request(app).put(`/api/projects/${project.id}/report-config`).set(auth(owner.accessToken))
    .send({ data: edited, base_updated_at: saved.updated_at });
  assert.equal(put.status, 200, JSON.stringify(put.body));

  for (const id of [sec.data.proposal_id, sub.data.proposal_id]) {
    const res = await approveProposal(owner.accessToken, project.id, id);
    assert.equal(res.status, 409, JSON.stringify(res.body));
    assert.match(res.body.error, /no longer available/);
    assert.equal(await proposalStatus(id), 'pending');
  }
  assert.deepEqual((await storedReport(project.id)).data, edited);
});
