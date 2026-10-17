// Integración con Claude Code (servidor MCP en /mcp). Lo que se fija acá es la
// frontera de seguridad: los tokens fdt_ solo abren /mcp (nunca /api), un
// proyecto sin opt-in es invisible, un viewer lee pero no propone, el scope
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
    'get_finding', 'get_project', 'get_upload_instructions', 'list_endpoints', 'list_findings',
    'list_my_proposals', 'list_ports', 'list_projects', 'list_targets', 'propose_finding',
    'propose_note', 'update_proposal', 'withdraw_proposal',
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

test('viewer can read but cannot propose', async () => {
  const { owner, project, target } = await setup();
  const viewer = await addMember(owner.accessToken, project.id, 'viewer');
  const tok = await createToken(viewer.accessToken);

  const targets = await callTool(tok.token, 'list_targets', { project_id: project.id });
  assert.equal(targets.isError, false);
  assert.equal(targets.data.targets[0].id, target.id);

  const prop = await callTool(tok.token, 'propose_finding', { project_id: project.id, target_id: target.id, ...FINDING });
  assert.equal(prop.isError, true);
  assert.match(prop.text, /role in this project is "viewer"/);
  const { rows } = await db.query('SELECT COUNT(*)::int AS n FROM mcp_proposals');
  assert.equal(rows[0].n, 0);
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
