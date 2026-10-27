// AI agent over the real WebSocket server: joining a project room only needs
// membership, but operating the agent (ai_scan:* messages) needs a writer role,
// same as the REST routes.
const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { WebSocket } = require('ws');
const { app, db, resetDb, registerUser, createProject } = require('./helpers');
const wsService = require('../src/services/ws');
const agentLoop = require('../src/services/ai/agentLoop');

let server, port;
before(async () => {
  await resetDb();
  server = http.createServer(app);
  wsService.setup(server);
  await new Promise(resolve => server.listen(0, resolve));
  port = server.address().port;
});
beforeEach(async () => { await resetDb(); });
after(async () => {
  await new Promise(resolve => server.close(resolve));
  await db.pool.end();
});

async function connect(projectId, token) {
  const socket = new WebSocket(`ws://127.0.0.1:${port}/ws?projectId=${projectId}`);
  await new Promise((resolve, reject) => { socket.once('open', resolve); socket.once('error', reject); });
  socket.send(JSON.stringify({ type: 'auth', token }));
  await new Promise((resolve, reject) => {
    socket.on('message', data => { if (JSON.parse(data).type === 'auth_ok') resolve(); });
    socket.once('close', code => reject(new Error(`closed ${code}`)));
  });
  return socket;
}

async function setup() {
  const owner = await registerUser();
  const project = await createProject(owner.accessToken);
  const viewer = await registerUser();
  await db.query(`INSERT INTO project_members (project_id, user_id, role) VALUES ($1,$2,'viewer')`, [project.id, viewer.user.id]);
  const { session } = await agentLoop.createSessionWithPrimaryThread(project.id, null, owner.user.id, 'en', null);
  // idle, so a pause from anyone allowed would be visible right away
  await db.query(`UPDATE ai_scan_sessions SET status='idle' WHERE id=$1`, [session.id]);
  return { owner, viewer, project, session };
}

const statusOf = async id => (await db.query(`SELECT status FROM ai_scan_sessions WHERE id=$1`, [id])).rows[0].status;
const sleep = ms => new Promise(r => setTimeout(r, ms));

test('canOperateAiScan: writer roles yes, viewers and outsiders no', async () => {
  const { owner, viewer, project } = await setup();
  const outsider = await registerUser();
  assert.equal(await wsService.canOperateAiScan(owner.user.id, project.id), true);
  assert.equal(await wsService.canOperateAiScan(viewer.user.id, project.id), false);
  assert.equal(await wsService.canOperateAiScan(outsider.user.id, project.id), false);
  await db.query(`UPDATE project_members SET role='pentester' WHERE project_id=$1 AND user_id=$2`, [project.id, viewer.user.id]);
  assert.equal(await wsService.canOperateAiScan(viewer.user.id, project.id), true);
});

test('a viewer can join the room but cannot operate the agent', async () => {
  const { owner, viewer, project, session } = await setup();

  const viewerSocket = await connect(project.id, viewer.accessToken);
  viewerSocket.send(JSON.stringify({ type: 'ai_scan:pause', session_id: session.id }));
  viewerSocket.send(JSON.stringify({ type: 'ai_scan:send_message', session_id: session.id, text: 'hi' }));
  await sleep(300);
  assert.equal(await statusOf(session.id), 'idle');
  const { rows } = await db.query(`SELECT 1 FROM ai_scan_events WHERE session_id=$1 AND type='chat.message'`, [session.id]);
  assert.equal(rows.length, 0);
  viewerSocket.close();

  const ownerSocket = await connect(project.id, owner.accessToken);
  ownerSocket.send(JSON.stringify({ type: 'ai_scan:pause', session_id: session.id }));
  for (let i = 0; i < 30 && (await statusOf(session.id)) !== 'paused'; i++) await sleep(50);
  assert.equal(await statusOf(session.id), 'paused');
  ownerSocket.close();
});

// Junta los mensajes de un tipo que le llegan a un socket ya autenticado.
function collect(socket, type) {
  const got = [];
  socket.on('message', data => { const m = JSON.parse(data); if (m.type === type) got.push(m); });
  return got;
}

test('editing a finding pings writers with vulns:changed, never the client socket', async () => {
  const { owner, viewer, project } = await setup();
  const { rows: [vuln] } = await db.query(
    `INSERT INTO custom_vulns (project_id, name, category, severity, created_by) VALUES ($1,'XSS','XSS','high',$2) RETURNING id`,
    [project.id, owner.user.id]
  );
  const ownerSocket  = await connect(project.id, owner.accessToken);
  const viewerSocket = await connect(project.id, viewer.accessToken);
  const toOwner = collect(ownerSocket, 'vulns:changed');
  const toViewer = collect(viewerSocket, 'vulns:changed');

  const res = await require('supertest')(app).patch(`/api/projects/${project.id}/vulns/${vuln.id}`)
    .set('Authorization', `Bearer ${owner.accessToken}`).send({ description: 'updated' });
  assert.equal(res.status, 200);
  for (let i = 0; i < 30 && !toOwner.length; i++) await sleep(25);
  await sleep(100);
  assert.equal(toOwner.length, 1);
  assert.equal(toViewer.length, 0);
  ownerSocket.close();
  viewerSocket.close();
});

test('a proposal status change broadcasts the pending count to writers only, report proposals counted apart', async () => {
  const { owner, viewer, project } = await setup();
  const proposals = require('../src/services/mcp/proposals');
  const { rows: [p] } = await db.query(
    `INSERT INTO mcp_proposals (project_id, kind, payload, proposed_by) VALUES ($1,'note',$2,$3) RETURNING id`,
    [project.id, JSON.stringify({ text: 'n', entity_name: 'x' }), owner.user.id]
  );
  await db.query(
    `INSERT INTO mcp_proposals (project_id, kind, payload, proposed_by) VALUES ($1,'note',$2,$3)`,
    [project.id, JSON.stringify({ text: 'n2', entity_name: 'x' }), owner.user.id]
  );
  // Reviewed in the report builder: not part of the Findings count.
  await db.query(
    `INSERT INTO mcp_proposals (project_id, kind, payload, proposed_by) VALUES ($1,'report_section',$2,$3)`,
    [project.id, JSON.stringify({ section_id: 'custom-1', field: 'content', content: '<p>x</p>' }), owner.user.id]
  );
  const ownerSocket  = await connect(project.id, owner.accessToken);
  const viewerSocket = await connect(project.id, viewer.accessToken);
  const toOwner = collect(ownerSocket, 'mcp_proposals:changed');
  const toViewer = collect(viewerSocket, 'mcp_proposals:changed');

  await proposals.rejectProposal({ projectId: project.id, proposalId: p.id, user: { id: owner.user.id, username: owner.user.username } });
  for (let i = 0; i < 30 && !toOwner.length; i++) await sleep(25);
  await sleep(100);
  assert.deepEqual(toOwner.map(m => [m.pending, m.report_pending]), [[1, 1]]);
  assert.equal(toViewer.length, 0);
  ownerSocket.close();
  viewerSocket.close();
});

test('whiteboard additions from Claude Code reach writer sockets as wb:patch items_add, never the client', async () => {
  const { owner, viewer, project } = await setup();
  const wb = require('../src/services/mcp/whiteboard');
  const ownerSocket  = await connect(project.id, owner.accessToken);
  const viewerSocket = await connect(project.id, viewer.accessToken);
  const toOwner = collect(ownerSocket, 'wb:patch');
  const toViewer = collect(viewerSocket, 'wb:patch');

  await wb.addItems({ projectId: project.id, user: { id: owner.user.id, username: owner.user.username }, notes: [{ text: 'hola' }] });
  for (let i = 0; i < 30 && !toOwner.length; i++) await sleep(25);
  await sleep(100);
  assert.equal(toOwner.length, 1);
  assert.equal(toOwner[0].op, 'items_add');
  assert.equal(toOwner[0].notes[0].text, 'hola');
  assert.equal(toOwner[0].notes[0].created_by, 'claude_code');
  assert.equal(toViewer.length, 0);
  ownerSocket.close();
  viewerSocket.close();
});
