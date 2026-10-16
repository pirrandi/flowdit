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
