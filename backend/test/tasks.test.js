// Task assignment + notification inbox. Pins the permission matrix server-side
// (lead creates/assigns/edits/deletes; the assignee or a lead changes status
// and comments; portal sessions get nothing) and the notification fan-out
// (right recipients, never the actor, each user sees only their own).
const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const request = require('supertest');
const { app, db, resetDb, registerUser, createProject } = require('./helpers');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

const auth = t => ({ Authorization: `Bearer ${t}` });

async function addMember(ownerToken, projectId, role) {
  const user = await registerUser();
  const inv = await request(app)
    .post(`/api/projects/${projectId}/invites`)
    .set(auth(ownerToken))
    .send({ role });
  assert.equal(inv.status, 201, `invite for ${role}: ${JSON.stringify(inv.body)}`);
  const join = await request(app)
    .post('/api/projects/join')
    .set(auth(user.accessToken))
    .send({ token: inv.body.token });
  assert.equal(join.status, 200);
  return user;
}

async function setup() {
  const owner = await registerUser();
  const project = await createProject(owner.accessToken);
  const editor     = await addMember(owner.accessToken, project.id, 'editor');
  const pentester  = await addMember(owner.accessToken, project.id, 'pentester');
  const pentester2 = await addMember(owner.accessToken, project.id, 'pentester');
  const viewer     = await addMember(owner.accessToken, project.id, 'viewer');
  return { owner, project, editor, pentester, pentester2, viewer };
}

async function createTask(token, projectId, body = {}) {
  return request(app)
    .post(`/api/projects/${projectId}/tasks`)
    .set(auth(token))
    .send({ title: 'Test the login form', description: 'Focus on **SQLi**', ...body });
}

async function notificationsOf(userId) {
  const { rows } = await db.query(
    `SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at`, [userId]
  );
  return rows;
}

test('lead creates and assigns a task; assignee is notified, actor is not', async () => {
  const { owner, project, pentester } = await setup();
  const res = await createTask(owner.accessToken, project.id, {
    assignee_id: pentester.user.id, priority: 'high', due_date: '2026-12-01',
  });
  assert.equal(res.status, 201, JSON.stringify(res.body));
  assert.equal(res.body.assignee_id, pentester.user.id);
  assert.equal(res.body.created_by, owner.user.id);
  assert.equal(res.body.status, 'pending');
  assert.equal(res.body.priority, 'high');
  assert.equal(res.body.due_date, '2026-12-01');

  const toAssignee = await notificationsOf(pentester.user.id);
  assert.equal(toAssignee.length, 1);
  assert.equal(toAssignee[0].type, 'task_assigned');
  assert.equal(toAssignee[0].entity_id, res.body.id);
  assert.equal(toAssignee[0].payload.task_title, 'Test the login form');
  assert.equal((await notificationsOf(owner.user.id)).length, 0, 'actor never notified');

  // Logged to the team activity feed
  const { rows } = await db.query(
    `SELECT action FROM activity_log WHERE project_id=$1 AND entity_type='task'`, [project.id]
  );
  assert.deepEqual(rows.map(r => r.action), ['task_created']);
});

test('assigning a task to yourself raises no notification', async () => {
  const { project, editor } = await setup();
  const res = await createTask(editor.accessToken, project.id, { assignee_id: editor.user.id });
  assert.equal(res.status, 201);
  assert.equal((await notificationsOf(editor.user.id)).length, 0);
});

test('assignee pentester can change status and comment', async () => {
  const { owner, project, pentester } = await setup();
  const task = (await createTask(owner.accessToken, project.id, { assignee_id: pentester.user.id })).body;

  const st = await request(app)
    .patch(`/api/projects/${project.id}/tasks/${task.id}`)
    .set(auth(pentester.accessToken))
    .send({ status: 'in_progress' });
  assert.equal(st.status, 200, JSON.stringify(st.body));
  assert.equal(st.body.status, 'in_progress');

  const c = await request(app)
    .post(`/api/projects/${project.id}/tasks/${task.id}/comments`)
    .set(auth(pentester.accessToken))
    .send({ body: 'Started — found a reflected param' });
  assert.equal(c.status, 201);
  assert.equal(c.body.author_username, pentester.credentials.username);

  const done = await request(app)
    .patch(`/api/projects/${project.id}/tasks/${task.id}`)
    .set(auth(pentester.accessToken))
    .send({ status: 'done' });
  assert.equal(done.status, 200);
  assert.ok(done.body.completed_at, 'completed_at set on done');

  // Creator: comment + done. Assignee (the actor): only the original assignment.
  const toOwner = await notificationsOf(owner.user.id);
  assert.deepEqual(toOwner.map(n => n.type), ['task_comment', 'task_done']);
  assert.equal(toOwner[0].actor_id, pentester.user.id);
  const toPentester = await notificationsOf(pentester.user.id);
  assert.deepEqual(toPentester.map(n => n.type), ['task_assigned']);

  const detail = await request(app)
    .get(`/api/projects/${project.id}/tasks/${task.id}`)
    .set(auth(owner.accessToken));
  assert.equal(detail.status, 200);
  assert.equal(detail.body.comments.length, 1);

  // Reopening clears completed_at
  const reopen = await request(app)
    .patch(`/api/projects/${project.id}/tasks/${task.id}`)
    .set(auth(owner.accessToken))
    .send({ status: 'pending' });
  assert.equal(reopen.status, 200);
  assert.equal(reopen.body.completed_at, null);
});

test('lead comment notifies assignee and creator once each, minus the author', async () => {
  const { owner, project, editor, pentester } = await setup();
  const task = (await createTask(owner.accessToken, project.id, { assignee_id: pentester.user.id })).body;
  await db.query('DELETE FROM notifications');

  const c = await request(app)
    .post(`/api/projects/${project.id}/tasks/${task.id}/comments`)
    .set(auth(editor.accessToken))
    .send({ body: 'Also check the reset flow' });
  assert.equal(c.status, 201);
  assert.deepEqual((await notificationsOf(pentester.user.id)).map(n => n.type), ['task_comment']);
  assert.deepEqual((await notificationsOf(owner.user.id)).map(n => n.type), ['task_comment']);
  assert.equal((await notificationsOf(editor.user.id)).length, 0);

  // Creator commenting on a task assigned to themself: nobody to notify.
  const own = (await createTask(owner.accessToken, project.id, { assignee_id: owner.user.id })).body;
  await db.query('DELETE FROM notifications');
  await request(app)
    .post(`/api/projects/${project.id}/tasks/${own.id}/comments`)
    .set(auth(owner.accessToken))
    .send({ body: 'note to self' });
  const { rows } = await db.query('SELECT COUNT(*)::int AS n FROM notifications');
  assert.equal(rows[0].n, 0);
});

test('non-assigned pentester and viewer cannot change status or comment', async () => {
  const { owner, project, pentester, pentester2, viewer } = await setup();
  const task = (await createTask(owner.accessToken, project.id, { assignee_id: pentester.user.id })).body;

  for (const [who, token] of [['pentester2', pentester2.accessToken], ['viewer', viewer.accessToken]]) {
    const st = await request(app)
      .patch(`/api/projects/${project.id}/tasks/${task.id}`)
      .set(auth(token))
      .send({ status: 'done' });
    assert.equal(st.status, 403, `${who} status`);
    const c = await request(app)
      .post(`/api/projects/${project.id}/tasks/${task.id}/comments`)
      .set(auth(token))
      .send({ body: 'hi' });
    assert.equal(c.status, 403, `${who} comment`);

    // ...a non-assigned pentester can still read; the viewer (client) cannot
    const list = await request(app).get(`/api/projects/${project.id}/tasks`).set(auth(token));
    if (who === 'viewer') { assert.equal(list.status, 403, `${who} list`); continue; }
    assert.equal(list.status, 200, `${who} list`);
    assert.equal(list.body.length, 1);
  }
  const { rows } = await db.query(`SELECT status FROM project_tasks WHERE id=$1`, [task.id]);
  assert.equal(rows[0].status, 'pending');
});

test('pentester cannot create, delete, reassign or edit a task (even their own)', async () => {
  const { owner, project, pentester, pentester2 } = await setup();
  const create = await createTask(pentester.accessToken, project.id);
  assert.equal(create.status, 403);

  const task = (await createTask(owner.accessToken, project.id, { assignee_id: pentester.user.id })).body;
  const reassign = await request(app)
    .patch(`/api/projects/${project.id}/tasks/${task.id}`)
    .set(auth(pentester.accessToken))
    .send({ assignee_id: pentester2.user.id });
  assert.equal(reassign.status, 403);
  const edit = await request(app)
    .patch(`/api/projects/${project.id}/tasks/${task.id}`)
    .set(auth(pentester.accessToken))
    .send({ title: 'Renamed', status: 'done' });
  assert.equal(edit.status, 403, 'mixing a lead-only field with status is refused as a whole');
  const del = await request(app)
    .delete(`/api/projects/${project.id}/tasks/${task.id}`)
    .set(auth(pentester.accessToken));
  assert.equal(del.status, 403);

  const { rows } = await db.query(`SELECT title, status, assignee_id FROM project_tasks WHERE id=$1`, [task.id]);
  assert.deepEqual(rows[0], { title: 'Test the login form', status: 'pending', assignee_id: pentester.user.id });
});

test('lead reassigns (new assignee notified) and deletes (inbox entries removed)', async () => {
  const { owner, project, editor, pentester, pentester2 } = await setup();
  const task = (await createTask(owner.accessToken, project.id, { assignee_id: pentester.user.id })).body;

  const r = await request(app)
    .patch(`/api/projects/${project.id}/tasks/${task.id}`)
    .set(auth(editor.accessToken))
    .send({ assignee_id: pentester2.user.id });
  assert.equal(r.status, 200);
  assert.equal(r.body.assignee_id, pentester2.user.id);
  assert.deepEqual((await notificationsOf(pentester2.user.id)).map(n => n.type), ['task_assigned']);

  // The previous assignee lost the right to change status
  const st = await request(app)
    .patch(`/api/projects/${project.id}/tasks/${task.id}`)
    .set(auth(pentester.accessToken))
    .send({ status: 'done' });
  assert.equal(st.status, 403);

  const del = await request(app)
    .delete(`/api/projects/${project.id}/tasks/${task.id}`)
    .set(auth(editor.accessToken));
  assert.equal(del.status, 200);
  const { rows } = await db.query(`SELECT COUNT(*)::int AS n FROM notifications WHERE entity_id=$1`, [task.id]);
  assert.equal(rows[0].n, 0);
});

test('assignee must be an internal member of the project', async () => {
  const { owner, project, viewer } = await setup();
  const outsider = await registerUser();
  const other = await createProject(outsider.accessToken);

  const a = await createTask(owner.accessToken, project.id, { assignee_id: outsider.user.id });
  assert.equal(a.status, 400);
  const v = await createTask(owner.accessToken, project.id, { assignee_id: viewer.user.id });
  assert.equal(v.status, 400, 'viewer (client account) is not assignable');

  const task = (await createTask(owner.accessToken, project.id)).body;
  const p = await request(app)
    .patch(`/api/projects/${project.id}/tasks/${task.id}`)
    .set(auth(owner.accessToken))
    .send({ assignee_id: outsider.user.id });
  assert.equal(p.status, 400);
  assert.equal((await notificationsOf(outsider.user.id)).length, 0);

  // Links must belong to the same project too
  const foreignTarget = await request(app)
    .post(`/api/projects/${other.id}/targets`)
    .set(auth(outsider.accessToken))
    .send({ host: 'foreign.example.com', type: 'domain' });
  assert.equal(foreignTarget.status, 201);
  const t = await createTask(owner.accessToken, project.id, { target_id: foreignTarget.body.id });
  assert.equal(t.status, 400);

  // Valid links + WSTG reference are accepted
  const own = await request(app)
    .post(`/api/projects/${project.id}/targets`)
    .set(auth(owner.accessToken))
    .send({ host: 'app.example.com', type: 'domain' });
  const ok = await createTask(owner.accessToken, project.id, { target_id: own.body.id, wstg_test_id: 'WSTG-INPV-05' });
  assert.equal(ok.status, 201);
  assert.equal(ok.body.target_host, 'app.example.com');
  assert.equal(ok.body.wstg_test_id, 'WSTG-INPV-05');
  const badWstg = await createTask(owner.accessToken, project.id, { wstg_test_id: 'nope' });
  assert.equal(badWstg.status, 400);
});

test('outsiders cannot reach a project\'s tasks', async () => {
  const { owner, project } = await setup();
  const task = (await createTask(owner.accessToken, project.id)).body;
  const outsider = await registerUser();
  const res = await request(app)
    .get(`/api/projects/${project.id}/tasks/${task.id}`)
    .set(auth(outsider.accessToken));
  assert.equal(res.status, 404);
});

test('portal session gets 403 on tasks, me/tasks and notifications', async () => {
  const { owner, project } = await setup();
  await createTask(owner.accessToken, project.id);
  const patch = await request(app)
    .patch(`/api/projects/${project.id}`)
    .set(auth(owner.accessToken))
    .send({ client_view_enabled: true, show_activity: true });
  assert.equal(patch.status, 200);
  const tok = await request(app)
    .post(`/api/projects/${project.id}/portal/token`)
    .set(auth(owner.accessToken));
  const sess = await request(app).post('/api/portal/auth').send({ token: tok.body.portal_token });
  assert.equal(sess.status, 200);
  const portal = sess.body.accessToken;

  const calls = [
    ['get',  `/api/projects/${project.id}/tasks`],
    ['post', `/api/projects/${project.id}/tasks`],
    ['get',  '/api/me/tasks'],
    ['get',  '/api/notifications'],
    ['get',  '/api/notifications/unread-count'],
    ['post', '/api/notifications/read-all'],
  ];
  for (const [method, url] of calls) {
    const res = await request(app)[method](url).set(auth(portal)).send({ title: 'x' });
    assert.equal(res.status, 403, `${method.toUpperCase()} ${url}`);
  }

  // Internal task activity is logged, but never reaches the portal's feed
  const feed = await request(app)
    .get(`/api/projects/${project.id}/activity`)
    .set(auth(portal));
  assert.equal(feed.status, 200);
  assert.equal(feed.body.filter(e => e.entity_type === 'task').length, 0);
  const teamFeed = await request(app)
    .get(`/api/projects/${project.id}/activity`)
    .set(auth(owner.accessToken));
  assert.ok(teamFeed.body.some(e => e.action === 'task_created'));
});

test('a user can only read and mark their own notifications', async () => {
  const { owner, project, pentester, pentester2 } = await setup();
  await createTask(owner.accessToken, project.id, { assignee_id: pentester.user.id });
  await createTask(owner.accessToken, project.id, { assignee_id: pentester.user.id, title: 'Second' });
  const [mine] = await notificationsOf(pentester.user.id);

  const otherList = await request(app).get('/api/notifications').set(auth(pentester2.accessToken));
  assert.equal(otherList.status, 200);
  assert.equal(otherList.body.length, 0);

  const steal = await request(app)
    .post(`/api/notifications/${mine.id}/read`)
    .set(auth(pentester2.accessToken));
  assert.equal(steal.status, 404);
  await request(app).post('/api/notifications/read-all').set(auth(pentester2.accessToken));
  const { rows } = await db.query(`SELECT COUNT(*)::int AS n FROM notifications WHERE read_at IS NOT NULL`);
  assert.equal(rows[0].n, 0, 'nobody else can mark my notifications read');

  const count = await request(app).get('/api/notifications/unread-count').set(auth(pentester.accessToken));
  assert.equal(count.body.count, 2);
  const list = await request(app).get('/api/notifications?unread=1').set(auth(pentester.accessToken));
  assert.equal(list.body.length, 2);
  assert.equal(list.body[0].payload.task_title, 'Second', 'newest first');
  assert.equal(list.body[0].actor_username, owner.credentials.username);

  const read = await request(app).post(`/api/notifications/${mine.id}/read`).set(auth(pentester.accessToken));
  assert.equal(read.status, 200);
  assert.ok(read.body.read_at);
  assert.equal((await request(app).get('/api/notifications/unread-count').set(auth(pentester.accessToken))).body.count, 1);
  const all = await request(app).post('/api/notifications/read-all').set(auth(pentester.accessToken));
  assert.equal(all.body.updated, 1);
  assert.equal((await request(app).get('/api/notifications?unread=1').set(auth(pentester.accessToken))).body.length, 0);
  assert.equal((await request(app).get('/api/notifications').set(auth(pentester.accessToken))).body.length, 2);

  const bad = await request(app).post('/api/notifications/not-a-uuid/read').set(auth(pentester.accessToken));
  assert.equal(bad.status, 404);
});

test('/me/tasks returns only my tasks from projects I can still access', async () => {
  const { owner, project, pentester, pentester2 } = await setup();
  await createTask(owner.accessToken, project.id, { assignee_id: pentester.user.id, title: 'Mine' });
  await createTask(owner.accessToken, project.id, { assignee_id: pentester2.user.id, title: 'Theirs' });
  const doneTask = (await createTask(owner.accessToken, project.id, { assignee_id: pentester.user.id, title: 'Finished' })).body;
  await request(app)
    .patch(`/api/projects/${project.id}/tasks/${doneTask.id}`)
    .set(auth(pentester.accessToken))
    .send({ status: 'done' });

  // A second project the pentester belongs to, then gets removed from
  const owner2 = await registerUser();
  const project2 = await createProject(owner2.accessToken, { name: 'Other engagement' });
  const inv = await request(app)
    .post(`/api/projects/${project2.id}/invites`).set(auth(owner2.accessToken)).send({ role: 'pentester' });
  await request(app).post('/api/projects/join').set(auth(pentester.accessToken)).send({ token: inv.body.token });
  await createTask(owner2.accessToken, project2.id, { assignee_id: pentester.user.id, title: 'Elsewhere' });

  let res = await request(app).get('/api/me/tasks').set(auth(pentester.accessToken));
  assert.equal(res.status, 200);
  assert.deepEqual(res.body.map(t => t.title).sort(), ['Elsewhere', 'Mine']);
  assert.ok(res.body.every(t => t.project_name));

  res = await request(app).get('/api/me/tasks?include_done=1').set(auth(pentester.accessToken));
  assert.deepEqual(res.body.map(t => t.title).sort(), ['Elsewhere', 'Finished', 'Mine']);

  await db.query(`DELETE FROM project_members WHERE project_id=$1 AND user_id=$2`, [project2.id, pentester.user.id]);
  res = await request(app).get('/api/me/tasks').set(auth(pentester.accessToken));
  assert.deepEqual(res.body.map(t => t.title), ['Mine']);
  // ...and its notification disappears from the inbox with the access
  const inbox = await request(app).get('/api/notifications').set(auth(pentester.accessToken));
  assert.ok(inbox.body.every(n => n.project_id === project.id));
});

test('task migrations are idempotent and their CHECK constraints still bite', async () => {
  const MIGRATE = path.join(__dirname, '..', 'src', 'db', 'migrate.js');
  const run = () => execFileSync(process.execPath, [MIGRATE], {
    env: { ...process.env, DB_NAME: process.env.DB_NAME }, stdio: 'pipe',
  });
  run(); run();

  const { rows: cons } = await db.query(`
    SELECT con.conname FROM pg_constraint con
    JOIN pg_class rel ON rel.oid = con.conrelid
    WHERE con.contype = 'c' AND rel.relname IN ('project_tasks','task_comments','notifications')
    ORDER BY 1`);
  assert.deepEqual(cons.map(r => r.conname), ['project_tasks_priority_check', 'project_tasks_status_check']);

  const { owner, project } = await setup();
  await assert.rejects(
    db.query(`INSERT INTO project_tasks (project_id, title, status, created_by) VALUES ($1,'x','bogus',$2)`,
      [project.id, owner.user.id]),
    /violates check constraint/
  );
});

test('notifications are pushed live over WS only to the recipient', async () => {
  const http = require('node:http');
  const WebSocket = require('ws');
  const wsService = require('../src/services/ws');
  const { owner, project, pentester, pentester2 } = await setup();

  const server = http.createServer(app);
  wsService.setup(server);
  await new Promise(r => server.listen(0, r));
  const { port } = server.address();

  const connect = token => new Promise((resolve, reject) => {
    const sock = new WebSocket(`ws://127.0.0.1:${port}/ws?projectId=${project.id}`);
    sock.received = [];
    sock.on('message', d => {
      const msg = JSON.parse(d);
      if (msg.type === 'auth_ok') resolve(sock);
      sock.received.push(msg);
    });
    sock.on('open', () => sock.send(JSON.stringify({ type: 'auth', token })));
    sock.on('error', reject);
  });

  const recipient = await connect(pentester.accessToken);
  const bystander = await connect(pentester2.accessToken);
  const actor     = await connect(owner.accessToken);
  try {
    const res = await createTask(owner.accessToken, project.id, { assignee_id: pentester.user.id });
    assert.equal(res.status, 201);
    await new Promise(r => setTimeout(r, 200));
    const only = s => s.received.filter(m => m.type === 'notification');
    assert.equal(only(recipient).length, 1);
    assert.equal(only(recipient)[0].notification.type, 'task_assigned');
    assert.equal(only(recipient)[0].notification.actor_username, owner.credentials.username);
    assert.equal(only(bystander).length, 0);
    assert.equal(only(actor).length, 0);
  } finally {
    [recipient, bystander, actor].forEach(s => s.close());
    await new Promise(r => server.close(r));
  }
});

test('viewer (client account) cannot read internal tasks', async () => {
  const { owner, project, pentester, viewer } = await setup();
  const created = await createTask(owner.accessToken, project.id, { assignee_id: pentester.user.id });
  assert.equal(created.status, 201);
  const list = await request(app)
    .get(`/api/projects/${project.id}/tasks`)
    .set({ Authorization: `Bearer ${viewer.accessToken}` });
  assert.equal(list.status, 403);
  const one = await request(app)
    .get(`/api/projects/${project.id}/tasks/${created.body.id}`)
    .set({ Authorization: `Bearer ${viewer.accessToken}` });
  assert.equal(one.status, 403);
});
