// PUT /whiteboard guarda un blob que dibuja el navegador de cada miembro: lo
// que se fija acá es que solo sobreviven campos conocidos con colores de la
// allowlist (un color con markup era XSS almacenado), sin romper un tablero legítimo.
const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { app, db, resetDb, registerUser, createProject } = require('./helpers');

before(async () => { await resetDb(); });
beforeEach(async () => { await resetDb(); });
after(async () => { await db.pool.end(); });

const auth = t => ({ Authorization: `Bearer ${t}` });

async function setup() {
  const owner = await registerUser();
  const project = await createProject(owner.accessToken);
  const target = (await request(app).post(`/api/projects/${project.id}/targets`).set(auth(owner.accessToken))
    .send({ host: 'app.example.com', type: 'domain' })).body;
  return { owner, project, target };
}

const put = (owner, project, data) =>
  request(app).put(`/api/projects/${project.id}/whiteboard`).set(auth(owner.accessToken)).send({ data });

test('a legit full board round-trips unchanged', async () => {
  const { owner, project, target } = await setup();
  const card = '22222222-2222-4222-8222-222222222222';
  const board = {
    nodes: [
      { id: target.id, x: 80, y: 80, collapsed: false },
      { id: '33333333-3333-4333-8333-333333333333', x: 400, y: 80, w: 320, h: 200, collapsed: true, created_by: 'claude_code' },
    ],
    notes: [{ id: '11111111-1111-4111-8111-111111111111', x: 500, y: 100, text: 'humano\n**md**', color: '#a8edab', created_by: 'claude_code' }],
    cards: [{
      id: card, x: 100.5, y: -600, w: 260, h: 140, title: 'TLS', body: '# Revisar\n- cifrados', color: '#5f1e1e',
      ref: { type: 'port', id: '44444444-4444-4444-8444-444444444444', target_id: target.id, label: 'app.example.com:443/tcp' },
      created_by: 'claude_code',
    }],
    edges: [
      { id: 'e1', fromId: card, toId: target.id, label: 'expone', created_by: 'claude_code' },
      {
        id: 'e2', fromId: target.id, fromEp: '55555555-5555-4555-8555-555555555555', toId: card,
        toPort: '44444444-4444-4444-8444-444444444444', label: '', style: 'dotted', arrow: 'both', color: '#1e88e5',
      },
    ],
    strokes: [
      { id: 's1', d: 'M 900 50 L 950 60', color: '#e94141', width: 2 },
      { id: 's2', d: 'M-12.5,40.0 L13.1,-2.4', color: 'var(--t1)', width: 8 },
    ],
    view: { panX: -120.5, panY: 33, zoom: 0.75 },
  };
  const res = await put(owner, project, board);
  assert.equal(res.status, 200, JSON.stringify(res.body));
  assert.deepEqual(res.body.data, board);

  const get = await request(app).get(`/api/projects/${project.id}/whiteboard`).set(auth(owner.accessToken));
  assert.deepEqual(get.body.data, board);
});

test('malicious colors, unknown fields and unsafe stroke paths are neutralised', async () => {
  const { owner, project } = await setup();
  const xss = '"><img src=x onerror=alert(1)>';
  const res = await put(owner, project, {
    cards: [{ id: 'c1', x: '10;color:red', y: 5, title: 'T', color: xss, onclick: 'alert(1)' }],
    notes: [{ id: 'n1', x: 1, y: 2, text: 'hola', color: 'url(https://evil.example/x)' }],
    strokes: [
      { id: 's1', d: 'M 1 1 L 2 2', color: xss, width: 'big' },
      { id: 's2', d: 'M 1 1"/><script>alert(1)</script>', color: '#fff', width: 2 },
    ],
    edges: [{ id: 'e1', fromId: 'c1', toId: '"]x', label: 'l' }],
    nodes: [{ id: 'bad"id', x: 0, y: 0 }],
    view: { panX: 'x', panY: 3, zoom: -1, extra: 1 },
    evil: '<script>',
  });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  const d = res.body.data;
  assert.deepEqual(d.cards, [{ id: 'c1', x: 0, y: 5, title: 'T', color: '#1e3a5f' }]);
  assert.equal(d.notes[0].color, '#ffd96a');
  assert.deepEqual(d.strokes, [{ id: 's1', d: 'M 1 1 L 2 2', color: '#e94141', width: 2 }]);
  assert.deepEqual(d.edges, []);
  assert.deepEqual(d.nodes, []);
  assert.deepEqual(d.view, { panX: 0, panY: 3, zoom: 1 });
  assert.equal(d.evil, undefined);
});

test('edge style fields and endpoint anchors are kept only when valid', async () => {
  const { owner, project, target } = await setup();
  const xss = '"><img src=x onerror=alert(1)>';
  const res = await put(owner, project, {
    edges: [
      { id: 'e1', fromId: target.id, toId: 'n1', fromEp: xss, toEp: 'ep-2', fromPort: 'bad id', toPort: 'p_1',
        style: xss, arrow: 'sideways', color: 'red' },
      { id: 'e2', fromId: 'n1', toId: target.id, style: 'dashed', arrow: 'none', color: '#8e24aa' },
      { id: 'e3', fromId: 'n1', toId: target.id, style: 'DASHED', arrow: ['end'], color: '#E53935' },
    ],
  });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  const d = res.body.data;
  assert.deepEqual(d.edges[0], { id: 'e1', fromId: target.id, toId: 'n1', toEp: 'ep-2', toPort: 'p_1' });
  assert.deepEqual(d.edges[1], { id: 'e2', fromId: 'n1', toId: target.id, style: 'dashed', arrow: 'none', color: '#8e24aa' });
  assert.deepEqual(d.edges[2], { id: 'e3', fromId: 'n1', toId: target.id });
});

test('item sizes: notes keep w/h, and w/h of every type are clamped or dropped', async () => {
  const { owner, project, target } = await setup();
  const res = await put(owner, project, {
    nodes: [{ id: target.id, x: 0, y: 0, w: 1e9, h: 5 }],
    cards: [{ id: 'c1', x: 0, y: 0, w: 'wide', h: 300, title: 'T', color: '#1e3a5f' }],
    notes: [
      { id: 'n1', x: 1, y: 2, w: 240, h: 180, text: 'grande', color: '#ffd96a' },
      { id: 'n2', x: 1, y: 2, w: -10, h: null, text: 'mal', color: '#ffd96a' },
    ],
  });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  const d = res.body.data;
  assert.deepEqual(d.nodes[0], { id: target.id, x: 0, y: 0, w: 4000, h: 60 });
  assert.deepEqual(d.cards[0], { id: 'c1', x: 0, y: 0, h: 300, title: 'T', color: '#1e3a5f' });
  assert.deepEqual(d.notes[0], { id: 'n1', x: 1, y: 2, w: 240, h: 180, text: 'grande', color: '#ffd96a' });
  assert.deepEqual(d.notes[1], { id: 'n2', x: 1, y: 2, w: 60, text: 'mal', color: '#ffd96a' });
});

test('non-object data is rejected with 400 and nothing is stored', async () => {
  const { owner, project } = await setup();
  for (const data of ['<svg onload=alert(1)>', [], 42]) {
    const res = await put(owner, project, data);
    assert.equal(res.status, 400, `data=${JSON.stringify(data)}`);
  }
  assert.equal((await db.query(`SELECT 1 FROM whiteboard_state`)).rows.length, 0);
});

// ── Imágenes (POST/GET /whiteboard/images) ──────────────────────────────

function pngOf(w, h) {
  const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    u32(13), Buffer.from('IHDR'), u32(w), u32(h), Buffer.from([8, 6, 0, 0, 0]), u32(0),
  ]);
}
const PNG = pngOf(640, 480);

async function addMember(ownerToken, projectId, role) {
  const user = await registerUser();
  const inv = await request(app).post(`/api/projects/${projectId}/invites`).set(auth(ownerToken)).send({ role });
  assert.equal(inv.status, 201);
  const join = await request(app).post('/api/projects/join').set(auth(user.accessToken)).send({ token: inv.body.token });
  assert.equal(join.status, 200);
  return user;
}

const uploadImage = (token, project, buf, name = 'shot.png', contentType = 'image/png') =>
  request(app).post(`/api/projects/${project.id}/whiteboard/images`).set(auth(token))
    .attach('file', buf, { filename: name, contentType });
const getImage = (token, project, id) =>
  request(app).get(`/api/projects/${project.id}/whiteboard/images/${id}`).set(auth(token))
    .buffer(true).parse((res, cb) => { const c = []; res.on('data', d => c.push(d)); res.on('end', () => cb(null, Buffer.concat(c))); });

test('images upload by magic bytes and are served with locked-down headers', async () => {
  const { owner, project } = await setup();
  const up = await uploadImage(owner.accessToken, project, PNG, 'x.gif', 'image/gif');
  assert.equal(up.status, 201, JSON.stringify(up.body));
  assert.deepEqual(Object.keys(up.body).sort(), ['height', 'id', 'mime', 'size', 'width']);
  assert.equal(up.body.mime, 'image/png');
  assert.equal(up.body.size, PNG.length);
  assert.equal(up.body.width, 640);
  assert.equal(up.body.height, 480);

  const res = await getImage(owner.accessToken, project, up.body.id);
  assert.equal(res.status, 200);
  assert.equal(res.headers['content-type'], 'image/png');
  assert.equal(res.headers['x-content-type-options'], 'nosniff');
  assert.equal(res.headers['content-disposition'], 'inline');
  assert.match(res.headers['cache-control'], /^private/);
  assert.match(res.headers['content-security-policy'], /^default-src 'none'/);
  assert.ok(res.body.equals(PNG));
});

test('non-images and SVG are rejected, and nothing is stored', async () => {
  const { owner, project } = await setup();
  const svg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><rect/></svg>');
  for (const [buf, name, type] of [
    [svg, 'a.svg', 'image/svg+xml'],
    [Buffer.from('<html><script>alert(1)</script></html>'), 'a.png', 'image/png'],
    [Buffer.from('GIF89a-not-allowed-here'), 'a.gif', 'image/gif'],
  ]) {
    const res = await uploadImage(owner.accessToken, project, buf, name, type);
    assert.equal(res.status, 415, name);
  }
  const big = await uploadImage(owner.accessToken, project, Buffer.concat([PNG, Buffer.alloc(4 * 1024 * 1024)]));
  assert.equal(big.status, 413);
  const none = await request(app).post(`/api/projects/${project.id}/whiteboard/images`).set(auth(owner.accessToken)).field('x', '1');
  assert.equal(none.status, 400);
  assert.equal((await db.query('SELECT 1 FROM whiteboard_images')).rows.length, 0);
});

test('viewers (client accounts) and non-members cannot upload or read images; pentesters can', async () => {
  const { owner, project } = await setup();
  const id = (await uploadImage(owner.accessToken, project, PNG)).body.id;
  const viewer = await addMember(owner.accessToken, project.id, 'viewer');
  const pentester = await addMember(owner.accessToken, project.id, 'pentester');
  const stranger = await registerUser();

  assert.equal((await uploadImage(viewer.accessToken, project, PNG)).status, 403);
  assert.equal((await getImage(viewer.accessToken, project, id)).status, 403);
  assert.equal((await uploadImage(stranger.accessToken, project, PNG)).status, 404);
  assert.equal((await getImage(stranger.accessToken, project, id)).status, 404);
  assert.equal((await uploadImage(pentester.accessToken, project, PNG)).status, 201);
  assert.equal((await getImage(pentester.accessToken, project, id)).status, 200);
});

test('an image is only served through its own project', async () => {
  const { owner, project } = await setup();
  const other = await createProject(owner.accessToken);
  const id = (await uploadImage(owner.accessToken, project, PNG)).body.id;
  assert.equal((await getImage(owner.accessToken, other, id)).status, 404);
  assert.equal((await getImage(owner.accessToken, project, 'not-a-uuid')).status, 404);
  assert.equal((await getImage(owner.accessToken, project, '00000000-0000-4000-8000-000000000000')).status, 404);
});

test('uploading sweeps old unreferenced images but keeps referenced and recent ones', async () => {
  const { owner, project } = await setup();
  const ids = [];
  for (let i = 0; i < 3; i++) ids.push((await uploadImage(owner.accessToken, project, PNG)).body.id);
  await db.query(`UPDATE whiteboard_images SET created_at = NOW() - INTERVAL '25 hours' WHERE id = ANY($1::uuid[])`, [ids.slice(0, 2)]);
  const saved = await put(owner, project, { images: [{ id: 'img1', imageId: ids[0], x: 0, y: 0, w: 320, h: 240 }] });
  assert.equal(saved.status, 200, JSON.stringify(saved.body));

  const fresh = (await uploadImage(owner.accessToken, project, PNG)).body.id;
  const { rows } = await db.query('SELECT id FROM whiteboard_images WHERE project_id = $1', [project.id]);
  assert.deepEqual(rows.map(r => r.id).sort(), [ids[0], ids[2], fresh].sort());
});

test('per-project image cap is enforced', async () => {
  const { owner, project } = await setup();
  await db.query(
    `INSERT INTO whiteboard_images (project_id, mime, bytes, size)
     SELECT $1, 'image/png', '\\x00'::bytea, 1 FROM generate_series(1, 300)`,
    [project.id]
  );
  const res = await uploadImage(owner.accessToken, project, PNG);
  assert.equal(res.status, 409);
  assert.match(res.body.error, /300/);
});

test('board image items keep only known fields and need a valid imageId', async () => {
  const { owner, project } = await setup();
  const imageId = '66666666-6666-4666-8666-666666666666';
  const res = await put(owner, project, {
    images: [
      { id: 'i1', imageId, x: 10, y: 20, w: 320, h: 240, caption: 'captura <b>', created_by: 'claude_code', src: 'javascript:alert(1)' },
      { id: 'i2', imageId: '../../etc/passwd', x: 0, y: 0 },
      { id: 'i3', x: 0, y: 0 },
      { id: 'i4', imageId, x: 'x', y: 0, w: 1, h: 1e9, caption: 'x'.repeat(600) },
    ],
  });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  const d = res.body.data;
  assert.equal(d.images.length, 2);
  assert.deepEqual(d.images[0], { id: 'i1', imageId, x: 10, y: 20, w: 320, h: 240, caption: 'captura <b>', created_by: 'claude_code' });
  assert.deepEqual(d.images[1], { id: 'i4', imageId, x: 0, y: 0, w: 60, h: 4000, caption: 'x'.repeat(500) });
});
