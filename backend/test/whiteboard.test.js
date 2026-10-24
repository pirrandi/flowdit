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

test('card refs: finding is an allowed type; unknown types drop the ref and bad ids are dropped', async () => {
  const { owner, project, target } = await setup();
  const finding = '66666666-6666-4666-8666-666666666666';
  const xss = '"><img src=x onerror=alert(1)>';
  const card = (id, ref) => ({ id, x: 0, y: 0, title: 'T', color: '#1e3a5f', ref });
  const res = await put(owner, project, {
    cards: [
      card('c1', { type: 'finding', id: finding, target_id: target.id, label: 'XSS', extra: 1 }),
      card('c2', { type: 'finding', id: finding, target_id: null }),
      card('c3', { type: 'script', id: finding }),
      card('c4', { type: 'finding', id: xss, target_id: xss, label: 'x' }),
    ],
  });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  const d = res.body.data;
  assert.deepEqual(d.cards[0].ref, { type: 'finding', id: finding, target_id: target.id, label: 'XSS' });
  assert.deepEqual(d.cards[1].ref, { type: 'finding', id: finding, target_id: null });
  assert.equal(d.cards[2].ref, undefined);
  assert.deepEqual(d.cards[3].ref, { type: 'finding', label: 'x' });
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

// ── Sync por ítem (services/whiteboardSync.js) ──────────────────────────
// Cada pestaña manda su revisión base, lo que cambió y lo que borró; el
// servidor mezcla ítem por ítem. Lo que se fija acá: un PUT con datos viejos
// (pestaña desconectada, whiteboard.js viejo en caché) no resucita lo borrado
// ni pisa lo que otros cambiaron o agregaron.
const wbSync = require('../src/services/whiteboardSync');
const mcpWhiteboard = require('../src/services/mcp/whiteboard');

const syncPut = (owner, project, body) =>
  request(app).put(`/api/projects/${project.id}/whiteboard`).set(auth(owner.accessToken)).send(body);
const getBoard = (owner, project, query = '') =>
  request(app).get(`/api/projects/${project.id}/whiteboard${query}`).set(auth(owner.accessToken));

const note = (id, extra = {}) => ({ id, x: 10, y: 20, text: id, color: '#ffd96a', ...extra });

// Tablero con dos notas guardado por una pestaña nueva; devuelve su revisión.
async function seedBoard(owner, project) {
  const res = await syncPut(owner, project, { base_revision: 0, data: { notes: [note('n1'), note('n2')] } });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  assert.equal(res.body.full, false);
  assert.deepEqual(res.body.changes.notes.map(n => n.id), ['n1', 'n2']);
  return res.body.revision;
}

test('a stale PUT cannot resurrect an item deleted after its base revision', async () => {
  const { owner, project } = await setup();
  const base = await seedBoard(owner, project);

  const del = await syncPut(owner, project, { base_revision: base, data: {}, removed: { notes: ['n1'] } });
  assert.equal(del.status, 200, JSON.stringify(del.body));
  assert.ok(del.body.revision > base);

  // Otra pestaña, todavía en `base`, edita n1 (que para ella sigue vivo).
  const stale = await syncPut(owner, project, { base_revision: base, data: { notes: [note('n1', { text: 'editada' })] } });
  assert.equal(stale.status, 200);
  assert.deepEqual(stale.body.deleted.notes, ['n1'], 'the stale tab is told to drop it');
  // Y un whiteboard.js viejo que manda el tablero entero tampoco lo revive.
  const legacy = await put(owner, project, { notes: [note('n1'), note('n2')] });
  assert.equal(legacy.status, 200);
  assert.deepEqual(legacy.body.data.notes.map(n => n.id), ['n2']);

  const get = await getBoard(owner, project);
  assert.deepEqual(get.body.data.notes.map(n => n.id), ['n2']);
});

test('a stale PUT does not overwrite a newer edit of an item it did not touch', async () => {
  const { owner, project } = await setup();
  const base = await seedBoard(owner, project);

  const moved = await syncPut(owner, project, { base_revision: base, data: { notes: [note('n2', { x: 500 })] } });
  assert.equal(moved.status, 200);

  // La pestaña B (base vieja) solo cambió n1: su copia vieja de n2 no viaja.
  const b = await syncPut(owner, project, { base_revision: base, data: { notes: [note('n1', { text: 'B' })] } });
  assert.equal(b.status, 200);
  const byId = Object.fromEntries((await getBoard(owner, project)).body.data.notes.map(n => [n.id, n]));
  assert.equal(byId.n2.x, 500);
  assert.equal(byId.n1.text, 'B');
  // B recibe la edición de A para ponerse al día.
  assert.deepEqual(b.body.changes.notes.map(n => n.id).sort(), ['n1', 'n2']);
  assert.equal(b.body.changes.notes.find(n => n.id === 'n2').x, 500);
});

test('concurrent additions from two clients both survive', async () => {
  const { owner, project } = await setup();
  const base = await seedBoard(owner, project);
  const a = await syncPut(owner, project, { base_revision: base, data: { notes: [note('a1')], cards: [{ id: 'c-a', x: 0, y: 0, title: 'A', color: '#1e3a5f' }] } });
  const b = await syncPut(owner, project, { base_revision: base, data: { notes: [note('b1')] } });
  assert.equal(a.status, 200);
  assert.equal(b.status, 200);
  const d = (await getBoard(owner, project)).body.data;
  assert.deepEqual(d.notes.map(n => n.id).sort(), ['a1', 'b1', 'n1', 'n2']);
  assert.deepEqual(d.cards.map(c => c.id), ['c-a']);
});

test('a Claude Code addition survives a stale tab PUT and is sent to it as a change', async () => {
  const { owner, project } = await setup();
  const base = await seedBoard(owner, project);
  const added = await mcpWhiteboard.addItems({ projectId: project.id, user: owner.user, notes: [{ text: 'de Claude' }] });
  const aiId = added.added.notes[0].id;

  // Pestaña nueva con base vieja y PUT de un whiteboard.js viejo sin la nota.
  const fresh = await syncPut(owner, project, { base_revision: base, data: { notes: [note('n2', { x: 99 })] } });
  assert.equal(fresh.status, 200);
  assert.ok(fresh.body.changes.notes.some(n => n.id === aiId));
  const legacy = await put(owner, project, { notes: [note('n1'), note('n2')] });
  assert.equal(legacy.status, 200);

  const d = (await getBoard(owner, project)).body.data;
  assert.ok(d.notes.some(n => n.id === aiId && n.text === 'de Claude'));
});

test('a legacy PUT without base revision never deletes, but still updates and adds', async () => {
  const { owner, project } = await setup();
  await seedBoard(owner, project);
  const res = await put(owner, project, { notes: [note('n2', { text: 'cambiada' }), note('n3')] });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  assert.ok(Number.isInteger(res.body.revision));
  assert.deepEqual(res.body.data.notes.map(n => [n.id, n.text]), [['n1', 'n1'], ['n2', 'cambiada'], ['n3', 'n3']]);

  // `removed` solo vale con base_revision; una base inválida se rechaza.
  assert.equal((await syncPut(owner, project, { data: {}, removed: { notes: ['n1'] } })).status, 400);
  assert.equal((await syncPut(owner, project, { base_revision: -1, data: {} })).status, 400);
  assert.equal((await syncPut(owner, project, { base_revision: '3', data: {} })).status, 400);
  assert.equal((await getBoard(owner, project)).body.data.notes.length, 3);
});

test('GET ?since returns only what changed after that revision', async () => {
  const { owner, project } = await setup();
  const base = await seedBoard(owner, project);
  await syncPut(owner, project, { base_revision: base, data: { notes: [note('n3')] }, removed: { notes: ['n1'] } });

  const full = await getBoard(owner, project);
  assert.ok(full.body.revision > base);
  assert.equal(full.body.sync, undefined, 'item revisions and tombstones stay server-side');

  const delta = await getBoard(owner, project, `?since=${base}`);
  assert.equal(delta.body.full, false);
  assert.deepEqual(delta.body.changes.notes.map(n => n.id), ['n3']);
  assert.deepEqual(delta.body.deleted.notes, ['n1']);
  assert.equal((await getBoard(owner, project, `?since=${full.body.revision}`)).body.changes.notes.length, 0);
  assert.equal((await getBoard(owner, project, '?since=999999')).body.full, true);
  assert.equal((await getBoard(owner, project, '?since=abc')).body.full, true);
});

test('a re-added node comes back only when the client already knew it was removed', async () => {
  const { owner, project, target } = await setup();
  const node = { id: target.id, x: 0, y: 0, collapsed: false };
  const r1 = (await syncPut(owner, project, { base_revision: 0, data: { nodes: [node], initialized: true } })).body.revision;
  const r2 = (await syncPut(owner, project, { base_revision: r1, data: {}, removed: { nodes: [target.id] } })).body.revision;
  // Base vieja: no lo revive.
  await syncPut(owner, project, { base_revision: r1, data: { nodes: [node] } });
  assert.deepEqual((await getBoard(owner, project)).body.data.nodes, []);
  // Base que ya incluye el borrado ("sync targets"): vuelve.
  await syncPut(owner, project, { base_revision: r2, data: { nodes: [node] } });
  assert.deepEqual((await getBoard(owner, project)).body.data.nodes.map(n => n.id), [target.id]);
});

test('undoing a delete persists: the same ids come back with a base that includes the removal', async () => {
  const { owner, project } = await setup();
  const base = await seedBoard(owner, project);
  const arrow = { id: 'e1', fromId: 'n1', toId: 'n2', label: 'x' };
  const r1 = (await syncPut(owner, project, { base_revision: base, data: { edges: [arrow] } })).body.revision;

  // Delete n1 with its arrow, then undo: the client re-adds both from its
  // copies, with the revision the delete returned as base.
  const del = await syncPut(owner, project, { base_revision: r1, data: {}, removed: { notes: ['n1'], edges: ['e1'] } });
  assert.equal(del.status, 200);
  const undo = await syncPut(owner, project, { base_revision: del.body.revision, data: { notes: [note('n1')], edges: [arrow] } });
  assert.equal(undo.status, 200, JSON.stringify(undo.body));
  assert.ok(undo.body.revision > del.body.revision);

  const d = (await getBoard(owner, project)).body.data;
  assert.deepEqual(d.notes.map(n => n.id).sort(), ['n1', 'n2']);
  assert.deepEqual(d.edges.map(e => e.id), ['e1']);
  // Another tab that saw the delete gets them back as changes, not deletions.
  const since = (await getBoard(owner, project, `?since=${del.body.revision}`)).body;
  assert.deepEqual(since.changes.notes.map(n => n.id), ['n1']);
  assert.deepEqual(since.changes.edges.map(e => e.id), ['e1']);
  assert.deepEqual(since.deleted.notes, []);
  // A save from before the delete still cannot bring them back on its own.
  const again = await syncPut(owner, project, { base_revision: del.body.revision, data: {}, removed: { notes: ['n1'] } });
  await syncPut(owner, project, { base_revision: r1, data: { notes: [note('n1')] } });
  assert.ok(!(await getBoard(owner, project)).body.data.notes.some(n => n.id === 'n1'), JSON.stringify(again.body));
});

test('removing every target node persists: the board stays initialized', async () => {
  const { owner, project, target } = await setup();
  let get = await getBoard(owner, project);
  assert.equal(get.body.initialized, false);
  assert.equal(get.body.revision, 0);

  const r1 = (await syncPut(owner, project, {
    base_revision: 0, data: { nodes: [{ id: target.id, x: 80, y: 80, collapsed: false }], initialized: true },
  })).body.revision;
  const res = await syncPut(owner, project, { base_revision: r1, data: {}, removed: { nodes: [target.id] } });
  assert.equal(res.body.initialized, true);
  get = await getBoard(owner, project);
  assert.deepEqual(get.body.data.nodes, []);
  assert.equal(get.body.initialized, true);
  assert.equal(get.body.data.initialized, undefined, 'the flag lives outside the blob');
});

test('legacy boards: with nodes they count as initialized, with only notes they do not', async () => {
  const { owner, project, target } = await setup();
  await db.query(
    `INSERT INTO whiteboard_state (project_id, data) VALUES ($1, $2)`,
    [project.id, JSON.stringify({ nodes: [{ id: target.id, x: 0, y: 0 }], notes: [note('n1')] })]
  );
  const get = await getBoard(owner, project);
  assert.equal(get.body.initialized, true);
  assert.equal(get.body.revision, 0);
  assert.deepEqual(get.body.data.notes, [note('n1')]);

  const other = await createProject(owner.accessToken);
  await db.query(`INSERT INTO whiteboard_state (project_id, data) VALUES ($1, $2)`, [other.id, JSON.stringify({ notes: [note('n1')] })]);
  assert.equal((await getBoard(owner, other)).body.initialized, false);
});

test('tombstones are bounded: the oldest are pruned and a client older than them gets the full board', () => {
  const deleted = {};
  for (let i = 1; i <= wbSync.MAX_TOMBSTONES; i++) deleted[`notes:old${i}`] = i;
  const state = { data: { notes: [note('n1')] }, revision: wbSync.MAX_TOMBSTONES, sync: { deleted } };
  const merged = wbSync.mergeBoard(state, {}, { baseRevision: state.revision, removed: { notes: ['n1'] } });
  assert.equal(Object.keys(merged.sync.deleted).length, wbSync.MAX_TOMBSTONES);
  assert.equal(merged.sync.deleted['notes:old1'], undefined);
  assert.equal(merged.sync.deleted['notes:n1'], merged.revision);
  assert.equal(merged.sync.floor, 1);
  assert.equal(wbSync.changesSince(merged, 0).full, true);
  const recent = wbSync.changesSince(merged, 1);
  assert.equal(recent.full, false);
  assert.ok(recent.deleted.notes.includes('n1'));
});

test('image GC treats tombstoned image items as unreferenced', async () => {
  const { owner, project } = await setup();
  const imgId = (await uploadImage(owner.accessToken, project, PNG)).body.id;
  const r1 = (await syncPut(owner, project, { base_revision: 0, data: { images: [{ id: 'img1', imageId: imgId, x: 0, y: 0, w: 320, h: 240 }] } })).body.revision;
  await syncPut(owner, project, { base_revision: r1, data: {}, removed: { images: ['img1'] } });
  await db.query(`UPDATE whiteboard_images SET created_at = NOW() - INTERVAL '25 hours' WHERE id = $1`, [imgId]);
  // Un PUT viejo con el ítem no lo revive, así que la próxima subida lo barre.
  await put(owner, project, { images: [{ id: 'img1', imageId: imgId, x: 0, y: 0, w: 320, h: 240 }] });
  await uploadImage(owner.accessToken, project, PNG);
  const { rows } = await db.query('SELECT id FROM whiteboard_images WHERE id = $1', [imgId]);
  assert.equal(rows.length, 0);
});

test('mergeBoard: the same item with keys in another order is not a change', () => {
  const stored = { id: 'c1', x: 10, y: 20, title: 'T', color: '#3d8bfd', ref: { id: 'r', type: 'target' } };
  const state = { data: { cards: [stored] }, revision: 3, sync: {} };
  const reordered = { ref: { type: 'target', id: 'r' }, color: '#3d8bfd', title: 'T', y: 20, x: 10, id: 'c1' };
  const merged = wbSync.mergeBoard(state, { cards: [reordered] });
  assert.equal(merged.changed, false);
  assert.equal(merged.revision, 3);
});
