// Whiteboard para Claude Code: leer un resumen y AGREGAR cosas (notas,
// tarjetas, nodos de target, flechas). Nunca borra, mueve ni edita lo que ya
// está: el tablero es del equipo.
//
// El tablero es un único JSON por proyecto (whiteboard_state.data) que el
// navegador guarda entero con PUT (gana el último). Por eso:
//   1. la escritura acá es atómica (SELECT ... FOR UPDATE, merge, UPDATE), y
//   2. después se avisa a la sala del proyecto con un 'wb:patch' op
//      'items_add': whiteboard.js lo mezcla en su wbData en memoria, así el
//      próximo autosave de un navegador abierto INCLUYE lo agregado en vez
//      de pisarlo (ver _handleRemotePatch / scheduleSave en whiteboard.js).
const crypto = require('node:crypto');
const db       = require('../../db');
const ws       = require('../ws');
const activity = require('../activity');

const MAX_ITEMS_PER_CALL = 30;
const MAX_EDGES_PER_CALL = 50;
// Tope del tablero entero: un Claude Code en loop no debe poder inflar el
// JSON (que cada navegador baja y re-sube completo en cada autosave).
const MAX_BOARD_ITEMS = 1500;
const CREATED_BY = 'claude_code';

// Mismos valores que whiteboard.js (NOTE_COLORS / CARD_COLORS): un color
// fuera de la paleta no tiene punto para volver a elegirlo en la UI.
const NOTE_COLORS = ['#ffd96a', '#a8edab', '#a8d8f0', '#f7b8b8', '#e0b8f7'];
const CARD_COLORS = ['#1e3a5f', '#3a1e5f', '#1e5230', '#5f1e1e', '#5f3a1e', '#1e4a4f'];
// Estilo de las flechas (whiteboard.js EDGE_COLORS / EDGE_STYLES / EDGE_ARROWS).
// Sin color, la flecha usa el color del tema; estos tonos medios se leen
// sobre fondo claro y oscuro. Sin style/arrow: sólida con punta al final.
const EDGE_COLORS = ['#e53935', '#f57c00', '#f9a825', '#43a047', '#1e88e5', '#8e24aa'];
const EDGE_STYLES = ['solid', 'dashed', 'dotted'];
const EDGE_ARROWS = ['end', 'start', 'both', 'none'];

// Tamaños por defecto con los que whiteboard.js dibuja cada cosa (sin w/h
// propio). La nota no tiene alto fijo en el navegador: 100 es el típico.
const SIZE = {
  node: { w: 290, h: 380 },
  card: { w: 240, h: 110 },
  note: { w: 170, h: 100 },
};
// Mínimos por tipo (los mismos que usa el resize de whiteboard.js) y máximo
// común para un w/h explícito.
const MIN_SIZE = {
  node: { w: 200, h: 120 },
  card: { w: 160, h: 80 },
  note: { w: 120, h: 80 },
};
const MAX_ITEM_SIZE = 4000;
// Grilla del auto-layout (celda = tamaño + separación). Si el lote trae
// ítems más grandes que el default, la celda crece para que no se pisen.
const GRID = {
  node: { cols: 3, cw: 350, ch: 430, gapX: 60, gapY: 50 },
  small: { cols: 4, cw: 280, ch: 150, gapX: 40, gapY: 40 },
};
const BATCH_GAP = 120;
const ORIGIN = 80;
const MAX_OFFSET = 5000;

class WhiteboardError extends Error {}

function emptyBoard() {
  return { nodes: [], strokes: [], notes: [], edges: [], cards: [], view: { panX: 0, panY: 0, zoom: 1 } };
}

function normalizeBoard(data) {
  const b = { ...emptyBoard(), ...(data || {}) };
  for (const k of ['nodes', 'strokes', 'notes', 'edges', 'cards']) if (!Array.isArray(b[k])) b[k] = [];
  return b;
}

function clampSize(kind, dim, v) {
  if (!Number.isFinite(v)) return undefined;
  return Math.round(Math.min(MAX_ITEM_SIZE, Math.max(MIN_SIZE[kind][dim], v)));
}

// Posición y tamaño efectivo de un ítem: su w/h si lo tiene, si no el
// default con que lo dibuja el navegador.
function geometry(kind, it) {
  const dim = (v, d) => (Number.isFinite(v) && v > 0 ? v : d);
  return { x: it.x, y: it.y, w: dim(it.w, SIZE[kind].w), h: dim(it.h, SIZE[kind].h) };
}

// Caja que ocupa todo lo que ya está dibujado. Los trazos libres son un path
// SVG ("M x y L x y ..."): se toman sus pares de números.
function boundingBox(board) {
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  const add = (x, y, w, h) => {
    if (!Number.isFinite(x) || !Number.isFinite(y)) return;
    minX = Math.min(minX, x); minY = Math.min(minY, y);
    maxX = Math.max(maxX, x + w); maxY = Math.max(maxY, y + h);
  };
  for (const kind of ['node', 'card', 'note']) {
    board[`${kind}s`].forEach(it => { const g = geometry(kind, it); add(g.x, g.y, g.w, g.h); });
  }
  board.strokes.forEach(s => {
    for (const m of String(s.d || '').matchAll(/(-?\d+(?:\.\d+)?)[ ,]+(-?\d+(?:\.\d+)?)/g)) add(+m[1], +m[2], 0, 0);
  });
  return Number.isFinite(minX) ? { minX, minY, maxX, maxY } : null;
}

function itemCount(board) {
  return board.nodes.length + board.cards.length + board.notes.length + board.edges.length;
}

// Ubica el lote nuevo en espacio libre: a la derecha de todo lo existente,
// arrancando a la altura del borde superior. Sin posiciones explícitas, una
// grilla (primero los nodos de target, debajo tarjetas y notas); con
// dx/dy, relativo al origen del lote. Como el lote siempre empieza pasado el
// borde derecho actual, dos llamadas seguidas nunca se pisan.
function layoutBatch(board, items) {
  const box = boundingBox(board);
  const ox = box ? box.maxX + BATCH_GAP : ORIGIN;
  const oy = box ? box.minY : ORIGIN;
  const clamp = v => Math.max(0, Math.min(MAX_OFFSET, v));
  const hasOffset = it => Number.isFinite(it.dx) && Number.isFinite(it.dy);

  // Celda de la grilla: la default, o más grande si algún ítem del grupo
  // trae w/h mayor.
  const cell = (group, g) => {
    const sizes = group.map(it => geometry(it.kind, it.data));
    return {
      cols: g.cols,
      cw: Math.max(g.cw, ...sizes.map(s => s.w + g.gapX)),
      ch: Math.max(g.ch, ...sizes.map(s => s.h + g.gapY)),
    };
  };

  const nodes = items.filter(it => it.kind === 'node' && !hasOffset(it));
  const small = items.filter(it => it.kind !== 'node' && !hasOffset(it));
  const nc = cell(nodes, GRID.node);
  nodes.forEach((it, i) => {
    it.x = ox + (i % nc.cols) * nc.cw;
    it.y = oy + Math.floor(i / nc.cols) * nc.ch;
  });
  const smallTop = oy + Math.ceil(nodes.length / nc.cols) * nc.ch;
  const sc = cell(small, GRID.small);
  small.forEach((it, i) => {
    it.x = ox + (i % sc.cols) * sc.cw;
    it.y = smallTop + Math.floor(i / sc.cols) * sc.ch;
  });
  items.filter(hasOffset).forEach(it => { it.x = ox + clamp(it.dx); it.y = oy + clamp(it.dy); });
  items.forEach(it => { it.x = Math.round(it.x); it.y = Math.round(it.y); });
}

async function lockBoard(client, projectId) {
  await client.query(
    `INSERT INTO whiteboard_state (project_id, data) VALUES ($1, $2) ON CONFLICT (project_id) DO NOTHING`,
    [projectId, JSON.stringify(emptyBoard())]
  );
  const { rows } = await client.query(
    `SELECT data FROM whiteboard_state WHERE project_id = $1 FOR UPDATE`, [projectId]
  );
  return normalizeBoard(rows[0].data);
}

async function inTransaction(fn) {
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// Texto corto de a qué apunta una tarjeta (target / puerto / endpoint del
// proyecto). Lanza si el id no es de este proyecto.
async function resolveLink(projectId, link) {
  const q = {
    target: `SELECT t.id AS target_id, t.host AS label FROM targets t WHERE t.id = $1 AND t.project_id = $2`,
    port: `SELECT p.target_id, t.host || ':' || p.port || '/' || p.protocol AS label
           FROM target_ports p JOIN targets t ON t.id = p.target_id WHERE p.id = $1 AND t.project_id = $2`,
    endpoint: `SELECT e.target_id, e.method || ' ' || t.host || e.path AS label
               FROM target_endpoints e JOIN targets t ON t.id = e.target_id WHERE e.id = $1 AND t.project_id = $2`,
  }[link.type];
  const { rows } = await db.query(q, [link.id, projectId]);
  if (!rows.length) throw new WhiteboardError(`${link.type} "${link.id}" does not belong to this project`);
  return { type: link.type, id: link.id, target_id: rows[0].target_id, label: rows[0].label };
}

function clip(s, max) {
  return typeof s === 'string' && s.length > max ? `${s.slice(0, max)}…` : s;
}

async function getWhiteboard(projectId) {
  const { rows } = await db.query(`SELECT data, updated_at FROM whiteboard_state WHERE project_id = $1`, [projectId]);
  const board = normalizeBoard(rows[0]?.data);
  const { rows: targets } = await db.query(
    `SELECT id, host, type, scope, status FROM targets WHERE project_id = $1`, [projectId]
  );
  const byId = new Map(targets.map(t => [t.id, t]));
  return {
    updated_at: rows[0]?.updated_at || null,
    nodes: board.nodes.filter(n => byId.has(n.id)).map(n => {
      const t = byId.get(n.id);
      return {
        id: n.id, kind: 'target', target_id: n.id, host: t.host, type: t.type, scope: t.scope, status: t.status,
        ...geometry('node', n),
      };
    }),
    cards: board.cards.map(c => ({
      id: c.id, title: c.title || '', body: clip(c.body || '', 1000), link: c.ref || null,
      created_by: c.created_by || null, ...geometry('card', c),
    })),
    notes: board.notes.map(n => ({
      id: n.id, text: clip(n.text || '', 1000), created_by: n.created_by || null, ...geometry('note', n),
    })),
    edges: board.edges.map(e => ({
      id: e.id, from_id: e.fromId, to_id: e.toId, label: e.label || '',
      from_endpoint_id: e.fromEp || null, to_endpoint_id: e.toEp || null,
      from_port_id: e.fromPort || null, to_port_id: e.toPort || null,
      style: e.style || 'solid', arrow: e.arrow || 'end', color: e.color || null,
    })),
    strokes: board.strokes.length,
    targets_not_on_board: targets.filter(t => !board.nodes.some(n => n.id === t.id)).map(t => ({ id: t.id, host: t.host })),
  };
}

function broadcastAdd(projectId, added) {
  ws.broadcastWhiteboardPatch(projectId, { op: 'items_add', source: CREATED_BY, ...added });
}

async function addItems({ projectId, user, nodes = [], cards = [], notes = [] }) {
  const total = nodes.length + cards.length + notes.length;
  if (!total) throw new WhiteboardError('nothing to add — pass at least one of nodes, cards or notes');
  if (total > MAX_ITEMS_PER_CALL) throw new WhiteboardError(`at most ${MAX_ITEMS_PER_CALL} items per call`);

  // Validación previa (fuera del lock): ids de targets y links.
  const { rows: targets } = await db.query(`SELECT id, host FROM targets WHERE project_id = $1`, [projectId]);
  const targetIds = new Set(targets.map(t => t.id));
  for (const n of nodes) {
    if (!targetIds.has(n.target_id)) throw new WhiteboardError(`target_id "${n.target_id}" does not belong to this project — call list_targets`);
  }
  const links = await Promise.all(cards.map(c => (c.link ? resolveLink(projectId, c.link) : null)));

  const result = await inTransaction(async client => {
    const board = await lockBoard(client, projectId);
    if (itemCount(board) + total > MAX_BOARD_ITEMS) {
      throw new WhiteboardError(`the whiteboard already has ${itemCount(board)} items — it cannot grow past ${MAX_BOARD_ITEMS}`);
    }
    const onBoard = new Set(board.nodes.map(n => n.id));
    const skipped = [];
    const batch = [];
    const seenNodes = new Set();
    // w/h solo para lo que se crea acá; nunca toca ítems existentes.
    const sized = (kind, it, data) => {
      const w = clampSize(kind, 'w', it.w), h = clampSize(kind, 'h', it.h);
      if (w !== undefined) data.w = w;
      if (h !== undefined) data.h = h;
      return data;
    };
    for (const n of nodes) {
      if (onBoard.has(n.target_id) || seenNodes.has(n.target_id)) { skipped.push({ target_id: n.target_id, reason: 'target is already on the board' }); continue; }
      seenNodes.add(n.target_id);
      batch.push({ kind: 'node', dx: n.dx, dy: n.dy, data: sized('node', n, { id: n.target_id, collapsed: false, created_by: CREATED_BY }) });
    }
    cards.forEach((c, i) => batch.push({
      kind: 'card', dx: c.dx, dy: c.dy,
      data: sized('card', c, {
        id: crypto.randomUUID(), title: c.title, body: c.body || '',
        color: CARD_COLORS.includes(c.color) ? c.color : CARD_COLORS[0],
        ...(links[i] ? { ref: links[i] } : {}),
        created_by: CREATED_BY,
      }),
    }));
    notes.forEach(n => batch.push({
      kind: 'note', dx: n.dx, dy: n.dy,
      data: sized('note', n, { id: crypto.randomUUID(), text: n.text, color: NOTE_COLORS.includes(n.color) ? n.color : NOTE_COLORS[0], created_by: CREATED_BY }),
    }));

    layoutBatch(board, batch);
    const added = { nodes: [], cards: [], notes: [], edges: [] };
    for (const it of batch) {
      const item = { ...it.data, x: it.x, y: it.y };
      added[`${it.kind}s`].push(item);
      board[`${it.kind}s`].push(item);
    }
    // Una tarjeta enlazada a un target/puerto/endpoint se conecta con el
    // nodo de ese target si está en el tablero (o llegó en este lote).
    const nodeIds = new Set(board.nodes.map(n => n.id));
    for (const c of added.cards) {
      if (c.ref && nodeIds.has(c.ref.target_id)) {
        const edge = { id: crypto.randomUUID(), fromId: c.id, toId: c.ref.target_id, label: '', created_by: CREATED_BY };
        board.edges.push(edge);
        added.edges.push(edge);
      }
    }
    await client.query(
      `UPDATE whiteboard_state SET data = $2, updated_by = $3, updated_at = NOW() WHERE project_id = $1`,
      [projectId, JSON.stringify(board), user.id]
    );
    return { added, skipped };
  });

  broadcastAdd(projectId, result.added);
  const n = result.added.nodes.length + result.added.cards.length + result.added.notes.length;
  if (n) {
    await activity.log({
      projectId, user, action: 'claude_code_whiteboard_added', entityType: 'whiteboard',
      entityName: 'Whiteboard', meta: { via: 'claude-code', count: n },
    });
  }
  return result;
}

// Extremo de una flecha: el ítem y, si apunta a una fila de un nodo de
// target, el endpoint o puerto. Misma clave que _endKey en whiteboard.js.
const endKey = (id, ep, port) => `${id}|${ep || ''}|${port || ''}`;
// A→B y B→A son la misma conexión.
const pairKey = (a, b) => [a, b].sort().join('>');

// Verifica que cada endpoint/puerto pedido sea del target cuyo nodo es ese
// extremo y que el target sea de este proyecto.
async function checkSubAnchors(projectId, edges) {
  const want = { endpoint: new Set(), port: new Set() };
  for (const e of edges) {
    for (const side of ['from', 'to']) {
      if (e[`${side}_endpoint_id`] && e[`${side}_port_id`]) {
        throw new WhiteboardError(`pass either ${side}_endpoint_id or ${side}_port_id, not both`);
      }
      if (e[`${side}_endpoint_id`]) want.endpoint.add(e[`${side}_endpoint_id`]);
      if (e[`${side}_port_id`]) want.port.add(e[`${side}_port_id`]);
    }
  }
  const found = { endpoint: new Map(), port: new Map() };
  for (const [kind, table] of [['endpoint', 'target_endpoints'], ['port', 'target_ports']]) {
    if (!want[kind].size) continue;
    const { rows } = await db.query(
      `SELECT x.id, x.target_id FROM ${table} x JOIN targets t ON t.id = x.target_id
       WHERE x.id = ANY($1::uuid[]) AND t.project_id = $2`,
      [[...want[kind]], projectId]
    );
    rows.forEach(r => found[kind].set(r.id, r.target_id));
  }
  for (const e of edges) {
    for (const side of ['from', 'to']) {
      for (const kind of ['endpoint', 'port']) {
        const id = e[`${side}_${kind}_id`];
        if (!id) continue;
        const targetId = found[kind].get(id);
        if (!targetId) throw new WhiteboardError(`${kind} "${id}" does not belong to this project — call list_${kind}s`);
        if (targetId !== e[`${side}_id`]) {
          throw new WhiteboardError(`${kind} "${id}" is not on target node "${e[`${side}_id`]}" — ${side}_id must be the node of the target that owns it`);
        }
      }
    }
  }
}

async function connectItems({ projectId, user, edges }) {
  if (!edges.length) throw new WhiteboardError('pass at least one edge');
  if (edges.length > MAX_EDGES_PER_CALL) throw new WhiteboardError(`at most ${MAX_EDGES_PER_CALL} edges per call`);
  await checkSubAnchors(projectId, edges);
  const result = await inTransaction(async client => {
    const board = await lockBoard(client, projectId);
    if (itemCount(board) + edges.length > MAX_BOARD_ITEMS) {
      throw new WhiteboardError(`the whiteboard already has ${itemCount(board)} items — it cannot grow past ${MAX_BOARD_ITEMS}`);
    }
    const ids = new Set([...board.nodes, ...board.cards, ...board.notes].map(it => it.id));
    const nodeIds = new Set(board.nodes.map(n => n.id));
    const existing = new Set(board.edges.map(x => pairKey(
      endKey(x.fromId, x.fromEp, x.fromPort), endKey(x.toId, x.toEp, x.toPort)
    )));
    const added = [], skipped = [];
    for (const e of edges) {
      for (const side of ['from', 'to']) {
        const id = e[`${side}_id`];
        if (!ids.has(id)) throw new WhiteboardError(`"${id}" is not a target node, card or note on this whiteboard — call get_whiteboard`);
        // El endpoint/puerto ya se verificó contra el target; además el
        // target tiene que estar en el tablero como nodo.
        if ((e[`${side}_endpoint_id`] || e[`${side}_port_id`]) && !nodeIds.has(id)) {
          throw new WhiteboardError(`"${id}" is not a target node — endpoints and ports can only anchor on target nodes`);
        }
      }
      if (e.from_id === e.to_id) { skipped.push({ ...e, reason: 'an item cannot connect to itself' }); continue; }
      const key = pairKey(
        endKey(e.from_id, e.from_endpoint_id, e.from_port_id), endKey(e.to_id, e.to_endpoint_id, e.to_port_id)
      );
      if (existing.has(key)) { skipped.push({ ...e, reason: 'connection already exists' }); continue; }
      existing.add(key);
      const edge = { id: crypto.randomUUID(), fromId: e.from_id, toId: e.to_id, label: e.label || '' };
      if (e.from_endpoint_id) edge.fromEp = e.from_endpoint_id;
      if (e.to_endpoint_id) edge.toEp = e.to_endpoint_id;
      if (e.from_port_id) edge.fromPort = e.from_port_id;
      if (e.to_port_id) edge.toPort = e.to_port_id;
      if (EDGE_STYLES.includes(e.style)) edge.style = e.style;
      if (EDGE_ARROWS.includes(e.arrow)) edge.arrow = e.arrow;
      if (EDGE_COLORS.includes(e.color)) edge.color = e.color;
      edge.created_by = CREATED_BY;
      board.edges.push(edge);
      added.push(edge);
    }
    if (added.length) {
      await client.query(
        `UPDATE whiteboard_state SET data = $2, updated_by = $3, updated_at = NOW() WHERE project_id = $1`,
        [projectId, JSON.stringify(board), user.id]
      );
    }
    return { added, skipped };
  });
  if (result.added.length) broadcastAdd(projectId, { nodes: [], cards: [], notes: [], edges: result.added });
  return result;
}

module.exports = {
  getWhiteboard, addItems, connectItems, geometry, WhiteboardError,
  MAX_ITEMS_PER_CALL, MAX_EDGES_PER_CALL, MAX_BOARD_ITEMS, NOTE_COLORS, CARD_COLORS,
  EDGE_COLORS, EDGE_STYLES, EDGE_ARROWS,
  SIZE, MIN_SIZE, MAX_ITEM_SIZE,
};
