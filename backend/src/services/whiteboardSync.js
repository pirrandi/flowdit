// Sincronización del whiteboard entre pestañas, Claude Code y pestañas viejas.
//
// El contenido sigue siendo un único JSON por proyecto (whiteboard_state.data,
// que el navegador y get_whiteboard leen tal cual). Al lado viven:
//   - whiteboard_state.revision: contador del servidor; sube con cada
//     escritura que cambia ítems (PUT, add/connect de Claude Code).
//   - whiteboard_state.sync: { revs, deleted, floor, initialized }
//       revs:    'kind:id' → revisión en la que ese ítem cambió por última vez
//       deleted: 'kind:id' → revisión en la que se borró (tombstone). Acotado a
//                MAX_TOMBSTONES; los más viejos se descartan y `floor` guarda la
//                revisión más alta descartada.
//       initialized: los nodos de target ya se auto-ubicaron una vez (si el
//                usuario después los quita todos, no vuelven solos).
//
// Nadie pisa el tablero entero: un PUT trae la revisión base del cliente, los
// ítems que ESE cliente cambió y los que borró, y se mezcla ítem por ítem bajo
// SELECT ... FOR UPDATE (ver mergeBoard). Lo que otros cambiaron después de la
// base no se toca, y lo borrado después de la base no resucita.
const db = require('../db');

const KINDS = ['nodes', 'cards', 'notes', 'images', 'edges', 'strokes'];
const MAX_TOMBSTONES = 5000;

const keyOf = (kind, id) => `${kind}:${id}`;
const isPlainObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const isRev = v => Number.isSafeInteger(v) && v >= 0;

// Lo guardado lo escribe solo el servidor, pero igual se lee a la defensiva:
// una fila vieja tiene sync = {} y revision = 0.
function normalizeSync(sync) {
  const s = isPlainObject(sync) ? sync : {};
  const revMap = m => Object.fromEntries(Object.entries(isPlainObject(m) ? m : {}).filter(([, v]) => isRev(v)));
  return {
    revs: revMap(s.revs),
    deleted: revMap(s.deleted),
    floor: isRev(s.floor) ? s.floor : 0,
    initialized: s.initialized === true,
  };
}

// Un tablero de antes de este flag que ya tiene nodos cuenta como
// inicializado. Sin nodos (aunque Claude Code haya agregado notas o
// tarjetas) todavía no: el navegador ubica los targets la primera vez.
function isInitialized(data, sync) {
  return sync.initialized || (Array.isArray(data?.nodes) && data.nodes.length > 0);
}

// JSONB devuelve las claves en su propio orden, no en el del cliente: se
// compara con claves ordenadas para que un ítem igual no cuente como cambio.
const canonical = v => Array.isArray(v) ? v.map(canonical)
  : isPlainObject(v) ? Object.fromEntries(Object.keys(v).sort().map(k => [k, canonical(v[k])])) : v;
const sameItem = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));

function pruneTombstones(sync) {
  const entries = Object.entries(sync.deleted);
  if (entries.length <= MAX_TOMBSTONES) return;
  entries.sort((a, b) => a[1] - b[1]);
  const drop = entries.slice(0, entries.length - MAX_TOMBSTONES);
  for (const [key, rev] of drop) {
    delete sync.deleted[key];
    sync.floor = Math.max(sync.floor, rev);
  }
}

// Mezcla un PUT ya sanitizado sobre el estado guardado. Puro: no toca la base.
//   state:    { data, revision, sync } tal como está guardado (lockeado)
//   incoming: tablero sanitizado. Con baseRevision son SOLO los ítems que el
//             cliente cambió o agregó desde su base; sin ella (pestaña con el
//             whiteboard.js viejo) es el tablero entero.
//   opts:     { baseRevision, removed: { kind: [ids] }, limits: { kind: max } }
//
// Reglas por ítem:
//   - con tombstone: solo vuelve si el cliente ya conocía el borrado
//     (tombstone <= base) y lo agrega de nuevo a propósito (p. ej. "sync
//     targets" re-agrega un nodo quitado). Un PUT viejo nunca lo resucita.
//   - existente: gana la copia del cliente (que la cambió); si es igual no
//     cuenta como cambio.
//   - nuevo: se agrega (hasta el tope de la lista).
//   - removed: se borra y queda tombstone, aunque todavía no estuviera (otra
//     pestaña lo agregó y no guardó aún: su guardado no lo revive).
//   - lo que el cliente no menciona queda como está.
// Un PUT sin base (cliente viejo) no puede borrar: no hay forma de distinguir
// "lo borré" de "nunca me llegó" (lo que agregó otro, o Claude Code).
function mergeBoard(state, incoming, { baseRevision, removed = {}, limits = {} } = {}) {
  const sync = normalizeSync(state.sync);
  sync.revs = { ...sync.revs };
  sync.deleted = { ...sync.deleted };
  const prev = isPlainObject(state.data) ? state.data : {};
  const data = { ...prev };
  const delta = baseRevision !== undefined;
  const rev = (isRev(state.revision) ? state.revision : 0) + 1;
  const wasInitialized = isInitialized(prev, sync);
  let changed = false;

  for (const kind of KINDS) {
    const incomingList = Array.isArray(incoming[kind]) ? incoming[kind] : [];
    const removedIds = delta && Array.isArray(removed[kind]) ? removed[kind] : [];
    if (!Array.isArray(prev[kind]) && !incomingList.length && !removedIds.length && !Array.isArray(incoming[kind])) continue;
    const list = Array.isArray(prev[kind]) ? prev[kind].slice() : [];
    const max = limits[kind] ?? Infinity;

    for (const item of incomingList) {
      const key = keyOf(kind, item.id);
      const tomb = sync.deleted[key];
      if (tomb !== undefined) {
        if (!delta || tomb > baseRevision) continue;
        delete sync.deleted[key];
      }
      const i = list.findIndex(x => x?.id === item.id);
      if (i >= 0) {
        if (sameItem(list[i], item)) continue;
        list[i] = item;
      } else {
        if (list.length >= max) continue;
        list.push(item);
      }
      sync.revs[key] = rev;
      changed = true;
    }

    for (const id of removedIds) {
      const key = keyOf(kind, id);
      const i = list.findIndex(x => x?.id === id);
      if (i >= 0) list.splice(i, 1);
      delete sync.revs[key];
      if (sync.deleted[key] === undefined) {
        sync.deleted[key] = rev;
        changed = true;
      } else if (i >= 0) {
        changed = true;
      }
    }
    data[kind] = list;
  }

  if (incoming.view) data.view = incoming.view;
  sync.initialized = wasInitialized || incoming.initialized === true || isInitialized(data, sync);
  if (sync.initialized !== wasInitialized) changed = true;
  if (changed) pruneTombstones(sync);

  return { data, sync, revision: changed ? rev : state.revision || 0, changed };
}

// Altas y movidas del servidor (Claude Code): ítems nuevos o cambiados con
// la revisión siguiente. Si era un nodo quitado antes (mismo id de target), es un alta explícita y
// se levanta el tombstone. `added`: { kind: [items] } ya metidos en `data`.
function stampAdded(state, added) {
  const sync = normalizeSync(state.sync);
  const rev = (isRev(state.revision) ? state.revision : 0) + 1;
  for (const kind of KINDS) {
    for (const item of added[kind] || []) {
      const key = keyOf(kind, item.id);
      delete sync.deleted[key];
      sync.revs[key] = rev;
    }
  }
  sync.initialized = isInitialized(state.data, sync);
  return { sync, revision: rev };
}

// Lo que cambió desde `since`: los ítems con revisión mayor y los borrados
// después. Si el cliente viene de antes de los tombstones que se descartaron
// (o de una revisión que no existe) se manda el tablero entero.
function changesSince(state, since) {
  const sync = normalizeSync(state.sync);
  const revision = isRev(state.revision) ? state.revision : 0;
  const data = isPlainObject(state.data) ? state.data : {};
  const out = { revision, initialized: isInitialized(data, sync) };
  if (!isRev(since) || since < sync.floor || since > revision) return { ...out, full: true, data };
  const changes = {}, deleted = {};
  for (const kind of KINDS) {
    changes[kind] = (Array.isArray(data[kind]) ? data[kind] : []).filter(it => (sync.revs[keyOf(kind, it?.id)] || 0) > since);
    deleted[kind] = [];
  }
  for (const [key, rev] of Object.entries(sync.deleted)) {
    if (rev <= since) continue;
    const i = key.indexOf(':');
    const kind = key.slice(0, i);
    if (deleted[kind]) deleted[kind].push(key.slice(i + 1));
  }
  return { ...out, full: false, changes, deleted };
}

// Fila del tablero lockeada dentro de la transacción del caller. Si no
// existe se crea con `initialData`.
async function lockState(client, projectId, initialData = {}) {
  await client.query(
    `INSERT INTO whiteboard_state (project_id, data) VALUES ($1, $2) ON CONFLICT (project_id) DO NOTHING`,
    [projectId, JSON.stringify(initialData)]
  );
  const { rows } = await client.query(
    `SELECT data, revision, sync FROM whiteboard_state WHERE project_id = $1 FOR UPDATE`, [projectId]
  );
  return { data: rows[0].data, revision: Number(rows[0].revision) || 0, sync: normalizeSync(rows[0].sync) };
}

async function writeState(client, projectId, { data, revision, sync }, userId) {
  const { rows } = await client.query(
    `UPDATE whiteboard_state SET data = $2, revision = $3, sync = $4, updated_by = $5, updated_at = NOW()
     WHERE project_id = $1
     RETURNING id, project_id, data, revision, updated_by, updated_at`,
    [projectId, JSON.stringify(data), revision, JSON.stringify(sync), userId]
  );
  return rows[0];
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

// PUT /whiteboard: lock, merge y guardado en una transacción.
async function saveFromClient({ projectId, userId, data, baseRevision, removed, limits }) {
  return inTransaction(async client => {
    const state = await lockState(client, projectId);
    const merged = mergeBoard(state, data, { baseRevision, removed, limits });
    const row = await writeState(client, projectId, merged, userId);
    return { row, merged, previousRevision: state.revision };
  });
}

module.exports = {
  KINDS, MAX_TOMBSTONES,
  normalizeSync, isInitialized, mergeBoard, stampAdded, changesSince,
  lockState, writeState, inTransaction, saveFromClient,
};
