// ── Whiteboard view ────────────────────────────────────────────────────
'use strict';

// ── Module state ───────────────────────────────────────────────────────
let wbData = { nodes: [], strokes: [], notes: [], edges: [], cards: [], images: [], view: { panX: 0, panY: 0, zoom: 1 } };
let _mode = 'select';
let _drawColor = '#e94141';
let _drawWidth = 2;
let _saveTimer = null;
let _activeStrokeEl = null;

// Fetched per-target data (not persisted)
let _portsMap = {};
let _endpointsMap = {};

// Undo / redo (local per session, see the History section). Entries:
// { items: [{ key, before, after }], seq, tag?, at? } with before/after the
// item's JSON copy ('kind:id' key, null = not on the board).
const HISTORY_MAX = 100;
let _undoStack = [];
let _redoStack = [];
// Items changed by someone else ('kind:id' → _remoteSeq when it happened):
// undo/redo leaves them alone if that was after the entry.
const _remoteTouched = new Map();
let _remoteSeq = 0;

// Selected board items ('nodes:id', 'cards:id', 'notes:id', 'images:id').
const _selection = new Set();

// Eraser ring DOM element
let _eraserRing;

// Search
let _searchQuery = '';

// Sync con el servidor (ver backend services/whiteboardSync.js). El servidor
// mezcla ítem por ítem: cada guardado manda la revisión base, SOLO los ítems
// que esta pestaña cambió o agregó y los ids que borró. Para saber cuáles son,
// _syncBase guarda cada ítem ('kind:id' → JSON canónico) tal como lo conoce el
// servidor en _syncRev; lo que difiere es una edición local pendiente. Los
// cambios que llegan de otros (wb:patch, respuestas del servidor) actualizan
// también la base, así no se re-mandan como propios.
const SYNC_KINDS = ['nodes', 'cards', 'notes', 'images', 'edges', 'strokes'];
const _syncBase = new Map();
let _syncRev = 0;
let _syncChain = Promise.resolve(); // guardados y lecturas, de a uno
let _pullTimer = null;
let _initPending = false; // los targets se auto-ubicaron y falta avisarlo
let _loadFailed = false;  // la carga inicial falló: la próxima lectura es completa
let _wbReady = false;

// Edges / connect mode
let _edgeSvg;
let _connectFrom    = null;  // first end picked in connect mode: { id, ep?, port?, el }
let _selectedEdgeId = null;
let _edgeToolbar    = null;  // floating toolbar of the selected edge
let _edgeRaf        = 0;     // pending requestAnimationFrame for _scheduleEdgeUpdate

// Images: imageId → { promise, url } of the blob: URL each image is shown
// with (the API needs the Bearer header, so <img src="/api/..."> cannot
// load it). Revoked once no item on the board uses that imageId.
const _imgUrls = new Map();
let _lastPointer = null; // last client {x, y} over the viewport, for paste

// Remote cursors
let _cursorLayer;
const _cursorEls   = new Map(); // userId → DOM el
const _cursorData  = new Map(); // userId → { wx, wy }
const _cursorHide  = new Map(); // userId → timeout

// DOM refs
let _vp, _ws, _svg, _nl;

const SEV_COLOR = {
  critical: '#e53935', high: '#f57c00', medium: '#f9a825', low: '#43a047', info: '#1e88e5',
};
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_LABEL = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja', info: 'Info' };
const SEV_SHORT = { critical: 'CRÍT', high: 'ALTA', medium: 'MED', low: 'BAJA', info: 'INFO' };
const REMEDIATION_LABEL = { open: 'Abierto', remediated: 'Remediado', not_remediated: 'No remediado', verified_closed: 'Verificado y cerrado' };
const REF_TYPE_LABEL = { target: 'Target', port: 'Puerto', endpoint: 'Endpoint', finding: 'Finding' };
const TARGET_STATUS_LABEL = { active: 'Activo', completed: 'Completado', 'out-of-scope': 'Fuera de alcance' };
const METHOD_COLOR = {
  GET: '#43a047', POST: '#1e88e5', PUT: '#f57c00', PATCH: '#f57c00',
  DELETE: '#e53935', HEAD: '#9e9e9e', OPTIONS: '#9e9e9e', OTHER: '#9e9e9e',
};
const NOTE_COLORS  = ['#ffd96a', '#a8edab', '#a8d8f0', '#f7b8b8', '#e0b8f7'];
const CARD_COLORS  = ['#1e3a5f', '#3a1e5f', '#1e5230', '#5f1e1e', '#5f3a1e', '#1e4a4f'];
// Edge style allowlists, same values as the server (services/mcp/whiteboard.js
// EDGE_*). No color = the theme color; these mid tones read on light and dark.
const EDGE_COLORS  = ['#e53935', '#f57c00', '#f9a825', '#43a047', '#1e88e5', '#8e24aa'];
const EDGE_COLOR_NAMES = ['Rojo', 'Naranja', 'Amarillo', 'Verde', 'Azul', 'Violeta'];
const EDGE_STYLES  = ['solid', 'dashed', 'dotted'];
const EDGE_ARROWS  = ['end', 'start', 'both', 'none'];
const EDGE_DASH    = { solid: '', dashed: '7 5', dotted: '1 4' };
const ID_RE        = /^[\w-]{1,100}$/;

// The saved board and live wb:patch messages are written by other project
// members, so colors and numbers are checked before they reach a style,
// attribute or markup: a color like `"><img onerror=…>` is stored XSS.
const SAFE_COLOR_RE = /^(#[0-9a-f]{3,8}|var\(--[a-z0-9-]+\))$/i;
const SAFE_PATH_RE  = /^[MLHVCSQTAZmlhvcsqtaz0-9.,eE+\- ]*$/;
function _cardColor(c) { return CARD_COLORS.includes(c) ? c : CARD_COLORS[0]; }
function _noteColor(c) { return NOTE_COLORS.includes(c) ? c : NOTE_COLORS[0]; }
function _safeColor(c, fallback) { return typeof c === 'string' && SAFE_COLOR_RE.test(c) ? c : fallback; }
function _edgeColor(c) { return EDGE_COLORS.includes(c) ? c : null; }
function _edgeStyle(v) { return EDGE_STYLES.includes(v) ? v : 'solid'; }
function _edgeArrow(v) { return EDGE_ARROWS.includes(v) ? v : 'end'; }
function _validId(v) { return typeof v === 'string' && ID_RE.test(v); }
function _num(v, fallback = 0) { const n = Number(v); return v !== null && v !== '' && Number.isFinite(n) ? n : fallback; }

// Item sizes. DEFAULT_SIZE is what an item without w/h is drawn with (an
// unsized note/card grows with its text, so it is only an estimate there);
// MIN_SIZE is the resize floor per type. Same values as the MCP server
// (services/mcp/whiteboard.js) so its auto-layout matches what is drawn.
const DEFAULT_SIZE  = { node: { w: 290, h: 380 }, card: { w: 240, h: 110 }, note: { w: 170, h: 100 }, image: { w: 320, h: 240 } };
const MIN_SIZE      = { node: { w: 200, h: 120 }, card: { w: 160, h: 80 },  note: { w: 120, h: 80 },  image: { w: 80, h: 60 } };
const MAX_ITEM_SIZE = 4000;
// Optional w/h from the board or a remote patch: clamped, or 0 when absent/invalid.
function _dim(v, min) { const n = _num(v, 0); return n > 0 ? Math.min(MAX_ITEM_SIZE, Math.max(min, n)) : 0; }

function _itemEl(kind, id) {
  const sel = kind === 'note' ? `[data-note-id="${CSS.escape(String(id))}"]` : `[data-node-id="${CSS.escape(String(id))}"]`;
  return _nl ? _nl.querySelector(sel) : null;
}

// World-space box of an item: rendered size when it is on screen, otherwise
// its saved w/h or the type default.
function _itemBox(kind, d) {
  const el  = _itemEl(kind, d.id);
  const min = MIN_SIZE[kind], def = DEFAULT_SIZE[kind];
  return {
    x: _num(d.x), y: _num(d.y),
    w: (el && el.offsetWidth)  || _dim(d.w, min.w) || def.w,
    h: (el && el.offsetHeight) || _dim(d.h, min.h) || def.h,
  };
}

// marked does not strip embedded HTML, so its output must be sanitised before it
// reaches innerHTML — whiteboard notes are stored and shown to every member and
// to the client portal, which makes raw HTML here stored XSS. If either library
// is unavailable, fall back to escaped plain text rather than rendering unsafe
// markup: losing bold and headings beats executing a note's <script>.
function renderMd(text) {
  if (!text || !text.trim()) return '';
  if (window.marked && window.DOMPurify) {
    return window.DOMPurify.sanitize(window.marked.parse(text));
  }
  return esc(text).replace(/\n/g, '<br>');
}

// ── Init ───────────────────────────────────────────────────────────────
async function initWhiteboard() {
  if (window.marked) window.marked.setOptions({ breaks: true });
  _vp          = document.getElementById('wb-viewport');
  _ws          = document.getElementById('wb-workspace');
  _svg         = document.getElementById('wb-svg');
  _nl          = document.getElementById('wb-nodes-layer');
  _cursorLayer = document.getElementById('wb-cursor-layer');
  _edgeSvg     = document.getElementById('wb-edges-svg');
  _ensureEdgeMarkers();

  // Eraser ring cursor
  _eraserRing = document.createElement('div');
  _eraserRing.className = 'wb-eraser-ring';
  _eraserRing.style.display = 'none';
  _vp.appendChild(_eraserRing);

  const pid = state.currentProject.id;

  const [res] = await Promise.all([
    // Si falla no se adivina nada (ni se auto-ubican targets): se vuelve a
    // leer entero al reconectar o en la próxima lectura (_pullFromServer).
    api.whiteboard.get(pid).catch(() => { _loadFailed = true; return { data: {}, revision: 0, initialized: true }; }),
    _loadPortsAndEndpoints(pid, state.targets),
  ]);

  const saved = res.data || {};
  SYNC_KINDS.forEach(kind => { wbData[kind] = Array.isArray(saved[kind]) ? saved[kind] : []; });
  wbData.view = saved.view || { panX: 0, panY: 0, zoom: 1 };
  _syncRev = Number.isSafeInteger(res.revision) ? res.revision : 0;
  _resetSyncBase();
  // Los targets se ubican solos UNA vez por tablero (initialized lo guarda
  // el servidor): si después se quitan todos los nodos, no vuelven al
  // recargar. Notas/tarjetas/flechas de Claude Code en un tablero todavía sin
  // nodos se conservan: el auto-layout va debajo de ellas.
  const initialized = typeof res.initialized === 'boolean' ? res.initialized : wbData.nodes.length > 0;
  if (!initialized) {
    _autoLayout(state.targets, _itemsBottom());
    if (wbData.nodes.length) { _initPending = true; scheduleSave(); }
  }
  const v = wbData.view || {};
  wbData.view = { panX: _num(v.panX), panY: _num(v.panY), zoom: _num(v.zoom, 1) > 0 ? _num(v.zoom, 1) : 1 };

  _applyTransform();
  _renderAll();
  _wireEvents();
  _wireKeyboard();
  _wireWs();
  _updateHistoryButtons();
  _wbReady = true;
  if (_loadFailed) _pullFromServer();
}

// ── Remote data loading ────────────────────────────────────────────────
async function _loadPortsAndEndpoints(pid, targets) {
  if (!targets || !targets.length) return;
  try {
    const [portsArr, epArr] = await Promise.all([
      Promise.all(targets.map(t =>
        api.targets.listPorts(pid, t.id)
          .then(r => [t.id, Array.isArray(r) ? r : []])
          .catch(() => [t.id, []])
      )),
      Promise.all(targets.map(t =>
        api.targets.listEndpoints(pid, t.id)
          .then(r => [t.id, Array.isArray(r) ? r : []])
          .catch(() => [t.id, []])
      )),
    ]);
    _portsMap     = Object.fromEntries(portsArr);
    _endpointsMap = Object.fromEntries(epArr);
  } catch {
    _portsMap = {};
    _endpointsMap = {};
  }
}

// Borde inferior de las notas/tarjetas existentes (80 si no hay), para que
// el auto-layout inicial de nodos no las tape.
function _itemsBottom() {
  const bottoms = [
    ...wbData.notes.map(n => { const b = _itemBox('note', n); return b.y + b.h; }),
    ...wbData.cards.map(c => { const b = _itemBox('card', c); return b.y + b.h; }),
    ...wbData.images.map(i => { const b = _itemBox('image', i); return b.y + b.h; }),
  ].filter(Number.isFinite);
  return bottoms.length ? Math.max(...bottoms) + 50 : 80;
}

function _autoLayout(targets, top = 80) {
  const cols = 3, nodeW = DEFAULT_SIZE.node.w, nodeH = DEFAULT_SIZE.node.h, gapX = 60, gapY = 50;
  wbData.nodes = targets.map((t, i) => ({
    id:        t.id,
    x:         80 + (i % cols) * (nodeW + gapX),
    y:         top + Math.floor(i / cols) * (nodeH + gapY),
    collapsed: false,
  }));
}

function _applyTransform() {
  const { panX, panY, zoom } = wbData.view;
  _ws.style.transform = `translate(${panX}px,${panY}px) scale(${zoom})`;

  // Two-level dot grid — opacity fades on zoom out to avoid visual noise
  const cell  = 20;
  const sz    = cell * zoom;
  const szMaj = sz * 5;
  const ox    = ((panX % szMaj) + szMaj) % szMaj;
  const oy    = ((panY % szMaj) + szMaj) % szMaj;
  const oxMin = ((panX % sz)    + sz)    % sz;
  const oyMin = ((panY % sz)    + sz)    % sz;

  const majA  = (Math.min(0.12, Math.max(0.03, 0.09 * zoom + 0.03))).toFixed(3);
  const minA  = zoom > 0.45 ? (Math.min(0.05, 0.04 * zoom)).toFixed(3) : '0';

  _vp.style.backgroundImage    = `radial-gradient(circle,rgba(255,255,255,${majA}) 1.2px,transparent 1.2px),radial-gradient(circle,rgba(255,255,255,${minA}) 0.8px,transparent 0.8px)`;
  _vp.style.backgroundSize     = `${szMaj}px ${szMaj}px, ${sz}px ${sz}px`;
  _vp.style.backgroundPosition = `${ox}px ${oy}px, ${oxMin}px ${oyMin}px`;

  _updateStrokeWidths();
  _refreshCursorPositions();
  if (_selectedEdgeId) {
    const edge = wbData.edges.find(e => e.id === _selectedEdgeId);
    const pts = edge && _edgeEndpoints(edge);
    if (pts) _positionEdgeToolbar(pts);
  }
}

function _updateStrokeWidths() {
  const z = wbData.view.zoom;
  _svg.querySelectorAll('path[data-stroke]').forEach(p => {
    p.setAttribute('stroke-width', String(parseFloat(p.dataset.strokeW || '2') / z));
  });
}

function _renderAll() {
  _nl.innerHTML = '';
  _svg.innerHTML = '';
  wbData.nodes.forEach(n => {
    const t = state.targets.find(t => t.id === n.id);
    if (t) _nl.appendChild(_buildNode(n, t));
  });
  wbData.strokes.forEach(s => _renderStroke(s));
  wbData.notes.forEach(n => _nl.appendChild(_buildNote(n)));
  wbData.cards.forEach(c => _nl.appendChild(_buildCard(c)));
  wbData.images.forEach(i => _nl.appendChild(_buildImage(i)));
  wbData.edges.forEach(e => _renderEdge(e));
}

// ── Nodes ──────────────────────────────────────────────────────────────
function _buildNode(nodeData, target) {
  const pid       = state.currentProject.id;
  const vulns     = (state.customVulns || []).filter(v => v.target_id === target.id);
  const ports     = _portsMap[target.id]     || [];
  const endpoints = _endpointsMap[target.id] || [];
  const statusDot = { active: '#4caf50', completed: '#2196f3', 'out-of-scope': '#9e9e9e' }[target.status] || '#9e9e9e';

  const el = document.createElement('div');
  el.className = 'wb-node' + (nodeData.collapsed ? ' collapsed' : '') + (nodeData.h ? ' wb-node--sized' : '');
  el.dataset.nodeId = nodeData.id;
  el.style.left  = _num(nodeData.x) + 'px';
  el.style.top   = _num(nodeData.y) + 'px';
  el.style.width = (_dim(nodeData.w, MIN_SIZE.node.w) || DEFAULT_SIZE.node.w) + 'px';
  if (_dim(nodeData.h, MIN_SIZE.node.h)) el.style.height = _dim(nodeData.h, MIN_SIZE.node.h) + 'px';

  // A finding row can be dragged onto the board as a finding card (_startFindingDrag).
  const vulnRows = vulns.length
    ? vulns.map(v => `
        <div class="wb-vuln-row" data-vuln-id="${esc(v.id)}" style="border-left-color:${SEV_COLOR[v.severity]||'#666'}"
             title="${esc(v.name)} · arrastrar al tablero para crear una tarjeta">
          <span class="wb-vuln-sev" style="color:${SEV_COLOR[v.severity]||'#666'}">${SEV_SHORT[v.severity] || '?'}</span>
          <span class="wb-vuln-name">${esc(v.name)}</span>
        </div>`).join('')
    : '<div class="wb-empty-section">Sin findings</div>';

  const portChips = ports.length
    ? `<div class="wb-ports-wrap">`
      + ports.map(p =>
          `<span class="wb-port-chip ${p.state === 'open' ? 'open' : 'closed'}" data-port-id="${esc(p.id)}">
             <span class="wb-port-num">${p.port}</span>${p.protocol !== 'tcp' ? `<span class="wb-port-svc">/${esc(p.protocol)}</span>` : ''}${p.service ? `<span class="wb-port-svc"> ${esc(p.service)}</span>` : ''}
           </span>`
        ).join('')
      + `</div>`
    : '<div class="wb-empty-section">Sin puertos</div>';

  const epRows = endpoints.length
    ? endpoints.map(e =>
        `<div class="wb-ep-row" data-ep-id="${esc(e.id)}" data-ep-host="${esc(target.host)}" data-ep-path="${esc(e.path)}">
           <span class="wb-ep-method" style="color:${METHOD_COLOR[e.method]||'#aaa'}">${esc(e.method)}</span>
           <span class="wb-ep-path" title="${esc(e.path)}">${esc(e.path)}</span>
           ${e.interesting ? `<span class="wb-ep-star" title="Interesante">${icon('star',{size:10})}</span>` : ''}
           <span class="wb-ep-copy">copiar</span>
         </div>`
      ).join('')
    : '<div class="wb-empty-section">Sin endpoints</div>';

  el.innerHTML = `
    <div class="wb-node-head" data-drag-handle>
      <span class="wb-node-type">${esc(target.type)}</span>
      <span class="wb-node-host" title="${esc(target.host)}">${esc(target.host)}</span>
      <span class="wb-node-status" style="background:${statusDot}" title="${esc(TARGET_STATUS_LABEL[target.status] || target.status)}"></span>
      <span class="wb-node-collapse" onclick="wbToggleCollapse('${target.id}')">${nodeData.collapsed ? icon('chevron-right',{size:11}) : icon('chevron-down',{size:11})}</span>
      <span class="wb-node-remove" onclick="wbRemoveNode('${target.id}')" title="Quitar del tablero">×</span>
    </div>
    <div class="wb-node-body">
      <div class="wb-section">
        <div class="wb-section-head">
          <span class="wb-section-label">Findings</span>
          <span class="wb-section-count">${vulns.length}</span>
        </div>
        ${vulnRows}
      </div>
      <hr class="wb-section-divider">
      <div class="wb-section">
        <div class="wb-section-head">
          <span class="wb-section-label">Puertos</span>
          <span class="wb-section-count">${ports.length}</span>
        </div>
        ${portChips}
      </div>
      <hr class="wb-section-divider">
      <div class="wb-section">
        <div class="wb-section-head">
          <span class="wb-section-label">Endpoints</span>
          <span class="wb-section-count">${endpoints.length}</span>
        </div>
        ${epRows}
      </div>
      <div class="wb-node-footer">
        <a href="targets?pid=${pid}" target="_blank">Ver en Targets →</a>
      </div>
    </div>`;

  // Copy endpoint on click (in connect mode the click picks the row instead)
  const body = el.querySelector('.wb-node-body');
  body.addEventListener('click', e => {
    if (_mode === 'connect') return;
    const row = e.target.closest('.wb-ep-row');
    if (!row) return;
    const host = (row.dataset.epHost || '').replace(/\/$/, '');
    const path = row.dataset.epPath || '';
    const text = host + path;
    navigator.clipboard.writeText(text).then(() => showToast(`Copiado: ${text}`, 'success')).catch(() => showToast('No se pudo copiar', 'error'));
  });
  body.addEventListener('pointerdown', e => {
    const row = e.target.closest('.wb-vuln-row[data-vuln-id]');
    if (!row || _mode !== 'select' || e.button !== 0) return;
    e.stopPropagation();
    e.preventDefault();
    _startFindingDrag(e, row, el);
  });
  // Arrows anchored on an endpoint/port row follow it while the body scrolls.
  body.addEventListener('scroll', _scheduleEdgeUpdate, { passive: true });

  _makeNodeDraggable(el, nodeData);
  _makeResizable(el, nodeData, 'node');
  return el;
}

function _makeNodeDraggable(el, nodeData) {
  const head = el.querySelector('[data-drag-handle]');
  head.addEventListener('pointerdown', e => {
    if (_mode !== 'select' || e.button !== 0) return;
    e.stopPropagation();
    e.preventDefault();
    _startItemDrag(e, head, `nodes:${nodeData.id}`);
  });
}

// Drag from an item's handle. Past the 5px threshold it moves the item, or
// the whole selection when the item is part of a multi-selection, as one
// undo entry. `onClick`: what a press without dragging does.
function _startItemDrag(e, handle, key, onClick) {
  const startX = e.clientX, startY = e.clientY;
  const keys = _selection.has(key) && _selection.size > 1 ? [..._selection] : [key];
  let group = null, before = null;

  function onMove(ev) {
    const dx = ev.clientX - startX, dy = ev.clientY - startY;
    if (!group) {
      if (dx * dx + dy * dy < 25) return;
      handle.setPointerCapture(ev.pointerId);
      group = keys.map(k => {
        const [kind, id] = _splitKey(k);
        const data = _localItem(kind, id), el = _keyEl(k);
        return data && el ? { kind, data, el, x: _num(data.x), y: _num(data.y) } : null;
      }).filter(Boolean);
      before = _snapshot(group.map(g => `${g.kind}:${g.data.id}`));
      group.forEach(g => {
        g.el.classList.add('dragging');
        // Dismiss any open contenteditable inside the item
        g.el.querySelectorAll('[contenteditable="true"]').forEach(ce => ce.blur());
      });
    }
    const z = wbData.view.zoom;
    group.forEach(g => {
      g.data.x = g.x + dx / z;
      g.data.y = g.y + dy / z;
      g.el.style.left = g.data.x + 'px';
      g.el.style.top  = g.data.y + 'px';
    });
    _updateAllEdges();
  }
  function onUp() {
    handle.removeEventListener('pointermove', onMove);
    if (!group) { onClick?.(); return; }
    group.forEach(g => { g.el.classList.remove('dragging'); _broadcastMove(g.kind, g.data); });
    _commitHistory(before);
    scheduleSave();
  }
  handle.addEventListener('pointermove', onMove);
  handle.addEventListener('pointerup', onUp, { once: true });
}

function _broadcastMove(kind, d) {
  if (kind === 'nodes') _broadcast({ op: 'node_move', nodeId: d.id, x: d.x, y: d.y });
  else if (kind === 'cards') _broadcast({ op: 'card_update', cardId: d.id, changes: { x: d.x, y: d.y } });
  else if (kind === 'notes') _broadcast({ op: 'note_update', noteId: d.id, changes: { x: d.x, y: d.y } });
  else if (kind === 'images') _broadcast({ op: 'image_update', imageId: d.id, changes: { x: d.x, y: d.y } });
}

function wbToggleCollapse(targetId) {
  const nd = wbData.nodes.find(n => n.id === targetId);
  if (!nd) return;
  const before = _snapshot([`nodes:${targetId}`]);
  nd.collapsed = !nd.collapsed;
  _commitHistory(before);
  const el = _nl.querySelector(`[data-node-id="${targetId}"]`);
  if (el) {
    el.classList.toggle('collapsed', nd.collapsed);
    const btn = el.querySelector('.wb-node-collapse');
    if (btn) btn.innerHTML = nd.collapsed ? icon('chevron-right',{size:11}) : icon('chevron-down',{size:11});
  }
  _broadcast({ op: 'node_toggle', nodeId: targetId, collapsed: nd.collapsed });
  scheduleSave();
  _updateAllEdges();
}

// Removes the node from the board only; the target itself stays.
function wbRemoveNode(targetId) {
  _trackRemoval([`nodes:${targetId}`]);
}

function _removeNode(targetId) {
  wbData.nodes = wbData.nodes.filter(n => n.id !== targetId);
  _nl.querySelector(`[data-node-id="${targetId}"]`)?.remove();
  _removeItemEdges(targetId, true);
  _broadcast({ op: 'node_remove', nodeId: targetId });
  scheduleSave();
}

// ── Custom cards ───────────────────────────────────────────────────────
// A finding card (ref.type 'finding') is a card about one custom_vuln. It
// stores only the finding's id (plus its name when placed, ref.label, shown
// if the finding is later deleted) and draws title, severity and remediation
// status from state.customVulns, the same GET /vulns list this member already
// sees, so it is always the CURRENT finding (wbRefreshFindings redraws it
// when page.js refreshes the list). The card's own markdown body stays below.
function _isFindingCard(cardData) {
  return cardData?.ref?.type === 'finding' && typeof cardData.ref.id === 'string';
}

function _findingOf(ref) {
  return (state.customVulns || []).find(v => v.id === ref.id) || null;
}

function _findingBlock(cardData) {
  const v = _findingOf(cardData.ref);
  if (!v) {
    return `<div class="wb-finding wb-finding--gone">${icon('triangle-alert', { size: 11 })} Finding eliminado: ya no existe en el proyecto</div>`;
  }
  const t = v.target_id && (state.targets || []).find(x => x.id === v.target_id);
  const cvss = v.cvss_score != null && v.cvss_score !== '' && Number.isFinite(+v.cvss_score) ? (+v.cvss_score).toFixed(1) : '';
  const rem = v.remediation_status || 'open';
  return `
    <div class="wb-finding">
      <span class="wb-finding-sev" style="background:${SEV_COLOR[v.severity] || '#666'}">${esc(SEV_LABEL[v.severity] || v.severity || '?')}</span>
      <span class="wb-finding-status wb-finding-status--${rem === 'open' ? 'open' : 'closed'}">${esc(REMEDIATION_LABEL[rem] || rem)}</span>
      ${cvss ? `<span class="wb-finding-cvss">CVSS ${cvss}</span>` : ''}
    </div>
    ${t ? `<div class="wb-card-ref" title="${esc(t.host)}">↳ ${esc(t.host)}</div>` : ''}`;
}

function _buildCard(cardData) {
  const finding = _isFindingCard(cardData);
  const vuln    = finding ? _findingOf(cardData.ref) : null;
  // A finding card's title is the finding's current one; while it exists the
  // header is not editable (the finding is edited on the Findings page).
  const title = finding ? (vuln ? vuln.name : (cardData.ref.label || cardData.title || 'Finding')) : (cardData.title || '');
  const el = document.createElement('div');
  el.className = 'wb-card' + (finding ? ' wb-card--finding' : '') + (finding && !vuln ? ' wb-card--gone' : '');
  if (vuln) el.style.setProperty('--wb-sev', SEV_COLOR[vuln.severity] || '#666');
  el.dataset.nodeId = cardData.id; // same attr as target nodes → arrows work
  el.style.left  = _num(cardData.x) + 'px';
  el.style.top   = _num(cardData.y) + 'px';
  el.style.width = (_dim(cardData.w, MIN_SIZE.card.w) || DEFAULT_SIZE.card.w) + 'px';
  if (_dim(cardData.h, MIN_SIZE.card.h)) el.style.height = _dim(cardData.h, MIN_SIZE.card.h) + 'px';

  const colorDots = CARD_COLORS.map(c =>
    `<span class="wb-card-col" style="background:${c}" data-color="${c}"></span>`
  ).join('');

  el.innerHTML = `
    <div class="wb-card-head" data-drag-handle style="background:${_cardColor(cardData.color)}">
      ${icon('grip-vertical', { size: 13, class: 'wb-card-grip' })}
      <span class="wb-card-title" data-title contenteditable="false"${finding ? ` title="${esc(title)}"` : ''}>${esc(title)}</span>
      <div class="wb-card-colors">${colorDots}</div>
      <span class="wb-card-rm">×</span>
    </div>
    <div class="wb-card-body">
      ${finding ? _findingBlock(cardData)
        : cardData.ref ? `<div class="wb-card-ref" title="${esc(REF_TYPE_LABEL[cardData.ref.type] || cardData.ref.type)}">↳ ${esc(cardData.ref.label || '')}</div>` : ''}
      <div class="wb-card-text" data-text contenteditable="false"
           data-placeholder="Doble clic para agregar notas…">${renderMd(cardData.body)}</div>
      <div class="wb-card-hint">${cardData.created_by === 'claude_code' ? '<span class="wb-cc-tag">Claude Code</span> · ' : ''}doble clic para editar · arrastrar el encabezado para mover</div>
    </div>`;

  const titleEl = el.querySelector('[data-title]');
  const textEl  = el.querySelector('[data-text]');

  // Title editing (double-click); not on a finding card (see above)
  titleEl.addEventListener('dblclick', e => {
    e.stopPropagation();
    if (finding) return;
    titleEl.contentEditable = 'true';
    titleEl.focus();
    const r = document.createRange();
    r.selectNodeContents(titleEl);
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(r);
  });
  titleEl.addEventListener('blur', () => {
    titleEl.contentEditable = 'false';
    const before = _snapshot([`cards:${cardData.id}`]);
    cardData.title = titleEl.innerText.trim() || 'Tarjeta';
    _commitHistory(before);
    if (titleEl.innerText.trim() === '') titleEl.textContent = 'Tarjeta';
    _broadcast({ op: 'card_update', cardId: cardData.id, changes: { title: cardData.title } });
    scheduleSave();
  });
  titleEl.addEventListener('keydown', e => {
    e.stopPropagation();
    if (e.key === 'Enter' || e.key === 'Escape') titleEl.blur();
  });
  titleEl.addEventListener('pointerdown', e => e.stopPropagation());

  // Body editing (double-click)
  textEl.addEventListener('dblclick', e => {
    e.stopPropagation();
    textEl.contentEditable = 'true'; // set first so pre-wrap CSS applies before textContent
    textEl.textContent = cardData.body || '';
    textEl.focus();
    // move cursor to end
    const range = document.createRange();
    range.selectNodeContents(textEl);
    range.collapse(false);
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(range);
  });
  textEl.addEventListener('blur', () => {
    const raw = textEl.innerText.replace(/\n$/, ''); // drop single trailing newline browsers add
    textEl.contentEditable = 'false';
    const before = _snapshot([`cards:${cardData.id}`]);
    cardData.body = raw;
    _commitHistory(before);
    textEl.innerHTML = renderMd(raw);
    _updateAllEdges(); // an unsized card's height follows its text
    _broadcast({ op: 'card_update', cardId: cardData.id, changes: { body: raw } });
    scheduleSave();
  });
  textEl.addEventListener('keydown', e => {
    e.stopPropagation();
    if (e.key === 'Escape') textEl.blur();
  });
  textEl.addEventListener('pointerdown', e => e.stopPropagation());

  // Color dots
  el.querySelector('.wb-card-colors').addEventListener('click', e => {
    const dot = e.target.closest('[data-color]');
    if (!dot) return;
    e.stopPropagation();
    wbCardColor(cardData.id, dot.dataset.color);
  });

  // Remove button
  el.querySelector('.wb-card-rm').addEventListener('click', e => {
    e.stopPropagation();
    wbRemoveCard(cardData.id);
  });

  _makeCardDraggable(el, cardData);
  _makeResizable(el, cardData, 'card');
  return el;
}

function _makeCardDraggable(el, cardData) {
  const head = el.querySelector('[data-drag-handle]');
  head.addEventListener('pointerdown', e => {
    if (e.button !== 0) return;
    if (e.target.closest('.wb-card-rm, .wb-card-col')) return;
    if (_mode !== 'select') return;
    e.stopPropagation();
    // No preventDefault — allows dblclick editing to work normally
    _startItemDrag(e, head, `cards:${cardData.id}`);
  });
}

function _makeResizable(el, data, type) {
  const min = MIN_SIZE[type];
  const handle = document.createElement('div');
  handle.className = 'wb-resize-handle';
  el.appendChild(handle);

  handle.addEventListener('pointerdown', e => {
    if (e.button !== 0) return;
    e.stopPropagation();
    e.preventDefault();
    handle.setPointerCapture(e.pointerId);

    const startX = e.clientX, startY = e.clientY;
    const startW = el.offsetWidth,  startH = el.offsetHeight;
    const ratio  = startH / (startW || 1);
    const before = _snapshot([`${type}s:${data.id}`]);

    function onMove(e) {
      const z = wbData.view.zoom;
      data.w = Math.round(_dim(startW + (e.clientX - startX) / z, min.w) || min.w);
      // An image keeps its proportions unless Shift is held.
      data.h = type === 'image' && !e.shiftKey
        ? Math.round(_dim(data.w * ratio, min.h) || min.h)
        : Math.round(_dim(startH + (e.clientY - startY) / z, min.h) || min.h);
      el.style.width  = data.w + 'px';
      el.style.height = data.h + 'px';
      if (type === 'node') el.classList.add('wb-node--sized');
      if (type === 'note') el.classList.add('wb-sticky--sized');
      _updateAllEdges();
    }
    function onUp() {
      handle.removeEventListener('pointermove', onMove);
      if (type === 'card') {
        _broadcast({ op: 'card_update', cardId: data.id, changes: { w: data.w, h: data.h } });
      } else if (type === 'note') {
        _broadcast({ op: 'note_update', noteId: data.id, changes: { w: data.w, h: data.h } });
      } else if (type === 'image') {
        _broadcast({ op: 'image_update', imageId: data.id, changes: { w: data.w, h: data.h } });
      } else {
        _broadcast({ op: 'node_resize', nodeId: data.id, w: data.w, h: data.h });
      }
      _commitHistory(before);
      scheduleSave();
    }
    handle.addEventListener('pointermove', onMove);
    handle.addEventListener('pointerup', onUp, { once: true });
  });
}

function _addCard(x, y) {
  const id = crypto.randomUUID();
  const cardData = { id, x, y, title: 'Tarjeta', body: '', color: CARD_COLORS[0] };
  wbData.cards.push(cardData);
  const el = _nl.appendChild(_buildCard(cardData));
  _broadcast({ op: 'card_add', card: cardData });
  _commitHistory(new Map([[`cards:${id}`, null]]));
  scheduleSave();
  setTimeout(() => {
    const titleEl = el.querySelector('[data-title]');
    if (!titleEl) return;
    titleEl.contentEditable = 'true';
    titleEl.focus();
    const r = document.createRange();
    r.selectNodeContents(titleEl);
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(r);
  }, 40);
}

function wbRemoveCard(id) {
  _trackRemoval([`cards:${id}`]);
}

function _removeCard(id) {
  wbData.cards = wbData.cards.filter(c => c.id !== id);
  _nl.querySelector(`[data-node-id="${id}"]`)?.remove();
  _removeItemEdges(id, true);
  _broadcast({ op: 'card_remove', cardId: id });
  scheduleSave();
}

function wbCardColor(id, color) {
  const cd = wbData.cards.find(c => c.id === id);
  if (!cd) return;
  const before = _snapshot([`cards:${id}`]);
  cd.color = color = _cardColor(color);
  _commitHistory(before);
  const head = _nl.querySelector(`[data-node-id="${id}"] .wb-card-head`);
  if (head) head.style.background = color;
  _broadcast({ op: 'card_update', cardId: id, changes: { color } });
  scheduleSave();
}

// ── Finding cards ──────────────────────────────────────────────────────
// Placed from the toolbar picker (wbPickFinding) or by dragging a finding row
// out of a target node (_startFindingDrag). Like the MCP add_whiteboard_items
// link, the card gets an arrow to its target's node when that node is on the
// board; card and arrow are one undo entry.
function _addFindingCard(v, wx, wy) {
  const id = crypto.randomUUID();
  const card = {
    id, x: Math.round(wx - DEFAULT_SIZE.card.w / 2), y: Math.round(wy - 30),
    title: String(v.name || 'Finding').slice(0, 500), body: '', color: CARD_COLORS[0],
    ref: { type: 'finding', id: v.id, target_id: v.target_id || null, label: String(v.name || '').slice(0, 1000) },
  };
  wbData.cards.push(card);
  _nl.appendChild(_buildCard(card));
  _broadcast({ op: 'card_add', card });
  const keys = [`cards:${id}`];
  if (card.ref.target_id && _localItem('nodes', card.ref.target_id) && _itemEl('node', card.ref.target_id)) {
    const edge = { id: crypto.randomUUID(), fromId: id, toId: card.ref.target_id, label: '' };
    wbData.edges.push(edge);
    _renderEdge(edge);
    _broadcast({ op: 'edge_add', edge });
    keys.push(`edges:${edge.id}`);
  }
  _commitHistory(new Map(keys.map(k => [k, null])));
  _updateAllEdges();
  scheduleSave();
  if (_mode === 'select') _setSelection([`cards:${id}`]);
}

// Drag a finding row of a target node onto the board: a ghost follows the
// pointer and dropping it outside that node places the finding card there.
function _startFindingDrag(e, row, nodeEl) {
  const vulnId = row.dataset.vulnId;
  const startX = e.clientX, startY = e.clientY;
  let ghost = null;
  row.setPointerCapture(e.pointerId);

  function onMove(ev) {
    if (!ghost) {
      const dx = ev.clientX - startX, dy = ev.clientY - startY;
      if (dx * dx + dy * dy < 25) return;
      ghost = document.createElement('div');
      ghost.className = 'wb-drag-ghost';
      ghost.textContent = row.querySelector('.wb-vuln-name')?.textContent || 'Finding';
      _vp.appendChild(ghost);
    }
    const r = _vp.getBoundingClientRect();
    ghost.style.left = (ev.clientX - r.left) + 'px';
    ghost.style.top  = (ev.clientY - r.top) + 'px';
  }
  function onEnd(ev) {
    row.removeEventListener('pointermove', onMove);
    row.removeEventListener('pointerup', onEnd);
    row.removeEventListener('pointercancel', onEnd);
    if (!ghost) return;
    ghost.remove();
    if (ev.type === 'pointercancel') return;
    const r = _vp.getBoundingClientRect();
    const inside = ev.clientX >= r.left && ev.clientX <= r.right && ev.clientY >= r.top && ev.clientY <= r.bottom;
    const over = document.elementFromPoint(ev.clientX, ev.clientY);
    if (!inside || (over && nodeEl.contains(over))) return;
    const v = (state.customVulns || []).find(x => x.id === vulnId);
    if (!v) { showToast('Ese finding ya no existe', 'error'); return; }
    const w = _screenToWorld(ev.clientX, ev.clientY);
    _addFindingCard(v, w.x, w.y);
  }
  row.addEventListener('pointermove', onMove);
  row.addEventListener('pointerup', onEnd);
  row.addEventListener('pointercancel', onEnd);
}

// Toolbar "Finding": searchable list of the project's findings (the same
// state.customVulns this member already sees); picking one places its card
// in the middle of the screen.
function wbPickFinding() {
  document.querySelector('.wb-picker-overlay')?.remove();
  const overlay = document.createElement('div');
  overlay.className = 'wb-modal-overlay wb-picker-overlay';
  overlay.innerHTML = `
    <div class="wb-modal wb-picker" role="dialog" aria-modal="true" aria-label="Agregar un finding al tablero">
      <p class="wb-modal-title">Agregar un finding al tablero</p>
      <input type="text" class="wb-picker-search" placeholder="Buscar por título, severidad o target…"
             autocomplete="off" aria-label="Buscar findings">
      <div class="wb-picker-list" role="listbox"></div>
      <div class="wb-modal-btns"><button class="wb-modal-btn wb-modal-cancel">Cancelar</button></div>
    </div>`;
  document.body.appendChild(overlay);
  const input = overlay.querySelector('.wb-picker-search');
  const list  = overlay.querySelector('.wb-picker-list');
  const hostOf = v => (v.target_id && (state.targets || []).find(t => t.id === v.target_id)?.host) || '';
  let shown = [];

  const render = () => {
    const vulns = state.customVulns || [];
    const q = input.value.trim().toLowerCase();
    const onBoard = new Set(wbData.cards.filter(_isFindingCard).map(c => c.ref.id));
    shown = vulns
      .filter(v => !q || [v.name, SEV_LABEL[v.severity], v.severity, hostOf(v)].join(' ').toLowerCase().includes(q))
      .sort((a, b) => (SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)) || String(a.name).localeCompare(String(b.name)));
    if (!vulns.length) { list.innerHTML = '<div class="wb-picker-empty">Este proyecto todavía no tiene findings</div>'; return; }
    if (!shown.length) { list.innerHTML = '<div class="wb-picker-empty">Ningún finding coincide con la búsqueda</div>'; return; }
    list.innerHTML = shown.map((v, i) => `
      <button class="wb-picker-item" data-i="${i}" role="option">
        <span class="wb-finding-sev" style="background:${SEV_COLOR[v.severity] || '#666'}">${esc(SEV_LABEL[v.severity] || v.severity || '?')}</span>
        <span class="wb-picker-name">${esc(v.name)}</span>
        ${hostOf(v) ? `<span class="wb-picker-host">${esc(hostOf(v))}</span>` : ''}
        ${onBoard.has(v.id) ? '<span class="wb-picker-on">en el tablero</span>' : ''}
      </button>`).join('');
  };
  const close = () => { overlay.remove(); };
  const pick = v => {
    close();
    const c = _viewportCenter();
    _addFindingCard(v, c.x, c.y);
  };
  overlay._render = render;

  input.addEventListener('input', render);
  input.addEventListener('keydown', e => {
    if (e.key === 'Escape') { e.preventDefault(); close(); }
    if (e.key === 'Enter' && shown[0]) { e.preventDefault(); pick(shown[0]); }
  });
  list.addEventListener('click', e => {
    const btn = e.target.closest('[data-i]');
    if (btn && shown[+btn.dataset.i]) pick(shown[+btn.dataset.i]);
  });
  overlay.addEventListener('keydown', e => { if (e.key === 'Escape') close(); });
  overlay.querySelector('.wb-modal-cancel').addEventListener('click', close);
  overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
  render();
  input.focus();
}

// The findings list changed (page.js scheduleVulnsRefresh: live through the
// 'vulns:changed' WS ping and custom_vuln Activity events). Redraws what
// shows findings — target nodes' finding rows and finding cards — keeping
// each node's scroll, plus the open picker.
function wbRefreshFindings() {
  if (!_wbReady) return;
  wbData.nodes.forEach(nd => {
    const scroll = _itemEl('node', nd.id)?.querySelector('.wb-node-body')?.scrollTop || 0;
    _renderItem('nodes', nd);
    const body = _itemEl('node', nd.id)?.querySelector('.wb-node-body');
    if (body && scroll) body.scrollTop = scroll;
  });
  wbData.cards.filter(_isFindingCard).forEach(c => _renderItem('cards', c));
  _updateAllEdges();
  if (_searchQuery) _applySearch();
  document.querySelector('.wb-picker-overlay')?._render?.();
}

// ── Images ─────────────────────────────────────────────────────────────
// An image item only holds the id of its row in whiteboard_images
// (imageId); the bytes are fetched with the API and shown via a blob: URL.
// Same type/size limits as the server, checked here only to fail early.
const IMAGE_TYPES     = ['image/png', 'image/jpeg', 'image/webp'];
const MAX_IMAGE_BYTES = 4 * 1024 * 1024;

// Items from the saved board or a wb:patch: the imageId ends up in a URL.
function _validImage(im) {
  return !!im && typeof im === 'object' && _validId(im.id) && _validId(im.imageId);
}

function _viewportCenter() {
  const r = _vp.getBoundingClientRect();
  return _screenToWorld(r.left + r.width / 2, r.top + r.height / 2);
}

// Initial size: the image's own width up to the default, keeping its
// proportions (4:3 when the server could not read them). Same rule as the
// MCP server (services/mcp/whiteboard.js imageBox).
function _imageInitialSize(meta) {
  const ratio = meta.width > 0 && meta.height > 0 ? meta.height / meta.width : DEFAULT_SIZE.image.h / DEFAULT_SIZE.image.w;
  const w = Math.round(_dim(Math.min(DEFAULT_SIZE.image.w, meta.width || DEFAULT_SIZE.image.w), MIN_SIZE.image.w));
  const h = Math.round(_dim(w * ratio, MIN_SIZE.image.h));
  return { w, h };
}

function _imageUrl(imageId) {
  let entry = _imgUrls.get(imageId);
  if (entry) return entry.promise;
  entry = { url: null };
  entry.promise = api.whiteboard.imageBlob(state.currentProject.id, imageId).then(blob => {
    // Released while downloading (the item was removed): no URL to leak.
    if (_imgUrls.get(imageId) !== entry) throw new Error('released');
    entry.url = URL.createObjectURL(blob);
    return entry.url;
  });
  // A failed download is retried the next time the image is drawn.
  entry.promise.catch(() => { if (_imgUrls.get(imageId) === entry) _imgUrls.delete(imageId); });
  _imgUrls.set(imageId, entry);
  return entry.promise;
}

function _releaseImageUrl(imageId) {
  if (wbData.images.some(i => i.imageId === imageId)) return;
  const entry = _imgUrls.get(imageId);
  if (!entry) return;
  _imgUrls.delete(imageId);
  if (entry.url) URL.revokeObjectURL(entry.url);
}

function _applyImageGeometry(el, im) {
  el.style.left   = _num(im.x) + 'px';
  el.style.top    = _num(im.y) + 'px';
  el.style.width  = (_dim(im.w, MIN_SIZE.image.w) || DEFAULT_SIZE.image.w) + 'px';
  el.style.height = (_dim(im.h, MIN_SIZE.image.h) || DEFAULT_SIZE.image.h) + 'px';
}

function _applyImageCaption(el, im) {
  const cap = el.querySelector('[data-caption]');
  if (cap && cap.contentEditable !== 'true') cap.textContent = im.caption || '';
  const img = el.querySelector('.wb-image-img');
  if (img) img.alt = im.caption || '';
}

function _buildImage(im) {
  const el = document.createElement('div');
  el.className = 'wb-image';
  el.dataset.nodeId = im.id; // same attr as cards → arrows and _itemEl work
  _applyImageGeometry(el, im);
  el.innerHTML = `
    <div class="wb-image-head" data-drag-handle>
      ${icon('grip-vertical', { size: 13, class: 'wb-card-grip' })}
      ${im.created_by === 'claude_code' ? '<span class="wb-cc-tag">Claude Code</span>' : ''}
      <span class="wb-image-cap" title="Editar pie de imagen">${icon('pencil', { size: 11 })}</span>
      <span class="wb-image-rm" title="Quitar del tablero">×</span>
    </div>
    <div class="wb-image-frame" data-drag-handle title="Clic para ampliar"><span class="wb-image-status">Cargando imagen…</span></div>
    <div class="wb-image-caption" data-caption contenteditable="false" data-placeholder="Pie de imagen…"></div>`;
  _applyImageCaption(el, im);

  const frame = el.querySelector('.wb-image-frame');
  const fail = () => {
    frame.classList.add('error');
    frame.querySelector('.wb-image-status').textContent = 'No se pudo cargar la imagen';
  };
  if (_validId(im.imageId)) {
    _imageUrl(im.imageId).then(url => {
      const img = document.createElement('img');
      img.className = 'wb-image-img';
      img.draggable = false;
      img.alt = im.caption || '';
      img.src = url; // by property, never interpolated into markup
      frame.replaceChildren(img);
    }).catch(fail);
  } else {
    fail();
  }

  const cap = el.querySelector('[data-caption]');
  const editCaption = () => {
    cap.contentEditable = 'true';
    cap.focus();
    const r = document.createRange();
    r.selectNodeContents(cap);
    r.collapse(false);
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(r);
  };
  el.querySelector('.wb-image-cap').addEventListener('click', e => { e.stopPropagation(); editCaption(); });
  cap.addEventListener('dblclick', e => { e.stopPropagation(); editCaption(); });
  cap.addEventListener('pointerdown', e => e.stopPropagation());
  cap.addEventListener('blur', () => {
    cap.contentEditable = 'false';
    const text = cap.innerText.trim().slice(0, 500);
    if ((im.caption || '') === text) { cap.textContent = text; return; }
    const before = _snapshot([`images:${im.id}`]);
    if (text) im.caption = text; else delete im.caption;
    _commitHistory(before);
    _applyImageCaption(el, im);
    _broadcast({ op: 'image_update', imageId: im.id, changes: { caption: text } });
    scheduleSave();
  });
  cap.addEventListener('keydown', e => {
    e.stopPropagation();
    if (e.key === 'Enter' || e.key === 'Escape') { e.preventDefault(); cap.blur(); }
  });

  el.querySelector('.wb-image-rm').addEventListener('click', e => {
    e.stopPropagation();
    wbRemoveImage(im.id);
  });

  _makeImageDraggable(el, im);
  _makeResizable(el, im, 'image');
  return el;
}

// Drag from the header or the picture; a click on the picture without
// dragging opens it full size.
function _makeImageDraggable(el, im) {
  el.querySelectorAll('[data-drag-handle]').forEach(handle => {
    handle.addEventListener('pointerdown', e => {
      if (e.button !== 0 || _mode !== 'select') return;
      if (e.target.closest('.wb-image-rm, .wb-image-cap')) return;
      e.stopPropagation();
      e.preventDefault();
      const zoomIn = handle.classList.contains('wb-image-frame') ? () => _openImageLightbox(im) : null;
      _startItemDrag(e, handle, `images:${im.id}`, zoomIn);
    });
  });
}

// Full-size view, with the shared .img-lb styles (css/main.css). Esc or a
// click outside the picture closes it; while open, keys stay here so the
// board shortcuts do not fire underneath.
function _openImageLightbox(im) {
  const entry = _imgUrls.get(im.imageId);
  if (!entry?.url) return;
  document.getElementById('img-lb')?._close?.();
  const overlay = document.createElement('div');
  overlay.className = 'img-lb';
  overlay.id = 'img-lb';
  overlay.innerHTML = `
    <div class="img-lb-bar">
      <span class="img-lb-name"></span>
      <button class="img-lb-btn img-lb-close" title="Cerrar (Esc)">${icon('x', { size: 20 })}</button>
    </div>
    <div class="img-lb-stage"><img class="img-lb-img" alt=""></div>`;
  const imgEl = overlay.querySelector('.img-lb-img');
  imgEl.src = entry.url;
  imgEl.alt = im.caption || '';
  overlay.querySelector('.img-lb-name').textContent = im.caption || 'Imagen';

  const onKey = e => {
    e.stopPropagation();
    if (e.key === 'Escape') { e.preventDefault(); close(); }
  };
  const close = () => {
    window.removeEventListener('keydown', onKey, true);
    overlay.remove();
  };
  overlay._close = close;
  overlay.addEventListener('click', e => {
    if (e.target.closest('.img-lb-close') || e.target === overlay || e.target.classList.contains('img-lb-stage')) close();
  });
  window.addEventListener('keydown', onKey, true);
  document.body.appendChild(overlay);
}

// Uploads each file, then places it centered on (wx, wy); several files
// cascade a little so they do not stack exactly.
async function _addImageFiles(files, wx, wy) {
  const list = [...(files || [])];
  let placed = 0;
  for (const file of list) {
    const name = file.name || 'Imagen';
    if (file.type && !IMAGE_TYPES.includes(file.type)) { showToast(`${name}: solo se aceptan PNG, JPEG o WebP`, 'error'); continue; }
    if (file.size > MAX_IMAGE_BYTES) { showToast(`${name}: supera los 4 MB`, 'error'); continue; }
    try {
      const meta = await api.whiteboard.uploadImage(state.currentProject.id, file);
      const { w, h } = _imageInitialSize(meta);
      const off = placed * 24;
      const im = { id: crypto.randomUUID(), imageId: meta.id, x: Math.round(wx - w / 2 + off), y: Math.round(wy - h / 2 + off), w, h };
      wbData.images.push(im);
      _nl.appendChild(_buildImage(im));
      _broadcast({ op: 'image_add', image: im });
      _commitHistory(new Map([[`images:${im.id}`, null]]));
      scheduleSave();
      placed++;
    } catch (err) {
      showToast(`${name}: no se pudo subir (${err.message})`, 'error');
    }
  }
}

function wbPickImages() {
  document.getElementById('wb-image-input')?.click();
}

function _removeImage(id, broadcast) {
  const im = wbData.images.find(i => i.id === id);
  if (!im) return;
  wbData.images = wbData.images.filter(i => i.id !== id);
  _itemEl('image', id)?.remove();
  _removeItemEdges(id, broadcast);
  _releaseImageUrl(im.imageId);
  if (broadcast) {
    _broadcast({ op: 'image_remove', imageId: id });
    scheduleSave();
  }
}

function wbRemoveImage(id) {
  _trackRemoval([`images:${id}`]);
}

// ── Edges ──────────────────────────────────────────────────────────────
// An edge joins two ends. Each end is a board item (target node, card or
// note: fromId/toId) and, on a target node, optionally one of its endpoint
// rows (fromEp/toEp) or port chips (fromPort/toPort). Optional style fields:
// style (line), arrow (which ends get an arrowhead, default end), color.
const SVG_NS = 'http://www.w3.org/2000/svg';
const EDGE_END_KEYS = ['Id', 'Ep', 'Port'];

function _edgeEl(edgeId) {
  return _edgeSvg ? _edgeSvg.querySelector(`[data-edge-id="${CSS.escape(String(edgeId))}"]`) : null;
}

function _findItem(id) {
  for (const kind of ['node', 'card', 'note', 'image']) {
    const data = wbData[`${kind}s`].find(x => x.id === id);
    if (data) return { kind, data };
  }
  return null;
}

// side: 'from' | 'to'
function _edgeEnd(edge, side) {
  return { id: edge[`${side}Id`], ep: edge[`${side}Ep`], port: edge[`${side}Port`] };
}
function _endKey(end) { return `${end.id}|${end.ep || ''}|${end.port || ''}`; }
// A→B and B→A are the same connection.
function _pairKey(a, b) { return [_endKey(a), _endKey(b)].sort().join('>'); }

// Why a connection between these ends cannot be made (null when it can).
// `ignoreId`: the edge being re-pointed, which must not count as its own duplicate.
function _edgeProblem(from, to, ignoreId = null) {
  if (from.id === to.id) return 'Un elemento no se puede conectar consigo mismo';
  const key = _pairKey(from, to);
  const dup = wbData.edges.some(e => e.id !== ignoreId && _pairKey(_edgeEnd(e, 'from'), _edgeEnd(e, 'to')) === key);
  return dup ? 'Esa conexión ya existe' : null;
}

// Board end under a DOM element: a note, card or target node, or the
// endpoint row / port chip of a target node.
function _endFromElement(target) {
  if (!(target instanceof Element) || !_nl.contains(target)) return null;
  const itemEl = target.closest('.wb-node, .wb-card, .wb-sticky, .wb-image');
  if (!itemEl) return null;
  if (itemEl.classList.contains('wb-sticky')) return { id: itemEl.dataset.noteId, el: itemEl };
  const id = itemEl.dataset.nodeId;
  if (itemEl.classList.contains('wb-node')) {
    const row = target.closest('[data-ep-id], [data-port-id]');
    if (row && itemEl.contains(row)) {
      return row.dataset.epId ? { id, ep: row.dataset.epId, el: row } : { id, port: row.dataset.portId, el: row };
    }
  }
  return { id, el: itemEl };
}

// World-space box of the endpoint row / port chip an end points at, or null
// when the edge should anchor on the whole node instead: no row, the node is
// collapsed, the endpoint/port no longer exists, or the row is scrolled out
// of the node body.
function _rowBox(end) {
  if (!end.ep && !end.port) return null;
  const nd = wbData.nodes.find(n => n.id === end.id);
  const el = nd && !nd.collapsed && _itemEl('node', end.id);
  if (!el) return null;
  const row = end.ep
    ? el.querySelector(`[data-ep-id="${CSS.escape(String(end.ep))}"]`)
    : el.querySelector(`[data-port-id="${CSS.escape(String(end.port))}"]`);
  const body = el.querySelector('.wb-node-body');
  if (!row || !body) return null;
  const r = row.getBoundingClientRect(), b = body.getBoundingClientRect();
  const cy = r.top + r.height / 2;
  if (!r.height || cy < b.top || cy > b.bottom) return null;
  const p1 = _screenToWorld(r.left, r.top), p2 = _screenToWorld(r.right, r.bottom);
  return { x: p1.x, y: p1.y, w: p2.x - p1.x, h: p2.y - p1.y };
}

function _endGeom(end) {
  const it = _findItem(end.id);
  if (!it || !_itemEl(it.kind, end.id)) return null;
  const box = _itemBox(it.kind, it.data);
  const row = it.kind === 'node' ? _rowBox(end) : null;
  return { box, row, cx: box.x + box.w / 2, cy: row ? row.y + row.h / 2 : box.y + box.h / 2 };
}

// Where the line leaves `g` towards `other`: a row anchors on the node's
// left/right side at the row's height; otherwise the line from the item's
// center is clipped to its box. `gap` leaves room for an arrowhead.
function _anchorPoint(g, other, gap) {
  if (g.row) {
    const right = other.cx >= g.cx;
    return { x: right ? g.box.x + g.box.w + 2 + gap : g.box.x - 2 - gap, y: g.cy };
  }
  const dx = other.cx - g.cx, dy = other.cy - g.cy;
  const len = Math.sqrt(dx * dx + dy * dy) || 1;
  const ux = dx / len, uy = dy / len;
  const t = Math.min((g.box.w / 2 + 2) / (Math.abs(ux) || 0.001), (g.box.h / 2 + 2) / (Math.abs(uy) || 0.001)) + gap;
  return { x: g.cx + ux * t, y: g.cy + uy * t };
}

function _edgeEndpoints(edge) {
  const from = _endGeom(_edgeEnd(edge, 'from'));
  const to   = _endGeom(_edgeEnd(edge, 'to'));
  if (!from || !to) return null;

  const arrow = _edgeArrow(edge.arrow);
  const s = _anchorPoint(from, to, arrow === 'start' || arrow === 'both' ? 8 : 0);
  const e = _anchorPoint(to, from, arrow === 'end'   || arrow === 'both' ? 8 : 0);
  const sx = s.x, sy = s.y, ex = e.x, ey = e.y;

  // Bezier control points (same logic as _edgeCubic uses)
  const cdx = ex - sx, cdy = ey - sy;
  const adx = Math.abs(cdx), ady = Math.abs(cdy);
  const total = adx + ady || 1;
  const bendX = (adx / total) * Math.max(50, adx * 0.5);
  const bendY = (ady / total) * Math.max(50, ady * 0.5);
  const signX = cdx >= 0 ? 1 : -1, signY = cdy >= 0 ? 1 : -1;
  const cp1x = sx + signX * bendX, cp1y = sy + signY * bendY;
  const cp2x = ex - signX * bendX, cp2y = ey - signY * bendY;

  // True bezier midpoint at t=0.5
  const mx = 0.125*sx + 0.375*cp1x + 0.375*cp2x + 0.125*ex;
  const my = 0.125*sy + 0.375*cp1y + 0.375*cp2y + 0.125*ey;

  return { sx, sy, ex, ey, mx, my };
}

function _edgeCubic(pts) {
  const dx    = pts.ex - pts.sx;
  const dy    = pts.ey - pts.sy;
  const adx   = Math.abs(dx), ady = Math.abs(dy);
  const total = adx + ady || 1;

  const bendX = (adx / total) * Math.max(50, adx * 0.5);
  const bendY = (ady / total) * Math.max(50, ady * 0.5);
  const signX = dx >= 0 ? 1 : -1;
  const signY = dy >= 0 ? 1 : -1;

  const cp1x = pts.sx + signX * bendX, cp1y = pts.sy + signY * bendY;
  const cp2x = pts.ex - signX * bendX, cp2y = pts.ey - signY * bendY;

  return `M${pts.sx.toFixed(1)},${pts.sy.toFixed(1)} C${cp1x.toFixed(1)},${cp1y.toFixed(1)} ${cp2x.toFixed(1)},${cp2y.toFixed(1)} ${pts.ex.toFixed(1)},${pts.ey.toFixed(1)}`;
}

// One arrowhead marker per edge color plus the theme default and the accent
// (hover/selection of an uncolored edge, see whiteboard.html). Fills are CSS
// so the default follows the light/dark theme; orient auto-start-reverse lets
// the same marker serve marker-start and marker-end.
function _ensureEdgeMarkers() {
  const defs = _edgeSvg.querySelector('defs') || _edgeSvg.insertBefore(document.createElementNS(SVG_NS, 'defs'), _edgeSvg.firstChild);
  defs.innerHTML = '';
  const fills = { default: 'var(--t3)', accent: 'var(--a)' };
  EDGE_COLORS.forEach(c => { fills[c.slice(1)] = c; });
  Object.entries(fills).forEach(([key, fill]) => {
    const m = document.createElementNS(SVG_NS, 'marker');
    m.id = `wb-arrow-${key}`;
    m.setAttribute('markerWidth', '10');
    m.setAttribute('markerHeight', '7');
    m.setAttribute('refX', '9');
    m.setAttribute('refY', '3.5');
    m.setAttribute('orient', 'auto-start-reverse');
    m.setAttribute('markerUnits', 'userSpaceOnUse');
    const p = document.createElementNS(SVG_NS, 'path');
    p.setAttribute('d', 'M0,0 L10,3.5 L0,7 Z');
    p.style.fill = fill;
    m.appendChild(p);
    defs.appendChild(m);
  });
}

function _renderEdge(edge) {
  const g = document.createElementNS(SVG_NS, 'g');
  g.dataset.edgeId = edge.id;
  g.classList.add('wb-edge-group');

  const title = document.createElementNS(SVG_NS, 'title');

  const hit = document.createElementNS(SVG_NS, 'path');
  hit.classList.add('wb-edge-hit');

  const line = document.createElementNS(SVG_NS, 'path');
  line.classList.add('wb-edge-line');

  const dot = document.createElementNS(SVG_NS, 'circle');
  dot.classList.add('wb-edge-dot');
  dot.setAttribute('r', '4');

  const label = document.createElementNS(SVG_NS, 'text');
  label.classList.add('wb-edge-label');

  g.appendChild(title);
  g.appendChild(hit);
  g.appendChild(line);
  g.appendChild(dot);
  g.appendChild(label);
  _edgeSvg.appendChild(g);

  hit.addEventListener('click', ev => {
    if (_mode !== 'select') return;
    ev.stopPropagation();
    _selectEdge(edge.id);
  });
  hit.addEventListener('dblclick', ev => {
    if (_mode !== 'select') return;
    ev.stopPropagation();
    _editEdgeLabel(edge);
  });

  _applyEdgeStyle(edge);
  _updateEdgePath(edge);
  return g;
}

// "GET /login" / "443/tcp" for an end pointing at an endpoint/port row.
function _endRowText(end) {
  if (end.ep) {
    const e = (_endpointsMap[end.id] || []).find(x => x.id === end.ep);
    return e ? `${e.method} ${e.path}` : 'endpoint eliminado';
  }
  if (end.port) {
    const p = (_portsMap[end.id] || []).find(x => x.id === end.port);
    return p ? `${p.port}/${p.protocol}` : 'puerto eliminado';
  }
  return '';
}

// Label, tooltip, line style, color and arrowheads from the edge's fields.
// Every value goes through an allowlist: edges come from other members.
function _applyEdgeStyle(edge) {
  const g = _edgeEl(edge.id);
  if (!g) return;
  const color = _edgeColor(edge.color), arrow = _edgeArrow(edge.arrow), style = _edgeStyle(edge.style);
  const line = g.querySelector('.wb-edge-line');
  const marker = `url(#wb-arrow-${color ? color.slice(1) : 'default'})`;
  line.style.stroke = color || '';
  if (EDGE_DASH[style]) line.setAttribute('stroke-dasharray', EDGE_DASH[style]);
  else line.removeAttribute('stroke-dasharray');
  line.classList.toggle('wb-edge-line--dotted', style === 'dotted');
  if (arrow === 'end' || arrow === 'both') line.setAttribute('marker-end', marker);
  else line.removeAttribute('marker-end');
  if (arrow === 'start' || arrow === 'both') line.setAttribute('marker-start', marker);
  else line.removeAttribute('marker-start');
  g.classList.toggle('wb-edge--colored', !!color);

  const dot = g.querySelector('.wb-edge-dot');
  dot.style.fill = color || '';
  dot.style.display = arrow === 'start' || arrow === 'both' ? 'none' : '';

  g.querySelector('.wb-edge-label').textContent = edge.label || '';
  const rows = ['from', 'to'].map(side => _endRowText(_edgeEnd(edge, side)));
  g.querySelector('title').textContent = [edge.label, rows[0] && `Desde: ${rows[0]}`, rows[1] && `Hasta: ${rows[1]}`]
    .filter(Boolean).join('\n');
}

function _updateEdgePath(edge) {
  const g = _edgeEl(edge.id);
  if (!g) return;
  const pts = _edgeEndpoints(edge);
  if (!pts) { g.style.display = 'none'; if (edge.id === _selectedEdgeId) _hideEdgeToolbar(); return; }
  g.style.display = '';
  const d = _edgeCubic(pts);
  g.querySelector('.wb-edge-line').setAttribute('d', d);
  g.querySelector('.wb-edge-hit').setAttribute('d', d);
  const dot = g.querySelector('.wb-edge-dot');
  if (dot) { dot.setAttribute('cx', pts.sx.toFixed(1)); dot.setAttribute('cy', pts.sy.toFixed(1)); }
  const lbl = g.querySelector('.wb-edge-label');
  lbl.setAttribute('x', pts.mx.toFixed(1));
  lbl.setAttribute('y', (pts.my - 8).toFixed(1));
  g.querySelectorAll('.wb-edge-handle').forEach(h => {
    const from = h.dataset.end === 'from';
    h.setAttribute('cx', (from ? pts.sx : pts.ex).toFixed(1));
    h.setAttribute('cy', (from ? pts.sy : pts.ey).toFixed(1));
  });
  if (edge.id === _selectedEdgeId) _positionEdgeToolbar(pts);
}

function _updateAllEdges() {
  wbData.edges.forEach(e => _updateEdgePath(e));
}

// Coalesces bursts (node body scroll) into one redraw per frame.
function _scheduleEdgeUpdate() {
  if (_edgeRaf) return;
  _edgeRaf = requestAnimationFrame(() => { _edgeRaf = 0; _updateAllEdges(); });
}

// Removes the edges touching an item that was removed. `broadcast`: local
// removal (a remote one already reached every tab).
function _removeItemEdges(itemId, broadcast) {
  wbData.edges = wbData.edges.filter(e => {
    if (e.fromId !== itemId && e.toId !== itemId) return true;
    if (_selectedEdgeId === e.id) _deselectEdge();
    _edgeEl(e.id)?.remove();
    if (broadcast) _broadcast({ op: 'edge_remove', edgeId: e.id });
    return false;
  });
}

// Applies edge field changes (local or from a wb:patch) through the
// allowlists; null/invalid removes an optional field.
function _mergeEdgeChanges(edge, changes) {
  if (!changes || typeof changes !== 'object') return;
  for (const [k, v] of Object.entries(changes)) {
    if (k === 'label') {
      if (typeof v === 'string') edge.label = v.slice(0, 500);
    } else if (k === 'fromId' || k === 'toId') {
      if (_validId(v)) edge[k] = v;
    } else if (['fromEp', 'toEp', 'fromPort', 'toPort'].includes(k)) {
      if (_validId(v)) edge[k] = v; else delete edge[k];
    } else if (k === 'style' || k === 'arrow' || k === 'color') {
      const ok = { style: EDGE_STYLES, arrow: EDGE_ARROWS, color: EDGE_COLORS }[k].includes(v);
      if (ok) edge[k] = v; else delete edge[k];
    }
  }
}

function _setEdgeProps(edge, changes) {
  const before = _snapshot([`edges:${edge.id}`]);
  _applyEdgeProps(edge, changes);
  _commitHistory(before);
}

// Same without an undo entry (undo/redo itself).
function _applyEdgeProps(edge, changes) {
  _mergeEdgeChanges(edge, changes);
  _applyEdgeStyle(edge);
  _updateEdgePath(edge);
  if (edge.id === _selectedEdgeId) _refreshEdgeToolbar(edge);
  _broadcast({ op: 'edge_update', edgeId: edge.id, changes });
  scheduleSave();
}

function _addEdge(from, to) {
  const problem = _edgeProblem(from, to);
  if (problem) {
    showToast(problem, 'info');
    return;
  }
  const edge = { id: crypto.randomUUID(), fromId: from.id, toId: to.id, label: '' };
  if (from.ep) edge.fromEp = from.ep; else if (from.port) edge.fromPort = from.port;
  if (to.ep)   edge.toEp   = to.ep;   else if (to.port)   edge.toPort   = to.port;
  wbData.edges.push(edge);
  _renderEdge(edge);
  _broadcast({ op: 'edge_add', edge });
  _commitHistory(new Map([[`edges:${edge.id}`, null]]));
  scheduleSave();
  showToast('Conexión creada — clic en la flecha para editarla', 'success');
}

function _removeEdge(edgeId) {
  if (_selectedEdgeId === edgeId) _deselectEdge();
  wbData.edges = wbData.edges.filter(e => e.id !== edgeId);
  _edgeEl(edgeId)?.remove();
  _broadcast({ op: 'edge_remove', edgeId });
  scheduleSave();
}

function wbDeleteEdge(edgeId) {
  const before = _snapshot([`edges:${edgeId}`]);
  _removeEdge(edgeId);
  _commitHistory(before);
}

function _selectEdge(edgeId) {
  if (_selectedEdgeId === edgeId) return;
  _deselectEdge();
  _clearSelection();
  const edge = wbData.edges.find(e => e.id === edgeId);
  const g = _edgeEl(edgeId);
  if (!edge || !g) return;
  _selectedEdgeId = edgeId;
  g.classList.add('selected');
  // Reconnect handles on both ends (drag one onto another item or row).
  ['from', 'to'].forEach(side => {
    const h = document.createElementNS(SVG_NS, 'circle');
    h.classList.add('wb-edge-handle');
    h.dataset.end = side;
    h.setAttribute('r', '6');
    const t = document.createElementNS(SVG_NS, 'title');
    t.textContent = 'Arrastrar para reconectar';
    h.appendChild(t);
    h.addEventListener('pointerdown', ev => _startEdgeReconnect(ev, edge, side));
    g.appendChild(h);
  });
  _refreshEdgeToolbar(edge);
  _updateEdgePath(edge);
}

function _deselectEdge() {
  if (!_selectedEdgeId) return;
  const g = _edgeEl(_selectedEdgeId);
  if (g) {
    g.classList.remove('selected');
    g.querySelectorAll('.wb-edge-handle').forEach(h => h.remove());
  }
  _selectedEdgeId = null;
  _hideEdgeToolbar();
}

// ── Edge toolbar ─────────────────────────────────────────────────────────
// Static markup: only allowlisted values (EDGE_*) reach it.
function _buildEdgeToolbar() {
  const bar = document.createElement('div');
  bar.className = 'wb-edge-toolbar';
  const styleTitles = { solid: 'Línea sólida', dashed: 'Línea discontinua', dotted: 'Línea punteada' };
  const arrowBtns = { end: ['→', 'Flecha al final'], start: ['←', 'Flecha al inicio'], both: ['↔', 'Flecha en ambos extremos'], none: ['—', 'Sin flecha'] };
  bar.innerHTML = `
    <div class="wb-et-group">
      ${EDGE_STYLES.map(st => `
        <button class="wb-et-btn" data-edge-style="${st}" title="${styleTitles[st]}">
          <svg width="20" height="8" viewBox="0 0 20 8"><line x1="1" y1="4" x2="19" y2="4" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" ${EDGE_DASH[st] ? `stroke-dasharray="${st === 'dotted' ? '0.5 4' : '5 3'}"` : ''}/></svg>
        </button>`).join('')}
    </div>
    <div class="wb-et-sep"></div>
    <div class="wb-et-group">
      ${EDGE_ARROWS.map(a => `<button class="wb-et-btn" data-edge-arrow="${a}" title="${arrowBtns[a][1]}">${arrowBtns[a][0]}</button>`).join('')}
    </div>
    <div class="wb-et-sep"></div>
    <div class="wb-et-group">
      <button class="wb-et-col wb-et-col--default" data-edge-color="" title="Color por defecto"></button>
      ${EDGE_COLORS.map((c, i) => `<button class="wb-et-col" data-edge-color="${c}" style="background:${c}" title="${EDGE_COLOR_NAMES[i]}"></button>`).join('')}
    </div>
    <div class="wb-et-sep"></div>
    <button class="wb-et-btn" data-edge-action="label" title="Editar etiqueta">${icon('pencil', { size: 12 })}</button>
    <button class="wb-et-btn wb-et-del" data-edge-action="delete" title="Eliminar conexión">${icon('trash-2', { size: 12 })}</button>`;

  // Keep clicks on the toolbar from panning/deselecting the board.
  bar.addEventListener('pointerdown', e => e.stopPropagation());
  bar.addEventListener('wheel', e => e.stopPropagation(), { passive: true });
  bar.addEventListener('click', e => {
    const btn = e.target.closest('button');
    const edge = wbData.edges.find(x => x.id === _selectedEdgeId);
    if (!btn || !edge) return;
    e.stopPropagation();
    if (btn.dataset.edgeStyle) _setEdgeProps(edge, { style: btn.dataset.edgeStyle });
    else if (btn.dataset.edgeArrow) _setEdgeProps(edge, { arrow: btn.dataset.edgeArrow });
    else if (btn.dataset.edgeColor !== undefined) _setEdgeProps(edge, { color: btn.dataset.edgeColor || null });
    else if (btn.dataset.edgeAction === 'label') _editEdgeLabel(edge);
    else if (btn.dataset.edgeAction === 'delete') wbDeleteEdge(edge.id);
  });
  _vp.appendChild(bar);
  return bar;
}

function _refreshEdgeToolbar(edge) {
  if (!_edgeToolbar) _edgeToolbar = _buildEdgeToolbar();
  const style = _edgeStyle(edge.style), arrow = _edgeArrow(edge.arrow), color = _edgeColor(edge.color) || '';
  _edgeToolbar.querySelectorAll('[data-edge-style]').forEach(b => b.classList.toggle('active', b.dataset.edgeStyle === style));
  _edgeToolbar.querySelectorAll('[data-edge-arrow]').forEach(b => b.classList.toggle('active', b.dataset.edgeArrow === arrow));
  _edgeToolbar.querySelectorAll('[data-edge-color]').forEach(b => b.classList.toggle('active', b.dataset.edgeColor === color));
  _edgeToolbar.classList.add('visible');
}

function _hideEdgeToolbar() {
  _edgeToolbar?.classList.remove('visible');
}

// Above the edge's midpoint, in viewport (screen) coordinates.
function _positionEdgeToolbar(pts) {
  if (!_edgeToolbar || !_selectedEdgeId) return;
  const { panX, panY, zoom } = wbData.view;
  _edgeToolbar.style.left = (pts.mx * zoom + panX) + 'px';
  _edgeToolbar.style.top  = ((pts.my - 18) * zoom + panY) + 'px';
  _edgeToolbar.classList.add('visible');
}

// Drag one end handle of the selected edge onto another item, endpoint row
// or port chip to re-point that end.
function _startEdgeReconnect(e, edge, side) {
  if (_mode !== 'select' || e.button !== 0) return;
  e.stopPropagation();
  e.preventDefault();
  const handle = e.currentTarget;
  handle.setPointerCapture(e.pointerId);
  const g = _edgeEl(edge.id);
  g?.classList.add('reconnecting');
  _hideEdgeToolbar();

  const pts = _edgeEndpoints(edge);
  const fixed = pts ? (side === 'from' ? { x: pts.ex, y: pts.ey } : { x: pts.sx, y: pts.sy }) : null;
  const ghost = document.createElementNS(SVG_NS, 'path');
  ghost.classList.add('wb-edge-ghost');
  _edgeSvg.appendChild(ghost);
  let hover = null;

  const endAt = ev => {
    const end = _endFromElement(document.elementFromPoint(ev.clientX, ev.clientY));
    if (!end) return null;
    const other = _edgeEnd(edge, side === 'from' ? 'to' : 'from');
    const [from, to] = side === 'from' ? [end, other] : [other, end];
    return _edgeProblem(from, to, edge.id) ? null : end;
  };

  function onMove(ev) {
    const w = _screenToWorld(ev.clientX, ev.clientY);
    if (fixed) ghost.setAttribute('d', `M${fixed.x.toFixed(1)},${fixed.y.toFixed(1)} L${w.x.toFixed(1)},${w.y.toFixed(1)}`);
    const end = endAt(ev);
    if (hover !== end?.el) {
      hover?.classList.remove('connect-target');
      hover = end?.el || null;
      hover?.classList.add('connect-target');
    }
  }
  function onUp(ev) {
    handle.removeEventListener('pointermove', onMove);
    hover?.classList.remove('connect-target');
    ghost.remove();
    g?.classList.remove('reconnecting');
    const end = _endFromElement(document.elementFromPoint(ev.clientX, ev.clientY));
    const cur = _edgeEnd(edge, side);
    if (end && _endKey(end) !== _endKey(cur)) {
      const other = _edgeEnd(edge, side === 'from' ? 'to' : 'from');
      const problem = side === 'from' ? _edgeProblem(end, other, edge.id) : _edgeProblem(other, end, edge.id);
      if (problem) showToast(problem, 'info');
      else _setEdgeProps(edge, { [`${side}Id`]: end.id, [`${side}Ep`]: end.ep || null, [`${side}Port`]: end.port || null });
    }
    if (_selectedEdgeId === edge.id) { _refreshEdgeToolbar(edge); _updateEdgePath(edge); }
  }
  handle.addEventListener('pointermove', onMove);
  handle.addEventListener('pointerup', onUp, { once: true });
}

function _editEdgeLabel(edge) {
  const pts = _edgeEndpoints(edge);
  if (!pts) return;

  const { panX, panY, zoom } = wbData.view;
  const inp = document.createElement('input');
  inp.className = 'wb-label-input';
  inp.type = 'text';
  inp.value = edge.label || '';
  inp.placeholder = 'Etiqueta…';
  inp.style.left = (pts.mx * zoom + panX) + 'px';
  inp.style.top  = ((pts.my - 10) * zoom + panY) + 'px';
  _vp.appendChild(inp);
  inp.focus();
  inp.select();

  let committed = false;
  function commit() {
    if (committed) return;
    committed = true;
    inp.remove();
    _setEdgeProps(edge, { label: inp.value.trim() });
  }
  inp.addEventListener('pointerdown', e => e.stopPropagation());
  inp.addEventListener('keydown', e => {
    e.stopPropagation();
    if (e.key === 'Enter') commit();
    if (e.key === 'Escape') { committed = true; inp.remove(); }
  });
  inp.addEventListener('blur', commit);
}

function _clearConnectFrom() {
  _connectFrom?.el?.classList.remove('connect-from');
  _connectFrom = null;
}

// Connect mode: the first click picks one end (item, endpoint row or port
// chip), the second one creates the edge. Runs in the capture phase so item
// handlers (note editing, endpoint copy) do not also react.
function _handleConnectClick(e) {
  const end = _endFromElement(e.target);
  if (!end) { _clearConnectFrom(); return; }
  e.stopPropagation();
  e.preventDefault();
  if (!_connectFrom) {
    _connectFrom = end;
    end.el.classList.add('connect-from');
  } else if (_endKey(_connectFrom) === _endKey(end)) {
    _clearConnectFrom();
  } else {
    const from = _connectFrom;
    _clearConnectFrom();
    _addEdge(from, end);
  }
}

async function syncTargets() {
  const existing = new Set(wbData.nodes.map(n => n.id));
  const toAdd = (state.targets || []).filter(t => !existing.has(t.id));
  if (!toAdd.length) { showToast('Todos los targets ya están en el tablero', 'info'); return; }

  await _loadPortsAndEndpoints(state.currentProject.id, toAdd);

  const maxY = wbData.nodes.reduce((m, n) => { const b = _itemBox('node', n); return Math.max(m, b.y + b.h); }, 80);
  const startY = maxY + 50;
  const newNodes = [];
  toAdd.forEach((t, i) => {
    const nd = { id: t.id, x: 80 + (i % 3) * 350, y: startY + Math.floor(i / 3) * 430, collapsed: false };
    wbData.nodes.push(nd);
    newNodes.push(nd);
    _nl.appendChild(_buildNode(nd, t));
  });
  _broadcast({ op: 'nodes_sync', nodes: newNodes });
  _commitHistory(new Map(newNodes.map(nd => [`nodes:${nd.id}`, null])));
  scheduleSave();
  showToast(toAdd.length > 1 ? `Se agregaron ${toAdd.length} targets` : 'Se agregó 1 target', 'success');
}

// ── Strokes ────────────────────────────────────────────────────────────
function _renderStroke(stroke) {
  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  const width = _num(stroke.width, 2) > 0 ? _num(stroke.width, 2) : 2;
  path.setAttribute('d', typeof stroke.d === 'string' && SAFE_PATH_RE.test(stroke.d) ? stroke.d : '');
  path.setAttribute('stroke', _safeColor(stroke.color, '#e94141'));
  path.setAttribute('stroke-width', String(width / wbData.view.zoom));
  path.setAttribute('fill', 'none');
  path.setAttribute('stroke-linecap', 'round');
  path.setAttribute('stroke-linejoin', 'round');
  path.dataset.stroke  = stroke.id;
  path.dataset.strokeW = String(width);
  _svg.appendChild(path);
  return path;
}

function _pointsToPath(pts) {
  return pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ');
}

function _showConfirm(title, message) {
  return new Promise(resolve => {
    const overlay = document.createElement('div');
    overlay.className = 'wb-modal-overlay';
    overlay.innerHTML = `
      <div class="wb-modal">
        <p class="wb-modal-title">${esc(title)}</p>
        <p class="wb-modal-msg">${esc(message)}</p>
        <div class="wb-modal-btns">
          <button class="wb-modal-btn wb-modal-cancel">Cancelar</button>
          <button class="wb-modal-btn wb-modal-confirm">Confirmar</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    const close = (val) => { overlay.remove(); resolve(val); };
    overlay.querySelector('.wb-modal-cancel').addEventListener('click',  () => close(false));
    overlay.querySelector('.wb-modal-confirm').addEventListener('click', () => close(true));
    overlay.addEventListener('click', e => { if (e.target === overlay) close(false); });
    overlay.querySelector('.wb-modal-confirm').focus();
  });
}

async function clearDrawing() {
  if (!wbData.strokes.length) return;
  if (!await _showConfirm('Borrar trazos', 'Se quitarán todos los trazos del tablero. Se puede deshacer con Ctrl+Z.')) return;
  const before = _snapshot(wbData.strokes.map(s => `strokes:${s.id}`));
  wbData.strokes = [];
  _svg.querySelectorAll('path[data-stroke]').forEach(p => p.remove());
  _broadcast({ op: 'strokes_clear' });
  _commitHistory(before);
  scheduleSave();
}

// ── Notes ──────────────────────────────────────────────────────────────
function _buildNote(noteData) {
  const el = document.createElement('div');
  el.className = 'wb-sticky';
  el.dataset.noteId = noteData.id;
  el.style.left = _num(noteData.x) + 'px';
  el.style.top  = _num(noteData.y) + 'px';
  el.style.background = _noteColor(noteData.color);
  _applyNoteSize(el, noteData);

  const colorDots = NOTE_COLORS.map(c =>
    `<span class="wb-sticky-col" style="background:${c}" data-color="${c}"></span>`
  ).join('');

  el.innerHTML = `
    <div class="wb-sticky-head" data-drag-handle>
      <div class="wb-sticky-colors">${colorDots}</div>
      <span class="wb-sticky-rm">×</span>
    </div>
    <div class="wb-sticky-text" data-text contenteditable="false">${esc(noteData.text || '')}</div>
    ${noteData.created_by === 'claude_code' ? '<div class="wb-sticky-by">Claude Code</div>' : ''}`;

  const textEl = el.querySelector('[data-text]');

  el.querySelector('.wb-sticky-rm').addEventListener('click', e => {
    e.stopPropagation();
    wbRemoveNote(noteData.id);
  });

  el.querySelector('.wb-sticky-colors').addEventListener('click', e => {
    const dot = e.target.closest('[data-color]');
    if (!dot) return;
    e.stopPropagation();
    wbNoteColor(noteData.id, dot.dataset.color);
  });

  textEl.addEventListener('pointerdown', e => e.stopPropagation());
  textEl.addEventListener('click', e => {
    if (_mode === 'connect') return;
    e.stopPropagation();
    if (textEl.contentEditable !== 'true') {
      textEl.contentEditable = 'true';
      textEl.focus();
    }
  });
  textEl.addEventListener('blur', () => {
    textEl.contentEditable = 'false';
    const before = _snapshot([`notes:${noteData.id}`]);
    noteData.text = textEl.innerText.trim();
    _commitHistory(before);
    _updateAllEdges(); // an unsized note's height follows its text
    _broadcast({ op: 'note_update', noteId: noteData.id, changes: { text: noteData.text } });
    scheduleSave();
  });
  textEl.addEventListener('keydown', e => {
    e.stopPropagation();
    if (e.key === 'Escape') textEl.blur();
  });

  _makeNoteDraggable(el, noteData);
  _makeResizable(el, noteData, 'note');
  return el;
}

// A note without w/h keeps the CSS default (170px wide, grows with its
// text); once sized, its text area scrolls inside the fixed box.
function _applyNoteSize(el, noteData) {
  const w = _dim(noteData.w, MIN_SIZE.note.w), h = _dim(noteData.h, MIN_SIZE.note.h);
  el.style.width  = w ? w + 'px' : '';
  el.style.height = h ? h + 'px' : '';
  el.classList.toggle('wb-sticky--sized', !!h);
}

function _makeNoteDraggable(el, noteData) {
  const head = el.querySelector('[data-drag-handle]');
  head.addEventListener('pointerdown', e => {
    if (e.button !== 0) return;
    if (e.target.closest('.wb-sticky-rm, [data-color]')) return;
    e.stopPropagation();
    e.preventDefault();
    _startItemDrag(e, head, `notes:${noteData.id}`);
  });
}

function _addNote(wx, wy) {
  const id = crypto.randomUUID();
  const noteData = { id, x: wx - 85, y: wy - 40, text: '', color: NOTE_COLORS[0] };
  wbData.notes.push(noteData);
  _nl.appendChild(_buildNote(noteData));
  _broadcast({ op: 'note_add', note: noteData });
  _commitHistory(new Map([[`notes:${id}`, null]]));
  scheduleSave();
  setTimeout(() => {
    const textEl = _nl.querySelector(`[data-note-id="${id}"] [data-text]`);
    if (textEl) { textEl.contentEditable = 'true'; textEl.focus(); }
  }, 50);
}

function wbRemoveNote(id) {
  _trackRemoval([`notes:${id}`]);
}

function _removeNote(id) {
  wbData.notes = wbData.notes.filter(n => n.id !== id);
  _nl.querySelector(`[data-note-id="${id}"]`)?.remove();
  _removeItemEdges(id, true);
  _broadcast({ op: 'note_remove', noteId: id });
  scheduleSave();
}

function wbNoteColor(id, color) {
  const nd = wbData.notes.find(n => n.id === id);
  if (!nd) return;
  const before = _snapshot([`notes:${id}`]);
  nd.color = color = _noteColor(color);
  _commitHistory(before);
  const el = _nl.querySelector(`[data-note-id="${id}"]`);
  if (el) el.style.background = color;
  _broadcast({ op: 'note_update', noteId: id, changes: { color } });
  scheduleSave();
}

// ── Pan / Zoom ─────────────────────────────────────────────────────────
function _startPan(e) {
  e.preventDefault();
  const startX = e.clientX, startY = e.clientY;
  const origPX = wbData.view.panX, origPY = wbData.view.panY;
  _vp.classList.add('dragging');
  _vp.setPointerCapture(e.pointerId);

  function onMove(e) {
    wbData.view.panX = origPX + (e.clientX - startX);
    wbData.view.panY = origPY + (e.clientY - startY);
    _applyTransform();
  }
  function onUp() {
    _vp.classList.remove('dragging');
    _vp.removeEventListener('pointermove', onMove);
    scheduleSave();
  }
  _vp.addEventListener('pointermove', onMove);
  _vp.addEventListener('pointerup', onUp, { once: true });
}

function _screenToWorld(sx, sy) {
  const rect = _vp.getBoundingClientRect();
  const { panX, panY, zoom } = wbData.view;
  return { x: (sx - rect.left - panX) / zoom, y: (sy - rect.top - panY) / zoom };
}

function fitToScreen() {
  const items = [
    ...wbData.nodes.map(n => _itemBox('node', n)),
    ...wbData.notes.map(n => _itemBox('note', n)),
    ...wbData.cards.map(c => _itemBox('card', c)),
    ...wbData.images.map(i => _itemBox('image', i)),
  ];
  if (!items.length) return;
  const minX = Math.min(...items.map(i => i.x));
  const minY = Math.min(...items.map(i => i.y));
  const maxX = Math.max(...items.map(i => i.x + i.w));
  const maxY = Math.max(...items.map(i => i.y + i.h));
  const zoom = Math.min(3, Math.max(0.1, Math.min((_vp.clientWidth - 80) / (maxX - minX), (_vp.clientHeight - 80) / (maxY - minY))));
  wbData.view = { zoom, panX: 40 - minX * zoom, panY: 40 - minY * zoom };
  _applyTransform();
  scheduleSave();
}

// ── Draw ───────────────────────────────────────────────────────────────
function _startDraw(e) {
  e.preventDefault();
  _vp.setPointerCapture(e.pointerId);

  const w = _screenToWorld(e.clientX, e.clientY);
  const pts = [[w.x, w.y]];
  const id  = crypto.randomUUID();

  _activeStrokeEl = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  _activeStrokeEl.setAttribute('stroke', _drawColor);
  _activeStrokeEl.setAttribute('stroke-width', String(_drawWidth / wbData.view.zoom));
  _activeStrokeEl.setAttribute('fill', 'none');
  _activeStrokeEl.setAttribute('stroke-linecap', 'round');
  _activeStrokeEl.setAttribute('stroke-linejoin', 'round');
  _svg.appendChild(_activeStrokeEl);

  function onMove(e) {
    const w = _screenToWorld(e.clientX, e.clientY);
    pts.push([w.x, w.y]);
    _activeStrokeEl.setAttribute('d', _pointsToPath(pts));
  }
  function onUp() {
    _vp.removeEventListener('pointermove', onMove);
    if (pts.length > 1) {
      const stroke = { id, d: _pointsToPath(pts), color: _drawColor, width: _drawWidth };
      wbData.strokes.push(stroke);
      _activeStrokeEl.dataset.stroke  = id;
      _activeStrokeEl.dataset.strokeW = String(_drawWidth);
      _broadcast({ op: 'stroke_add', stroke });
      _commitHistory(new Map([[`strokes:${id}`, null]]));
      scheduleSave();
    } else {
      _activeStrokeEl.remove();
    }
    _activeStrokeEl = null;
  }
  _vp.addEventListener('pointermove', onMove);
  _vp.addEventListener('pointerup', onUp, { once: true });
}

// ── History (undo / redo) ──────────────────────────────────────────────
// Every local action records the items it touched as before/after JSON
// copies; a multi-item action (group move, multi-delete, removing an item
// with its arrows) is one entry. Undo/redo writes the copies back through the
// same paths as a local edit: wbData + DOM, the wb:patch op the single-item
// action broadcasts, and scheduleSave (the sync diff sends what changed or
// was removed). A removed item comes back with its own id: the next save's
// base revision already includes the removal, so the server lifts the
// tombstone (see mergeBoard).
//
// Changes from others are never undone: an item that another tab, user or
// Claude Code changed after the entry was recorded (_remoteTouched) is
// skipped, the rest of the entry still applies, and a toast says so. An
// arrow whose ends are no longer on the board is skipped too.

function _snap(key) {
  const [kind, id] = _splitKey(key);
  const it = _localItem(kind, id);
  return it ? JSON.parse(JSON.stringify(it)) : null;
}

function _snapshot(keys) {
  return new Map(keys.map(k => [k, _snap(k)]));
}

// Keys of the arrows touching these items (they go with a removed item).
function _withEdgeKeys(keys) {
  const ids = new Set(keys.map(k => _splitKey(k)[1]));
  const edges = wbData.edges.filter(e => ids.has(e.fromId) || ids.has(e.toId)).map(e => `edges:${e.id}`);
  return [...new Set([...keys, ...edges])];
}

// Records an entry from the `before` copies (and null for items that did not
// exist yet) against the current state. `tag`: consecutive entries with the
// same tag within a second merge into one (arrow-key nudges).
function _commitHistory(before, tag) {
  const items = [];
  before.forEach((b, key) => {
    const a = _snap(key);
    if (_canon(a) !== _canon(b)) items.push({ key, before: b, after: a });
  });
  if (!items.length) return;
  const top = _undoStack[_undoStack.length - 1];
  const now = Date.now();
  if (tag && top && top.tag === tag && now - top.at < 1000 && !_redoStack.length) {
    items.forEach(it => {
      const prev = top.items.find(x => x.key === it.key);
      if (prev) prev.after = it.after; else top.items.push(it);
    });
    top.at = now;
    top.seq = _remoteSeq;
  } else {
    _undoStack.push({ items, seq: _remoteSeq, tag, at: now });
    if (_undoStack.length > HISTORY_MAX) _undoStack.shift();
  }
  _redoStack = [];
  _updateHistoryButtons();
}

// Removes items (and their arrows) as one undo entry.
function _trackRemoval(keys) {
  const before = _snapshot(_withEdgeKeys(keys));
  keys.forEach(k => _setItemState(k, null));
  _commitHistory(before);
}

function _markRemote(keys) {
  _remoteSeq++;
  keys.forEach(k => _remoteTouched.set(k, _remoteSeq));
}

function wbUndo() { _stepHistory(_undoStack, _redoStack, 'before'); }
function wbRedo() { _stepHistory(_redoStack, _undoStack, 'after'); }

function _stepHistory(from, to, side) {
  const entry = from.pop();
  if (!entry) return;
  const skipped = _applyHistoryEntry(entry, side);
  entry.seq = _remoteSeq;
  entry.tag = null;
  to.push(entry);
  _updateHistoryButtons();
  if (skipped) showToast('Algunos elementos cambiaron por otra persona y no se modificaron', 'info');
}

// Writes `side` ('before' | 'after') of every item. Removals go first
// (arrows before their items), then additions/updates (items before the
// arrows that point at them). Returns how many items were skipped.
function _applyHistoryEntry(entry, side) {
  const isEdge = it => it.key.startsWith('edges:');
  const removals  = entry.items.filter(it => !it[side]).sort((a, b) => isEdge(b) - isEdge(a));
  const additions = entry.items.filter(it => it[side]).sort((a, b) => isEdge(a) - isEdge(b));
  let skipped = 0;
  for (const it of [...removals, ...additions]) {
    if ((_remoteTouched.get(it.key) || 0) > entry.seq) { skipped++; continue; }
    if (_canon(_snap(it.key)) === _canon(it[side])) continue;
    if (!_setItemState(it.key, it[side])) skipped++;
  }
  _updateAllEdges();
  if (_searchQuery) _applySearch();
  return skipped;
}

// Puts one item in the given state (null = removed) as a local edit: DOM,
// wb:patch broadcast and save. Returns false when it cannot be applied.
function _setItemState(key, snap) {
  const [kind, id] = _splitKey(key);
  const local = _localItem(kind, id);
  if (!snap) {
    if (!local) return true;
    if (kind === 'nodes') _removeNode(id);
    else if (kind === 'cards') _removeCard(id);
    else if (kind === 'notes') _removeNote(id);
    else if (kind === 'images') _removeImage(id, true);
    else if (kind === 'edges') _removeEdge(id);
    else if (kind === 'strokes') _removeStroke(id);
    _selection.delete(key);
    return true;
  }
  const item = JSON.parse(JSON.stringify(snap));
  if (kind === 'edges') {
    if (!_findItem(item.fromId) || !_findItem(item.toId)) return false;
    if (local) {
      // Every field, null for the optional ones it does not have.
      const changes = { label: item.label || '', fromId: item.fromId, toId: item.toId };
      ['fromEp', 'toEp', 'fromPort', 'toPort', 'style', 'arrow', 'color'].forEach(k => { changes[k] = item[k] ?? null; });
      _applyEdgeProps(local, changes);
      return true;
    }
  }
  if (kind === 'nodes' && !local && !state.targets.find(t => t.id === id)) return false;
  if (local) {
    // Same object: the DOM handlers hold it.
    Object.keys(local).forEach(k => delete local[k]);
    Object.assign(local, item);
    _renderItem(kind, local);
    _broadcastItem(kind, local, false);
  } else {
    wbData[kind].push(item);
    _renderItem(kind, item);
    _broadcastItem(kind, item, true);
  }
  scheduleSave();
  return true;
}

// The wb:patch op of an added or replaced item (the same ops the single-item
// actions send). A field an op cannot clear (e.g. a node's w/h) reaches the
// other tabs with the next save's rev notice.
function _broadcastItem(kind, item, isNew) {
  const { id, ...fields } = item;
  if (kind === 'nodes') {
    if (isNew) { _broadcast({ op: 'nodes_sync', nodes: [item] }); return; }
    _broadcast({ op: 'node_move', nodeId: id, x: item.x, y: item.y });
    _broadcast({ op: 'node_toggle', nodeId: id, collapsed: !!item.collapsed });
    if (item.w || item.h) _broadcast({ op: 'node_resize', nodeId: id, w: item.w, h: item.h });
  } else if (kind === 'cards') {
    _broadcast(isNew ? { op: 'card_add', card: item } : { op: 'card_update', cardId: id, changes: fields });
  } else if (kind === 'notes') {
    _broadcast(isNew ? { op: 'note_add', note: item } : { op: 'note_update', noteId: id, changes: fields });
  } else if (kind === 'images') {
    _broadcast(isNew ? { op: 'image_add', image: item }
      : { op: 'image_update', imageId: id, changes: { x: item.x, y: item.y, w: item.w, h: item.h, caption: item.caption || '' } });
  } else if (kind === 'edges') {
    _broadcast({ op: 'edge_add', edge: item });
  } else if (kind === 'strokes') {
    _broadcast({ op: 'stroke_add', stroke: item });
  }
}

function _removeStroke(id) {
  wbData.strokes = wbData.strokes.filter(s => s.id !== id);
  _svg.querySelector(`path[data-stroke="${CSS.escape(id)}"]`)?.remove();
  _broadcast({ op: 'stroke_remove', strokeId: id });
  scheduleSave();
}

function _updateHistoryButtons() {
  const u = document.getElementById('wb-btn-undo'), r = document.getElementById('wb-btn-redo');
  if (u) u.disabled = !_undoStack.length;
  if (r) r.disabled = !_redoStack.length;
}

// ── Selection ──────────────────────────────────────────────────────────
// Click selects an item, Shift/Ctrl/Cmd+click toggles it, dragging on the
// empty board (select mode) draws a selection box, Ctrl/Cmd+A selects all
// and Esc clears. Dragging a selected item moves the whole selection.
const ITEM_SELECTOR = '.wb-node, .wb-card, .wb-sticky, .wb-image';

function _keyOfEl(el) {
  const itemEl = el instanceof Element && _nl.contains(el) ? el.closest(ITEM_SELECTOR) : null;
  return itemEl ? _keyOfItemEl(itemEl) : null;
}

// 'kind:id' of an item element (also of html2canvas' clone of one).
function _keyOfItemEl(itemEl) {
  if (itemEl.classList.contains('wb-sticky')) return `notes:${itemEl.dataset.noteId}`;
  const kind = itemEl.classList.contains('wb-node') ? 'nodes' : itemEl.classList.contains('wb-card') ? 'cards' : 'images';
  return `${kind}:${itemEl.dataset.nodeId}`;
}

function _keyEl(key) {
  const [kind, id] = _splitKey(key);
  return _itemEl(kind === 'notes' ? 'note' : 'node', id);
}

// Every selectable item drawn on the board.
function _allItemKeys() {
  return ['nodes', 'cards', 'notes', 'images']
    .flatMap(kind => wbData[kind].map(it => `${kind}:${it.id}`))
    .filter(k => _keyEl(k));
}

function _setSelection(keys) {
  _selection.forEach(k => _keyEl(k)?.classList.remove('wb-selected'));
  _selection.clear();
  keys.forEach(k => { const el = _keyEl(k); if (el) { _selection.add(k); el.classList.add('wb-selected'); } });
}

function _toggleSelected(key) {
  const next = new Set(_selection);
  if (next.has(key)) next.delete(key); else next.add(key);
  _setSelection([...next]);
}

function _clearSelection() {
  if (_selection.size) _setSelection([]);
}

// Drops keys whose item is gone (removed here or by someone else).
function _liveSelection() {
  [..._selection].forEach(k => { if (!_snap(k) || !_keyEl(k)) _selection.delete(k); });
  return [..._selection];
}

function _startMarquee(e) {
  // preventDefault keeps the drag from selecting page text, but also the
  // focus change: an item being edited is closed (and saved) by hand.
  e.preventDefault();
  if (document.activeElement?.isContentEditable || document.activeElement?.tagName === 'INPUT') document.activeElement.blur();
  const additive = e.shiftKey || e.ctrlKey || e.metaKey;
  const base = additive ? _liveSelection() : [];
  const startX = e.clientX, startY = e.clientY;
  const rect = _vp.getBoundingClientRect();
  let box = null;
  _vp.setPointerCapture(e.pointerId);

  function onMove(ev) {
    const dx = ev.clientX - startX, dy = ev.clientY - startY;
    if (!box) {
      if (dx * dx + dy * dy < 25) return;
      box = document.createElement('div');
      box.className = 'wb-marquee';
      _vp.appendChild(box);
    }
    const l = Math.min(startX, ev.clientX), t = Math.min(startY, ev.clientY);
    const w = Math.abs(dx), h = Math.abs(dy);
    box.style.left = (l - rect.left) + 'px';
    box.style.top = (t - rect.top) + 'px';
    box.style.width = w + 'px';
    box.style.height = h + 'px';
    const a = _screenToWorld(l, t), b = _screenToWorld(l + w, t + h);
    const hits = _allItemKeys().filter(k => {
      const [kind, id] = _splitKey(k);
      const bx = _itemBox(kind.slice(0, -1), _localItem(kind, id));
      return bx.x < b.x && bx.x + bx.w > a.x && bx.y < b.y && bx.y + bx.h > a.y;
    });
    _setSelection([...new Set([...base, ...hits])]);
  }
  function onUp() {
    _vp.removeEventListener('pointermove', onMove);
    if (box) box.remove();
    else if (!additive) _clearSelection();
  }
  _vp.addEventListener('pointermove', onMove);
  _vp.addEventListener('pointerup', onUp, { once: true });
}

// Delete/Backspace: the selected items with their arrows, as one undo entry.
function _deleteSelection() {
  const keys = _liveSelection();
  if (!keys.length) return;
  _trackRemoval(keys);
  _clearSelection();
}

// Arrow keys move the selection 1px (10px with Shift); a run of presses is
// one undo entry.
function _nudgeSelection(dx, dy) {
  const keys = _liveSelection();
  if (!keys.length) return;
  const before = _snapshot(keys);
  keys.forEach(k => {
    const [kind, id] = _splitKey(k);
    const d = _localItem(kind, id), el = _keyEl(k);
    d.x = _num(d.x) + dx;
    d.y = _num(d.y) + dy;
    if (el) { el.style.left = d.x + 'px'; el.style.top = d.y + 'px'; }
    _broadcastMove(kind, d);
  });
  _updateAllEdges();
  _commitHistory(before, `nudge:${keys.sort().join(',')}`);
  scheduleSave();
}

// Ctrl/Cmd+D: copies of the selected cards, notes and images (target nodes
// are one per target), 24px down-right, selected afterwards.
function _duplicateSelection() {
  const keys = _liveSelection().filter(k => !k.startsWith('nodes:'));
  if (!keys.length) return;
  const added = keys.map(k => {
    const [kind] = _splitKey(k);
    const copy = _snap(k);
    delete copy.created_by; // the copy is this user's, not Claude Code's
    copy.id = crypto.randomUUID();
    copy.x = _num(copy.x) + 24;
    copy.y = _num(copy.y) + 24;
    _setItemState(`${kind}:${copy.id}`, copy);
    return `${kind}:${copy.id}`;
  });
  _commitHistory(new Map(added.map(k => [k, null])));
  _updateAllEdges();
  _setSelection(added);
}

// ── Eraser ─────────────────────────────────────────────────────────────
function _startErase(e) {
  e.preventDefault();
  _vp.setPointerCapture(e.pointerId);

  const erasedStrokes = [];

  function erase(ev) {
    // Keep ring following cursor even while button held (setPointerCapture blocks mousemove)
    const rect = _vp.getBoundingClientRect();
    _eraserRing.style.left = (ev.clientX - rect.left) + 'px';
    _eraserRing.style.top  = (ev.clientY - rect.top)  + 'px';

    const w      = _screenToWorld(ev.clientX, ev.clientY);
    const radius = 20 / wbData.view.zoom;

    _svg.querySelectorAll('path[data-stroke]').forEach(pathEl => {
      if (!_strokeNearPoint(pathEl, w.x, w.y, radius)) return;
      const id     = pathEl.dataset.stroke;
      const stroke = wbData.strokes.find(s => s.id === id);
      if (stroke) erasedStrokes.push(stroke);
      wbData.strokes = wbData.strokes.filter(s => s.id !== id);
      pathEl.remove();
      _broadcast({ op: 'stroke_remove', strokeId: id });
    });
    if (erasedStrokes.length) scheduleSave();
  }

  erase(e);
  _vp.addEventListener('pointermove', erase);
  _vp.addEventListener('pointerup', () => {
    _vp.removeEventListener('pointermove', erase);
    // One undo entry per eraser drag; the copies were taken as they went.
    if (erasedStrokes.length) _commitHistory(new Map(erasedStrokes.map(s => [`strokes:${s.id}`, s])));
  }, { once: true });
}

function _strokeNearPoint(pathEl, px, py, radius) {
  try {
    const len   = pathEl.getTotalLength();
    if (len === 0) return false;
    const steps = Math.max(8, Math.ceil(len / 8));
    const r2    = radius * radius;
    for (let i = 0; i <= steps; i++) {
      const pt = pathEl.getPointAtLength((i / steps) * len);
      if ((pt.x - px) ** 2 + (pt.y - py) ** 2 <= r2) return true;
    }
  } catch {}
  return false;
}

// ── Events ─────────────────────────────────────────────────────────────
function _wireEvents() {
  // Zoom (or let a scrollable item body scroll, see _wheelScrollsItem)
  _vp.addEventListener('wheel', e => {
    if (_wheelScrollsItem(e)) return;
    e.preventDefault();
    const factor  = e.deltaY > 0 ? 0.9 : 1.1;
    const newZoom = Math.max(0.1, Math.min(3, wbData.view.zoom * factor));
    const rect    = _vp.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    const wx = (mx - wbData.view.panX) / wbData.view.zoom;
    const wy = (my - wbData.view.panY) / wbData.view.zoom;
    wbData.view.panX = mx - wx * newZoom;
    wbData.view.panY = my - wy * newZoom;
    wbData.view.zoom = newZoom;
    _applyTransform();
    scheduleSave();
  }, { passive: false });

  // Connect mode picks ends before any item handler sees the event (note
  // text and card bodies stop pointerdown; endpoint rows copy on click). The
  // item's own controls (collapse, remove, colors) keep working.
  const ITEM_CONTROLS = '.wb-node-collapse, .wb-node-remove, .wb-card-rm, .wb-sticky-rm, .wb-image-rm, .wb-image-cap, [data-color], .wb-resize-handle';
  _vp.addEventListener('pointerdown', e => {
    if (_mode !== 'connect' || e.button !== 0) return;
    if (e.target instanceof Element && e.target.closest(ITEM_CONTROLS)) return;
    _handleConnectClick(e);
  }, true);
  _vp.addEventListener('click', e => {
    if (_mode !== 'connect' || !(e.target instanceof Element) || !_nl.contains(e.target)) return;
    if (!e.target.closest(ITEM_CONTROLS)) e.stopPropagation();
  }, true);

  // Selecting items (select mode), before the item's own drag/edit handlers:
  // a press selects the item (a selected one keeps the group, so dragging it
  // moves the whole selection); with Shift/Ctrl/Cmd it only toggles it.
  _vp.addEventListener('pointerdown', e => {
    if (_mode !== 'select' || e.button !== 0) return;
    const key = _keyOfEl(e.target);
    if (!key || e.target.closest(ITEM_CONTROLS)) return;
    _deselectEdge();
    if (e.shiftKey || e.ctrlKey || e.metaKey) {
      e.stopPropagation();
      e.preventDefault();
      _toggleSelected(key);
    } else if (!_selection.has(key)) {
      _setSelection([key]);
    }
  }, true);

  // Pan / Draw / Erase / Note placement
  _vp.addEventListener('pointerdown', e => {
    if (_mode === 'draw'   && e.button === 0) { _startDraw(e);  return; }
    if (_mode === 'eraser'  && e.button === 0) { _startErase(e);         return; }
    if (_mode === 'connect' && e.button === 0) return; // handled in the capture phase above
    const onBg = e.target === _vp || e.target === _ws || e.target === _svg || e.target === _nl;
    if (_mode === 'select' && e.button === 0 && onBg) { _deselectEdge(); _startMarquee(e); return; }
    if ((_mode === 'pan' && onBg) || e.button === 1) { _startPan(e); return; }
    if (_mode === 'note' && e.button === 0 && onBg) {
      e.preventDefault();
      const w = _screenToWorld(e.clientX, e.clientY);
      _addNote(w.x, w.y);
    }
    if (_mode === 'card' && e.button === 0 && onBg) {
      e.preventDefault();
      const w = _screenToWorld(e.clientX, e.clientY);
      _addCard(w.x - 120, w.y - 20);
    }
  });

  // Eraser ring follows mouse
  _vp.addEventListener('mousemove', e => {
    if (_mode === 'eraser') {
      const rect = _vp.getBoundingClientRect();
      _eraserRing.style.left = (e.clientX - rect.left) + 'px';
      _eraserRing.style.top  = (e.clientY - rect.top)  + 'px';
    }
  });
  _vp.addEventListener('mouseleave', () => { _eraserRing.style.display = 'none'; _lastPointer = null; });
  _vp.addEventListener('mousemove', e => { _lastPointer = { x: e.clientX, y: e.clientY }; });

  // Images: file picker (toolbar), drag & drop onto the board, paste.
  const fileInput = document.getElementById('wb-image-input');
  fileInput?.addEventListener('change', () => {
    const c = _viewportCenter();
    _addImageFiles(fileInput.files, c.x, c.y);
    fileInput.value = '';
  });
  const hasFiles = e => [...(e.dataTransfer?.types || [])].includes('Files');
  _vp.addEventListener('dragover', e => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
    _vp.classList.add('wb-drop');
  });
  _vp.addEventListener('dragleave', e => {
    if (!_vp.contains(e.relatedTarget)) _vp.classList.remove('wb-drop');
  });
  _vp.addEventListener('drop', e => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    _vp.classList.remove('wb-drop');
    const w = _screenToWorld(e.clientX, e.clientY);
    _addImageFiles(e.dataTransfer.files, w.x, w.y);
  });
  document.addEventListener('paste', e => {
    const t = e.target;
    if (t instanceof Element && (t.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName))) return;
    const files = [...(e.clipboardData?.files || [])].filter(f => f.type.startsWith('image/'));
    if (!files.length) return;
    e.preventDefault();
    const w = _lastPointer ? _screenToWorld(_lastPointer.x, _lastPointer.y) : _viewportCenter();
    _addImageFiles(files, w.x, w.y);
  });
  window.addEventListener('pagehide', () => {
    _imgUrls.forEach(entry => { if (entry.url) URL.revokeObjectURL(entry.url); });
    _imgUrls.clear();
  });

  // Cursor broadcasting (throttled to 40ms)
  let _cursorThrottle = false;
  _vp.addEventListener('mousemove', e => {
    if (_cursorThrottle) return;
    _cursorThrottle = true;
    setTimeout(() => { _cursorThrottle = false; }, 40);
    const w = _screenToWorld(e.clientX, e.clientY);
    wsClient.send({ type: 'wb:cursor', wx: Math.round(w.x), wy: Math.round(w.y) });
  });

}

// True when the wheel should scroll an item instead of zooming: the pointer is
// over an overflowing element inside a node/card/note that can still move in
// the wheel's direction. Ctrl/Meta+wheel (trackpad pinch sends ctrlKey)
// always zooms, and so does a wheel over the board or an item that has
// already scrolled to its end.
function _wheelScrollsItem(e) {
  if (e.ctrlKey || e.metaKey) return false;
  if (!(e.target instanceof Element) || !_nl.contains(e.target)) return false;
  for (let el = e.target; el && el !== _nl; el = el.parentElement) {
    if (_canScroll(el, e.deltaX, e.deltaY)) return true;
  }
  return false;
}

function _canScroll(el, dx, dy) {
  const s = getComputedStyle(el);
  const scrolls = o => o === 'auto' || o === 'scroll';
  if (dy && scrolls(s.overflowY) && el.scrollHeight > el.clientHeight) {
    if (dy < 0 ? el.scrollTop > 0 : el.scrollTop + el.clientHeight < el.scrollHeight - 1) return true;
  }
  if (dx && scrolls(s.overflowX) && el.scrollWidth > el.clientWidth) {
    if (dx < 0 ? el.scrollLeft > 0 : el.scrollLeft + el.clientWidth < el.scrollWidth - 1) return true;
  }
  return false;
}

function _wireKeyboard() {
  document.addEventListener('keydown', e => {
    // Focus search on /
    if (e.key === '/' && !e.ctrlKey && !e.metaKey &&
        !e.target.isContentEditable && !['INPUT','TEXTAREA','SELECT'].includes(e.target.tagName)) {
      e.preventDefault();
      document.getElementById('wb-search')?.focus();
      return;
    }
    if (e.target.isContentEditable || ['INPUT','TEXTAREA','SELECT'].includes(e.target.tagName)) return;
    // A modal (confirm, image lightbox) owns the keyboard.
    if (document.querySelector('.wb-modal-overlay, #img-lb')) return;
    const mod = e.ctrlKey || e.metaKey;
    const key = e.key.length === 1 ? e.key.toLowerCase() : e.key;
    if (mod) {
      if (key === 'z' && !e.shiftKey) { e.preventDefault(); wbUndo(); }
      else if (key === 'y' || (key === 'z' && e.shiftKey)) { e.preventDefault(); wbRedo(); }
      else if (key === 'a') { e.preventDefault(); setWbMode('select'); _setSelection(_allItemKeys()); }
      else if (key === 'd') { e.preventDefault(); _duplicateSelection(); }
      return;
    }
    if (!e.altKey) {
      if (key === 'v') setWbMode('select');
      if (key === 'h') setWbMode('pan');
      if (key === 'd') setWbMode('draw');
      if (key === 'e') setWbMode('eraser');
      if (key === 'n') setWbMode('note');
      if (key === 'f') fitToScreen();
      if (key === 'a') setWbMode('card');
      if (key === 'c') setWbMode('connect');
    }
    if (e.key === 'Delete' || e.key === 'Backspace') {
      e.preventDefault();
      if (_selectedEdgeId) wbDeleteEdge(_selectedEdgeId);
      else _deleteSelection();
    }
    const arrows = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] };
    if (arrows[e.key] && _selection.size) {
      e.preventDefault();
      const step = e.shiftKey ? 10 : 1;
      _nudgeSelection(arrows[e.key][0] * step, arrows[e.key][1] * step);
    }
    if (e.key === 'Escape') {
      if (_searchQuery) { wbSearchClear(); return; }
      _clearConnectFrom();
      _deselectEdge();
      _clearSelection();
    }
  });
}

// ── WebSocket: cursors + patches ───────────────────────────────────────
function _wireWs() {
  wsClient.on('wb:cursor', _handleRemoteCursor);
  wsClient.on('wb:patch',  _handleRemotePatch);
  // 'connected' se emite en cada auth_ok, también al reconectar.
  wsClient.on('connected', _resyncFromServer);
  // Remove cursor when user goes offline
  wsClient.on('presence', ({ online = [] }) => {
    const onlineIds = new Set(online.map(u => u.id));
    _cursorEls.forEach((el, uid) => {
      if (!onlineIds.has(uid)) {
        el.remove();
        _cursorEls.delete(uid);
        _cursorData.delete(uid);
        clearTimeout(_cursorHide.get(uid));
        _cursorHide.delete(uid);
      }
    });
  });
}

function _handleRemoteCursor({ userId, username, display_name, wx, wy }) {
  if (!userId || userId === state.user?.id) return;
  _cursorData.set(userId, { wx, wy });

  let el = _cursorEls.get(userId);
  if (!el) {
    const color = _safeColor(_memberColor(userId), '#7c3aed');
    el = document.createElement('div');
    el.className = 'wb-cursor';
    el.innerHTML = `
      <svg width="14" height="18" viewBox="0 0 14 18" fill="none">
        <path d="M1 1L1 13L4.5 10L7 16L9 15L6.5 9L11 9L1 1Z" fill="${color}" stroke="#fff" stroke-width="1"/>
      </svg>
      <span class="wb-cursor-label" style="background:${color}">${esc(display_name || username || '?')}</span>`;
    _cursorLayer.appendChild(el);
    _cursorEls.set(userId, el);
  }

  _positionCursor(el, wx, wy);

  clearTimeout(_cursorHide.get(userId));
  el.style.opacity = '1';
  _cursorHide.set(userId, setTimeout(() => { el.style.opacity = '0'; }, 4000));
}

function _positionCursor(el, wx, wy) {
  const { panX, panY, zoom } = wbData.view;
  el.style.left = (_num(wx) * zoom + panX) + 'px';
  el.style.top  = (_num(wy) * zoom + panY) + 'px';
}

function _refreshCursorPositions() {
  _cursorData.forEach(({ wx, wy }, userId) => {
    const el = _cursorEls.get(userId);
    if (el) _positionCursor(el, wx, wy);
  });
}

function _memberColor(userId) {
  const m = (state.members || []).find(m => m.id === userId || m.user_id === userId);
  return m?.avatar_color || '#7c3aed';
}

// Altas que hizo el servidor (Claude Code vía MCP, op 'items_add'), ya
// guardadas en la base: se suman a wbData las que falten. Devuelve cuántas
// agregó. Un nodo de target usa el id del target, así que si acá se había
// quitado ese nodo y Claude Code lo vuelve a agregar, es un alta nueva.
async function _mergeItems({ nodes = [], cards = [], notes = [], images = [], edges = [] }) {
  const fresh = (list, item) => item?.id && !list.some(x => x.id === item.id);
  let n = 0;
  // Un nodo de un target que esta pestaña todavía no conoce (agregado
  // después de cargarla): se recargan los targets para poder dibujarlo.
  const newNodes = nodes.filter(nd => fresh(wbData.nodes, nd));
  await _ensureTargets(newNodes);
  newNodes.forEach(nd => {
    if (!fresh(wbData.nodes, nd)) return; // llegó por otro lado mientras se esperaba
    wbData.nodes.push(nd);
    const t = state.targets.find(t => t.id === nd.id);
    if (t) _nl.appendChild(_buildNode(nd, t));
    n++;
  });
  cards.filter(c => fresh(wbData.cards, c)).forEach(c => { wbData.cards.push(c); _nl.appendChild(_buildCard(c)); n++; });
  notes.filter(x => fresh(wbData.notes, x)).forEach(x => { wbData.notes.push(x); _nl.appendChild(_buildNote(x)); n++; });
  (Array.isArray(images) ? images : []).filter(x => _validImage(x) && fresh(wbData.images, x))
    .forEach(x => { wbData.images.push(x); _nl.appendChild(_buildImage(x)); n++; });
  edges.filter(e => fresh(wbData.edges, e)).forEach(e => { wbData.edges.push(e); _renderEdge(e); n++; });
  if (n) _updateAllEdges();
  return n;
}

// Nodos de targets que esta pestaña no conoce: recarga la lista de targets
// y sus puertos/endpoints para poder dibujarlos.
async function _ensureTargets(nodes) {
  if (nodes.some(nd => !state.targets.find(t => t.id === nd.id))) {
    try { state.targets = await api.targets.list(state.currentProject.id); } catch {}
  }
  const missing = nodes.map(nd => state.targets.find(t => t.id === nd.id)).filter(Boolean)
    .filter(t => !_portsMap[t.id]);
  if (missing.length) {
    const ports = _portsMap, eps = _endpointsMap;
    await _loadPortsAndEndpoints(state.currentProject.id, missing);
    _portsMap = { ...ports, ..._portsMap };
    _endpointsMap = { ...eps, ..._endpointsMap };
  }
}

// Al reconectar: los patches emitidos con el socket caído no llegan nunca.
// Se pide al servidor lo que cambió desde _syncRev (altas, ediciones Y
// borrados) y se manda lo pendiente de esta pestaña.
async function _resyncFromServer() {
  if (!_wbReady) return;
  _pullFromServer();
  if (_hasLocalChanges()) scheduleSave();
}

// Patch de otra pestaña o del servidor. Lo que cambia NO es una edición de
// esta pestaña: los ítems que tenían la base al día la siguen teniendo (no se
// re-mandan al guardar); uno con una edición local pendiente la conserva.
function _handleRemotePatch(msg) {
  if (!msg || typeof msg !== 'object') return;
  // El servidor guardó cambios (de otra pestaña): se piden los que falten.
  if (msg.op === 'rev') {
    if (Number.isSafeInteger(msg.revision) && msg.revision > _syncRev) _schedulePull();
    return;
  }
  const keys = _patchKeys(msg);
  const clean = keys.filter(_isSynced);
  _markRemote(keys);
  // Altas que hizo el servidor (Claude Code vía MCP), ya guardadas en la
  // base: el merge del servidor las conserva aunque un guardado de acá no
  // las incluya. No entran al undo: no son acciones locales.
  if (msg.op === 'items_add') {
    _mergeItems(msg).then(() => clean.forEach(_rebaseKey));
    return;
  }
  _applyRemotePatch(msg);
  clean.forEach(_rebaseKey);
}

// Claves 'kind:id' que toca un patch, incluidas las flechas que se van con
// un ítem borrado.
function _patchKeys(msg) {
  const withEdges = (kind, id) => [
    `${kind}:${id}`,
    ...wbData.edges.filter(e => e.fromId === id || e.toId === id).map(e => `edges:${e.id}`),
  ];
  const listKeys = (kind, list) => (Array.isArray(list) ? list : []).filter(it => it?.id).map(it => `${kind}:${it.id}`);
  switch (msg.op) {
    case 'items_add':
      return SYNC_KINDS.flatMap(kind => listKeys(kind, msg[kind]));
    case 'node_move': case 'node_toggle': case 'node_resize': return [`nodes:${msg.nodeId}`];
    case 'node_remove': return withEdges('nodes', msg.nodeId);
    case 'nodes_sync': return listKeys('nodes', msg.nodes);
    case 'stroke_add': return [`strokes:${msg.stroke?.id}`];
    case 'stroke_remove': return [`strokes:${msg.strokeId}`];
    case 'strokes_clear': return listKeys('strokes', wbData.strokes);
    case 'note_add': return [`notes:${msg.note?.id}`];
    case 'note_update': return [`notes:${msg.noteId}`];
    case 'note_remove': return withEdges('notes', msg.noteId);
    case 'edge_add': return [`edges:${msg.edge?.id}`];
    case 'edge_update': case 'edge_remove': return [`edges:${msg.edgeId}`];
    case 'image_add': return [`images:${msg.image?.id}`];
    case 'image_update': return [`images:${msg.imageId}`];
    case 'image_remove': return withEdges('images', msg.imageId);
    case 'card_add': return [`cards:${msg.card?.id}`];
    case 'card_update': return [`cards:${msg.cardId}`];
    case 'card_remove': return withEdges('cards', msg.cardId);
    default: return [];
  }
}

function _applyRemotePatch(msg) {
  switch (msg.op) {
    case 'node_move': {
      const nd = wbData.nodes.find(n => n.id === msg.nodeId);
      if (!nd) return;
      nd.x = _num(msg.x, nd.x); nd.y = _num(msg.y, nd.y);
      const el = _nl.querySelector(`[data-node-id="${msg.nodeId}"]`);
      if (el) { el.style.left = nd.x + 'px'; el.style.top = nd.y + 'px'; }
      _updateAllEdges();
      break;
    }
    case 'node_toggle': {
      const nd = wbData.nodes.find(n => n.id === msg.nodeId);
      if (!nd) return;
      nd.collapsed = !!msg.collapsed;
      const el = _nl.querySelector(`[data-node-id="${msg.nodeId}"]`);
      if (el) {
        el.classList.toggle('collapsed', nd.collapsed);
        const btn = el.querySelector('.wb-node-collapse');
        if (btn) btn.innerHTML = nd.collapsed ? icon('chevron-right',{size:11}) : icon('chevron-down',{size:11});
      }
      _updateAllEdges();
      break;
    }
    case 'node_resize': {
      const nd = wbData.nodes.find(n => n.id === msg.nodeId);
      if (!nd) return;
      nd.w = _dim(msg.w, MIN_SIZE.node.w) || nd.w; nd.h = _dim(msg.h, MIN_SIZE.node.h) || nd.h;
      const el = _nl.querySelector(`[data-node-id="${msg.nodeId}"]`);
      if (el) {
        el.style.width = (_dim(nd.w, MIN_SIZE.node.w) || DEFAULT_SIZE.node.w) + 'px';
        const h = _dim(nd.h, MIN_SIZE.node.h);
        el.style.height = h ? h + 'px' : '';
        el.classList.toggle('wb-node--sized', !!h);
      }
      _updateAllEdges();
      break;
    }
    case 'node_remove':
      wbData.nodes = wbData.nodes.filter(n => n.id !== msg.nodeId);
      _nl.querySelector(`[data-node-id="${msg.nodeId}"]`)?.remove();
      _removeItemEdges(msg.nodeId, false);
      break;
    case 'nodes_sync':
      (msg.nodes || []).forEach(nd => {
        if (wbData.nodes.find(n => n.id === nd.id)) return;
        wbData.nodes.push(nd);
        const t = state.targets.find(t => t.id === nd.id);
        if (t) _nl.appendChild(_buildNode(nd, t));
      });
      _updateAllEdges();
      break;
    case 'stroke_add':
      if (!wbData.strokes.find(s => s.id === msg.stroke.id)) {
        wbData.strokes.push(msg.stroke);
        _renderStroke(msg.stroke);
      }
      break;
    case 'stroke_remove':
      wbData.strokes = wbData.strokes.filter(s => s.id !== msg.strokeId);
      _svg.querySelector(`path[data-stroke="${msg.strokeId}"]`)?.remove();
      break;
    case 'strokes_clear':
      wbData.strokes = [];
      _svg.querySelectorAll('path[data-stroke]').forEach(p => p.remove());
      break;
    case 'note_add':
      if (!wbData.notes.find(n => n.id === msg.note.id)) {
        wbData.notes.push(msg.note);
        _nl.appendChild(_buildNote(msg.note));
        _updateAllEdges();
      }
      break;
    case 'note_update': {
      const nd = wbData.notes.find(n => n.id === msg.noteId);
      if (!nd) return;
      Object.assign(nd, msg.changes);
      const el = _nl.querySelector(`[data-note-id="${msg.noteId}"]`);
      if (!el) return;
      if (msg.changes.color !== undefined) el.style.background = _noteColor(msg.changes.color);
      if (msg.changes.x !== undefined) el.style.left = _num(msg.changes.x) + 'px';
      if (msg.changes.y !== undefined) el.style.top  = _num(msg.changes.y) + 'px';
      if (msg.changes.w !== undefined || msg.changes.h !== undefined) _applyNoteSize(el, nd);
      if (msg.changes.text !== undefined) {
        const textEl = el.querySelector('[data-text]');
        if (textEl && textEl.contentEditable !== 'true') textEl.textContent = msg.changes.text;
      }
      if (['x', 'y', 'w', 'h', 'text'].some(k => msg.changes[k] !== undefined)) _updateAllEdges();
      break;
    }
    case 'note_remove':
      wbData.notes = wbData.notes.filter(n => n.id !== msg.noteId);
      _nl.querySelector(`[data-note-id="${msg.noteId}"]`)?.remove();
      _removeItemEdges(msg.noteId, false);
      break;
    case 'edge_add':
      if (!wbData.edges.find(e => e.id === msg.edge.id)) {
        wbData.edges.push(msg.edge);
        _renderEdge(msg.edge);
      }
      break;
    case 'edge_remove':
      if (_selectedEdgeId === msg.edgeId) _deselectEdge();
      wbData.edges = wbData.edges.filter(e => e.id !== msg.edgeId);
      _edgeEl(msg.edgeId)?.remove();
      break;
    case 'edge_update': {
      const ed = wbData.edges.find(e => e.id === msg.edgeId);
      if (!ed) return;
      _mergeEdgeChanges(ed, msg.changes);
      _applyEdgeStyle(ed);
      _updateEdgePath(ed);
      if (ed.id === _selectedEdgeId) _refreshEdgeToolbar(ed);
      break;
    }
    case 'image_add':
      if (_validImage(msg.image) && !wbData.images.find(i => i.id === msg.image.id)) {
        wbData.images.push(msg.image);
        _nl.appendChild(_buildImage(msg.image));
        _updateAllEdges();
      }
      break;
    case 'image_update': {
      const im = wbData.images.find(i => i.id === msg.imageId);
      if (!im || !msg.changes || typeof msg.changes !== 'object') return;
      const c = msg.changes;
      for (const k of ['x', 'y', 'w', 'h']) if (c[k] !== undefined) im[k] = _num(c[k], im[k]);
      if (typeof c.caption === 'string') {
        if (c.caption) im.caption = c.caption.slice(0, 500); else delete im.caption;
      }
      const el = _itemEl('image', im.id);
      if (el) {
        _applyImageGeometry(el, im);
        if (c.caption !== undefined) _applyImageCaption(el, im);
      }
      _updateAllEdges();
      break;
    }
    case 'image_remove':
      _removeImage(msg.imageId, false);
      break;
    case 'card_add':
      if (!wbData.cards.find(c => c.id === msg.card.id)) {
        wbData.cards.push(msg.card);
        _nl.appendChild(_buildCard(msg.card));
        _updateAllEdges();
      }
      break;
    case 'card_remove':
      wbData.cards = wbData.cards.filter(c => c.id !== msg.cardId);
      _nl.querySelector(`[data-node-id="${msg.cardId}"]`)?.remove();
      _removeItemEdges(msg.cardId, false);
      break;
    case 'card_update': {
      const cd = wbData.cards.find(c => c.id === msg.cardId);
      if (!cd) return;
      Object.assign(cd, msg.changes);
      const el = _nl.querySelector(`[data-node-id="${msg.cardId}"]`);
      if (!el) return;
      if (msg.changes.x !== undefined) el.style.left   = _num(msg.changes.x) + 'px';
      if (msg.changes.y !== undefined) el.style.top    = _num(msg.changes.y) + 'px';
      if (msg.changes.w !== undefined) el.style.width  = (_dim(msg.changes.w, MIN_SIZE.card.w) || DEFAULT_SIZE.card.w) + 'px';
      if (msg.changes.h !== undefined) { const h = _dim(msg.changes.h, MIN_SIZE.card.h); el.style.height = h ? h + 'px' : ''; }
      if (msg.changes.color !== undefined) {
        const head = el.querySelector('.wb-card-head');
        if (head) head.style.background = _cardColor(msg.changes.color);
      }
      if (msg.changes.ref !== undefined) { _renderItem('cards', cd); _updateAllEdges(); break; }
      if (msg.changes.title !== undefined && !_isFindingCard(cd)) {
        const t = el.querySelector('[data-title]');
        if (t && t.contentEditable !== 'true') t.textContent = msg.changes.title;
      }
      if (msg.changes.body !== undefined) {
        const b = el.querySelector('[data-text]');
        if (b && b.contentEditable !== 'true') b.innerHTML = renderMd(msg.changes.body);
      }
      // Any geometry change, or a body/title edit that changes an unsized card's height.
      if (['x', 'y', 'w', 'h', 'title', 'body'].some(k => msg.changes[k] !== undefined)) _updateAllEdges();
      break;
    }
  }
}

function _broadcast(patch) {
  wsClient.send({ type: 'wb:patch', ...patch });
}

// ── Mode ───────────────────────────────────────────────────────────────
function setWbMode(m) {
  if (m !== 'connect') _clearConnectFrom();
  if (m !== 'select') _deselectEdge();
  if (m !== 'select' && m !== 'pan') _clearSelection();
  _mode = m;
  ['select','pan','draw','eraser','note','card','connect'].forEach(k => {
    document.getElementById(`wb-btn-${k}`)?.classList.toggle('active', k === m);
  });
  _vp.className = `mode-${m}`;
  document.getElementById('wb-draw-panel')?.classList.toggle('visible', m === 'draw' || m === 'eraser');
  if (_eraserRing) _eraserRing.style.display = m === 'eraser' ? 'block' : 'none';
}

function setDrawColor(color) {
  _drawColor = color;
  document.querySelectorAll('.wb-swatch').forEach(s => {
    s.classList.toggle('active', s.dataset.color === (color === 'var(--t1)' ? 't1' : color));
  });
}

function setDrawWidth(w, key) {
  _drawWidth = w;
  ['thin','medium','thick'].forEach(k => {
    document.getElementById(`wb-w-${k}`)?.classList.toggle('active', k === key);
  });
}

// ── Search ─────────────────────────────────────────────────────────────
function wbSearch(q) {
  _searchQuery = q.trim().toLowerCase();
  _applySearch();
}

function wbSearchClear() {
  _searchQuery = '';
  const input = document.getElementById('wb-search');
  if (input) input.value = '';
  _applySearch();
  input?.blur();
}

function _applySearch() {
  const q         = _searchQuery;
  const clearBtn  = document.getElementById('wb-search-clear');
  const countEl   = document.getElementById('wb-search-count');
  if (clearBtn) clearBtn.classList.toggle('visible', q.length > 0);

  if (!q) {
    _nl.querySelectorAll('.wb-highlight, .wb-dimmed').forEach(el =>
      el.classList.remove('wb-highlight', 'wb-dimmed')
    );
    if (countEl) countEl.textContent = '';
    return;
  }

  let hits = 0, total = 0;

  // Target nodes
  wbData.nodes.forEach(nd => {
    const el     = _nl.querySelector(`[data-node-id="${nd.id}"]`);
    const target = (state.targets || []).find(t => t.id === nd.id);
    if (!el || !target) return;
    total++;
    const hay = [
      target.host,
      target.type,
      target.status,
      ...(state.customVulns || []).filter(v => v.target_id === target.id).map(v => v.name),
      ...(_portsMap[target.id]     || []).map(p => `${p.port} ${p.service || ''}`),
      ...(_endpointsMap[target.id] || []).map(e => e.path),
    ].join(' ').toLowerCase();
    const match = hay.includes(q);
    el.classList.toggle('wb-highlight', match);
    el.classList.toggle('wb-dimmed',    !match);
    if (match) hits++;
  });

  // Custom cards
  wbData.cards.forEach(cd => {
    const el = _nl.querySelector(`[data-node-id="${cd.id}"]`);
    if (!el) return;
    total++;
    const finding = _isFindingCard(cd) ? _findingOf(cd.ref) : null;
    const match = `${cd.title} ${cd.body} ${finding ? `${finding.name} ${SEV_LABEL[finding.severity] || ''}` : ''}`.toLowerCase().includes(q);
    el.classList.toggle('wb-highlight', match);
    el.classList.toggle('wb-dimmed',    !match);
    if (match) hits++;
  });

  // Images (by caption)
  wbData.images.forEach(im => {
    const el = _itemEl('image', im.id);
    if (el) el.classList.toggle('wb-dimmed', !(im.caption || '').toLowerCase().includes(q));
  });

  // Sticky notes
  wbData.notes.forEach(n => {
    const el    = _nl.querySelector(`[data-note-id="${n.id}"]`);
    if (!el) return;
    const match = (n.text || '').toLowerCase().includes(q);
    el.classList.toggle('wb-dimmed', !match);
  });

  if (countEl) countEl.textContent = `${hits}/${total}`;
}

// ── Save ───────────────────────────────────────────────────────────────
function scheduleSave() {
  _updateSaveStatus('saving');
  clearTimeout(_saveTimer);
  _saveTimer = setTimeout(() => _enqueueSync(async () => {
    try {
      await _pushChanges();
      _updateSaveStatus('saved');
    } catch {
      _updateSaveStatus('error');
    }
  }), 1500);
}

// ── Sync ───────────────────────────────────────────────────────────────
// Ver SYNC_KINDS/_syncBase arriba y backend services/whiteboardSync.js.

// JSON con las claves ordenadas: la misma nota armada acá o devuelta por el
// servidor da el mismo texto.
function _canon(v) {
  return JSON.stringify(v, (k, val) => (val && typeof val === 'object' && !Array.isArray(val)
    ? Object.fromEntries(Object.keys(val).sort().map(key => [key, val[key]]))
    : val));
}

function _splitKey(key) {
  const i = key.indexOf(':');
  return [key.slice(0, i), key.slice(i + 1)];
}

function _localItem(kind, id) {
  return (wbData[kind] || []).find(it => it.id === id);
}

function _resetSyncBase() {
  _syncBase.clear();
  SYNC_KINDS.forEach(kind => wbData[kind].forEach(it => _syncBase.set(`${kind}:${it.id}`, _canon(it))));
}

// El ítem local coincide con lo que conoce el servidor (o no existe en
// ninguno de los dos): no hay edición local pendiente.
function _isSynced(key) {
  const [kind, id] = _splitKey(key);
  const it = _localItem(kind, id);
  return (it ? _canon(it) : undefined) === _syncBase.get(key);
}

function _rebaseKey(key) {
  const [kind, id] = _splitKey(key);
  const it = _localItem(kind, id);
  if (it) _syncBase.set(key, _canon(it)); else _syncBase.delete(key);
}

// Lo que esta pestaña cambió/agregó (ítems enteros) y borró (ids) desde la base.
function _collectChanges() {
  const data = {}, removed = {}, sent = new Map();
  const seen = new Set();
  SYNC_KINDS.forEach(kind => {
    data[kind] = [];
    removed[kind] = [];
    wbData[kind].forEach(it => {
      const key = `${kind}:${it.id}`, json = _canon(it);
      seen.add(key);
      if (_syncBase.get(key) !== json) { data[kind].push(it); sent.set(key, json); }
    });
  });
  _syncBase.forEach((_, key) => {
    if (seen.has(key)) return;
    const [kind, id] = _splitKey(key);
    removed[kind].push(id);
    sent.set(key, null);
  });
  return { data, removed, sent };
}

function _hasLocalChanges() {
  return _collectChanges().sent.size > 0;
}

function _enqueueSync(fn) {
  _syncChain = _syncChain.then(fn, fn);
  return _syncChain;
}

async function _pushChanges() {
  const { data, removed, sent } = _collectChanges();
  data.view = wbData.view;
  const initSent = _initPending;
  if (initSent) data.initialized = true;
  const res = await api.whiteboard.save(state.currentProject.id, data, { base_revision: _syncRev, removed });
  // Lo mandado ya es lo que conoce el servidor; si lo cambió (sanitizado) o
  // descartó (borrado por otro), la respuesta lo corrige abajo.
  sent.forEach((json, key) => { if (json === null) _syncBase.delete(key); else _syncBase.set(key, json); });
  if (initSent && res.initialized) _initPending = false;
  // The response lists this save's own removals as deleted. One that is back
  // on the board by now (undo while the save was in flight) is a pending
  // re-add, sent next with a base revision that already has the removal.
  const ownRemoved = new Set([...sent].filter(([, json]) => json === null).map(([key]) => key));
  await _applyServerChanges(res, ownRemoved);
}

function _schedulePull() {
  clearTimeout(_pullTimer);
  _pullTimer = setTimeout(_pullFromServer, 300);
}

function _pullFromServer() {
  return _enqueueSync(async () => {
    try {
      const pid = state.currentProject.id;
      if (_loadFailed) {
        await _applyServerChanges({ ...await api.whiteboard.get(pid), full: true });
        _loadFailed = false;
      } else {
        await _applyServerChanges(await api.whiteboard.get(pid, _syncRev));
      }
    } catch {}
  });
}

// Aplica lo que devolvió el servidor ({ revision, full, changes, deleted } o
// { full, data }). Una edición local pendiente gana (se manda en el próximo
// guardado), salvo contra un borrado: lo borrado por otro no vuelve.
async function _applyServerChanges(res, ownRemoved = new Set()) {
  if (!res || !Number.isSafeInteger(res.revision)) return;
  let changes = res.changes || {}, deleted = res.deleted || {};
  if (res.full) {
    const data = res.data || {};
    changes = data; deleted = {};
    SYNC_KINDS.forEach(kind => {
      const ids = new Set((Array.isArray(data[kind]) ? data[kind] : []).map(it => it?.id));
      // Lo que el servidor conocía y ya no tiene, se borró. Lo que nunca
      // conoció es un alta local pendiente.
      deleted[kind] = [..._syncBase.keys()].map(_splitKey)
        .filter(([k, id]) => k === kind && !ids.has(id)).map(([, id]) => id);
    });
  }
  const nodes = Array.isArray(changes.nodes) ? changes.nodes : [];
  await _ensureTargets(nodes.filter(nd => nd?.id && !_localItem('nodes', nd.id)));

  let touched = 0;
  SYNC_KINDS.forEach(kind => {
    (Array.isArray(deleted[kind]) ? deleted[kind] : []).forEach(id => {
      const key = `${kind}:${id}`;
      if (ownRemoved.has(key) || !_dropLocalItem(kind, id)) return;
      _markRemote([key]);
      touched++;
    });
    (Array.isArray(changes[kind]) ? changes[kind] : []).forEach(it => {
      if (!_applyServerItem(kind, it)) return;
      _markRemote([`${kind}:${it.id}`]);
      touched++;
    });
  });
  if (res.revision > _syncRev || res.full) _syncRev = res.revision;
  if (touched) {
    _updateAllEdges();
    if (_searchQuery) _applySearch();
  }
  if (_hasLocalChanges()) scheduleSave();
}

// Un ítem del servidor. Devuelve 1 si cambió algo en pantalla.
function _applyServerItem(kind, item) {
  if (!item || !_validId(item.id) || (kind === 'images' && !_validImage(item))) return 0;
  const key = `${kind}:${item.id}`, json = _canon(item);
  const local = _localItem(kind, item.id);
  if (!local) {
    // Borrado acá y todavía sin guardar: el borrado se manda igual.
    if (_syncBase.has(key)) { _syncBase.set(key, json); return 0; }
    _syncBase.set(key, json);
    wbData[kind].push(item);
    _renderItem(kind, item);
    return 1;
  }
  const pending = _canon(local) !== _syncBase.get(key);
  _syncBase.set(key, json);
  if (pending || _canon(local) === json) return 0;
  // Se reemplaza en el mismo objeto: los handlers del DOM lo tienen tomado.
  Object.keys(local).forEach(k => delete local[k]);
  Object.assign(local, item);
  _renderItem(kind, local);
  return 1;
}

// Dibuja (o vuelve a dibujar) un ítem. Si se está editando su texto o
// arrastrando, solo se mueve: la edición en curso termina y se guarda encima.
function _renderItem(kind, item) {
  if (kind === 'edges') {
    _edgeEl(item.id)?.remove();
    _renderEdge(item);
    if (item.id === _selectedEdgeId) _refreshEdgeToolbar(item);
    return;
  }
  if (kind === 'strokes') {
    _svg.querySelector(`path[data-stroke="${CSS.escape(item.id)}"]`)?.remove();
    _renderStroke(item);
    return;
  }
  const el = _itemEl(kind === 'notes' ? 'note' : 'node', item.id);
  if (el && (el.classList.contains('dragging') || el.querySelector('[contenteditable="true"]'))) {
    el.style.left = _num(item.x) + 'px';
    el.style.top  = _num(item.y) + 'px';
    return;
  }
  let built = null;
  if (kind === 'nodes') {
    const t = state.targets.find(t => t.id === item.id);
    if (t) built = _buildNode(item, t);
  } else if (kind === 'cards') built = _buildCard(item);
  else if (kind === 'notes') built = _buildNote(item);
  else if (kind === 'images') built = _buildImage(item);
  if (built && _selection.has(`${kind}:${item.id}`)) built.classList.add('wb-selected');
  if (el && built) el.replaceWith(built);
  else if (el) el.remove();
  else if (built) _nl.appendChild(built);
}

// Quita un ítem que se borró en el servidor. Devuelve 1 si estaba.
function _dropLocalItem(kind, id) {
  _syncBase.delete(`${kind}:${id}`);
  const it = _localItem(kind, id);
  if (!it) return 0;
  if (kind === 'images') {
    _removeImage(id, false);
  } else if (kind === 'edges') {
    if (_selectedEdgeId === id) _deselectEdge();
    wbData.edges = wbData.edges.filter(e => e.id !== id);
    _edgeEl(id)?.remove();
  } else if (kind === 'strokes') {
    _applyRemotePatch({ op: 'stroke_remove', strokeId: id });
  } else {
    wbData[kind] = wbData[kind].filter(x => x.id !== id);
    _itemEl(kind === 'notes' ? 'note' : 'node', id)?.remove();
    _removeItemEdges(id, false);
  }
  return 1;
}

function _updateSaveStatus(s) {
  const el = document.getElementById('wb-save-status');
  if (!el) return;
  el.className = `wb-save-status ${s}`;
  el.innerHTML = s === 'saving' ? 'Guardando…' : s === 'error' ? `Error al guardar ${icon('x',{size:11})}` : `Guardado ${icon('check',{size:11})}`;
}

// ── Export PNG ─────────────────────────────────────────────────────────
// html2canvas is vendored (js/vendor/README.md) and loaded on the first
// export. It renders its own clone of the page, so the live board is never
// touched: in the clone the viewport becomes a fixed box the size of the
// exported area and the workspace is shifted into it at zoom 1. The two SVG
// layers get a real size, a viewBox and inline styles: html2canvas draws each
// <svg> as a standalone image of its own box, where the page CSS and
// var(--…) colors do not apply, and at their live 1×1 size the arrows and
// strokes would be lost. Board images are same-origin blob: URLs, which
// html2canvas loads like any image without tainting the canvas (useCORS off:
// a blob: URL needs no CORS request).
const EXPORT_PAD      = 40;
const EXPORT_SCALE    = 2;
const EXPORT_MAX_DIM  = 16384; // per-side canvas limit of current browsers
const EXPORT_MAX_AREA = 120e6; // well under the canvas area limits
const SVG_STYLE_PROPS = ['fill', 'fill-opacity', 'stroke', 'stroke-width', 'stroke-dasharray', 'stroke-linecap',
  'stroke-linejoin', 'stroke-opacity', 'opacity', 'font-family', 'font-size', 'font-weight', 'paint-order',
  'dominant-baseline', 'text-anchor'];

let _html2canvasLoad = null;
function _loadHtml2canvas() {
  if (window.html2canvas) return Promise.resolve();
  if (!_html2canvasLoad) {
    _html2canvasLoad = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'js/vendor/html2canvas.min.js?v=1';
      s.onload = resolve;
      s.onerror = () => { _html2canvasLoad = null; s.remove(); reject(new Error('no se pudo cargar html2canvas')); };
      document.head.appendChild(s);
    });
  }
  return _html2canvasLoad;
}

// World-space box of the given items; for the whole board also the strokes
// and arrows (a curve can leave the items' boxes). null when there is nothing.
function _exportBounds(keys, withLines) {
  const boxes = keys.map(k => {
    const [kind, id] = _splitKey(k);
    const d = _localItem(kind, id);
    return d && _itemBox(kind.slice(0, -1), d);
  }).filter(Boolean);
  if (withLines) {
    const lines = [..._svg.querySelectorAll('path[data-stroke]'),
      ..._edgeSvg.querySelectorAll('.wb-edge-group:not([style*="display: none"]) .wb-edge-line')];
    lines.forEach(p => {
      try { const b = p.getBBox(); if (b.width || b.height) boxes.push({ x: b.x, y: b.y, w: b.width, h: b.height }); } catch {}
    });
  }
  if (!boxes.length) return null;
  return {
    minX: Math.min(...boxes.map(b => b.x)), minY: Math.min(...boxes.map(b => b.y)),
    maxX: Math.max(...boxes.map(b => b.x + b.w)), maxY: Math.max(...boxes.map(b => b.y + b.h)),
  };
}

// pizarra-<proyecto>-<AAAA-MM-DD>.png
function _exportFilename() {
  const slug = String(state.currentProject?.name || '').normalize('NFD').replace(/[̀-ͯ]/g, '')
    .toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'proyecto';
  const d = new Date(), two = n => String(n).padStart(2, '0');
  return `pizarra-${slug}-${d.getFullYear()}-${two(d.getMonth() + 1)}-${two(d.getDate())}.png`;
}

function wbExportMenu() {
  const menu = document.getElementById('wb-export-menu');
  if (!menu) { exportPng(false); return; }
  if (menu.classList.contains('visible')) { _closeExportMenu(); return; }
  const n = _liveSelection().length;
  const sel = menu.querySelector('[data-export="selection"]');
  sel.disabled = !n;
  sel.querySelector('.wb-export-sub').textContent = n
    ? `${n} elemento${n > 1 ? 's' : ''} seleccionado${n > 1 ? 's' : ''}`
    : 'No hay nada seleccionado';
  menu.classList.add('visible');
  document.getElementById('wb-export-btn')?.setAttribute('aria-expanded', 'true');
  document.addEventListener('pointerdown', _exportMenuOutside, true);
  document.addEventListener('keydown', _exportMenuKey, true);
  menu.querySelector('button:not(:disabled)')?.focus();
}

function _closeExportMenu() {
  document.getElementById('wb-export-menu')?.classList.remove('visible');
  document.getElementById('wb-export-btn')?.setAttribute('aria-expanded', 'false');
  document.removeEventListener('pointerdown', _exportMenuOutside, true);
  document.removeEventListener('keydown', _exportMenuKey, true);
}

function _exportMenuOutside(e) {
  if (!e.target.closest?.('#wb-export-wrap')) _closeExportMenu();
}

function _exportMenuKey(e) {
  if (e.key !== 'Escape') return;
  e.stopPropagation();
  _closeExportMenu();
}

// onlySelection: the selected items (others and their arrows are left out),
// cropped to their bounding box; otherwise the whole board fit to its content.
async function exportPng(onlySelection = false) {
  _closeExportMenu();
  const keys = onlySelection ? _liveSelection() : _allItemKeys();
  if (onlySelection && !keys.length) { showToast('No hay elementos seleccionados para exportar', 'info'); return; }
  const box = _exportBounds(keys, !onlySelection);
  if (!box) { showToast('El tablero está vacío: no hay nada para exportar', 'info'); return; }

  const btn = document.getElementById('wb-export-btn');
  if (btn) { btn.disabled = true; btn.setAttribute('aria-busy', 'true'); }
  try {
    await _loadHtml2canvas();
    _deselectEdge(); // its accent color and handles would be captured
    const x0 = Math.floor(box.minX - EXPORT_PAD), y0 = Math.floor(box.minY - EXPORT_PAD);
    const W = Math.ceil(box.maxX + EXPORT_PAD) - x0, H = Math.ceil(box.maxY + EXPORT_PAD) - y0;
    const scale = Math.max(0.1, Math.min(EXPORT_SCALE, EXPORT_MAX_DIM / W, EXPORT_MAX_DIM / H, Math.sqrt(EXPORT_MAX_AREA / (W * H))));
    const bg = getComputedStyle(_vp).backgroundColor || getComputedStyle(document.body).backgroundColor;
    // Resolved styles of every SVG element, read here where the page CSS applies.
    const svgStyles = [_svg, _edgeSvg].map(svg => [...svg.querySelectorAll('*')].map(n => {
      const cs = getComputedStyle(n);
      return SVG_STYLE_PROPS.map(p => [p, cs.getPropertyValue(p)]);
    }));
    const keep = onlySelection ? new Set(keys) : null;
    const keepIds = new Set(keys.map(k => _splitKey(k)[1]));

    const canvas = await window.html2canvas(_vp, {
      backgroundColor: bg,
      scale,
      useCORS: false,
      logging: false,
      width: W,
      height: H,
      windowWidth: Math.max(W, window.innerWidth),
      windowHeight: Math.max(H, window.innerHeight),
      scrollX: 0,
      scrollY: 0,
      onclone: (doc, vp) => {
        vp.className = '';
        Object.assign(vp.style, {
          position: 'fixed', left: '0', top: '0', width: `${W}px`, height: `${H}px`, zIndex: '2147483647',
          backgroundColor: bg, backgroundImage: 'none', boxShadow: 'none',
        });
        Object.assign(vp.querySelector('#wb-workspace').style, { transform: 'none', left: `${-x0}px`, top: `${-y0}px` });
        ['#wb-svg', '#wb-edges-svg'].forEach((sel, i) => {
          const svg = vp.querySelector(sel);
          const nodes = svg.querySelectorAll('*');
          svgStyles[i].forEach((props, j) => props.forEach(([p, v]) => { if (v && nodes[j]) nodes[j].style.setProperty(p, v); }));
          svg.setAttribute('viewBox', `${x0} ${y0} ${W} ${H}`);
          svg.setAttribute('width', W);
          svg.setAttribute('height', H);
          Object.assign(svg.style, { left: `${x0}px`, top: `${y0}px`, width: `${W}px`, height: `${H}px`, overflow: 'hidden' });
        });
        // Strokes keep their width in board px (live it is divided by the zoom).
        vp.querySelectorAll('#wb-svg path[data-stroke]').forEach(p => p.style.setProperty('stroke-width', p.dataset.strokeW || '2'));
        vp.querySelectorAll('#wb-cursor-layer, .wb-edge-toolbar, .wb-eraser-ring, .wb-marquee, .wb-label-input, .wb-drag-ghost, .wb-resize-handle, .wb-edge-hit, .wb-edge-handle')
          .forEach(n => n.remove());
        vp.querySelectorAll('.wb-selected, .wb-highlight, .wb-dimmed, .connect-from, .connect-target')
          .forEach(n => n.classList.remove('wb-selected', 'wb-highlight', 'wb-dimmed', 'connect-from', 'connect-target'));
        if (keep) {
          vp.querySelectorAll(ITEM_SELECTOR).forEach(n => { if (!keep.has(_keyOfItemEl(n))) n.remove(); });
          vp.querySelectorAll('.wb-edge-group').forEach(g => {
            const e = wbData.edges.find(x => x.id === g.dataset.edgeId);
            if (!e || !keepIds.has(e.fromId) || !keepIds.has(e.toId)) g.remove();
          });
        }
      },
    });

    const blob = await new Promise((resolve, reject) =>
      canvas.toBlob(b => (b ? resolve(b) : reject(new Error('el navegador no pudo generar la imagen'))), 'image/png'));
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.download = _exportFilename();
    link.href = url;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  } catch (err) {
    showToast(`No se pudo exportar la imagen: ${err?.message || err}`, 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.removeAttribute('aria-busy'); }
  }
}

// ── Exports ────────────────────────────────────────────────────────────
window.initWhiteboard   = initWhiteboard;
window.wbUndo           = wbUndo;
window.setWbMode        = setWbMode;
window.setDrawColor     = setDrawColor;
window.setDrawWidth     = setDrawWidth;
window.fitToScreen      = fitToScreen;
window.syncTargets      = syncTargets;
window.clearDrawing     = clearDrawing;
window.wbToggleCollapse = wbToggleCollapse;
window.wbRemoveNode     = wbRemoveNode;
window.wbRemoveNote     = wbRemoveNote;
window.wbNoteColor      = wbNoteColor;
window.wbRemoveCard     = wbRemoveCard;
window.wbCardColor      = wbCardColor;
window.wbPickImages     = wbPickImages;
window.wbRemoveImage    = wbRemoveImage;
window.wbSearch         = wbSearch;
window.wbSearchClear    = wbSearchClear;
window.wbRedo           = wbRedo;
window.exportPng        = exportPng;
window.wbExportMenu     = wbExportMenu;
window.wbPickFinding    = wbPickFinding;
window.wbRefreshFindings = wbRefreshFindings;
