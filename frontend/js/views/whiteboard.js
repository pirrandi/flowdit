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

// Undo / redo stacks (strokes only, local per session)
let _undoStack = [];
let _redoStack = [];

// Eraser ring DOM element
let _eraserRing;

// Search
let _searchQuery = '';

// Ids que ESTA pestaña vio borrar (local o remoto) en la sesión. Al
// reconectar el socket se re-lee el tablero del servidor y se suma lo que
// falte (lo que agregaron otros o Claude Code mientras no llegaban los
// patches); esto evita resucitar lo que acá ya se borró.
const _removedIds = new Set();
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
    api.whiteboard.get(pid).catch(() => ({ data: {} })),
    _loadPortsAndEndpoints(pid, state.targets),
  ]);

  const saved = res.data || {};
  if (saved.nodes && saved.nodes.length > 0) {
    wbData = { nodes: [], strokes: [], notes: [], edges: [], cards: [], view: { panX: 0, panY: 0, zoom: 1 }, ...saved };
  } else {
    wbData.strokes = saved.strokes || [];
    wbData.notes   = saved.notes   || [];
    // Tarjetas y flechas también: Claude Code puede haber agregado tarjetas
    // a un tablero que todavía no tenía nodos, y este primer guardado las
    // borraba.
    wbData.cards   = saved.cards   || [];
    wbData.edges   = saved.edges   || [];
    wbData.images  = saved.images  || [];
    wbData.view    = saved.view    || { panX: 0, panY: 0, zoom: 1 };
    _autoLayout(state.targets, _itemsBottom());
    scheduleSave();
  }
  if (!Array.isArray(wbData.images)) wbData.images = [];
  const v = wbData.view || {};
  wbData.view = { panX: _num(v.panX), panY: _num(v.panY), zoom: _num(v.zoom, 1) > 0 ? _num(v.zoom, 1) : 1 };

  _applyTransform();
  _renderAll();
  _wireEvents();
  _wireKeyboard();
  _wireWs();
  _wbReady = true;
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

  const vulnRows = vulns.length
    ? vulns.map(v => `
        <div class="wb-vuln-row" style="border-left-color:${SEV_COLOR[v.severity]||'#666'}">
          <span class="wb-vuln-sev" style="color:${SEV_COLOR[v.severity]||'#666'}">${v.severity.slice(0,4).toUpperCase()}</span>
          <span class="wb-vuln-name" title="${esc(v.name)}">${esc(v.name)}</span>
        </div>`).join('')
    : '<div class="wb-empty-section">No findings yet</div>';

  const portChips = ports.length
    ? `<div class="wb-ports-wrap">`
      + ports.map(p =>
          `<span class="wb-port-chip ${p.state === 'open' ? 'open' : 'closed'}" data-port-id="${esc(p.id)}">
             <span class="wb-port-num">${p.port}</span>${p.protocol !== 'tcp' ? `<span class="wb-port-svc">/${esc(p.protocol)}</span>` : ''}${p.service ? `<span class="wb-port-svc"> ${esc(p.service)}</span>` : ''}
           </span>`
        ).join('')
      + `</div>`
    : '<div class="wb-empty-section">No ports</div>';

  const epRows = endpoints.length
    ? endpoints.map(e =>
        `<div class="wb-ep-row" data-ep-id="${esc(e.id)}" data-ep-host="${esc(target.host)}" data-ep-path="${esc(e.path)}">
           <span class="wb-ep-method" style="color:${METHOD_COLOR[e.method]||'#aaa'}">${esc(e.method)}</span>
           <span class="wb-ep-path" title="${esc(e.path)}">${esc(e.path)}</span>
           ${e.interesting ? `<span class="wb-ep-star" title="Interesting">${icon('star',{size:10})}</span>` : ''}
           <span class="wb-ep-copy">copy</span>
         </div>`
      ).join('')
    : '<div class="wb-empty-section">No endpoints</div>';

  el.innerHTML = `
    <div class="wb-node-head" data-drag-handle>
      <span class="wb-node-type">${esc(target.type)}</span>
      <span class="wb-node-host" title="${esc(target.host)}">${esc(target.host)}</span>
      <span class="wb-node-status" style="background:${statusDot}" title="${esc(target.status)}"></span>
      <span class="wb-node-collapse" onclick="wbToggleCollapse('${target.id}')">${nodeData.collapsed ? icon('chevron-right',{size:11}) : icon('chevron-down',{size:11})}</span>
      <span class="wb-node-remove" onclick="wbRemoveNode('${target.id}')" title="Remove from board">×</span>
    </div>
    <div class="wb-node-body">
      <div class="wb-section">
        <div class="wb-section-head">
          <span class="wb-section-label">Vulnerabilities</span>
          <span class="wb-section-count">${vulns.length}</span>
        </div>
        ${vulnRows}
      </div>
      <hr class="wb-section-divider">
      <div class="wb-section">
        <div class="wb-section-head">
          <span class="wb-section-label">Ports</span>
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
        <a href="targets?pid=${pid}" target="_blank">View in Targets →</a>
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
    navigator.clipboard.writeText(text).then(() => showToast(`Copied: ${text}`, 'success')).catch(() => showToast('Copy failed', 'error'));
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

    const startX = e.clientX, startY = e.clientY;
    const origX = nodeData.x, origY = nodeData.y;
    let dragging = false;

    function onMove(e) {
      const dx = e.clientX - startX, dy = e.clientY - startY;
      if (!dragging) {
        if (dx * dx + dy * dy < 25) return;
        dragging = true;
        el.classList.add('dragging');
        head.setPointerCapture(e.pointerId);
      }
      nodeData.x = origX + dx / wbData.view.zoom;
      nodeData.y = origY + dy / wbData.view.zoom;
      el.style.left = nodeData.x + 'px';
      el.style.top  = nodeData.y + 'px';
      _updateAllEdges();
    }
    function onUp() {
      head.removeEventListener('pointermove', onMove);
      if (!dragging) return;
      el.classList.remove('dragging');
      _broadcast({ op: 'node_move', nodeId: nodeData.id, x: nodeData.x, y: nodeData.y });
      scheduleSave();
    }
    head.addEventListener('pointermove', onMove);
    head.addEventListener('pointerup', onUp, { once: true });
  });
}

function wbToggleCollapse(targetId) {
  const nd = wbData.nodes.find(n => n.id === targetId);
  if (!nd) return;
  nd.collapsed = !nd.collapsed;
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

function wbRemoveNode(targetId) {
  _removedIds.add(targetId);
  wbData.nodes = wbData.nodes.filter(n => n.id !== targetId);
  _nl.querySelector(`[data-node-id="${targetId}"]`)?.remove();
  _removeItemEdges(targetId, true);
  _broadcast({ op: 'node_remove', nodeId: targetId });
  scheduleSave();
}

// ── Custom cards ───────────────────────────────────────────────────────
function _buildCard(cardData) {
  const el = document.createElement('div');
  el.className = 'wb-card';
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
      <span class="wb-card-title" data-title contenteditable="false">${esc(cardData.title || '')}</span>
      <div class="wb-card-colors">${colorDots}</div>
      <span class="wb-card-rm">×</span>
    </div>
    <div class="wb-card-body">
      ${cardData.ref ? `<div class="wb-card-ref" title="${esc(cardData.ref.type)}">↳ ${esc(cardData.ref.label || '')}</div>` : ''}
      <div class="wb-card-text" data-text contenteditable="false"
           data-placeholder="Double-click to add notes…">${renderMd(cardData.body)}</div>
      <div class="wb-card-hint">${cardData.created_by === 'claude_code' ? '<span class="wb-cc-tag">Claude Code</span> · ' : ''}dbl-click to edit · drag header to move</div>
    </div>`;

  const titleEl = el.querySelector('[data-title]');
  const textEl  = el.querySelector('[data-text]');

  // Title editing (double-click)
  titleEl.addEventListener('dblclick', e => {
    e.stopPropagation();
    titleEl.contentEditable = 'true';
    titleEl.focus();
    const r = document.createRange();
    r.selectNodeContents(titleEl);
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(r);
  });
  titleEl.addEventListener('blur', () => {
    titleEl.contentEditable = 'false';
    cardData.title = titleEl.innerText.trim() || 'Card';
    if (titleEl.innerText.trim() === '') titleEl.textContent = 'Card';
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
    cardData.body = raw;
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

    const startX = e.clientX, startY = e.clientY;
    const origX  = cardData.x, origY = cardData.y;
    let dragging = false;

    function onMove(e) {
      const dx = e.clientX - startX, dy = e.clientY - startY;
      if (!dragging) {
        if (dx * dx + dy * dy < 25) return; // 5px threshold before committing to drag
        dragging = true;
        el.classList.add('dragging');
        head.setPointerCapture(e.pointerId);
        // Dismiss any open contenteditable inside the card
        el.querySelectorAll('[contenteditable="true"]').forEach(ce => ce.blur());
      }
      cardData.x = origX + dx / wbData.view.zoom;
      cardData.y = origY + dy / wbData.view.zoom;
      el.style.left = cardData.x + 'px';
      el.style.top  = cardData.y + 'px';
      _updateAllEdges();
    }
    function onUp() {
      head.removeEventListener('pointermove', onMove);
      if (!dragging) return;
      el.classList.remove('dragging');
      _broadcast({ op: 'card_update', cardId: cardData.id, changes: { x: cardData.x, y: cardData.y } });
      scheduleSave();
    }
    head.addEventListener('pointermove', onMove);
    head.addEventListener('pointerup', onUp, { once: true });
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
      scheduleSave();
    }
    handle.addEventListener('pointermove', onMove);
    handle.addEventListener('pointerup', onUp, { once: true });
  });
}

function _addCard(x, y) {
  const id = crypto.randomUUID();
  const cardData = { id, x, y, title: 'Card', body: '', color: CARD_COLORS[0] };
  wbData.cards.push(cardData);
  const el = _nl.appendChild(_buildCard(cardData));
  _broadcast({ op: 'card_add', card: cardData });
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
  _removedIds.add(id);
  wbData.cards = wbData.cards.filter(c => c.id !== id);
  _nl.querySelector(`[data-node-id="${id}"]`)?.remove();
  _removeItemEdges(id, true);
  _broadcast({ op: 'card_remove', cardId: id });
  scheduleSave();
}

function wbCardColor(id, color) {
  const cd = wbData.cards.find(c => c.id === id);
  if (!cd) return;
  cd.color = color = _cardColor(color);
  const head = _nl.querySelector(`[data-node-id="${id}"] .wb-card-head`);
  if (head) head.style.background = color;
  _broadcast({ op: 'card_update', cardId: id, changes: { color } });
  scheduleSave();
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
    if (text) im.caption = text; else delete im.caption;
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

      const startX = e.clientX, startY = e.clientY;
      const origX = _num(im.x), origY = _num(im.y);
      let dragging = false;

      function onMove(e) {
        const dx = e.clientX - startX, dy = e.clientY - startY;
        if (!dragging) {
          if (dx * dx + dy * dy < 25) return;
          dragging = true;
          el.classList.add('dragging');
          handle.setPointerCapture(e.pointerId);
        }
        im.x = origX + dx / wbData.view.zoom;
        im.y = origY + dy / wbData.view.zoom;
        el.style.left = im.x + 'px';
        el.style.top  = im.y + 'px';
        _updateAllEdges();
      }
      function onUp() {
        handle.removeEventListener('pointermove', onMove);
        if (!dragging) {
          if (handle.classList.contains('wb-image-frame')) _openImageLightbox(im);
          return;
        }
        el.classList.remove('dragging');
        _broadcast({ op: 'image_update', imageId: im.id, changes: { x: im.x, y: im.y } });
        scheduleSave();
      }
      handle.addEventListener('pointermove', onMove);
      handle.addEventListener('pointerup', onUp, { once: true });
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
  _removedIds.add(id);
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
  _removeImage(id, true);
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
  scheduleSave();
  showToast('Conexión creada — clic en la flecha para editarla', 'success');
}

function _removeEdge(edgeId) {
  _removedIds.add(edgeId);
  if (_selectedEdgeId === edgeId) _deselectEdge();
  wbData.edges = wbData.edges.filter(e => e.id !== edgeId);
  _edgeEl(edgeId)?.remove();
  _broadcast({ op: 'edge_remove', edgeId });
  scheduleSave();
}

function _selectEdge(edgeId) {
  if (_selectedEdgeId === edgeId) return;
  _deselectEdge();
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
    else if (btn.dataset.edgeAction === 'delete') _removeEdge(edge.id);
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
  if (!toAdd.length) { showToast('All targets are already on the board', 'info'); return; }

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
  scheduleSave();
  showToast(`Added ${toAdd.length} target${toAdd.length > 1 ? 's' : ''}`, 'success');
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
          <button class="wb-modal-btn wb-modal-cancel">Cancel</button>
          <button class="wb-modal-btn wb-modal-confirm">Confirm</button>
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
  if (!await _showConfirm('Clear strokes', 'This will remove all drawing strokes from the board.')) return;
  wbData.strokes = [];
  _undoStack = [];
  _redoStack = [];
  _svg.querySelectorAll('path[data-stroke]').forEach(p => p.remove());
  _broadcast({ op: 'strokes_clear' });
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
    noteData.text = textEl.innerText.trim();
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

    const startX = e.clientX, startY = e.clientY;
    const origX = noteData.x, origY = noteData.y;
    let dragging = false;

    function onMove(e) {
      const dx = e.clientX - startX, dy = e.clientY - startY;
      if (!dragging) {
        if (dx * dx + dy * dy < 25) return;
        dragging = true;
        head.setPointerCapture(e.pointerId);
      }
      noteData.x = origX + dx / wbData.view.zoom;
      noteData.y = origY + dy / wbData.view.zoom;
      el.style.left = noteData.x + 'px';
      el.style.top  = noteData.y + 'px';
      _updateAllEdges();
    }
    function onUp() {
      head.removeEventListener('pointermove', onMove);
      if (!dragging) return;
      _broadcast({ op: 'note_update', noteId: noteData.id, changes: { x: noteData.x, y: noteData.y } });
      scheduleSave();
    }
    head.addEventListener('pointermove', onMove);
    head.addEventListener('pointerup', onUp, { once: true });
  });
}

function _addNote(wx, wy) {
  const id = crypto.randomUUID();
  const noteData = { id, x: wx - 85, y: wy - 40, text: '', color: NOTE_COLORS[0] };
  wbData.notes.push(noteData);
  _nl.appendChild(_buildNote(noteData));
  _broadcast({ op: 'note_add', note: noteData });
  scheduleSave();
  setTimeout(() => {
    const textEl = _nl.querySelector(`[data-note-id="${id}"] [data-text]`);
    if (textEl) { textEl.contentEditable = 'true'; textEl.focus(); }
  }, 50);
}

function wbRemoveNote(id) {
  _removedIds.add(id);
  wbData.notes = wbData.notes.filter(n => n.id !== id);
  _nl.querySelector(`[data-note-id="${id}"]`)?.remove();
  _removeItemEdges(id, true);
  _broadcast({ op: 'note_remove', noteId: id });
  scheduleSave();
}

function wbNoteColor(id, color) {
  const nd = wbData.notes.find(n => n.id === id);
  if (!nd) return;
  nd.color = color = _noteColor(color);
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
      _undoStack.push({ type: 'add', id });
      _activeStrokeEl.dataset.stroke  = id;
      _activeStrokeEl.dataset.strokeW = String(_drawWidth);
      _redoStack = [];
      _broadcast({ op: 'stroke_add', stroke });
      scheduleSave();
    } else {
      _activeStrokeEl.remove();
    }
    _activeStrokeEl = null;
  }
  _vp.addEventListener('pointermove', onMove);
  _vp.addEventListener('pointerup', onUp, { once: true });
}

// ── Undo ───────────────────────────────────────────────────────────────
// Stack entries: { type:'add', id } | { type:'erase', strokes:[] }
function undoStroke() {
  if (!_undoStack.length) return;
  const op = _undoStack.pop();
  if (op.type === 'add') {
    const stroke = wbData.strokes.find(s => s.id === op.id);
    wbData.strokes = wbData.strokes.filter(s => s.id !== op.id);
    _svg.querySelector(`path[data-stroke="${op.id}"]`)?.remove();
    _broadcast({ op: 'stroke_remove', strokeId: op.id });
    if (stroke) _redoStack.push({ type: 'add', stroke });
  } else if (op.type === 'erase') {
    op.strokes.forEach(stroke => {
      if (!wbData.strokes.find(s => s.id === stroke.id)) {
        wbData.strokes.push(stroke);
        _renderStroke(stroke);
        _broadcast({ op: 'stroke_add', stroke });
      }
    });
    _redoStack.push({ type: 'erase', strokeIds: op.strokes.map(s => s.id) });
  }
  scheduleSave();
}

function redoStroke() {
  if (!_redoStack.length) return;
  const op = _redoStack.pop();
  if (op.type === 'add') {
    if (!wbData.strokes.find(s => s.id === op.stroke.id)) {
      wbData.strokes.push(op.stroke);
      _renderStroke(op.stroke);
      _broadcast({ op: 'stroke_add', stroke: op.stroke });
    }
    _undoStack.push({ type: 'add', id: op.stroke.id });
  } else if (op.type === 'erase') {
    const erased = [];
    op.strokeIds.forEach(id => {
      const stroke = wbData.strokes.find(s => s.id === id);
      if (!stroke) return;
      erased.push(stroke);
      wbData.strokes = wbData.strokes.filter(s => s.id !== id);
      _svg.querySelector(`path[data-stroke="${id}"]`)?.remove();
      _broadcast({ op: 'stroke_remove', strokeId: id });
    });
    if (erased.length) _undoStack.push({ type: 'erase', strokes: erased });
  }
  scheduleSave();
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
    if (erasedStrokes.length) {
      _undoStack.push({ type: 'erase', strokes: erasedStrokes });
      _redoStack = [];
    }
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

  // Pan / Draw / Erase / Note placement
  _vp.addEventListener('pointerdown', e => {
    if (_mode === 'draw'   && e.button === 0) { _startDraw(e);  return; }
    if (_mode === 'eraser'  && e.button === 0) { _startErase(e);         return; }
    if (_mode === 'connect' && e.button === 0) return; // handled in the capture phase above
    const onBg = e.target === _vp || e.target === _ws || e.target === _svg || e.target === _nl;
    if (_mode === 'select' && e.button === 0 && onBg) _deselectEdge();
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
    if (e.key === 'v' || e.key === 'V') setWbMode('select');
    if (e.key === 'h' || e.key === 'H') setWbMode('pan');
    if (e.key === 'd' || e.key === 'D') setWbMode('draw');
    if (e.key === 'e' || e.key === 'E') setWbMode('eraser');
    if (e.key === 'n' || e.key === 'N') setWbMode('note');
    if (e.key === 'f' || e.key === 'F') fitToScreen();
    if (e.key === 'a' || e.key === 'A') setWbMode('card');
    if (e.key === 'c' || e.key === 'C') setWbMode('connect');
    if ((e.ctrlKey || e.metaKey) && e.key === 'z' && !e.shiftKey) { e.preventDefault(); undoStroke(); }
    if ((e.ctrlKey || e.metaKey) && (e.key === 'y' || (e.key === 'z' && e.shiftKey))) { e.preventDefault(); redoStroke(); }
    if (e.key === 'Delete' || e.key === 'Backspace') {
      if (_selectedEdgeId) _removeEdge(_selectedEdgeId);
    }
    if (e.key === 'Escape') {
      if (_searchQuery) { wbSearchClear(); return; }
      _clearConnectFrom();
      _deselectEdge();
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

// Suma ítems que no están en wbData (por id) ni se borraron acá. Devuelve
// cuántos agregó. Compartido por el patch 'items_add' del servidor y por la
// re-lectura al reconectar.
// `explicit`: altas nuevas del servidor (items_add). Un nodo de target usa el
// id del target, así que si acá se había quitado ese nodo y Claude Code lo
// vuelve a agregar, es un alta nueva y se respeta.
async function _mergeItems({ nodes = [], cards = [], notes = [], images = [], edges = [] }, { explicit = false } = {}) {
  const fresh = (list, item) => item?.id && (explicit || !_removedIds.has(item.id)) && !list.some(x => x.id === item.id);
  if (explicit) [...nodes, ...cards, ...notes, ...images, ...edges].forEach(it => it?.id && _removedIds.delete(it.id));
  let n = 0;
  // Un nodo de un target que esta pestaña todavía no conoce (agregado
  // después de cargarla): se recargan los targets para poder dibujarlo.
  const newNodes = nodes.filter(nd => fresh(wbData.nodes, nd));
  if (newNodes.some(nd => !state.targets.find(t => t.id === nd.id))) {
    try { state.targets = await api.targets.list(state.currentProject.id); } catch {}
  }
  const missing = newNodes.map(nd => state.targets.find(t => t.id === nd.id)).filter(Boolean);
  if (missing.length) await _loadPortsAndEndpoints(state.currentProject.id, missing);
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

// Re-lectura al reconectar: los patches que se emitieron con el socket
// caído no llegan nunca, y el próximo autosave (PUT del blob entero) los
// borraría del servidor.
async function _resyncFromServer() {
  if (!_wbReady) return;
  try {
    const res = await api.whiteboard.get(state.currentProject.id);
    const n = await _mergeItems(res.data || {});
    if (n) scheduleSave();
  } catch {}
}

function _handleRemotePatch(msg) {
  switch (msg.op) {
    // Altas que hizo el servidor (Claude Code vía MCP), ya guardadas en la
    // base. Se mezclan en wbData y se agenda un guardado: así un autosave de
    // esta pestaña que viajaba con datos viejos (un PUT en vuelo cuando
    // Claude Code escribió) no deja al servidor sin estos ítems. No entran
    // al undo: no son acciones locales.
    case 'items_add':
      _mergeItems(msg, { explicit: true }).then(n => { if (n) scheduleSave(); });
      break;
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
      _removedIds.add(msg.nodeId);
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
      _undoStack = _undoStack.filter(op => {
        if (op.type === 'add') return op.id !== msg.strokeId;
        if (op.type === 'erase') { op.strokes = op.strokes.filter(s => s.id !== msg.strokeId); return op.strokes.length > 0; }
        return true;
      });
      _svg.querySelector(`path[data-stroke="${msg.strokeId}"]`)?.remove();
      break;
    case 'strokes_clear':
      wbData.strokes = [];
      _undoStack = [];
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
      _removedIds.add(msg.noteId);
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
      _removedIds.add(msg.edgeId);
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
      _removedIds.add(msg.cardId);
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
      if (msg.changes.title !== undefined) {
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
    const match = `${cd.title} ${cd.body}`.toLowerCase().includes(q);
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
  _saveTimer = setTimeout(async () => {
    try {
      await api.whiteboard.save(state.currentProject.id, wbData);
      _updateSaveStatus('saved');
    } catch {
      _updateSaveStatus('error');
    }
  }, 1500);
}

function _updateSaveStatus(s) {
  const el = document.getElementById('wb-save-status');
  if (!el) return;
  el.className = `wb-save-status ${s}`;
  el.innerHTML = s === 'saving' ? 'Saving…' : s === 'error' ? `Save failed ${icon('x',{size:11})}` : `Saved ${icon('check',{size:11})}`;
}

// ── Export PNG ─────────────────────────────────────────────────────────
async function exportPng() {
  const btn = document.getElementById('wb-export-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Exporting…'; }

  try {
    if (!window.html2canvas) {
      await new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = 'https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js';
        s.onload = resolve;
        s.onerror = reject;
        document.head.appendChild(s);
      });
    }

    _deselectEdge(); // the edge toolbar lives in the viewport and would be captured
    // Save current view, then fit to screen for capture
    const savedView = { ...wbData.view };
    fitToScreen();
    // Wait for layout
    await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));

    const canvas = await html2canvas(_vp, {
      backgroundColor: '#0f1117',
      useCORS: true,
      scale: window.devicePixelRatio || 1,
      logging: false,
    });

    // Restore view
    wbData.view = savedView;
    _applyTransform();

    const link = document.createElement('a');
    link.download = `whiteboard-${Date.now()}.png`;
    link.href = canvas.toDataURL('image/png');
    link.click();
  } catch (err) {
    showToast('Export failed: ' + err.message, 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = ''; btn.innerHTML = icon('download', { size: 16 }); }
  }
}

// ── Exports ────────────────────────────────────────────────────────────
window.initWhiteboard   = initWhiteboard;
window.undoStroke       = undoStroke;
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
window.redoStroke       = redoStroke;
window.exportPng        = exportPng;
