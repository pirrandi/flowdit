// ── Whiteboard view ────────────────────────────────────────────────────
'use strict';

// ── Module state ───────────────────────────────────────────────────────
let wbData = { nodes: [], strokes: [], notes: [], edges: [], cards: [], view: { panX: 0, panY: 0, zoom: 1 } };
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

// Edges / connect mode
let _edgeSvg;
let _connectFrom    = null;  // nodeId of first selected node in connect mode
let _selectedEdgeId = null;

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
    wbData.view    = saved.view    || { panX: 0, panY: 0, zoom: 1 };
    _autoLayout(state.targets);
    scheduleSave();
  }

  _applyTransform();
  _renderAll();
  _wireEvents();
  _wireKeyboard();
  _wireWs();
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

function _autoLayout(targets) {
  const cols = 3, nodeW = 290, nodeH = 380, gapX = 60, gapY = 50;
  wbData.nodes = targets.map((t, i) => ({
    id:        t.id,
    x:         80 + (i % cols) * (nodeW + gapX),
    y:         80 + Math.floor(i / cols) * (nodeH + gapY),
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
  el.style.left  = nodeData.x + 'px';
  el.style.top   = nodeData.y + 'px';
  el.style.width = (nodeData.w || 290) + 'px';
  if (nodeData.h) el.style.height = nodeData.h + 'px';

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
          `<span class="wb-port-chip ${p.state === 'open' ? 'open' : 'closed'}">
             <span class="wb-port-num">${p.port}</span>${p.protocol !== 'tcp' ? `<span class="wb-port-svc">/${esc(p.protocol)}</span>` : ''}${p.service ? `<span class="wb-port-svc"> ${esc(p.service)}</span>` : ''}
           </span>`
        ).join('')
      + `</div>`
    : '<div class="wb-empty-section">No ports</div>';

  const epRows = endpoints.length
    ? endpoints.map(e =>
        `<div class="wb-ep-row" data-ep-host="${esc(target.host)}" data-ep-path="${esc(e.path)}">
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

  // Copy endpoint on click
  el.querySelector('.wb-node-body').addEventListener('click', e => {
    const row = e.target.closest('.wb-ep-row');
    if (!row) return;
    const host = (row.dataset.epHost || '').replace(/\/$/, '');
    const path = row.dataset.epPath || '';
    const text = host + path;
    navigator.clipboard.writeText(text).then(() => showToast(`Copied: ${text}`, 'success')).catch(() => showToast('Copy failed', 'error'));
  });

  _makeNodeDraggable(el, nodeData);
  _makeResizable(el, nodeData, 200, 120, 'node');
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
  wbData.nodes = wbData.nodes.filter(n => n.id !== targetId);
  _nl.querySelector(`[data-node-id="${targetId}"]`)?.remove();
  // Remove all edges connected to this node
  wbData.edges
    .filter(e => e.fromId === targetId || e.toId === targetId)
    .forEach(e => {
      _edgeSvg.querySelector(`[data-edge-id="${e.id}"]`)?.remove();
      _broadcast({ op: 'edge_remove', edgeId: e.id });
    });
  wbData.edges = wbData.edges.filter(e => e.fromId !== targetId && e.toId !== targetId);
  _broadcast({ op: 'node_remove', nodeId: targetId });
  scheduleSave();
}

// ── Custom cards ───────────────────────────────────────────────────────
function _buildCard(cardData) {
  const el = document.createElement('div');
  el.className = 'wb-card';
  el.dataset.nodeId = cardData.id; // same attr as target nodes → arrows work
  el.style.left  = cardData.x + 'px';
  el.style.top   = cardData.y + 'px';
  el.style.width = (cardData.w || 240) + 'px';
  if (cardData.h) el.style.height = cardData.h + 'px';

  const colorDots = CARD_COLORS.map(c =>
    `<span class="wb-card-col" style="background:${c}" data-color="${c}"></span>`
  ).join('');

  el.innerHTML = `
    <div class="wb-card-head" data-drag-handle style="background:${cardData.color || CARD_COLORS[0]}">
      <svg class="wb-card-grip" width="8" height="12" viewBox="0 0 8 12" fill="currentColor">
        <circle cx="2" cy="2"  r="1.2"/><circle cx="6" cy="2"  r="1.2"/>
        <circle cx="2" cy="6"  r="1.2"/><circle cx="6" cy="6"  r="1.2"/>
        <circle cx="2" cy="10" r="1.2"/><circle cx="6" cy="10" r="1.2"/>
      </svg>
      <span class="wb-card-title" data-title contenteditable="false">${esc(cardData.title || '')}</span>
      <div class="wb-card-colors">${colorDots}</div>
      <span class="wb-card-rm">×</span>
    </div>
    <div class="wb-card-body">
      <div class="wb-card-text" data-text contenteditable="false"
           data-placeholder="Double-click to add notes…">${renderMd(cardData.body)}</div>
      <div class="wb-card-hint">dbl-click to edit · drag header to move</div>
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
  _makeResizable(el, cardData, 160, 80, 'card');
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

function _makeResizable(el, data, minW, minH, type) {
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

    function onMove(e) {
      const z = wbData.view.zoom;
      data.w = Math.round(Math.max(minW, startW + (e.clientX - startX) / z));
      data.h = Math.round(Math.max(minH, startH + (e.clientY - startY) / z));
      el.style.width  = data.w + 'px';
      el.style.height = data.h + 'px';
      if (type === 'node') el.classList.add('wb-node--sized');
      _updateAllEdges();
    }
    function onUp() {
      handle.removeEventListener('pointermove', onMove);
      if (type === 'card') {
        _broadcast({ op: 'card_update', cardId: data.id, changes: { w: data.w, h: data.h } });
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
  wbData.cards = wbData.cards.filter(c => c.id !== id);
  _nl.querySelector(`[data-node-id="${id}"]`)?.remove();
  wbData.edges
    .filter(e => e.fromId === id || e.toId === id)
    .forEach(e => {
      _edgeSvg.querySelector(`[data-edge-id="${e.id}"]`)?.remove();
      _broadcast({ op: 'edge_remove', edgeId: e.id });
    });
  wbData.edges = wbData.edges.filter(e => e.fromId !== id && e.toId !== id);
  _broadcast({ op: 'card_remove', cardId: id });
  scheduleSave();
}

function wbCardColor(id, color) {
  const cd = wbData.cards.find(c => c.id === id);
  if (!cd) return;
  cd.color = color;
  const head = _nl.querySelector(`[data-node-id="${id}"] .wb-card-head`);
  if (head) head.style.background = color;
  _broadcast({ op: 'card_update', cardId: id, changes: { color } });
  scheduleSave();
}

// ── Edges ──────────────────────────────────────────────────────────────
function _nodeInfo(nodeId) {
  const nd  = wbData.nodes.find(n => n.id === nodeId);
  const cd  = !nd && wbData.cards.find(c => c.id === nodeId);
  const src = nd || cd;
  if (!src) return null;
  const el  = _nl.querySelector(`[data-node-id="${nodeId}"]`);
  const h   = el ? el.offsetHeight : 40;
  const w   = el ? el.offsetWidth  : (nd ? (nd.w || 290) : (cd.w || 240));
  return { cx: src.x + w / 2, cy: src.y + h / 2, w, h };
}

function _edgeEndpoints(edge) {
  const from = _nodeInfo(edge.fromId);
  const to   = _nodeInfo(edge.toId);
  if (!from || !to) return null;

  const dx = to.cx - from.cx, dy = to.cy - from.cy;
  const len = Math.sqrt(dx * dx + dy * dy) || 1;
  const ux = dx / len, uy = dy / len;

  const fhw = from.w / 2 + 2, fhh = from.h / 2 + 2;
  const ft  = Math.min(fhw / (Math.abs(ux) || 0.001), fhh / (Math.abs(uy) || 0.001));
  const thw = to.w   / 2 + 2, thh = to.h   / 2 + 2;
  const tt  = Math.min(thw / (Math.abs(ux) || 0.001), thh / (Math.abs(uy) || 0.001)) + 8;

  const sx = from.cx + ux * ft, sy = from.cy + uy * ft;
  const ex = to.cx   - ux * tt, ey = to.cy   - uy * tt;

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

function _renderEdge(edge) {
  const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  g.dataset.edgeId = edge.id;
  g.classList.add('wb-edge-group');

  const hit = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  hit.classList.add('wb-edge-hit');

  const line = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  line.classList.add('wb-edge-line');
  line.setAttribute('marker-end', 'url(#wb-arrowhead)');

  const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  dot.classList.add('wb-edge-dot');
  dot.setAttribute('r', '4');

  const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
  label.classList.add('wb-edge-label');
  label.textContent = edge.label || '';

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

  _updateEdgePath(edge);
  return g;
}

function _updateEdgePath(edge) {
  const g = _edgeSvg.querySelector(`[data-edge-id="${edge.id}"]`);
  if (!g) return;
  const pts = _edgeEndpoints(edge);
  if (!pts) { g.style.display = 'none'; return; }
  g.style.display = '';
  const d = _edgeCubic(pts);
  g.querySelector('.wb-edge-line').setAttribute('d', d);
  g.querySelector('.wb-edge-hit').setAttribute('d', d);
  const dot = g.querySelector('.wb-edge-dot');
  if (dot) { dot.setAttribute('cx', pts.sx.toFixed(1)); dot.setAttribute('cy', pts.sy.toFixed(1)); }
  const lbl = g.querySelector('.wb-edge-label');
  lbl.setAttribute('x', pts.mx.toFixed(1));
  lbl.setAttribute('y', (pts.my - 8).toFixed(1));
}

function _updateAllEdges() {
  wbData.edges.forEach(e => _updateEdgePath(e));
}

function _addEdge(fromId, toId) {
  if (wbData.edges.find(e => e.fromId === fromId && e.toId === toId)) {
    showToast('Connection already exists', 'info');
    return;
  }
  const edge = { id: crypto.randomUUID(), fromId, toId, label: '' };
  wbData.edges.push(edge);
  _renderEdge(edge);
  _broadcast({ op: 'edge_add', edge });
  scheduleSave();
  showToast('Connection created — double-click arrow to label', 'success');
}

function _removeEdge(edgeId) {
  wbData.edges = wbData.edges.filter(e => e.id !== edgeId);
  _edgeSvg.querySelector(`[data-edge-id="${edgeId}"]`)?.remove();
  if (_selectedEdgeId === edgeId) _selectedEdgeId = null;
  _broadcast({ op: 'edge_remove', edgeId });
  scheduleSave();
}

function _selectEdge(edgeId) {
  if (_selectedEdgeId && _selectedEdgeId !== edgeId) {
    _edgeSvg.querySelector(`[data-edge-id="${_selectedEdgeId}"]`)?.classList.remove('selected');
  }
  _selectedEdgeId = edgeId;
  _edgeSvg.querySelector(`[data-edge-id="${edgeId}"]`)?.classList.add('selected');
}

function _editEdgeLabel(edge) {
  const pts = _edgeEndpoints(edge);
  if (!pts) return;

  const { panX, panY, zoom } = wbData.view;
  const inp = document.createElement('input');
  inp.className = 'wb-label-input';
  inp.type = 'text';
  inp.value = edge.label || '';
  inp.placeholder = 'Label…';
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
    edge.label = inp.value.trim();
    const textEl = _edgeSvg.querySelector(`[data-edge-id="${edge.id}"] .wb-edge-label`);
    if (textEl) textEl.textContent = edge.label;
    _broadcast({ op: 'edge_update', edgeId: edge.id, changes: { label: edge.label } });
    scheduleSave();
  }
  inp.addEventListener('keydown', e => {
    e.stopPropagation();
    if (e.key === 'Enter') commit();
    if (e.key === 'Escape') { committed = true; inp.remove(); }
  });
  inp.addEventListener('blur', commit);
}

function _handleConnectClick(e) {
  const nodeEl = e.target.closest('.wb-node, .wb-card');
  if (!nodeEl) {
    if (_connectFrom) {
      _nl.querySelector(`[data-node-id="${_connectFrom}"]`)?.classList.remove('connect-from');
      _connectFrom = null;
    }
    return;
  }
  e.stopPropagation();
  const nodeId = nodeEl.dataset.nodeId;
  if (!_connectFrom) {
    _connectFrom = nodeId;
    nodeEl.classList.add('connect-from');
  } else if (_connectFrom === nodeId) {
    nodeEl.classList.remove('connect-from');
    _connectFrom = null;
  } else {
    _nl.querySelector(`[data-node-id="${_connectFrom}"]`)?.classList.remove('connect-from');
    _addEdge(_connectFrom, nodeId);
    _connectFrom = null;
  }
}

async function syncTargets() {
  const existing = new Set(wbData.nodes.map(n => n.id));
  const toAdd = (state.targets || []).filter(t => !existing.has(t.id));
  if (!toAdd.length) { showToast('All targets are already on the board', 'info'); return; }

  await _loadPortsAndEndpoints(state.currentProject.id, toAdd);

  const maxY = wbData.nodes.reduce((m, n) => Math.max(m, n.y + 380), 80);
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
  path.setAttribute('d', stroke.d);
  path.setAttribute('stroke', stroke.color);
  path.setAttribute('stroke-width', String(stroke.width / wbData.view.zoom));
  path.setAttribute('fill', 'none');
  path.setAttribute('stroke-linecap', 'round');
  path.setAttribute('stroke-linejoin', 'round');
  path.dataset.stroke  = stroke.id;
  path.dataset.strokeW = String(stroke.width);
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
  el.style.left = noteData.x + 'px';
  el.style.top  = noteData.y + 'px';
  el.style.background = noteData.color || NOTE_COLORS[0];

  const colorDots = NOTE_COLORS.map(c =>
    `<span class="wb-sticky-col" style="background:${c}" data-color="${c}"></span>`
  ).join('');

  el.innerHTML = `
    <div class="wb-sticky-head" data-drag-handle>
      <div class="wb-sticky-colors">${colorDots}</div>
      <span class="wb-sticky-rm">×</span>
    </div>
    <div class="wb-sticky-text" data-text contenteditable="false">${esc(noteData.text || '')}</div>`;

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
    e.stopPropagation();
    if (textEl.contentEditable !== 'true') {
      textEl.contentEditable = 'true';
      textEl.focus();
    }
  });
  textEl.addEventListener('blur', () => {
    textEl.contentEditable = 'false';
    noteData.text = textEl.innerText.trim();
    _broadcast({ op: 'note_update', noteId: noteData.id, changes: { text: noteData.text } });
    scheduleSave();
  });
  textEl.addEventListener('keydown', e => {
    e.stopPropagation();
    if (e.key === 'Escape') textEl.blur();
  });

  _makeNoteDraggable(el, noteData);
  return el;
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
  wbData.notes = wbData.notes.filter(n => n.id !== id);
  _nl.querySelector(`[data-note-id="${id}"]`)?.remove();
  _broadcast({ op: 'note_remove', noteId: id });
  scheduleSave();
}

function wbNoteColor(id, color) {
  const nd = wbData.notes.find(n => n.id === id);
  if (!nd) return;
  nd.color = color;
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
    ...wbData.nodes.map(n => ({ x: n.x, y: n.y, w: n.w || 290, h: n.h || 380 })),
    ...wbData.notes.map(n => ({ x: n.x, y: n.y, w: 170, h: 100 })),
    ...wbData.cards.map(c => ({ x: c.x, y: c.y, w: c.w || 240, h: c.h || 110 })),
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
  // Zoom
  _vp.addEventListener('wheel', e => {
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

  // Pan / Draw / Erase / Note placement
  _vp.addEventListener('pointerdown', e => {
    if (_mode === 'draw'   && e.button === 0) { _startDraw(e);  return; }
    if (_mode === 'eraser'  && e.button === 0) { _startErase(e);         return; }
    if (_mode === 'connect' && e.button === 0) { _handleConnectClick(e); return; }
    const onBg = e.target === _vp || e.target === _ws || e.target === _svg || e.target === _nl;
    if (_mode === 'select' && e.button === 0 && onBg && _selectedEdgeId) {
      _edgeSvg.querySelector(`[data-edge-id="${_selectedEdgeId}"]`)?.classList.remove('selected');
      _selectedEdgeId = null;
    }
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
  _vp.addEventListener('mouseleave', () => { _eraserRing.style.display = 'none'; });

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
      if (_connectFrom) {
        _nl.querySelector(`[data-node-id="${_connectFrom}"]`)?.classList.remove('connect-from');
        _connectFrom = null;
      }
      if (_selectedEdgeId) {
        _edgeSvg.querySelector(`[data-edge-id="${_selectedEdgeId}"]`)?.classList.remove('selected');
        _selectedEdgeId = null;
      }
    }
  });
}

// ── WebSocket: cursors + patches ───────────────────────────────────────
function _wireWs() {
  wsClient.on('wb:cursor', _handleRemoteCursor);
  wsClient.on('wb:patch',  _handleRemotePatch);
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

function _handleRemoteCursor({ userId, username, wx, wy }) {
  if (!userId || userId === state.user?.id) return;
  _cursorData.set(userId, { wx, wy });

  let el = _cursorEls.get(userId);
  if (!el) {
    const color = _memberColor(userId);
    el = document.createElement('div');
    el.className = 'wb-cursor';
    el.innerHTML = `
      <svg width="14" height="18" viewBox="0 0 14 18" fill="none">
        <path d="M1 1L1 13L4.5 10L7 16L9 15L6.5 9L11 9L1 1Z" fill="${color}" stroke="#fff" stroke-width="1"/>
      </svg>
      <span class="wb-cursor-label" style="background:${color}">${esc(username || '?')}</span>`;
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
  el.style.left = (wx * zoom + panX) + 'px';
  el.style.top  = (wy * zoom + panY) + 'px';
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

function _handleRemotePatch(msg) {
  switch (msg.op) {
    case 'node_move': {
      const nd = wbData.nodes.find(n => n.id === msg.nodeId);
      if (!nd) return;
      nd.x = msg.x; nd.y = msg.y;
      const el = _nl.querySelector(`[data-node-id="${msg.nodeId}"]`);
      if (el) { el.style.left = nd.x + 'px'; el.style.top = nd.y + 'px'; }
      _updateAllEdges();
      break;
    }
    case 'node_toggle': {
      const nd = wbData.nodes.find(n => n.id === msg.nodeId);
      if (!nd) return;
      nd.collapsed = msg.collapsed;
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
      nd.w = msg.w; nd.h = msg.h;
      const el = _nl.querySelector(`[data-node-id="${msg.nodeId}"]`);
      if (el) { el.style.width = msg.w + 'px'; el.style.height = msg.h + 'px'; }
      _updateAllEdges();
      break;
    }
    case 'node_remove':
      wbData.nodes = wbData.nodes.filter(n => n.id !== msg.nodeId);
      _nl.querySelector(`[data-node-id="${msg.nodeId}"]`)?.remove();
      wbData.edges = wbData.edges.filter(e => {
        if (e.fromId === msg.nodeId || e.toId === msg.nodeId) {
          _edgeSvg.querySelector(`[data-edge-id="${e.id}"]`)?.remove();
          return false;
        }
        return true;
      });
      break;
    case 'nodes_sync':
      (msg.nodes || []).forEach(nd => {
        if (wbData.nodes.find(n => n.id === nd.id)) return;
        wbData.nodes.push(nd);
        const t = state.targets.find(t => t.id === nd.id);
        if (t) _nl.appendChild(_buildNode(nd, t));
      });
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
      }
      break;
    case 'note_update': {
      const nd = wbData.notes.find(n => n.id === msg.noteId);
      if (!nd) return;
      Object.assign(nd, msg.changes);
      const el = _nl.querySelector(`[data-note-id="${msg.noteId}"]`);
      if (!el) return;
      if (msg.changes.color !== undefined) el.style.background = msg.changes.color;
      if (msg.changes.x !== undefined) el.style.left = msg.changes.x + 'px';
      if (msg.changes.y !== undefined) el.style.top  = msg.changes.y + 'px';
      if (msg.changes.text !== undefined) {
        const textEl = el.querySelector('[data-text]');
        if (textEl && textEl.contentEditable !== 'true') textEl.textContent = msg.changes.text;
      }
      break;
    }
    case 'note_remove':
      wbData.notes = wbData.notes.filter(n => n.id !== msg.noteId);
      _nl.querySelector(`[data-note-id="${msg.noteId}"]`)?.remove();
      break;
    case 'edge_add':
      if (!wbData.edges.find(e => e.id === msg.edge.id)) {
        wbData.edges.push(msg.edge);
        _renderEdge(msg.edge);
      }
      break;
    case 'edge_remove':
      wbData.edges = wbData.edges.filter(e => e.id !== msg.edgeId);
      _edgeSvg.querySelector(`[data-edge-id="${msg.edgeId}"]`)?.remove();
      if (_selectedEdgeId === msg.edgeId) _selectedEdgeId = null;
      break;
    case 'edge_update': {
      const ed = wbData.edges.find(e => e.id === msg.edgeId);
      if (!ed) return;
      Object.assign(ed, msg.changes);
      if (msg.changes.label !== undefined) {
        const textEl = _edgeSvg.querySelector(`[data-edge-id="${msg.edgeId}"] .wb-edge-label`);
        if (textEl) textEl.textContent = msg.changes.label;
      }
      break;
    }
    case 'card_add':
      if (!wbData.cards.find(c => c.id === msg.card.id)) {
        wbData.cards.push(msg.card);
        _nl.appendChild(_buildCard(msg.card));
      }
      break;
    case 'card_remove':
      wbData.cards = wbData.cards.filter(c => c.id !== msg.cardId);
      _nl.querySelector(`[data-node-id="${msg.cardId}"]`)?.remove();
      wbData.edges = wbData.edges.filter(e => {
        if (e.fromId === msg.cardId || e.toId === msg.cardId) {
          _edgeSvg.querySelector(`[data-edge-id="${e.id}"]`)?.remove();
          return false;
        }
        return true;
      });
      break;
    case 'card_update': {
      const cd = wbData.cards.find(c => c.id === msg.cardId);
      if (!cd) return;
      Object.assign(cd, msg.changes);
      const el = _nl.querySelector(`[data-node-id="${msg.cardId}"]`);
      if (!el) return;
      if (msg.changes.x !== undefined) el.style.left   = msg.changes.x + 'px';
      if (msg.changes.y !== undefined) el.style.top    = msg.changes.y + 'px';
      if (msg.changes.w !== undefined) el.style.width  = msg.changes.w + 'px';
      if (msg.changes.h !== undefined) el.style.height = msg.changes.h + 'px';
      if (msg.changes.color !== undefined) {
        const head = el.querySelector('.wb-card-head');
        if (head) head.style.background = msg.changes.color;
      }
      if (msg.changes.title !== undefined) {
        const t = el.querySelector('[data-title]');
        if (t && t.contentEditable !== 'true') t.textContent = msg.changes.title;
      }
      if (msg.changes.body !== undefined) {
        const b = el.querySelector('[data-text]');
        if (b && b.contentEditable !== 'true') b.innerHTML = renderMd(msg.changes.body);
      }
      if (msg.changes.x !== undefined || msg.changes.y !== undefined || msg.changes.w !== undefined) _updateAllEdges();
      break;
    }
  }
}

function _broadcast(patch) {
  wsClient.send({ type: 'wb:patch', ...patch });
}

// ── Mode ───────────────────────────────────────────────────────────────
function setWbMode(m) {
  if (_connectFrom && m !== 'connect') {
    _nl.querySelector(`[data-node-id="${_connectFrom}"]`)?.classList.remove('connect-from');
    _connectFrom = null;
  }
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
    if (btn) { btn.disabled = false; btn.textContent = ''; btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>'; }
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
window.wbSearch         = wbSearch;
window.wbSearchClear    = wbSearchClear;
window.redoStroke       = redoStroke;
window.exportPng        = exportPng;
