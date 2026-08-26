// ── views/targets.js ─────────────────────────────────────────────────

const TARGET_TYPES  = ['domain','ip','cidr','url','other'];
const TARGET_STATUS_COLORS = { active:'var(--a)', completed:'var(--c-low)', 'out-of-scope':'var(--t3)' };

// Cache de ports/endpoints por target (lazy-loaded)
const _targetCache = {}; // { [targetId]: { ports:[], endpoints:[], loaded:false } }

function renderTargets() {
  const container = document.getElementById('targets-content');
  if (!container) return;

  if (!state.targets.length) {
    container.innerHTML = `<div class="empty-state">
      <div class="empty-icon">${icon('inbox', { size: 28 })}</div>
      <div class="empty-title">No targets defined</div>
      <div class="empty-sub">Add IPs, domains, URLs and CIDRs in scope for this engagement</div>
      <button class="btn btn-prim" style="margin-top:14px" onclick="openAddTargetModal()">+ Add Target</button>
    </div>`;
    return;
  }

  const inScope  = state.targets.filter(t => t.scope === 'in');
  const outScope = state.targets.filter(t => t.scope === 'out');

  container.innerHTML = '';
  if (inScope.length)  container.appendChild(buildTargetGroup('In Scope', inScope, 'var(--c-low)'));
  if (outScope.length) container.appendChild(buildTargetGroup('Out of Scope', outScope, 'var(--t3)'));
}

function buildTargetGroup(label, targets, color) {
  const section = document.createElement('div');
  section.style.marginBottom = '24px';
  section.innerHTML = `<div class="vuln-severity-header">
    <span style="font-family:var(--mono);font-size:11px;font-weight:700;color:${color}">${label}</span>
    <span class="vuln-severity-count">${targets.length} target${targets.length>1?'s':''}</span>
  </div>`;
  targets.forEach(t => section.appendChild(buildTargetCard(t)));
  return section;
}

function buildTargetCard(t) {
  const card = document.createElement('div');
  card.className = 'vuln-card';
  card.id = `target-${t.id}`;

  const statusColor = TARGET_STATUS_COLORS[t.status] || 'var(--t3)';
  const statusLabel = t.status === 'out-of-scope' ? 'Out of Scope' : t.status.charAt(0).toUpperCase() + t.status.slice(1);
  const linkedVulns = state.customVulns.filter(v => v.target_id === t.id);

  card.innerHTML = `
    <div class="vuln-header" onclick="toggleTargetBody('${t.id}',event)">
      <span class="vuln-tag" style="text-transform:uppercase">${t.type}</span>
      <span class="vuln-name" style="font-family:var(--mono);font-size:12px">${esc(t.host)}</span>
      <span style="font-family:var(--mono);font-size:10px;color:${statusColor};margin-left:auto;flex-shrink:0">${statusLabel}</span>
      ${linkedVulns.length ? `<span style="font-family:var(--mono);font-size:10px;color:var(--c-crit);margin-left:8px">${linkedVulns.length} finding${linkedVulns.length>1?'s':''}</span>` : ''}
      <div class="vuln-actions">
        <button class="btn-icon" title="Escanear con AI Agent" onclick="event.stopPropagation();window.location.href='ai-agent?pid=${state.currentProject.id}&target=${t.id}'">${icon('sparkles',{size:12})}</button>
        <button class="btn-icon edit"   onclick="openEditTarget('${t.id}',event)">${icon('square-pen',{size:12})}</button>
        <button class="btn-icon delete" onclick="deleteTarget('${t.id}',event)">${icon('x',{size:12})}</button>
      </div>
    </div>
    <div class="vuln-body" id="tbody-${t.id}">
      <div class="target-tabs" id="ttabs-${t.id}">
        ${linkedVulns.length ? `<button class="target-tab active" onclick="switchTargetTab('${t.id}','findings',event)">Findings <span class="target-tab-badge">${linkedVulns.length}</span></button>` : ''}
        <button class="target-tab ${!linkedVulns.length?'active':''}" onclick="switchTargetTab('${t.id}','ports',event)">Ports</button>
        <button class="target-tab" onclick="switchTargetTab('${t.id}','endpoints',event)">Endpoints</button>
        ${t.notes ? `<button class="target-tab" onclick="switchTargetTab('${t.id}','notes',event)">Notes</button>` : ''}
      </div>
      <div class="target-tab-body" id="ttab-findings-${t.id}" style="${linkedVulns.length?'':'display:none'}">
        ${buildFindingsTab(linkedVulns)}
      </div>
      <div class="target-tab-body" id="ttab-ports-${t.id}" style="${linkedVulns.length?'display:none':''}">
        <div class="target-loading">// loading ports...</div>
      </div>
      <div class="target-tab-body" id="ttab-endpoints-${t.id}" style="display:none">
        <div class="target-loading">// loading endpoints...</div>
      </div>
      ${t.notes ? `<div class="target-tab-body" id="ttab-notes-${t.id}" style="display:none">
        <div class="payload-code" style="color:var(--t2);white-space:pre-wrap;margin:8px 0">${esc(t.notes)}</div>
      </div>` : ''}
    </div>`;
  return card;
}

function buildFindingsTab(vulns) {
  if (!vulns.length) return `<div class="target-empty-tab">No findings linked to this target</div>`;
  return vulns.map(v => `
    <div class="item-row" style="gap:8px;padding:5px 0">
      <span class="sev-badge sev-${v.severity||'medium'}" style="font-size:9px">${v.severity||'medium'}</span>
      <span class="item-text">${esc(v.name)}</span>
    </div>`).join('');
}

// ── TAB SWITCHING ─────────────────────────────────────────────────────
function switchTargetTab(targetId, tab, e) {
  e?.stopPropagation();
  const tabsEl = document.getElementById(`ttabs-${targetId}`);
  if (!tabsEl) return;
  tabsEl.querySelectorAll('.target-tab').forEach(b => b.classList.remove('active'));
  e?.currentTarget?.classList.add('active');

  // find clicked button by tab name
  tabsEl.querySelectorAll('.target-tab').forEach(b => {
    if (b.getAttribute('onclick')?.includes(`'${tab}'`)) b.classList.add('active');
  });

  ['findings','ports','endpoints','notes'].forEach(name => {
    const el = document.getElementById(`ttab-${name}-${targetId}`);
    if (el) el.style.display = name === tab ? '' : 'none';
  });
}

// ── TOGGLE + LAZY LOAD ────────────────────────────────────────────────
async function toggleTargetBody(id, e) {
  if (e.target.closest('.vuln-actions')) return;
  const body = document.getElementById(`tbody-${id}`);
  if (!body) return;
  const opening = !body.classList.contains('open');
  body.classList.toggle('open');
  if (opening && !_targetCache[id]?.loaded) {
    await loadTargetDetail(id);
  }
}

async function loadTargetDetail(targetId) {
  const pid = state.currentProject?.id;
  if (!pid) return;
  const [ports, endpoints] = await Promise.all([
    api.targets.listPorts(pid, targetId).catch(() => []),
    api.targets.listEndpoints(pid, targetId).catch(() => []),
  ]);
  // Guard: target may have been deleted while loading
  if (!state.targets.find(t => t.id === targetId)) return;
  _targetCache[targetId] = { ports, endpoints, loaded: true };
  renderPortsTab(targetId);
  renderEndpointsTab(targetId);
}

// ── PORTS TAB ─────────────────────────────────────────────────────────
const PORT_STATE_COLORS = { open: 'var(--c-low)', filtered: 'var(--a)', closed: 'var(--t3)' };

function renderPortsTab(targetId) {
  const el = document.getElementById(`ttab-ports-${targetId}`);
  if (!el) return;
  const ports = _targetCache[targetId]?.ports || [];

  const rows = ports.map(p => portRowHtml(targetId, p)).join('');

  el.innerHTML = `
    ${rows || `<div class="target-empty-tab">No ports added yet</div>`}
    <div class="target-add-row" id="port-add-${targetId}">
      <input type="number" class="target-inline-input" style="width:70px" placeholder="Port" id="pa-port-${targetId}" min="1" max="65535"
        onkeydown="if(event.key==='Enter')addPort('${targetId}')">
      <select class="target-inline-select" id="pa-proto-${targetId}">
        <option value="tcp">tcp</option><option value="udp">udp</option>
      </select>
      <select class="target-inline-select" id="pa-state-${targetId}">
        <option value="open">open</option><option value="filtered">filtered</option><option value="closed">closed</option>
      </select>
      <input type="text" class="target-inline-input" style="flex:1" placeholder="Service (e.g. nginx)" id="pa-svc-${targetId}">
      <input type="text" class="target-inline-input" style="flex:1" placeholder="Version" id="pa-ver-${targetId}">
      <button class="btn-accent" style="padding:4px 10px;font-size:11px;flex-shrink:0" onclick="addPort('${targetId}')">+ Add</button>
    </div>`;
  if (window.initCsel) {
    initCsel(`pa-proto-${targetId}`, [{value:'tcp',label:'tcp'},{value:'udp',label:'udp'}]);
    initCsel(`pa-state-${targetId}`, [{value:'open',label:'open'},{value:'filtered',label:'filtered'},{value:'closed',label:'closed'}]);
  }
}

function portRowHtml(targetId, p) {
  return `
    <div class="target-data-row" id="port-row-${p.id}">
      <span class="port-num">${p.port}/${p.protocol}</span>
      <span style="font-family:var(--mono);font-size:10px;color:${PORT_STATE_COLORS[p.state]||'var(--t3)'}">${p.state}</span>
      <span style="font-family:var(--mono);font-size:11px;color:var(--t2);flex:1">${esc(p.service||'')}${p.version?` <span style="color:var(--t3)">${esc(p.version)}</span>`:''}</span>
      <button class="btn-icon edit"   onclick="editPort('${targetId}','${p.id}',event)">${icon('square-pen',{size:12})}</button>
      <button class="btn-icon delete" onclick="deletePort('${targetId}','${p.id}',event)">${icon('x',{size:12})}</button>
    </div>`;
}

function editPort(targetId, portId, e) {
  e.stopPropagation();
  const p   = _targetCache[targetId]?.ports.find(x => x.id === portId);
  const row = document.getElementById(`port-row-${portId}`);
  if (!p || !row) return;
  row.innerHTML = `
    <input type="number" class="target-inline-input" style="width:70px" value="${p.port}" id="pe-port-${portId}" min="1" max="65535">
    <select class="target-inline-select" id="pe-proto-${portId}">
      <option value="tcp" ${p.protocol==='tcp'?'selected':''}>tcp</option>
      <option value="udp" ${p.protocol==='udp'?'selected':''}>udp</option>
    </select>
    <select class="target-inline-select" id="pe-state-${portId}">
      <option value="open"     ${p.state==='open'?'selected':''}>open</option>
      <option value="filtered" ${p.state==='filtered'?'selected':''}>filtered</option>
      <option value="closed"   ${p.state==='closed'?'selected':''}>closed</option>
    </select>
    <input type="text" class="target-inline-input" style="flex:1" placeholder="Service" id="pe-svc-${portId}" value="${esc(p.service||'')}">
    <input type="text" class="target-inline-input" style="flex:1" placeholder="Version"  id="pe-ver-${portId}" value="${esc(p.version||'')}">
    <button class="btn-accent" style="padding:4px 10px;font-size:11px" onclick="savePort('${targetId}','${portId}',event)">Save</button>
    <button class="btn-icon"   onclick="cancelPortEdit('${targetId}','${portId}',event)">${icon('x',{size:12})}</button>`;
  if (window.initCsel) {
    initCsel(`pe-proto-${portId}`, [{value:'tcp',label:'tcp'},{value:'udp',label:'udp'}]);
    initCsel(`pe-state-${portId}`, [{value:'open',label:'open'},{value:'filtered',label:'filtered'},{value:'closed',label:'closed'}]);
  }
}

async function savePort(targetId, portId, e) {
  e.stopPropagation();
  const port     = parseInt(document.getElementById(`pe-port-${portId}`)?.value);
  const protocol = document.getElementById(`pe-proto-${portId}`)?.value;
  const state_   = document.getElementById(`pe-state-${portId}`)?.value;
  const service  = document.getElementById(`pe-svc-${portId}`)?.value.trim();
  const version  = document.getElementById(`pe-ver-${portId}`)?.value.trim();
  if (!port || port < 1 || port > 65535) { showToast('Invalid port', 'error'); return; }
  try {
    const updated = await api.targets.updatePort(state.currentProject.id, targetId, portId, { port, protocol, state: state_, service, version });
    const cache = _targetCache[targetId];
    if (cache) cache.ports = cache.ports.map(p => p.id === portId ? updated : p);
    const row = document.getElementById(`port-row-${portId}`);
    if (row) row.outerHTML = portRowHtml(targetId, updated);
    showToast('Port updated', 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

function cancelPortEdit(targetId, portId, e) {
  e.stopPropagation();
  const p   = _targetCache[targetId]?.ports.find(x => x.id === portId);
  const row = document.getElementById(`port-row-${portId}`);
  if (p && row) row.outerHTML = portRowHtml(targetId, p);
}

async function addPort(targetId) {
  const port     = parseInt(document.getElementById(`pa-port-${targetId}`)?.value);
  const protocol = document.getElementById(`pa-proto-${targetId}`)?.value;
  const state_   = document.getElementById(`pa-state-${targetId}`)?.value;
  const service  = document.getElementById(`pa-svc-${targetId}`)?.value.trim();
  const version  = document.getElementById(`pa-ver-${targetId}`)?.value.trim();
  if (!port || port < 1 || port > 65535) { showToast('Invalid port', 'error'); return; }
  try {
    const p = await api.targets.addPort(state.currentProject.id, targetId, { port, protocol, state: state_, service, version });
    if (!_targetCache[targetId]) _targetCache[targetId] = { ports: [], endpoints: [], loaded: true };
    _targetCache[targetId].ports.push(p);
    renderPortsTab(targetId);
    showToast(`${port}/${protocol} added`, 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

async function deletePort(targetId, portId, e) {
  e.stopPropagation();
  try {
    await api.targets.deletePort(state.currentProject.id, targetId, portId);
    _targetCache[targetId].ports = _targetCache[targetId].ports.filter(p => p.id !== portId);
    renderPortsTab(targetId);
    showToast('Port removed', 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

// ── ENDPOINTS TAB ─────────────────────────────────────────────────────
const METHOD_COLORS = {
  GET:'var(--c-low)', POST:'var(--a)', PUT:'var(--a)',
  PATCH:'#3b82f6', DELETE:'var(--c-crit)', HEAD:'var(--t3)',
  OPTIONS:'var(--t3)', OTHER:'var(--t3)'
};
const METHODS = ['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','OTHER'];

function renderEndpointsTab(targetId) {
  const el = document.getElementById(`ttab-endpoints-${targetId}`);
  if (!el) return;
  const endpoints = _targetCache[targetId]?.endpoints || [];

  const rows = endpoints.map(ep => endpointRowHtml(targetId, ep)).join('');

  el.innerHTML = `
    ${rows || `<div class="target-empty-tab">No endpoints added yet</div>`}
    <div class="target-add-row" id="ep-add-${targetId}">
      <select class="target-inline-select" id="ea-method-${targetId}">
        ${METHODS.map(m=>`<option>${m}</option>`).join('')}
      </select>
      <input type="text" class="target-inline-input" style="flex:1" placeholder="/path or /api/endpoint" id="ea-path-${targetId}"
        onkeydown="if(event.key==='Enter')addEndpoint('${targetId}')">
      <input type="number" class="target-inline-input" style="width:70px" placeholder="200" id="ea-code-${targetId}" min="100" max="599">
      <label style="display:flex;align-items:center;gap:4px;font-family:var(--mono);font-size:10px;color:var(--t3);flex-shrink:0;cursor:pointer">
        <input type="checkbox" id="ea-interesting-${targetId}"> ${icon('star',{size:11})}
      </label>
      <button class="btn-accent" style="padding:4px 10px;font-size:11px;flex-shrink:0" onclick="addEndpoint('${targetId}')">+ Add</button>
    </div>`;
  if (window.initCsel) {
    initCsel(`ea-method-${targetId}`, METHODS.map(m => ({value:m, label:m})));
  }
}

function endpointRowHtml(targetId, ep) {
  return `
    <div class="target-data-row" id="ep-row-${ep.id}">
      <span style="font-family:var(--mono);font-size:10px;font-weight:700;color:${METHOD_COLORS[ep.method]||'var(--t3)'};width:56px;flex-shrink:0">${ep.method}</span>
      <span style="font-family:var(--mono);font-size:11px;color:var(--t2);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(ep.path)}</span>
      ${ep.status_code ? `<span style="font-family:var(--mono);font-size:10px;color:var(--t3)">${ep.status_code}</span>` : ''}
      ${ep.interesting ? `<span style="color:var(--a);border:1px solid var(--a)44;border-radius:3px;padding:1px 5px;display:inline-flex" title="Interesting">${icon('star',{size:10})}</span>` : ''}
      <button class="btn-icon edit"   onclick="editEndpoint('${targetId}','${ep.id}',event)">${icon('square-pen',{size:12})}</button>
      <button class="btn-icon delete" onclick="deleteEndpoint('${targetId}','${ep.id}',event)">${icon('x',{size:12})}</button>
    </div>`;
}

function editEndpoint(targetId, epId, e) {
  e.stopPropagation();
  const ep  = _targetCache[targetId]?.endpoints.find(x => x.id === epId);
  const row = document.getElementById(`ep-row-${epId}`);
  if (!ep || !row) return;
  row.innerHTML = `
    <select class="target-inline-select" id="ee-method-${epId}">
      ${METHODS.map(m=>`<option ${ep.method===m?'selected':''}>${m}</option>`).join('')}
    </select>
    <input type="text" class="target-inline-input" style="flex:1" placeholder="/path" id="ee-path-${epId}" value="${esc(ep.path)}">
    <input type="number" class="target-inline-input" style="width:70px" placeholder="200" id="ee-code-${epId}" value="${ep.status_code||''}" min="100" max="599">
    <label style="display:flex;align-items:center;gap:4px;font-family:var(--mono);font-size:10px;color:var(--t3);flex-shrink:0;cursor:pointer">
      <input type="checkbox" id="ee-interesting-${epId}" ${ep.interesting?'checked':''}> ${icon('star',{size:11})}
    </label>
    <button class="btn-accent" style="padding:4px 10px;font-size:11px" onclick="saveEndpoint('${targetId}','${epId}',event)">Save</button>
    <button class="btn-icon"   onclick="cancelEndpointEdit('${targetId}','${epId}',event)">${icon('x',{size:12})}</button>`;
  if (window.initCsel) {
    initCsel(`ee-method-${epId}`, METHODS.map(m => ({value:m, label:m})));
  }
}

async function saveEndpoint(targetId, epId, e) {
  e.stopPropagation();
  const method      = document.getElementById(`ee-method-${epId}`)?.value;
  const path        = document.getElementById(`ee-path-${epId}`)?.value.trim();
  const status_code = parseInt(document.getElementById(`ee-code-${epId}`)?.value) || null;
  const interesting = document.getElementById(`ee-interesting-${epId}`)?.checked || false;
  if (!path) { showToast('Path is required', 'error'); return; }
  try {
    const updated = await api.targets.updateEndpoint(state.currentProject.id, targetId, epId, { method, path, status_code, interesting });
    const cache = _targetCache[targetId];
    if (cache) cache.endpoints = cache.endpoints.map(ep => ep.id === epId ? updated : ep);
    const row = document.getElementById(`ep-row-${epId}`);
    if (row) row.outerHTML = endpointRowHtml(targetId, updated);
    showToast('Endpoint updated', 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

function cancelEndpointEdit(targetId, epId, e) {
  e.stopPropagation();
  const ep  = _targetCache[targetId]?.endpoints.find(x => x.id === epId);
  const row = document.getElementById(`ep-row-${epId}`);
  if (ep && row) row.outerHTML = endpointRowHtml(targetId, ep);
}

async function addEndpoint(targetId) {
  const method      = document.getElementById(`ea-method-${targetId}`)?.value;
  const path        = document.getElementById(`ea-path-${targetId}`)?.value.trim();
  const status_code = parseInt(document.getElementById(`ea-code-${targetId}`)?.value) || null;
  const interesting = document.getElementById(`ea-interesting-${targetId}`)?.checked || false;
  if (!path) { showToast('Path is required', 'error'); return; }
  try {
    const ep = await api.targets.addEndpoint(state.currentProject.id, targetId, { method, path, status_code, interesting });
    if (!_targetCache[targetId]) _targetCache[targetId] = { ports: [], endpoints: [], loaded: true };
    _targetCache[targetId].endpoints.push(ep);
    renderEndpointsTab(targetId);
    showToast(`${method} ${path} added`, 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

async function deleteEndpoint(targetId, endpointId, e) {
  e.stopPropagation();
  try {
    await api.targets.deleteEndpoint(state.currentProject.id, targetId, endpointId);
    _targetCache[targetId].endpoints = _targetCache[targetId].endpoints.filter(ep => ep.id !== endpointId);
    renderEndpointsTab(targetId);
    showToast('Endpoint removed', 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

// ── MODAL ─────────────────────────────────────────────────────────────
let _editingTargetId = null;

function openAddTargetModal() {
  _editingTargetId = null;
  document.getElementById('target-modal-title').textContent = 'Add Target';
  document.getElementById('modal-target-host').value   = '';
  document.getElementById('modal-target-type').value   = 'domain';
  document.getElementById('modal-target-scope').value  = 'in';
  document.getElementById('modal-target-status').value = 'active';
  document.getElementById('modal-target-notes').value  = '';
  document.getElementById('target-error').style.display = 'none';
  if (window.cselSync) window.cselSync();
  document.getElementById('target-modal').classList.add('open');
  document.getElementById('modal-target-host').focus();
}

function openEditTarget(id, e) {
  e.stopPropagation();
  const t = state.targets.find(x => x.id === id);
  if (!t) return;
  _editingTargetId = id;
  document.getElementById('target-modal-title').textContent = 'Edit Target';
  document.getElementById('modal-target-host').value   = t.host;
  document.getElementById('modal-target-type').value   = t.type;
  document.getElementById('modal-target-scope').value  = t.scope;
  document.getElementById('modal-target-status').value = t.status;
  document.getElementById('modal-target-notes').value  = t.notes || '';
  document.getElementById('target-error').style.display = 'none';
  if (window.cselSync) window.cselSync();
  document.getElementById('target-modal').classList.add('open');
}

function closeTargetModal() {
  document.getElementById('target-modal').classList.remove('open');
  _editingTargetId = null;
}

async function saveTarget() {
  const host   = document.getElementById('modal-target-host').value.trim();
  const type   = document.getElementById('modal-target-type').value;
  const scope  = document.getElementById('modal-target-scope').value;
  const status = document.getElementById('modal-target-status').value;
  const notes  = document.getElementById('modal-target-notes').value;
  const errEl  = document.getElementById('target-error');
  const btn    = document.getElementById('target-save-btn');
  if (!host) { errEl.textContent = 'Host is required'; errEl.style.display = 'block'; return; }
  btn.disabled = true;
  try {
    if (_editingTargetId) {
      const updated = await api.targets.update(state.currentProject.id, _editingTargetId, { host, type, scope, status, notes });
      const idx = state.targets.findIndex(t => t.id === _editingTargetId);
      if (idx > -1) state.targets[idx] = updated;
      // Invalidate cache so ports/endpoints reload on next open
      if (_targetCache[_editingTargetId]) _targetCache[_editingTargetId].loaded = false;
    } else {
      const created = await api.targets.create(state.currentProject.id, { host, type, scope, status, notes });
      state.targets.push(created);
    }
    closeTargetModal();
    renderTargets();
    showToast('Saved', 'success');
  } catch(e) { errEl.textContent = e.message; errEl.style.display = 'block'; }
  finally { btn.disabled = false; }
}

async function deleteTarget(id, e) {
  e.stopPropagation();
  if (!confirm('Delete this target?')) return;
  try {
    await api.targets.delete(state.currentProject.id, id);
    state.targets = state.targets.filter(t => t.id !== id);
    delete _targetCache[id];
    renderTargets();
    showToast('Deleted', 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

function scrollToTarget(id) {
  document.getElementById(`target-${id}`)?.scrollIntoView({ behavior:'smooth', block:'start' });
}

window.renderTargets        = renderTargets;
window.buildTargetCard      = buildTargetCard;
window.toggleTargetBody     = toggleTargetBody;
window.switchTargetTab      = switchTargetTab;
window.openAddTargetModal   = openAddTargetModal;
window.openEditTarget       = openEditTarget;
window.closeTargetModal     = closeTargetModal;
window.saveTarget           = saveTarget;
window.deleteTarget         = deleteTarget;
window.scrollToTarget       = scrollToTarget;
window.addPort              = addPort;
window.editPort             = editPort;
window.savePort             = savePort;
window.cancelPortEdit       = cancelPortEdit;
window.deletePort           = deletePort;
window.addEndpoint          = addEndpoint;
window.editEndpoint         = editEndpoint;
window.saveEndpoint         = saveEndpoint;
window.cancelEndpointEdit   = cancelEndpointEdit;
window.deleteEndpoint       = deleteEndpoint;
