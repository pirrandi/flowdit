// ── views/targets.js ─────────────────────────────────────────────────
// Lista compacta de targets (agrupada por scope) + drawer lateral con el
// detalle (hallazgos / puertos / endpoints / notas en pestañas) y el modo de
// alta/edición en el mismo drawer. Mismo lenguaje visual que My Vulns
// (.vr-* filas, .vd-* drawer) más lo propio en .tr-* / .td-*.

const TARGET_TYPES  = ['domain','ip','cidr','url','other'];
const TARGET_STATUS_COLORS = { active:'var(--a)', completed:'var(--c-low)', 'out-of-scope':'var(--t3)' };
const TARGET_STATUS_LABELS = { active:'Active', completed:'Completed', 'out-of-scope':'Out of Scope' };
const TR_SEV_ORDER  = ['critical','high','medium','low','info'];
const TR_SEV_LABELS = { critical:'Critical', high:'High', medium:'Medium', low:'Low', info:'Info' };
const TD_PAGE = 200; // filas de puertos / endpoints que se pintan de una vez

// Cache de ports/endpoints por target (lazy-loaded)
const _targetCache = {}; // { [targetId]: { ports:[], endpoints:[], loaded:false } }
const _tdLoading   = new Set(); // targets con la carga de detalle en curso

function _trStatusLabel(s) {
  return TARGET_STATUS_LABELS[s] || (s ? s.charAt(0).toUpperCase() + s.slice(1) : '—');
}

function _trSev(v) {
  return TR_SEV_ORDER.includes(v?.severity) ? v.severity : 'medium';
}

function _trSevBadge(sev) {
  return `<span class="sev-badge sev-${sev}">${TR_SEV_LABELS[sev]}</span>`;
}

function _trFindings(targetId) {
  return state.customVulns
    .filter(v => v.target_id === targetId)
    .sort((a, b) => TR_SEV_ORDER.indexOf(_trSev(a)) - TR_SEV_ORDER.indexOf(_trSev(b)));
}

function _trPlural(n, one, many) { return `${n} ${n === 1 ? one : many}`; }

// Grupos tal como se ven: es también el orden del ‹ anterior / siguiente ›.
function _trGroups() {
  return [
    { label: 'In Scope',     color: 'var(--c-low)', items: state.targets.filter(t => t.scope === 'in') },
    { label: 'Out of Scope', color: 'var(--t3)',    items: state.targets.filter(t => t.scope === 'out') },
  ];
}

function renderTargets() {
  const container = document.getElementById('targets-content');
  if (!container) return;
  if (typeof renderScopeSummary === 'function') renderScopeSummary();

  if (!state.targets.length) {
    container.innerHTML = `<div class="empty-state">
      <div class="empty-icon">${icon('inbox', { size: 28 })}</div>
      <div class="empty-title">No targets defined</div>
      <div class="empty-sub">Add IPs, domains, URLs and CIDRs in scope for this engagement</div>
      <button class="btn btn-prim vr-empty-btn" onclick="openAddTargetModal()">+ Add Target</button>
    </div>`;
    _tdRefresh();
    return;
  }

  container.innerHTML = '';
  _trGroups().forEach(g => {
    if (g.items.length) container.appendChild(buildTargetGroup(g.label, g.items, g.color));
  });
  // El drawer abierto se redibuja con los datos frescos (o se cierra si el
  // target ya no existe). Todo cambio pasa por acá.
  _tdRefresh();
}

function buildTargetGroup(label, targets, color) {
  const section = document.createElement('div');
  section.className = 'vuln-severity-section';
  section.innerHTML = `<div class="vuln-severity-header">
    <span class="tr-group-label" style="color:${color}">${esc(label)}</span>
    <span class="vuln-severity-count">${targets.length} target${targets.length > 1 ? 's' : ''}</span>
  </div>`;
  targets.forEach(t => section.appendChild(buildTargetRow(t)));
  return section;
}

// Conteo de puertos / endpoints de la fila: aparece cuando el detalle ya
// está en cache (se precarga en segundo plano al entrar a la página).
function _trCountsHtml(targetId) {
  const c = _targetCache[targetId];
  if (!c) return '';
  const open = c.ports.filter(p => p.state === 'open').length;
  return `<span class="ccp-count" title="Puertos${c.ports.length ? ` (${open} abiertos)` : ''}">${_trPlural(c.ports.length, 'puerto', 'puertos')}</span>
    <span class="ccp-count" title="Endpoints">${_trPlural(c.endpoints.length, 'endpoint', 'endpoints')}</span>`;
}

function _trUpdateCounts(targetId) {
  const el = document.getElementById(`tr-counts-${targetId}`);
  if (el) el.innerHTML = _trCountsHtml(targetId);
}

// Fila compacta (mismo patrón que My Vulns): clic / Enter / Espacio abre el
// drawer de detalle. Las acciones rápidas no lo abren.
function buildTargetRow(t) {
  const id  = esc(t.id);
  const row = document.createElement('div');
  row.className = `vuln-card ccp-row vr-row tr-row${t.id === _tdOpenId && _tdMode ? ' is-active' : ''}`;
  row.id = `target-${t.id}`;
  row.tabIndex = 0;
  row.setAttribute('role', 'button');
  row.addEventListener('click', () => openTargetDetail(t.id));
  row.addEventListener('keydown', e => {
    if ((e.key === 'Enter' || e.key === ' ') && e.target === row) { e.preventDefault(); openTargetDetail(t.id); }
  });

  const findings = _trFindings(t.id);
  const statusColor = TARGET_STATUS_COLORS[t.status] || 'var(--t3)';
  const meta = [
    `<span class="tr-status" style="color:${statusColor}">${esc(_trStatusLabel(t.status))}</span>`,
    `<span class="tr-counts" id="tr-counts-${id}">${_trCountsHtml(t.id)}</span>`,
    findings.length ? `<span class="tr-findings" title="Peor severidad">${_trSevBadge(_trSev(findings[0]))}${_trPlural(findings.length, 'hallazgo', 'hallazgos')}</span>` : '',
    t.notes ? `<span class="vr-flag" title="Tiene notas">${icon('sticky-note',{size:10})}Notas</span>` : '',
    t.source === 'claude_code' ? `<span class="cc-src" title="Propuesto por Claude Code">Claude Code</span>` : '',
  ].filter(Boolean).join('');

  row.innerHTML = `
    <div class="ccp-row-main">
      <span class="vr-tag tr-type">${esc(t.type)}</span>
      <div class="ccp-row-text">
        <div class="ccp-row-title tr-host">${esc(t.host)}</div>
        <div class="ccp-row-meta">${meta}</div>
      </div>
    </div>
    <div class="ccp-row-actions vr-actions" onclick="event.stopPropagation()" onkeydown="event.stopPropagation()">
      <button class="btn-icon" title="Escanear con AI Agent" onclick="scanTargetWithAI('${id}',event)">${icon('sparkles',{size:12})}</button>
      <button class="btn-icon edit" onclick="openEditTarget('${id}',event)" title="Editar">${icon('square-pen',{size:12})}</button>
      <button class="btn-icon delete" onclick="deleteTarget('${id}',event)" title="Eliminar">${icon('trash-2',{size:12})}</button>
    </div>`;
  return row;
}

function scanTargetWithAI(id, e) {
  e?.stopPropagation();
  window.location.href = `ai-agent?pid=${encodeURIComponent(state.currentProject.id)}&target=${encodeURIComponent(id)}`;
}

// ── CARGA DE PUERTOS / ENDPOINTS ──────────────────────────────────────
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
  _trUpdateCounts(targetId);
  if (_tdMode === 'view' && _tdOpenId === targetId) _tdRenderView(true);
}

// Refresco en vivo (lo llama page.js al llegar un evento de Activity de
// targets/puertos/endpoints de otro miembro o de Claude Code): la lista se
// redibuja con state.targets ya actualizado y, si el evento trae el target,
// se recargan sus puertos/endpoints. renderTargets() conserva el drawer
// (en vista lo redibuja con scroll/filtros/foco; en edición no lo toca).
async function refreshTargetsLive(targetId) {
  if (targetId && _targetCache[targetId]) {
    _tdLoading.add(targetId);
    try { await loadTargetDetail(targetId); } finally { _tdLoading.delete(targetId); }
  }
  renderTargets();
  prefetchTargetCounts(); // targets nuevos: sus conteos
}

async function _tdEnsureDetail(targetId) {
  if (_targetCache[targetId]?.loaded || _tdLoading.has(targetId)) return;
  _tdLoading.add(targetId);
  try { await loadTargetDetail(targetId); }
  finally { _tdLoading.delete(targetId); }
}

// Precarga liviana (3 en paralelo, tope 100) para mostrar los conteos en
// las filas sin tener que abrir cada target.
async function prefetchTargetCounts() {
  const ids = state.targets.map(t => t.id).filter(id => !_targetCache[id]).slice(0, 100);
  let i = 0;
  const worker = async () => { while (i < ids.length) await _tdEnsureDetail(ids[i++]); };
  await Promise.all([worker(), worker(), worker()]);
}

// ── DRAWER DE TARGET (detalle + edición) ──────────────────────────────
// Un único drawer lateral (markup en targets.html) con dos modos: 'view'
// arma el detalle acá; 'edit' muestra el formulario de alta/edición.
let _tdOpenId      = null;  // target abierto (null en un alta)
let _tdMode        = null;  // 'view' | 'edit' | null (cerrado)
let _tdSnapshot    = '';    // estado del formulario al abrir, para avisar cambios sin guardar
let _tdReturnFocus = null;
let _tdTab         = null;  // 'findings' | 'ports' | 'endpoints' | 'notes'
let _tdFilter      = { ports: '', endpoints: '' };
let _tdLimit       = { ports: TD_PAGE, endpoints: TD_PAGE };
let _tdOnlyStar    = false; // endpoints: solo los marcados como interesantes
let _tdEditRow     = null;  // fila en edición inline: { kind:'port'|'ep', id }
let _editingTargetId = null;

function _tdOrder() {
  return _trGroups().flatMap(g => g.items.map(t => t.id));
}

function _tdResetViewState() {
  _tdTab = null;
  _tdFilter = { ports: '', endpoints: '' };
  _tdLimit  = { ports: TD_PAGE, endpoints: TD_PAGE };
  _tdOnlyStar = false;
  _tdEditRow  = null;
}

function _tdCurrentTab(t, findings) {
  if (_tdTab === 'notes' && !t.notes) _tdTab = null;
  return _tdTab || (findings.length ? 'findings' : 'ports');
}

function _tdHead(t, findings, tab) {
  const id = esc(t.id);
  const c  = _targetCache[t.id];
  const statusColor = TARGET_STATUS_COLORS[t.status] || 'var(--t3)';
  const chips = [
    `<span class="ccp-chip td-chip-type">${esc(t.type)}</span>`,
    t.scope === 'in'
      ? `<span class="ccp-chip vd-tone" style="--vd-tone:var(--c-low)">In scope</span>`
      : `<span class="ccp-chip vd-chip-muted">Out of scope</span>`,
    `<span class="ccp-chip vd-tone" style="--vd-tone:${statusColor}">${esc(_trStatusLabel(t.status))}</span>`,
    findings.length ? `<span class="ccp-chip td-chip-sev" title="Peor severidad">${_trSevBadge(_trSev(findings[0]))}${_trPlural(findings.length, 'hallazgo', 'hallazgos')}</span>` : '',
    t.notes ? `<button type="button" class="ccp-chip td-chip-btn" onclick="switchTargetTab('${id}','notes')" title="Ver notas">${icon('sticky-note',{size:10})} Notas</button>` : '',
  ].join('');
  const by = t.added_by_username || t.added_by_display_name
    ? `<div class="ccp-drw-by">agregado por ${esc(displayName(t, 'added_by_'))}${t.created_at ? ` · ${esc(timeAgo(t.created_at))}` : ''}</div>`
    : '';
  const n = list => c ? list.length : '…';
  const tabBtn = (key, label, count) => `
    <button type="button" class="td-tab${tab === key ? ' is-active' : ''}" role="tab" aria-selected="${tab === key}"
      onclick="switchTargetTab('${id}','${key}')">${label}${count !== '' ? `<span class="td-tab-n${key === 'findings' && findings.length ? ' is-alert' : ''}">${count}</span>` : ''}</button>`;
  return `
    <button class="drw-close" onclick="closeTargetDetail()" title="Cerrar (Esc)">${icon('x', { size: 16 })}</button>
    <div class="drw-id"><span class="vd-kind">Target</span></div>
    <div class="drw-title td-title" id="td-title">${esc(t.host)}</div>
    <div class="drw-meta">${chips}</div>
    ${by}
    <div class="td-tabs" role="tablist">
      ${tabBtn('findings', 'Hallazgos', findings.length)}
      ${tabBtn('ports', 'Puertos', n(c?.ports || []))}
      ${tabBtn('endpoints', 'Endpoints', n(c?.endpoints || []))}
      ${t.notes ? tabBtn('notes', 'Notas', '') : ''}
    </div>`;
}

function _tdFindingsHtml(findings) {
  if (!findings.length) return `<div class="ccp-muted td-empty">Sin hallazgos vinculados a este target. Se vinculan desde el campo Target de cada hallazgo en My Vulns.</div>`;
  const pid = encodeURIComponent(state.currentProject.id);
  return `<div class="td-list">${findings.map(v => {
    const st = v.status === 'done' ? `<span class="vd-status is-done">confirmado</span>`
      : v.status === 'fail' ? `<span class="vd-status is-fail">vulnerable</span>` : '';
    const score = v.cvss_score != null && v.cvss_score !== '' && !isNaN(+v.cvss_score) ? (+v.cvss_score).toFixed(1) : null;
    return `
      <a class="td-finding" href="vulns?pid=${pid}&amp;vuln=${esc(encodeURIComponent(v.id))}" title="Abrir en My Vulns">
        ${_trSevBadge(_trSev(v))}
        <span class="td-finding-text">
          <span class="td-finding-name">${esc(v.name)}</span>
          <span class="td-finding-meta">${[
            esc(v.category || 'Custom'),
            score ? `CVSS ${score}` : '',
            v.cwe ? esc(v.cwe) : '',
            st,
          ].filter(Boolean).join('<span class="td-dot">·</span>')}</span>
        </span>
        <span class="td-finding-go">${icon('arrow-right',{size:12})}</span>
      </a>`;
  }).join('')}</div>`;
}

// ── Puertos ──
const PORT_STATE_COLORS = { open: 'var(--c-low)', filtered: 'var(--a)', closed: 'var(--t3)' };

function _tdPortMatches(p, q) {
  return `${p.port}/${p.protocol} ${p.state} ${p.service || ''} ${p.version || ''}`.toLowerCase().includes(q);
}

function portRowHtml(targetId, p) {
  const tid = esc(targetId), pid = esc(p.id);
  if (_tdEditRow?.kind === 'port' && _tdEditRow.id === p.id) return _tdPortEditHtml(tid, p);
  return `
    <div class="target-data-row td-row" id="port-row-${pid}">
      <span class="port-num">${esc(String(p.port))}/${esc(p.protocol)}</span>
      <span class="td-state" style="color:${PORT_STATE_COLORS[p.state] || 'var(--t3)'}">${esc(p.state)}</span>
      <span class="td-svc">${esc(p.service || '')}${p.version ? ` <span class="td-ver">${esc(p.version)}</span>` : ''}</span>
      ${p.source === 'claude_code' ? `<span class="cc-src" title="Agregado por Claude Code">Claude Code</span>` : ''}
      <span class="td-row-actions">
        <button class="btn-icon edit"   onclick="editPort('${tid}','${pid}',event)" title="Editar">${icon('square-pen',{size:12})}</button>
        <button class="btn-icon delete" onclick="deletePort('${tid}','${pid}',event)" title="Eliminar">${icon('trash-2',{size:12})}</button>
      </span>
    </div>`;
}

function _tdPortEditHtml(tid, p) {
  const pid = esc(p.id);
  return `
    <div class="target-data-row td-row is-editing" id="port-row-${pid}" onkeydown="_tdInlineKey(event,'port','${tid}','${pid}')">
      <input type="number" class="target-inline-input td-in-port" value="${esc(String(p.port))}" id="pe-port-${pid}" min="1" max="65535" aria-label="Puerto">
      <select class="target-inline-select" id="pe-proto-${pid}" aria-label="Protocolo">
        <option value="tcp" ${p.protocol === 'tcp' ? 'selected' : ''}>tcp</option>
        <option value="udp" ${p.protocol === 'udp' ? 'selected' : ''}>udp</option>
      </select>
      <select class="target-inline-select" id="pe-state-${pid}" aria-label="Estado">
        <option value="open"     ${p.state === 'open' ? 'selected' : ''}>open</option>
        <option value="filtered" ${p.state === 'filtered' ? 'selected' : ''}>filtered</option>
        <option value="closed"   ${p.state === 'closed' ? 'selected' : ''}>closed</option>
      </select>
      <input type="text" class="target-inline-input td-in-grow" placeholder="Servicio" id="pe-svc-${pid}" value="${esc(p.service || '')}">
      <input type="text" class="target-inline-input td-in-grow" placeholder="Versión"  id="pe-ver-${pid}" value="${esc(p.version || '')}">
      <span class="td-row-actions">
        <button class="btn btn-prim ccp-btn" onclick="savePort('${tid}','${pid}',event)">Guardar</button>
        <button class="btn-icon" onclick="cancelPortEdit('${tid}','${pid}',event)" title="Cancelar (Esc)">${icon('x',{size:12})}</button>
      </span>
    </div>`;
}

function _tdPortAddHtml(tid) {
  return `
    <div class="td-add" id="port-add-${tid}" onkeydown="if(event.key==='Enter'&&!event.defaultPrevented&&event.target.tagName==='INPUT'){event.preventDefault();addPort('${tid}')}">
      <div class="td-add-label">Agregar puerto</div>
      <div class="td-add-row">
        <input type="number" class="target-inline-input td-in-port" placeholder="Puerto" id="pa-port-${tid}" min="1" max="65535" aria-label="Puerto">
        <select class="target-inline-select" id="pa-proto-${tid}" aria-label="Protocolo">
          <option value="tcp">tcp</option><option value="udp">udp</option>
        </select>
        <select class="target-inline-select" id="pa-state-${tid}" aria-label="Estado">
          <option value="open">open</option><option value="filtered">filtered</option><option value="closed">closed</option>
        </select>
        <input type="text" class="target-inline-input td-in-grow" placeholder="Servicio (ej. nginx)" id="pa-svc-${tid}">
        <input type="text" class="target-inline-input td-in-grow" placeholder="Versión" id="pa-ver-${tid}">
        <button class="btn btn-prim ccp-btn td-add-btn" onclick="addPort('${tid}')">${icon('plus',{size:11})} Agregar</button>
      </div>
    </div>`;
}

// ── Endpoints ──
const METHOD_COLORS = {
  GET:'var(--c-low)', POST:'var(--a)', PUT:'var(--a)',
  PATCH:'#3b82f6', DELETE:'var(--c-crit)', HEAD:'var(--t3)',
  OPTIONS:'var(--t3)', OTHER:'var(--t3)'
};
const METHODS = ['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','OTHER'];

function _tdEndpointMatches(ep, q) {
  return `${ep.method} ${ep.path} ${ep.status_code || ''}`.toLowerCase().includes(q);
}

function endpointRowHtml(targetId, ep) {
  const tid = esc(targetId), eid = esc(ep.id);
  if (_tdEditRow?.kind === 'ep' && _tdEditRow.id === ep.id) return _tdEndpointEditHtml(tid, ep);
  return `
    <div class="target-data-row td-row" id="ep-row-${eid}">
      <span class="td-method" style="color:${METHOD_COLORS[ep.method] || 'var(--t3)'}">${esc(ep.method)}</span>
      <span class="td-path" title="${esc(ep.path)}">${esc(ep.path)}</span>
      ${ep.status_code ? `<span class="td-code">${esc(String(ep.status_code))}</span>` : ''}
      ${ep.interesting ? `<span class="td-star" title="Interesante">${icon('star',{size:10})}</span>` : ''}
      ${ep.source === 'claude_code' ? `<span class="cc-src" title="Agregado por Claude Code">Claude Code</span>` : ''}
      <span class="td-row-actions">
        <button class="btn-icon edit"   onclick="editEndpoint('${tid}','${eid}',event)" title="Editar">${icon('square-pen',{size:12})}</button>
        <button class="btn-icon delete" onclick="deleteEndpoint('${tid}','${eid}',event)" title="Eliminar">${icon('trash-2',{size:12})}</button>
      </span>
    </div>`;
}

function _tdEndpointEditHtml(tid, ep) {
  const eid = esc(ep.id);
  return `
    <div class="target-data-row td-row is-editing" id="ep-row-${eid}" onkeydown="_tdInlineKey(event,'ep','${tid}','${eid}')">
      <select class="target-inline-select" id="ee-method-${eid}" aria-label="Método">
        ${METHODS.map(m => `<option ${ep.method === m ? 'selected' : ''}>${m}</option>`).join('')}
      </select>
      <input type="text" class="target-inline-input td-in-path" placeholder="/path" id="ee-path-${eid}" value="${esc(ep.path)}">
      <input type="number" class="target-inline-input td-in-code" placeholder="200" id="ee-code-${eid}" value="${esc(String(ep.status_code || ''))}" min="100" max="599" aria-label="Código de estado">
      <label class="td-star-check" title="Interesante">
        <input type="checkbox" id="ee-interesting-${eid}" ${ep.interesting ? 'checked' : ''}> ${icon('star',{size:11})}
      </label>
      <span class="td-row-actions">
        <button class="btn btn-prim ccp-btn" onclick="saveEndpoint('${tid}','${eid}',event)">Guardar</button>
        <button class="btn-icon" onclick="cancelEndpointEdit('${tid}','${eid}',event)" title="Cancelar (Esc)">${icon('x',{size:12})}</button>
      </span>
    </div>`;
}

function _tdEndpointAddHtml(tid) {
  return `
    <div class="td-add" id="ep-add-${tid}" onkeydown="if(event.key==='Enter'&&!event.defaultPrevented&&event.target.tagName==='INPUT'){event.preventDefault();addEndpoint('${tid}')}">
      <div class="td-add-label">Agregar endpoint</div>
      <div class="td-add-row">
        <select class="target-inline-select" id="ea-method-${tid}" aria-label="Método">
          ${METHODS.map(m => `<option>${m}</option>`).join('')}
        </select>
        <input type="text" class="target-inline-input td-in-path" placeholder="/path o /api/endpoint" id="ea-path-${tid}" aria-label="Path">
        <input type="number" class="target-inline-input td-in-code" placeholder="200" id="ea-code-${tid}" min="100" max="599" aria-label="Código de estado">
        <label class="td-star-check" title="Marcar como interesante">
          <input type="checkbox" id="ea-interesting-${tid}"> ${icon('star',{size:11})}
        </label>
        <button class="btn btn-prim ccp-btn td-add-btn" onclick="addEndpoint('${tid}')">${icon('plus',{size:11})} Agregar</button>
      </div>
    </div>`;
}

// Lista filtrada + paginada ("mostrar más") de puertos o endpoints.
function _tdFiltered(kind, targetId) {
  const c = _targetCache[targetId];
  const all = (kind === 'ports' ? c?.ports : c?.endpoints) || [];
  const q = _tdFilter[kind].trim().toLowerCase();
  let list = all;
  if (kind === 'endpoints' && _tdOnlyStar) list = list.filter(ep => ep.interesting);
  if (q) list = list.filter(x => kind === 'ports' ? _tdPortMatches(x, q) : _tdEndpointMatches(x, q));
  return { all, list };
}

function _tdListHtml(kind, targetId) {
  const { all, list } = _tdFiltered(kind, targetId);
  const noun = kind === 'ports' ? 'puertos' : 'endpoints';
  if (!all.length) return `<div class="ccp-muted td-empty">Todavía no hay ${noun}.</div>`;
  if (!list.length) return `<div class="ccp-muted td-empty">Ningún ${kind === 'ports' ? 'puerto' : 'endpoint'} coincide con el filtro.</div>`;
  // La fila en edición siempre se pinta aunque quede más allá del límite.
  let shown = list.slice(0, _tdLimit[kind]);
  const editing = _tdEditRow && list.find(x => x.id === _tdEditRow.id);
  if (editing && !shown.includes(editing)) shown = shown.concat(editing);
  const rest = list.length - shown.length;
  const rowFn = kind === 'ports' ? portRowHtml : endpointRowHtml;
  return `${shown.map(x => rowFn(targetId, x)).join('')}
    ${rest > 0 ? `<button type="button" class="btn btn-ghost ccp-btn td-more" onclick="_tdShowMore('${kind}')">Mostrar ${Math.min(TD_PAGE, rest)} más · quedan ${rest}</button>` : ''}`;
}

function _tdCountLabel(kind, targetId) {
  const { all, list } = _tdFiltered(kind, targetId);
  return list.length === all.length ? `${all.length}` : `${list.length} de ${all.length}`;
}

function _tdDataTabHtml(kind, t) {
  const c = _targetCache[t.id];
  const tid = esc(t.id);
  if (!c) return `<div class="ccp-muted td-empty">// cargando ${kind === 'ports' ? 'puertos' : 'endpoints'}...</div>`;
  const all = kind === 'ports' ? c.ports : c.endpoints;
  const toolbar = all.length ? `
    <div class="td-toolbar">
      <label class="td-search">
        ${icon('search',{size:12})}
        <input type="search" id="td-filter-${kind}" placeholder="${kind === 'ports' ? 'Filtrar por puerto, servicio, estado…' : 'Filtrar por método, path o código…'}"
          value="${esc(_tdFilter[kind])}" oninput="_tdSetFilter('${kind}', this.value)" autocomplete="off" aria-label="Filtrar ${kind === 'ports' ? 'puertos' : 'endpoints'}">
      </label>
      ${kind === 'endpoints' ? `<button type="button" class="td-toggle${_tdOnlyStar ? ' is-on' : ''}" id="td-only-star" aria-pressed="${_tdOnlyStar}"
        onclick="_tdToggleStar()" title="Solo interesantes">${icon('star',{size:11})} Interesantes</button>` : ''}
      <span class="td-count" id="td-count-${kind}">${_tdCountLabel(kind, t.id)}</span>
    </div>` : '';
  return `
    <div class="drw-sec">${kind === 'ports' ? _tdPortAddHtml(tid) : _tdEndpointAddHtml(tid)}</div>
    <div class="drw-sec">
      ${toolbar}
      <div class="td-list" id="td-list-${kind}">${_tdListHtml(kind, t.id)}</div>
    </div>`;
}

function _tdBody(t, findings, tab) {
  if (tab === 'findings') return `<div class="drw-sec">${_tdFindingsHtml(findings)}</div>`;
  if (tab === 'notes')    return `<div class="drw-sec"><div class="payload-code vd-notes td-notes">${esc(t.notes || '')}</div></div>`;
  return _tdDataTabHtml(tab, t);
}

function _tdFoot(t) {
  const id = esc(t.id);
  const order = _tdOrder();
  const idx = order.indexOf(t.id);
  const n = order.length;
  return `
    <div class="ccp-foot-nav">
      <button class="btn btn-ghost ccp-btn" onclick="stepTargetDetail(-1)" ${idx <= 0 ? 'disabled' : ''} title="Anterior (←)">‹ anterior</button>
      <span class="ccp-pos">${idx + 1} / ${n}</span>
      <button class="btn btn-ghost ccp-btn" onclick="stepTargetDetail(1)" ${idx >= n - 1 ? 'disabled' : ''} title="Siguiente (→)">siguiente ›</button>
    </div>
    <div class="ccp-foot-actions">
      <button class="btn btn-ghost ccp-btn-reject" onclick="deleteTarget('${id}',event)" title="Eliminar target">${icon('trash-2',{size:12})} Eliminar</button>
      <button class="btn" onclick="scanTargetWithAI('${id}',event)" title="Escanear con AI Agent">${icon('sparkles',{size:12})} Escanear</button>
      <button class="btn btn-prim" onclick="openEditTarget('${id}',event)">${icon('square-pen',{size:12})} Editar</button>
    </div>`;
}

// keep = redibujo del mismo target tras un cambio: conserva scroll, foco,
// pestaña, filtro y lo que haya tipeado en los formularios inline.
function _tdRenderView(keep) {
  const t = state.targets.find(x => x.id === _tdOpenId);
  if (!t) return;
  const body = document.getElementById('td-body');
  let prev = null;
  if (keep) {
    const active = document.activeElement;
    prev = {
      top: body.scrollTop,
      vals: [...body.querySelectorAll('input[id],select[id],textarea[id]')].map(el => [el.id, el.value, el.checked]),
      focus: active && body.contains(active) && active.id ? active.id : null,
      caret: active && typeof active.selectionStart === 'number' ? [active.selectionStart, active.selectionEnd] : null,
    };
  }
  const findings = _trFindings(t.id);
  const tab = _tdCurrentTab(t, findings);
  document.getElementById('td-head').innerHTML = _tdHead(t, findings, tab);
  body.innerHTML = _tdBody(t, findings, tab);
  document.getElementById('td-foot').innerHTML = _tdFoot(t);
  document.querySelectorAll('.tr-row.is-active').forEach(r => r.classList.remove('is-active'));
  document.getElementById(`target-${t.id}`)?.classList.add('is-active');
  if (prev) {
    prev.vals.forEach(([id, value, checked]) => {
      const el = document.getElementById(id);
      if (!el || !body.contains(el)) return;
      if (el.type === 'checkbox') el.checked = checked; else el.value = value;
    });
    body.scrollTop = prev.top;
    const f = prev.focus && document.getElementById(prev.focus);
    if (f) {
      f.focus({ preventScroll: true });
      if (prev.caret) try { f.setSelectionRange(prev.caret[0], prev.caret[1]); } catch {}
    }
  } else {
    body.scrollTop = 0;
  }
}

// Solo la lista + el contador (al tipear en el filtro no se toca el input).
function _tdRenderList(kind) {
  const list = document.getElementById(`td-list-${kind}`);
  if (!list || !_tdOpenId) return;
  list.innerHTML = _tdListHtml(kind, _tdOpenId);
  const count = document.getElementById(`td-count-${kind}`);
  if (count) count.textContent = _tdCountLabel(kind, _tdOpenId);
}

function _tdSetFilter(kind, value) {
  _tdFilter[kind] = value;
  _tdLimit[kind]  = TD_PAGE;
  _tdRenderList(kind);
}

function _tdToggleStar() {
  _tdOnlyStar = !_tdOnlyStar;
  _tdLimit.endpoints = TD_PAGE;
  const btn = document.getElementById('td-only-star');
  btn?.classList.toggle('is-on', _tdOnlyStar);
  btn?.setAttribute('aria-pressed', String(_tdOnlyStar));
  _tdRenderList('endpoints');
}

function _tdShowMore(kind) {
  _tdLimit[kind] += TD_PAGE;
  _tdRenderList(kind);
}

// Pestañas del drawer (mismo nombre que la vieja función de la tarjeta).
function switchTargetTab(targetId, tab, e) {
  e?.stopPropagation();
  if (targetId !== _tdOpenId || _tdMode !== 'view') openTargetDetail(targetId);
  if (_tdOpenId !== targetId) return;
  const fromTabs = !!document.activeElement?.closest?.('.td-tabs');
  _tdTab = tab;
  _tdEditRow = null;
  _tdRenderView(false);
  // Navegando con teclado por las pestañas, el foco sigue en la pestaña.
  if (fromTabs) document.querySelector('#td-head .td-tab.is-active')?.focus({ preventScroll: true });
}

function _tdShow(mode) {
  const bd  = document.getElementById('td-backdrop');
  const drw = document.getElementById('td-drw');
  if (!drw) return;
  _tdMode = mode;
  drw.classList.toggle('is-edit', mode === 'edit');
  drw.classList.toggle('is-add', mode === 'edit' && !_editingTargetId);
  drw.setAttribute('aria-labelledby', mode === 'edit' ? 'target-modal-title' : 'td-title');
  if (!drw.classList.contains('open')) {
    _tdReturnFocus = document.activeElement;
    drw.offsetHeight; // reflow para que se pinte primero el translateX(100%)
    bd.classList.add('open');
    drw.classList.add('open');
    document.addEventListener('keydown', _tdOnKey);
  }
}

function openTargetDetail(id) {
  if (!state.targets.some(t => t.id === id)) return;
  if (_tdOpenId !== id) _tdResetViewState();
  _tdOpenId = id;
  _tdShow('view');
  _tdRenderView(false);
  document.getElementById('td-drw').focus({ preventScroll: true });
  _tdEnsureDetail(id);
}

function stepTargetDetail(delta) {
  const order = _tdOrder();
  const next = order[order.indexOf(_tdOpenId) + delta];
  if (_tdMode === 'view' && next) openTargetDetail(next);
}

// force = sin preguntar por cambios sin guardar (tras guardar / al borrar).
function closeTargetDetail(force) {
  if (force !== true && !_tdConfirmDiscard()) return;
  const id = _tdOpenId;
  _tdMode = null;
  _tdOpenId = null;
  _editingTargetId = null;
  _tdEditRow = null;
  document.removeEventListener('keydown', _tdOnKey);
  document.getElementById('td-backdrop')?.classList.remove('open');
  document.getElementById('td-drw')?.classList.remove('open');
  document.querySelectorAll('.tr-row.is-active').forEach(r => r.classList.remove('is-active'));
  // El foco vuelve a la fila del target (o a donde estaba al abrir).
  const back = (id && document.getElementById(`target-${id}`)) || _tdReturnFocus;
  if (back?.isConnected) back.focus({ preventScroll: true });
  _tdReturnFocus = null;
}

function _tdRefresh() {
  if (_tdMode !== 'view') return; // en edición no se pisa el formulario
  if (state.targets.some(t => t.id === _tdOpenId)) _tdRenderView(true);
  else closeTargetDetail(true);
}

function _tdFormState() {
  const root = document.getElementById('td-edit');
  if (!root) return '';
  return JSON.stringify([...root.querySelectorAll('input,textarea,select')].map(el => el.value));
}

function _tdConfirmDiscard() {
  if (_tdMode !== 'edit' || _tdFormState() === _tdSnapshot) return true;
  return confirm('Hay cambios sin guardar. ¿Descartarlos?');
}

function _tdOnKey(e) {
  if (!_tdMode || e.defaultPrevented) return;
  if (_tdMode === 'edit') {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); saveTarget(); }
    else if (e.key === 'Escape') { e.preventDefault(); closeTargetModal(); }
    return;
  }
  if (e.altKey || e.ctrlKey || e.metaKey) return;
  if (e.target.closest?.('input,textarea,select,[contenteditable="true"]')) {
    // Esc en el filtro lo limpia (y recién el siguiente Esc cierra el drawer).
    if (e.key === 'Escape' && e.target.id?.startsWith('td-filter-') && e.target.value) {
      e.preventDefault();
      e.target.value = '';
      _tdSetFilter(e.target.id.slice('td-filter-'.length), '');
    }
    return;
  }
  if (e.key === 'Escape') { e.preventDefault(); closeTargetDetail(); }
  else if (e.key === 'ArrowLeft')  { e.preventDefault(); stepTargetDetail(-1); }
  else if (e.key === 'ArrowRight') { e.preventDefault(); stepTargetDetail(1); }
}

// Enter guarda / Esc cancela la fila en edición inline.
function _tdInlineKey(e, kind, targetId, rowId) {
  if (e.defaultPrevented) return;
  if (e.key === 'Escape') {
    e.preventDefault(); e.stopPropagation();
    kind === 'port' ? cancelPortEdit(targetId, rowId, e) : cancelEndpointEdit(targetId, rowId, e);
  } else if (e.key === 'Enter' && e.target.tagName === 'INPUT') {
    e.preventDefault();
    kind === 'port' ? savePort(targetId, rowId, e) : saveEndpoint(targetId, rowId, e);
  }
}

function _tdAfterDataChange(targetId) {
  _trUpdateCounts(targetId);
  if (_tdMode === 'view' && _tdOpenId === targetId) _tdRenderView(true);
}

function _tdFocusField(id) {
  const el = document.getElementById(id);
  if (el) el.focus({ preventScroll: false });
}

// ── PUERTOS: alta / edición / borrado inline ──────────────────────────
function editPort(targetId, portId, e) {
  e?.stopPropagation();
  if (!_targetCache[targetId]?.ports.some(x => x.id === portId)) return;
  _tdEditRow = { kind: 'port', id: portId };
  _tdAfterDataChange(targetId);
  _tdFocusField(`pe-port-${portId}`);
}

async function savePort(targetId, portId, e) {
  e?.stopPropagation();
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
    if (_tdEditRow?.id === portId) _tdEditRow = null;
    _tdAfterDataChange(targetId);
    showToast('Port updated', 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

function cancelPortEdit(targetId, portId, e) {
  e?.stopPropagation();
  if (_tdEditRow?.id === portId) _tdEditRow = null;
  _tdAfterDataChange(targetId);
}

async function addPort(targetId) {
  const portEl   = document.getElementById(`pa-port-${targetId}`);
  const port     = parseInt(portEl?.value);
  const protocol = document.getElementById(`pa-proto-${targetId}`)?.value;
  const state_   = document.getElementById(`pa-state-${targetId}`)?.value;
  const service  = document.getElementById(`pa-svc-${targetId}`)?.value.trim();
  const version  = document.getElementById(`pa-ver-${targetId}`)?.value.trim();
  if (!port || port < 1 || port > 65535) { showToast('Invalid port', 'error'); return; }
  try {
    const p = await api.targets.addPort(state.currentProject.id, targetId, { port, protocol, state: state_, service, version });
    if (!_targetCache[targetId]) _targetCache[targetId] = { ports: [], endpoints: [], loaded: true };
    _targetCache[targetId].ports.push(p);
    // Se vacía el formulario (el redibujo conserva lo tipeado) y se deja el
    // foco en el puerto para cargar varios seguidos.
    [`pa-port-${targetId}`, `pa-svc-${targetId}`, `pa-ver-${targetId}`].forEach(id => {
      const el = document.getElementById(id); if (el) el.value = '';
    });
    _tdAfterDataChange(targetId);
    _tdFocusField(`pa-port-${targetId}`);
    showToast(`${port}/${protocol} added`, 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

async function deletePort(targetId, portId, e) {
  e?.stopPropagation();
  try {
    await api.targets.deletePort(state.currentProject.id, targetId, portId);
    if (_targetCache[targetId]) _targetCache[targetId].ports = _targetCache[targetId].ports.filter(p => p.id !== portId);
    if (_tdEditRow?.id === portId) _tdEditRow = null;
    _tdAfterDataChange(targetId);
    showToast('Port removed', 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

// ── ENDPOINTS: alta / edición / borrado inline ────────────────────────
function editEndpoint(targetId, epId, e) {
  e?.stopPropagation();
  if (!_targetCache[targetId]?.endpoints.some(x => x.id === epId)) return;
  _tdEditRow = { kind: 'ep', id: epId };
  _tdAfterDataChange(targetId);
  _tdFocusField(`ee-path-${epId}`);
}

async function saveEndpoint(targetId, epId, e) {
  e?.stopPropagation();
  const method      = document.getElementById(`ee-method-${epId}`)?.value;
  const path        = document.getElementById(`ee-path-${epId}`)?.value.trim();
  const status_code = parseInt(document.getElementById(`ee-code-${epId}`)?.value) || null;
  const interesting = document.getElementById(`ee-interesting-${epId}`)?.checked || false;
  if (!path) { showToast('Path is required', 'error'); return; }
  try {
    const updated = await api.targets.updateEndpoint(state.currentProject.id, targetId, epId, { method, path, status_code, interesting });
    const cache = _targetCache[targetId];
    if (cache) cache.endpoints = cache.endpoints.map(ep => ep.id === epId ? updated : ep);
    if (_tdEditRow?.id === epId) _tdEditRow = null;
    _tdAfterDataChange(targetId);
    showToast('Endpoint updated', 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

function cancelEndpointEdit(targetId, epId, e) {
  e?.stopPropagation();
  if (_tdEditRow?.id === epId) _tdEditRow = null;
  _tdAfterDataChange(targetId);
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
    [`ea-path-${targetId}`, `ea-code-${targetId}`].forEach(id => {
      const el = document.getElementById(id); if (el) el.value = '';
    });
    const star = document.getElementById(`ea-interesting-${targetId}`);
    if (star) star.checked = false;
    _tdAfterDataChange(targetId);
    _tdFocusField(`ea-path-${targetId}`);
    showToast(`${method} ${path} added`, 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

async function deleteEndpoint(targetId, endpointId, e) {
  e?.stopPropagation();
  try {
    await api.targets.deleteEndpoint(state.currentProject.id, targetId, endpointId);
    if (_targetCache[targetId]) _targetCache[targetId].endpoints = _targetCache[targetId].endpoints.filter(ep => ep.id !== endpointId);
    if (_tdEditRow?.id === endpointId) _tdEditRow = null;
    _tdAfterDataChange(targetId);
    showToast('Endpoint removed', 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

// ── Alta / edición (modo edición del drawer) ─────────────────────────
// Conserva los nombres y los ids del viejo #target-modal.
function _tdFillForm(t) {
  document.getElementById('modal-target-host').value   = t?.host || '';
  document.getElementById('modal-target-type').value   = t?.type || 'domain';
  document.getElementById('modal-target-scope').value  = t?.scope || 'in';
  document.getElementById('modal-target-status').value = t?.status || 'active';
  document.getElementById('modal-target-notes').value  = t?.notes || '';
  document.getElementById('target-error').style.display = 'none';
}

function _tdEnterEdit(id) {
  if (id !== _tdOpenId) _tdResetViewState();
  _tdOpenId = id;
  document.getElementById('td-edit-body').scrollTop = 0;
  _tdShow('edit');
  _tdSnapshot = _tdFormState();
  document.getElementById('modal-target-host').focus({ preventScroll: true });
}

function openAddTargetModal() {
  _editingTargetId = null;
  document.getElementById('target-modal-title').textContent = 'Nuevo target';
  document.getElementById('td-edit-kind').textContent       = 'Nuevo target';
  _tdFillForm(null);
  _tdEnterEdit(null);
}

function openEditTarget(id, e) {
  e?.stopPropagation();
  const t = state.targets.find(x => x.id === id);
  if (!t) return;
  _editingTargetId = id;
  document.getElementById('target-modal-title').textContent = t.host;
  document.getElementById('td-edit-kind').textContent       = 'Editando target';
  _tdFillForm(t);
  _tdEnterEdit(id);
}

// Cancelar: vuelve al detalle del target que se editaba (o cierra el
// drawer si era un alta). Avisa si hay cambios sin guardar.
function closeTargetModal() {
  if (!_tdConfirmDiscard()) return false;
  const id = _editingTargetId;
  _editingTargetId = null;
  if (id && state.targets.some(t => t.id === id)) openTargetDetail(id);
  else closeTargetDetail(true);
  return true;
}

async function saveTarget() {
  const host   = document.getElementById('modal-target-host').value.trim();
  const type   = document.getElementById('modal-target-type').value;
  const scope  = document.getElementById('modal-target-scope').value;
  const status = document.getElementById('modal-target-status').value;
  const notes  = document.getElementById('modal-target-notes').value;
  const errEl  = document.getElementById('target-error');
  const btn    = document.getElementById('target-save-btn');
  if (btn.disabled) return; // Ctrl+Enter repetido mientras se guarda
  if (!host) { errEl.textContent = 'El host es obligatorio'; errEl.style.display = 'block'; return; }
  btn.disabled = true;
  try {
    let savedId = _editingTargetId;
    if (_editingTargetId) {
      const updated = await api.targets.update(state.currentProject.id, _editingTargetId, { host, type, scope, status, notes });
      const idx = state.targets.findIndex(t => t.id === _editingTargetId);
      if (idx > -1) state.targets[idx] = { ...state.targets[idx], ...updated };
      // Invalidate cache so ports/endpoints reload on next open
      if (_targetCache[_editingTargetId]) _targetCache[_editingTargetId].loaded = false;
    } else {
      const created = await api.targets.create(state.currentProject.id, { host, type, scope, status, notes });
      state.targets.push(created);
      savedId = created?.id || null;
      if (savedId) _targetCache[savedId] = { ports: [], endpoints: [], loaded: true };
    }
    // Guardado: se vuelve al detalle de ese target (también tras un alta).
    _editingTargetId = null;
    renderTargets();
    if (savedId && state.targets.some(t => t.id === savedId)) openTargetDetail(savedId);
    else closeTargetDetail(true);
    showToast('Saved', 'success');
  } catch(e) { errEl.textContent = e.message; errEl.style.display = 'block'; }
  finally { btn.disabled = false; }
}

async function deleteTarget(id, e) {
  e?.stopPropagation();
  if (!confirm('¿Eliminar este target? Se borran también sus puertos y endpoints.')) return;
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
window.buildTargetRow       = buildTargetRow;
window.buildTargetCard      = buildTargetRow;   // nombre viejo
window.toggleTargetBody     = id => openTargetDetail(id); // nombre viejo: ahora abre el drawer
window.switchTargetTab      = switchTargetTab;
window.openTargetDetail     = openTargetDetail;
window.closeTargetDetail    = closeTargetDetail;
window.stepTargetDetail     = stepTargetDetail;
window.prefetchTargetCounts = prefetchTargetCounts;
window.scanTargetWithAI     = scanTargetWithAI;
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
