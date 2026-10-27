// ── views/vulns.js ───────────────────────────────────────────────────
let _editingVulnId = null;

// ── TEMPLATE PICKER ──────────────────────────────────────────────────
const SEV_COLORS = { critical:'var(--c-crit)', high:'var(--c-high)', medium:'var(--c-med)', low:'var(--c-low)', info:'var(--c-info)' };
let _tplResults   = [];
let _tplFocusIdx  = -1;
let _tplDebounce  = null;

function _tplDot(sev) {
  return `<span style="width:7px;height:7px;border-radius:50%;background:${SEV_COLORS[sev]||'var(--t3)'};flex-shrink:0;display:inline-block"></span>`;
}

function tplSearch(q) {
  clearTimeout(_tplDebounce);
  _tplDebounce = setTimeout(async () => {
    try {
      _tplResults = await api.templates.search(q.trim());
      _tplFocusIdx = -1;
      _tplRender();
    } catch(e) { /* ignore */ }
  }, 200);
}

function _tplRender() {
  const dd = document.getElementById('tpl-dropdown');
  const inp = document.getElementById('tpl-search-input');
  if (!dd || !inp) return;

  if (_tplResults.length === 0) {
    dd.innerHTML = `<div class="tpl-empty">No templates found</div>`;
  } else {
    dd.innerHTML = _tplResults.map((t, i) => `
      <div class="tpl-item${i === _tplFocusIdx ? ' focused' : ''}" data-idx="${i}"
           onmousedown="tplApply(${i})">
        ${_tplDot(t.severity)}
        <span class="tpl-item-name">${esc(t.name)}</span>
        ${t.category ? `<span class="tpl-item-cat">${esc(t.category)}</span>` : ''}
        ${!t.is_builtin ? `<span class="tpl-item-own">mine</span>` : ''}
      </div>`).join('');
  }

  const rect = inp.getBoundingClientRect();
  dd.style.top      = (rect.bottom + 4) + 'px';
  dd.style.left     = rect.left + 'px';
  dd.style.width    = rect.width + 'px';
  dd.classList.add('open');
}

function _tplClose() {
  const dd = document.getElementById('tpl-dropdown');
  if (dd) dd.classList.remove('open');
  _tplResults = [];
  _tplFocusIdx = -1;
}

function tplKeydown(e) {
  if (!document.getElementById('tpl-dropdown')?.classList.contains('open')) return;
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    _tplFocusIdx = Math.min(_tplFocusIdx + 1, _tplResults.length - 1);
    _tplRender();
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    _tplFocusIdx = Math.max(_tplFocusIdx - 1, 0);
    _tplRender();
  } else if (e.key === 'Enter' && _tplFocusIdx >= 0) {
    e.preventDefault();
    tplApply(_tplFocusIdx);
  } else if (e.key === 'Escape') {
    e.preventDefault(); // que el drawer no lo tome también como "cerrar"
    _tplClose();
  }
}

function tplApply(idx) {
  const t = _tplResults[idx];
  if (!t) return;

  document.getElementById('modal-vuln-name').value  = t.name;
  document.getElementById('modal-vuln-cat').value   = t.category || '';
  document.getElementById('modal-vuln-cwe').value   = t.cwe || '';
  document.getElementById('modal-vuln-sev').value   = t.severity;
  document.getElementById('modal-vuln-desc').value  = t.description || '';
  document.getElementById('modal-vuln-rem').value   = t.remediation || '';

  const inp = document.getElementById('tpl-search-input');
  if (inp) inp.value = '';
  _tplClose();
}

async function tplSaveCurrent() {
  const name = document.getElementById('modal-vuln-name').value.trim();
  if (!name) { showToast('Enter a name first', 'error'); return; }
  const data = {
    name,
    category:    document.getElementById('modal-vuln-cat').value.trim() || null,
    severity:    document.getElementById('modal-vuln-sev').value,
    cwe:         document.getElementById('modal-vuln-cwe').value.trim() || null,
    description: document.getElementById('modal-vuln-desc').value.trim() || null,
    remediation: document.getElementById('modal-vuln-rem').value.trim() || null,
  };
  try {
    await api.templates.save(data);
    showToast('Template saved', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

document.addEventListener('click', (e) => {
  if (!e.target.closest('#tpl-search-wrap')) _tplClose();
});

function numberedCode(text) {
  if (!text) return '';
  const lines = text.split('\n');
  const pad = String(lines.length).length;
  return lines.map((line, i) =>
    `<span class="code-line"><span class="line-num">${String(i + 1).padStart(pad, ' ')}</span>${esc(line)}</span>`
  ).join('\n');
}

// ── CVSS v3.1 ────────────────────────────────────────────────────────
const _CVSS_W = {
  AV:  { N:0.85, A:0.62, L:0.55, P:0.2  },
  AC:  { L:0.77, H:0.44 },
  PR_U:{ N:0.85, L:0.62, H:0.27 },
  PR_C:{ N:0.85, L:0.68, H:0.50 },
  UI:  { N:0.85, R:0.62 },
  CIA: { N:0,    L:0.22, H:0.56 },
};
let _cvss = { AV:'N', AC:'L', PR:'N', UI:'N', S:'U', C:'N', I:'N', A:'N' };
let _cvssModified = false;
let _cvssCleared  = false;

function _cvssRoundUp(x) {
  const i = Math.ceil(x * 100000);
  return (i % 10000 === 0) ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

function calcCVSSScore(m) {
  const av  = _CVSS_W.AV[m.AV]  ?? 0.85;
  const ac  = _CVSS_W.AC[m.AC]  ?? 0.77;
  const pr  = (m.S === 'U' ? _CVSS_W.PR_U : _CVSS_W.PR_C)[m.PR] ?? 0.85;
  const ui  = _CVSS_W.UI[m.UI]  ?? 0.85;
  const c   = _CVSS_W.CIA[m.C]  ?? 0;
  const ii  = _CVSS_W.CIA[m.I]  ?? 0;
  const a   = _CVSS_W.CIA[m.A]  ?? 0;
  const iscBase = 1 - (1-c)*(1-ii)*(1-a);
  const isc = m.S === 'U'
    ? 6.42 * iscBase
    : 7.52*(iscBase-0.029) - 3.25*Math.pow(iscBase-0.02, 15);
  const exp = 8.22 * av * ac * pr * ui;
  if (isc <= 0) return 0;
  const raw = m.S === 'U' ? Math.min(isc+exp,10) : Math.min(1.08*(isc+exp),10);
  return _cvssRoundUp(raw);
}

function buildCVSSVector(m) {
  return `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`;
}

function parseCVSSVector(vec) {
  if (!vec?.startsWith('CVSS:3.1/')) return null;
  const r = {};
  vec.replace('CVSS:3.1/','').split('/').forEach(p => { const [k,v]=p.split(':'); r[k]=v; });
  return r;
}

function _cvssColor(s) {
  if (s >= 9) return '#dc2626'; if (s >= 7) return '#f97316';
  if (s >= 4) return '#f59e0b'; if (s > 0)  return '#059669';
  return 'var(--t3)';
}
function _cvssLabel(s) {
  if (s >= 9) return 'Critical'; if (s >= 7) return 'High';
  if (s >= 4) return 'Medium';   if (s > 0)  return 'Low';
  return 'None';
}
function _cvssSevClass(s) {
  if (s >= 9) return 'critical'; if (s >= 7) return 'high';
  if (s >= 4) return 'medium';   if (s > 0)  return 'low';
  return 'info';
}

function setCVSSMetric(metric, value) {
  _cvss[metric] = value;
  _cvssModified = true;
  _cvssCleared  = false;
  const clrBtn  = document.getElementById('cvss-clear-btn');
  if (clrBtn) clrBtn.style.display = 'inline';
  _renderCVSSCalc();
}

function _renderCVSSCalc() {
  const score  = calcCVSSScore(_cvss);
  const vector = buildCVSSVector(_cvss);
  const color  = _cvssColor(score);
  const label  = _cvssLabel(score);

  const sd = document.getElementById('cvss-score-display');
  if (sd) sd.innerHTML = `
    <span style="font-family:var(--mono);font-size:26px;font-weight:800;color:${color};line-height:1">${score.toFixed(1)}</span>
    <span class="sev-badge sev-${_cvssSevClass(score)}" style="margin-left:4px">${label}</span>`;

  const vd = document.getElementById('cvss-vector-display');
  if (vd) vd.textContent = vector;

  const hp = document.getElementById('cvss-header-pill');
  if (hp) { hp.style.color = color; hp.textContent = `${score.toFixed(1)} · ${label}`; }

  ['AV','AC','PR','UI','S','C','I','A'].forEach(m => {
    document.querySelectorAll(`.cvss-btn[data-metric="${m}"]`).forEach(btn => {
      btn.classList.toggle('active', btn.dataset.value === _cvss[m]);
    });
  });
}

function toggleCVSSSection() {
  const body = document.getElementById('cvss-calc');
  const btn  = document.getElementById('cvss-toggle-btn');
  if (!body) return;
  const opening = body.style.display === 'none';
  body.style.display = opening ? 'block' : 'none';
  if (btn) btn.innerHTML = opening ? `${icon('chevron-down',{size:11})} close` : `${icon('chevron-right',{size:11})} open`;
  if (opening) _renderCVSSCalc();
}

function _initCVSS(vector) {
  const parsed = parseCVSSVector(vector);
  _cvss = parsed
    ? { AV:parsed.AV||'N', AC:parsed.AC||'L', PR:parsed.PR||'N',
        UI:parsed.UI||'N', S:parsed.S||'U',   C:parsed.C||'N',
        I:parsed.I||'N',   A:parsed.A||'N' }
    : { AV:'N', AC:'L', PR:'N', UI:'N', S:'U', C:'N', I:'N', A:'N' };
  _cvssModified = !!vector;
  _cvssCleared  = false;

  const body  = document.getElementById('cvss-calc');
  const btn   = document.getElementById('cvss-toggle-btn');
  const clrBtn= document.getElementById('cvss-clear-btn');
  const hp    = document.getElementById('cvss-header-pill');
  if (body) body.style.display = vector ? 'block' : 'none';
  if (btn)  btn.innerHTML      = vector ? `${icon('chevron-down',{size:11})} close` : `${icon('chevron-right',{size:11})} open`;
  if (clrBtn) clrBtn.style.display = vector ? 'inline' : 'none';
  if (hp) {
    if (vector) {
      const s = calcCVSSScore(_cvss);
      hp.style.color = _cvssColor(s);
      hp.textContent = `${s.toFixed(1)} · ${_cvssLabel(s)}`;
    } else {
      hp.style.color = ''; hp.textContent = 'not scored';
    }
  }
  if (vector) _renderCVSSCalc();
}

function clearCVSS() {
  _cvssModified = true;
  _cvssCleared  = true;
  _cvss = { AV:'N', AC:'L', PR:'N', UI:'N', S:'U', C:'N', I:'N', A:'N' };
  const body   = document.getElementById('cvss-calc');
  const btn    = document.getElementById('cvss-toggle-btn');
  const clrBtn = document.getElementById('cvss-clear-btn');
  const hp     = document.getElementById('cvss-header-pill');
  if (body)   body.style.display   = 'none';
  if (btn)    btn.innerHTML         = `${icon('chevron-right',{size:11})} open`;
  if (clrBtn) clrBtn.style.display  = 'none';
  if (hp)     { hp.style.color = ''; hp.textContent = 'not scored'; }
}

async function copyCVSSVector() {
  await navigator.clipboard.writeText(buildCVSSVector(_cvss)).catch(()=>{});
  showToast('CVSS vector copied', 'info');
}

// ── PCI-DSS COMPLIANCE TAGS ──────────────────────────────────────────
let _selectedComplianceIds = new Set();

async function ensurePciControls() {
  if (state.pciControls) return state.pciControls;
  try {
    state.pciControls = await api.compliance.pciDss();
  } catch (e) {
    state.pciControls = [];
  }
  return state.pciControls;
}

function complianceBadge(tag) {
  return `<span class="compliance-badge" title="${esc(tag.title || '')}">PCI-DSS ${esc(tag.control_id)}</span>`;
}

async function renderCompliancePicker(selectedIds = []) {
  _selectedComplianceIds = new Set(selectedIds);
  const list = document.getElementById('modal-compliance-list');
  if (!list) return;
  const controls = await ensurePciControls();
  list.innerHTML = controls.map(c => `
    <label class="compliance-opt">
      <input type="checkbox" value="${esc(c.control_id)}" ${_selectedComplianceIds.has(c.control_id) ? 'checked' : ''} onchange="toggleComplianceTag('${esc(c.control_id)}', this.checked)">
      <span class="compliance-opt-id">${esc(c.control_id)}</span>
      <span class="compliance-opt-title">${esc(c.title)}</span>
    </label>`).join('');
}

function toggleComplianceTag(controlId, checked) {
  if (checked) _selectedComplianceIds.add(controlId);
  else _selectedComplianceIds.delete(controlId);
}

function collectComplianceTags() {
  const controls = state.pciControls || [];
  return controls
    .filter(c => _selectedComplianceIds.has(c.control_id))
    .map(c => ({ control_id: c.control_id, title: c.title }));
}

const SEVERITY_ORDER  = ['critical','high','medium','low','info'];

const SEVERITY_LABELS = { critical:'Critical', high:'High', medium:'Medium', low:'Low', info:'Info' };

function severityBadge(sev) {
  const s = sev || 'medium';
  return `<span class="sev-badge sev-${s}">${SEVERITY_LABELS[s]||s}</span>`;
}

const REMEDIATION_LABELS = { open: 'Open', remediated: 'Remediated', not_remediated: 'Not Remediated', verified_closed: 'Verified Closed' };
const REMEDIATION_COLORS = { open: 'var(--t3)', remediated: 'var(--c-med)', not_remediated: 'var(--c-crit)', verified_closed: 'var(--c-low)' };

function remediationBadge(status) {
  const s = status || 'open';
  const c = REMEDIATION_COLORS[s] || REMEDIATION_COLORS.open;
  return `<span class="vr-tag vd-tone" style="--vd-tone:${c}">${esc(REMEDIATION_LABELS[s] || s)}</span>`;
}

function _cvssScoreOf(v) {
  const s = v.cvss_score != null && v.cvss_score !== '' ? +v.cvss_score : null;
  return s != null && !isNaN(s) ? s : null;
}

// Agrupado por severidad, en el mismo orden en que se ven: es también el
// orden del ‹ anterior / siguiente › del drawer.
function _vulnsBySeverity() {
  const bySev = {};
  SEVERITY_ORDER.forEach(s => bySev[s] = []);
  state.customVulns.forEach(v => { const s = v.severity||'medium'; (bySev[s]||bySev['medium']).push(v); });
  return bySev;
}

function renderCustomVulns() {
  const container = document.getElementById('custom-content');
  if (!state.customVulns.length) {
    container.innerHTML = `<div class="empty-state"><div class="empty-icon">${icon('inbox', { size: 28 })}</div><div class="empty-title">No custom vulnerabilities</div><div class="empty-sub">Add findings, then write descriptions & export from the Export page</div><button class="btn btn-prim vr-empty-btn" onclick="openAddVulnModal()">+ Add Vulnerability</button></div>`;
    _vdRefresh();
    return;
  }
  const bySev = _vulnsBySeverity();

  container.innerHTML = '';
  SEVERITY_ORDER.forEach(sev => {
    if (!bySev[sev].length) return;
    const section = document.createElement('div');
    section.className = 'vuln-severity-section';
    section.innerHTML = `<div class="vuln-severity-header">
      <span class="sev-badge sev-${sev}">${SEVERITY_LABELS[sev]}</span>
      <span class="vuln-severity-count">${bySev[sev].length} finding${bySev[sev].length>1?'s':''}</span>
    </div>`;
    bySev[sev].forEach(v => section.appendChild(buildVulnCard(v)));
    container.appendChild(section);
  });
  // El drawer abierto se redibuja con los datos frescos (o se cierra si el
  // hallazgo ya no existe). Todo cambio pasa por acá.
  _vdRefresh();
}

// Check de estado (sin marcar → confirmado → vulnerable), compartido por la
// fila y la cabecera del drawer.
function _vrCheck(v) {
  const isDone = v.status === 'done';
  const isFail = v.status === 'fail';
  const st = isDone ? 'confirmado' : isFail ? 'vulnerable' : 'sin marcar';
  return `<button type="button" class="test-check vr-check${isDone ? ' is-done' : isFail ? ' is-fail' : ''}"
    onclick="cycleVulnStatus('${esc(v.id)}',event)" title="Estado: ${st} — clic para cambiar">${isDone ? icon('check',{size:12}) : isFail ? icon('x',{size:12}) : ''}</button>`;
}

function _vrPublishTitle(v) {
  return v.client_visible ? 'Visible para el cliente — clic para ocultar' : 'Oculto del cliente — clic para publicar en el portal';
}

// Fila compacta (mismo patrón que el inbox de propuestas): clic / Enter /
// Espacio abre el drawer de detalle. Las acciones rápidas no lo abren.
function buildVulnCard(v) {
  const id     = esc(v.id);
  const isDone = v.status === 'done';
  const isFail = v.status === 'fail';
  const row    = document.createElement('div');
  row.className = `vuln-card ccp-row vr-row${isDone ? ' completed' : ''}${isFail ? ' failed' : ''}${v.id === _vdOpenId && _vdMode ? ' is-active' : ''}`;
  row.id = `vuln-${v.id}`;
  row.tabIndex = 0;
  row.setAttribute('role', 'button');
  row.addEventListener('click', () => openVulnDetail(v.id));
  row.addEventListener('keydown', e => {
    if ((e.key === 'Enter' || e.key === ' ') && e.target === row) { e.preventDefault(); openVulnDetail(v.id); }
  });

  const score  = _cvssScoreOf(v);
  const items  = (v.items || []).length;
  const itemsDone = (v.items || []).filter((_, i) => v.checked_items?.[i]).length;
  const shots  = (v.evidence || []).length;
  const proofs = (v.http_proofs || []).length;
  const meta = [
    `<span>${esc(v.category || 'Custom')}</span>`,
    score != null ? `<span class="vr-tag vd-tone" style="--vd-tone:${_cvssColor(score)}">CVSS ${score.toFixed(1)}</span>` : '',
    v.cwe ? `<span>${esc(v.cwe)}</span>` : '',
    v.target_host ? `<span class="vr-target">${esc(v.target_host)}</span>` : '',
    ...(v.compliance_tags || []).map(t => complianceBadge(t)),
    (v.remediation_status && v.remediation_status !== 'open') ? remediationBadge(v.remediation_status) : '',
    !v.client_visible ? `<span class="vr-flag" title="No visible en el portal del cliente">${icon('eye-off',{size:10})}Oculto</span>` : '',
    v.ai_generated ? `<span class="vr-flag vr-flag-ai" title="Propuesto por el AI Agent">${icon('sparkles',{size:10})}AI</span>` : '',
    items  ? `<span class="ccp-count" title="Checklist">${icon('list-checks',{size:10})}${itemsDone}/${items}</span>` : '',
    shots  ? `<span class="ccp-count" title="Evidencia">${icon('image',{size:10})}${shots}</span>` : '',
    proofs ? `<span class="ccp-count" title="HTTP proofs">${icon('terminal',{size:10})}${proofs}</span>` : '',
    v.editor_username ? `<span class="vr-editor" title="Última edición">
      ${avatarHtml(displayName(v, 'editor_'), memberRoleColor(v.updated_by, v.editor_color||'#7c3aed'), 14, v.editor_avatar_url||null)}
      ${esc(displayName(v, 'editor_'))} · ${esc(timeAgo(v.updated_at))}</span>` : '',
  ].filter(Boolean).join('');

  row.innerHTML = `
    <div class="ccp-row-main">
      ${_vrCheck(v)}
      ${severityBadge(v.severity)}
      <div class="ccp-row-text">
        <div class="ccp-row-title">${esc(v.name)}</div>
        <div class="ccp-row-meta">${meta}</div>
      </div>
    </div>
    <div class="ccp-row-actions vr-actions" onclick="event.stopPropagation()" onkeydown="event.stopPropagation()">
      ${canActForClient() ? `<button class="btn-icon ${v.client_visible ? 'published' : ''}" onclick="toggleVulnPublish('${id}',event)"
        title="${_vrPublishTitle(v)}">${icon(v.client_visible ? 'eye' : 'eye-off',{size:12})}</button>` : ''}
      <button class="btn-icon edit" onclick="openEditVuln('${id}',event)" title="Editar">${icon('square-pen',{size:12})}</button>
      <button class="btn-icon delete" onclick="deleteVuln('${id}',event)" title="Eliminar">${icon('trash-2',{size:12})}</button>
    </div>`;
  return row;
}

function openEvidenceViewer(vulnId, idx) {
  const v = state.customVulns.find(x => x.id === vulnId);
  const img = v?.evidence?.[idx];
  if (!img) return;
  // Se navega solo dentro de la misma fase (original / retest), como se ven.
  const phase = img.phase || 'original';
  const same  = v.evidence.filter(e => (e.phase || 'original') === phase);
  openImageLightbox(same, same.indexOf(img));
}

// Lightbox genérico: images = [{ name, data }]. Esc / clic afuera cierra,
// ←/→ recorre. Las teclas se escuchan en captura y no se propagan, para
// que un drawer abierto debajo (ej. propuestas de Claude Code) no las reciba.
function openImageLightbox(images, startIdx = 0) {
  const start = (images || [])[startIdx];
  const list  = (images || []).filter(img => img?.data);
  if (!list.length) return;
  document.getElementById('img-lb')?._close?.();
  let idx = Math.max(list.indexOf(start), 0);

  const overlay = document.createElement('div');
  overlay.className = 'img-lb';
  overlay.id = 'img-lb';
  overlay.innerHTML = `
    <div class="img-lb-bar">
      <span class="img-lb-name"></span>
      <span class="img-lb-count"></span>
      <button class="img-lb-btn img-lb-close" title="Cerrar (Esc)">${icon('x', { size: 20 })}</button>
    </div>
    <div class="img-lb-stage">
      ${list.length > 1 ? `<button class="img-lb-btn img-lb-nav img-lb-prev" title="Anterior (←)">‹</button>` : ''}
      <img class="img-lb-img" alt="">
      ${list.length > 1 ? `<button class="img-lb-btn img-lb-nav img-lb-next" title="Siguiente (→)">›</button>` : ''}
    </div>`;

  const imgEl = overlay.querySelector('.img-lb-img');
  const show = i => {
    idx = (i + list.length) % list.length;
    const img = list[idx];
    // src y nombre por propiedad, nunca interpolados en HTML.
    imgEl.src = img.data;
    imgEl.alt = img.name || '';
    overlay.querySelector('.img-lb-name').textContent = img.name || 'evidence';
    overlay.querySelector('.img-lb-count').textContent = list.length > 1 ? `${idx + 1} / ${list.length}` : '';
  };
  const onKey = e => {
    if (e.key === 'Escape') close();
    else if (e.key === 'ArrowLeft')  show(idx - 1);
    else if (e.key === 'ArrowRight') show(idx + 1);
    else return;
    e.preventDefault();
    e.stopPropagation();
  };
  const close = () => {
    window.removeEventListener('keydown', onKey, true);
    overlay.remove();
  };
  overlay._close = close;

  overlay.addEventListener('click', e => {
    if (e.target.closest('.img-lb-close')) return close();
    if (e.target.closest('.img-lb-prev'))  return show(idx - 1);
    if (e.target.closest('.img-lb-next'))  return show(idx + 1);
    if (e.target === overlay || e.target.classList.contains('img-lb-stage')) close();
  });
  window.addEventListener('keydown', onKey, true);
  show(idx);
  document.body.appendChild(overlay);
}

// ── DRAWER DE HALLAZGO (detalle + edición) ────────────────────────────
// Un único drawer lateral (markup en vulns.html) con dos modos: 'view' arma
// el detalle acá; 'edit' muestra el formulario de alta/edición. Se navega
// con ‹ / › por la lista tal como se ve (agrupada por severidad).
let _vdOpenId     = null;      // hallazgo abierto (null en un alta)
let _vdMode       = null;      // 'view' | 'edit' | null (cerrado)
let _vdSnapshot   = '';        // estado del formulario al abrir, para avisar cambios sin guardar
let _vdOpenProofs = new Set(); // HTTP proofs expandidos del hallazgo abierto
let _vdNotesBase  = '';        // notas de retest tal como se pintaron (para no pisar un borrador)
let _vdReturnFocus = null;

const _VD_CVSS_METRICS = [
  ['AV', 'Attack Vector',     { N:'Network', A:'Adjacent', L:'Local', P:'Physical' }],
  ['AC', 'Attack Complexity', { L:'Low', H:'High' }],
  ['PR', 'Privileges',        { N:'None', L:'Low', H:'High' }],
  ['UI', 'User Interaction',  { N:'None', R:'Required' }],
  ['S',  'Scope',             { U:'Unchanged', C:'Changed' }],
  ['C',  'Confidentiality',   { N:'None', L:'Low', H:'High' }],
  ['I',  'Integrity',         { N:'None', L:'Low', H:'High' }],
  ['A',  'Availability',      { N:'None', L:'Low', H:'High' }],
];

function _vdOrder() {
  const bySev = _vulnsBySeverity();
  return SEVERITY_ORDER.flatMap(s => bySev[s].map(v => v.id));
}

function _vdSec(label, html, action = '') {
  return html ? `<div class="drw-sec"><div class="drw-sec-label">${label}${action ? `<span class="vd-sec-action">${action}</span>` : ''}</div>${html}</div>` : '';
}

function _vdUpload(id, phase, label) {
  return `<label class="btn btn-ghost ccp-btn vd-upload">${icon('upload',{size:11})} ${label}
    <input type="file" accept="image/*" hidden onchange="addEvidenceFile('${id}',this,'${phase}')"></label>`;
}

function _vdShots(id, list) {
  return `<div class="ccp-shots vd-shots">${list.map(({ img, i }) => `
    <button type="button" class="ccp-shot" onclick="openEvidenceViewer('${id}',${i})" title="${esc(img.name || '')}">
      <img src="${esc(img.data || '')}" alt="${esc(img.name || '')}" loading="lazy">
      <span class="ccp-shot-name">${esc(img.name || `evidencia ${i + 1}`)}</span>
    </button>`).join('')}</div>`;
}

function _vdHead(v) {
  const id = esc(v.id);
  const score = _cvssScoreOf(v);
  const chips = [
    v.target_host ? `<span class="ccp-chip ccp-chip-target">${esc(v.target_host)}</span>` : '',
    `<span class="ccp-chip">${esc(v.category || 'Custom')}</span>`,
    score != null ? `<span class="ccp-chip ccp-chip-cvss" style="--ccp-cvss:${_cvssColor(score)}">CVSS ${score.toFixed(1)}</span>` : '',
    v.cwe ? `<span class="ccp-chip">${esc(v.cwe)}</span>` : '',
    ...(v.compliance_tags || []).map(t => complianceBadge(t)),
    v.ai_generated ? `<span class="ccp-chip vr-flag-ai" title="Propuesto por el AI Agent">${icon('sparkles',{size:10})} AI</span>` : '',
    !v.client_visible ? `<span class="ccp-chip vd-chip-muted" title="No visible en el portal del cliente">${icon('eye-off',{size:10})} Oculto</span>` : '',
  ].join('');
  const status = v.status === 'done' ? `<span class="vd-status is-done">confirmado</span>`
    : v.status === 'fail' ? `<span class="vd-status is-fail">vulnerable</span>` : '';
  const editor = v.editor_username ? `
    <div class="ccp-drw-by vd-by">
      ${avatarHtml(displayName(v, 'editor_'), memberRoleColor(v.updated_by, v.editor_color||'#7c3aed'), 16, v.editor_avatar_url||null)}
      <span>editado por ${esc(displayName(v, 'editor_'))} · ${esc(timeAgo(v.updated_at))}</span>
    </div>` : '';
  return `
    <button class="drw-close" onclick="closeVulnDetail()" title="Cerrar (Esc)">${icon('x', { size: 16 })}</button>
    <div class="drw-id">
      ${_vrCheck(v)}
      <span class="vd-kind">Hallazgo</span>
      ${severityBadge(v.severity)}
      ${status}
      ${v.remediation_status && v.remediation_status !== 'open' ? remediationBadge(v.remediation_status) : ''}
    </div>
    <div class="drw-title" id="vd-title">${esc(v.name)}</div>
    <div class="drw-meta">${chips}</div>
    ${editor}`;
}

function _vdBody(v) {
  const id = esc(v.id);

  // CVSS: puntaje + vector + desglose de las 8 métricas.
  const score = _cvssScoreOf(v);
  const m = parseCVSSVector(v.cvss_vector);
  const cvssH = (score != null || v.cvss_vector) ? `
    <div class="vd-cvss-head">
      ${score != null ? `<span class="vd-cvss-num" style="color:${_cvssColor(score)}">${score.toFixed(1)}</span>
        <span class="sev-badge sev-${_cvssSevClass(score)}">${_cvssLabel(score)}</span>` : ''}
      ${v.cvss_vector ? `<code class="ccp-vector">${esc(v.cvss_vector)}</code>
        <button class="copy-btn" onclick="copyText(this,'${btoa(encodeURIComponent(v.cvss_vector))}')">copy</button>` : ''}
    </div>
    ${m ? `<div class="drw-cvss vd-cvss-grid">${_VD_CVSS_METRICS.map(([k, label, vals]) => `
      <div class="drw-cvss-cell">
        <div class="drw-cvss-label">${label}</div>
        <div class="drw-cvss-val">${esc(vals[m[k]] || m[k] || '—')}</div>
      </div>`).join('')}</div>` : ''}` : '';

  const complianceH = (v.compliance_tags || []).map(t => `
    <div class="item-row"><span class="compliance-opt-id">${esc(t.control_id)}</span><span class="item-text">${esc(t.title)}</span></div>`).join('');

  const items = v.items || [];
  const itemsDone = items.filter((_, i) => v.checked_items?.[i]).length;
  const itemsH = items.map((item, idx) => {
    const chk = v.checked_items?.[idx] || false;
    return `<div class="item-row vd-item">
      <div class="item-checkbox ${chk ? 'checked' : ''}" id="vd-item-${idx}" role="checkbox" tabindex="0" aria-checked="${chk}"
        onclick="toggleCustomItem('${id}',${idx},this)"
        onkeydown="if(event.key===' '||event.key==='Enter'){event.preventDefault();this.click()}">${chk ? icon('check',{size:11}) : ''}</div>
      <span class="item-text ${chk ? 'done' : ''}">${esc(item)}</span>
    </div>`;
  }).join('');

  const payH = (v.payloads || []).map(p => `<div class="payload-row">
      <div class="payload-code">${esc(p)}</div>
      <button class="copy-btn" onclick="copyText(this,'${btoa(encodeURIComponent(p))}')">copy</button>
    </div>`).join('');

  const evidAll      = (v.evidence || []).map((img, i) => ({ img, i }));
  const evidOriginal = evidAll.filter(e => (e.img.phase || 'original') === 'original');
  const evidRetest   = evidAll.filter(e => e.img.phase === 'retest');

  const proofs = v.http_proofs || [];
  const proofsH = proofs.map((pr, i) => {
    const open = _vdOpenProofs.has(i);
    return `
    <div class="http-proof${open ? ' is-open' : ''}" id="http-proof-${id}-${i}">
      <div class="http-proof-head ccp-proof-head" onclick="_vdToggleProof(${i})">
        <span class="http-proof-method">${esc(pr.method || 'HTTP')}</span>
        <span class="http-proof-label">Proof #${i + 1}</span>
        <label class="http-proof-include" title="Incluir en reporte" onclick="event.stopPropagation()">
          <input type="checkbox" ${pr.include !== false ? 'checked' : ''} onchange="toggleHttpProofInclude('${id}',${i},this.checked)">
          <span>reporte</span>
        </label>
        <button class="http-proof-edit-btn" onclick="event.stopPropagation();editHttpProof('${id}',${i})" title="Editar">${icon('square-pen',{size:11})}</button>
        <span class="http-proof-toggle">${icon('chevron-right',{size:11})}</span>
      </div>
      <div class="http-proof-body${open ? ' open' : ''}">
        ${pr.request  ? `<div class="http-proof-section-label">Request</div><pre class="http-proof-code">${numberedCode(pr.request)}</pre>` : ''}
        ${pr.response ? `<div class="http-proof-section-label">Response</div><pre class="http-proof-code">${numberedCode(pr.response)}</pre>` : ''}
        ${pr.annotation ? `<div class="http-proof-section-label">Anotación</div><div class="http-proof-annotation md-body">${renderMd(pr.annotation)}</div>` : ''}
      </div>
    </div>`;
  }).join('');

  // Estado de remediación: las acciones dependen del estado actual.
  const remStatus = v.remediation_status || 'open';
  const remBtn = (status, label, cls = 'btn-ghost') =>
    `<button class="btn ${cls} ccp-btn" onclick="setRemediationStatus('${id}','${status}')">${label}</button>`;
  const remActionsH = remStatus === 'open'
    ? remBtn('remediated', 'Marcar como remediado')
    : remStatus === 'remediated'
    ? remBtn('verified_closed', 'Verificar y cerrar', 'btn-prim') + remBtn('not_remediated', 'Marcar como no remediado', 'btn-ghost ccp-btn-reject') + remBtn('open', 'Reabrir')
    : remStatus === 'not_remediated'
    ? remBtn('remediated', 'Marcar como remediado') + remBtn('open', 'Reabrir')
    : remBtn('open', 'Reabrir', 'btn-ghost ccp-btn-reject');
  const remTrailH = [
    v.remediated_at ? `Remediado: ${new Date(v.remediated_at).toLocaleDateString()}` : '',
    v.verified_at   ? `Verificado: ${new Date(v.verified_at).toLocaleDateString()}${v.verifier_username ? ' por ' + esc(displayName(v, 'verifier_')) : ''}` : '',
  ].filter(Boolean).join(' · ');

  // Retest con acento propio (mismo color que "Notas de Retest" en el
  // reporte): es la parte del ciclo de vida que más importa distinguir.
  const retestH = `
    <div class="vd-retest">
      <div class="vd-field">
        <label class="vd-field-label" for="vd-retest-date">Fecha</label>
        <input type="date" class="form-input vd-retest-date" id="vd-retest-date" value="${v.retest_date ? esc(v.retest_date.slice(0,10)) : ''}" onchange="setRetestDate('${id}', this.value)">
      </div>
      <div class="vd-field">
        <label class="vd-field-label" for="vd-retest-notes">Notas — qué se probó y qué resultado se observó</label>
        <textarea class="form-input note-textarea" id="vd-retest-notes" rows="3" placeholder="Ej: se reintentó la validación del ticket QR con parámetros forjados; el endpoint ahora rechaza la solicitud...">${esc(v.retest_notes || '')}</textarea>
        <div class="vd-row-end">
          <button class="btn btn-prim ccp-btn" onclick="setRetestNotes('${id}', document.getElementById('vd-retest-notes').value)">Guardar nota</button>
        </div>
      </div>
      <div class="vd-field">
        <div class="vd-field-label vd-label-row">
          <span>Evidencia de retest${evidRetest.length ? ` (${evidRetest.length})` : ''}</span>
          ${_vdUpload(id, 'retest', 'Agregar')}
        </div>
        ${evidRetest.length ? _vdShots(id, evidRetest) : `<div class="ccp-muted">Sin evidencia de retest todavía</div>`}
      </div>
    </div>`;

  return [
    _vdSec('Descripción', v.description ? `<div class="drw-prose md-body">${renderMd(v.description)}</div>` : ''),
    _vdSec('Remediación', v.remediation ? `<div class="drw-prose md-body">${renderMd(v.remediation)}</div>` : ''),
    _vdSec('CVSS v3.1', cvssH),
    _vdSec('Cobertura PCI-DSS', complianceH),
    _vdSec(`Checklist <span class="ccp-sec-hint">· ${itemsDone}/${items.length}</span>`, itemsH),
    _vdSec(`Payloads (${(v.payloads || []).length})`, payH),
    _vdSec('Notas', v.notes ? `<div class="payload-code vd-notes">${esc(v.notes)}</div>` : ''),
    // Siempre visibles: tienen acciones (subir evidencia, remediación, retest).
    _vdSec(`Evidencia (${evidOriginal.length})`,
      evidOriginal.length ? _vdShots(id, evidOriginal) : `<div class="ccp-muted">Sin evidencia todavía</div>`,
      _vdUpload(id, 'original', 'Agregar evidencia')),
    _vdSec(`HTTP proofs (${proofs.length})`, proofsH),
    _vdSec('Estado de remediación', `
      <div class="vd-rem-row">${remediationBadge(remStatus)}${remActionsH}</div>
      ${remTrailH ? `<div class="vd-trail">${remTrailH}</div>` : ''}`),
    _vdSec(`${icon('rotate-ccw',{size:11})} Retest`, retestH),
  ].join('');
}

function _vdFoot(v) {
  const id = esc(v.id);
  const order = _vdOrder();
  const idx = order.indexOf(v.id);
  const n = order.length;
  return `
    <div class="ccp-foot-nav">
      <button class="btn btn-ghost ccp-btn" onclick="stepVulnDetail(-1)" ${idx <= 0 ? 'disabled' : ''} title="Anterior (←)">‹ anterior</button>
      <span class="ccp-pos">${idx + 1} / ${n}</span>
      <button class="btn btn-ghost ccp-btn" onclick="stepVulnDetail(1)" ${idx >= n - 1 ? 'disabled' : ''} title="Siguiente (→)">siguiente ›</button>
    </div>
    <div class="ccp-foot-actions">
      <button class="btn btn-ghost ccp-btn-reject" onclick="deleteVuln('${id}',event)" title="Eliminar hallazgo">${icon('trash-2',{size:12})} Eliminar</button>
      ${canActForClient() ? `<button class="btn ${v.client_visible ? 'vd-published' : ''}" onclick="toggleVulnPublish('${id}',event)" title="${_vrPublishTitle(v)}">
        ${icon(v.client_visible ? 'eye' : 'eye-off',{size:12})} ${v.client_visible ? 'Publicado' : 'Publicar'}</button>` : ''}
      <button class="btn btn-prim" onclick="openEditVuln('${id}',event)">${icon('square-pen',{size:12})} Editar</button>
    </div>`;
}

// keep = redibujo del mismo hallazgo tras un cambio: conserva scroll, foco
// y el borrador de las notas de retest.
function _vdRenderView(keep) {
  const v = state.customVulns.find(x => x.id === _vdOpenId);
  if (!v) return;
  const body = document.getElementById('vd-body');
  let prev = null;
  if (keep) {
    const notes = document.getElementById('vd-retest-notes');
    const active = document.activeElement;
    prev = {
      top:   body.scrollTop,
      draft: notes && notes.value !== _vdNotesBase ? notes.value : null,
      focus: active && body.contains(active) && active.id ? active.id : null,
    };
  }
  document.getElementById('vd-head').innerHTML = _vdHead(v);
  body.innerHTML = _vdBody(v);
  document.getElementById('vd-foot').innerHTML = _vdFoot(v);
  _vdNotesBase = v.retest_notes || '';
  document.querySelectorAll('.vr-row.is-active').forEach(r => r.classList.remove('is-active'));
  document.getElementById(`vuln-${v.id}`)?.classList.add('is-active');
  if (prev) {
    if (prev.draft != null) document.getElementById('vd-retest-notes').value = prev.draft;
    body.scrollTop = prev.top;
    if (prev.focus) document.getElementById(prev.focus)?.focus({ preventScroll: true });
  } else {
    body.scrollTop = 0;
  }
}

function _vdShow(mode) {
  const bd  = document.getElementById('vd-backdrop');
  const drw = document.getElementById('vd-drw');
  if (!drw) return;
  _vdMode = mode;
  drw.classList.toggle('is-edit', mode === 'edit');
  drw.classList.toggle('is-add', mode === 'edit' && !_editingVulnId);
  drw.setAttribute('aria-labelledby', mode === 'edit' ? 'modal-title' : 'vd-title');
  if (!drw.classList.contains('open')) {
    _vdReturnFocus = document.activeElement;
    drw.offsetHeight; // reflow para que se pinte primero el translateX(100%)
    bd.classList.add('open');
    drw.classList.add('open');
    document.addEventListener('keydown', _vdOnKey);
  }
}

function openVulnDetail(id) {
  if (!state.customVulns.some(v => v.id === id)) return;
  if (_vdOpenId !== id) _vdOpenProofs = new Set([0]); // el primer proof abierto, como en propuestas
  _vdOpenId = id;
  _vdShow('view');
  _vdRenderView(false);
  document.getElementById('vd-drw').focus({ preventScroll: true });
}

function _vdEnterEdit(id) {
  _vdOpenId = id;
  _tplClose();
  document.getElementById('vd-edit-body').scrollTop = 0;
  _vdShow('edit');
  _vdSnapshot = _vdFormState();
  // La lista de PCI-DSS llega async: la selección vive en _selectedComplianceIds,
  // que ya está seteada, así que el snapshot no depende de que termine.
  document.getElementById('modal-vuln-name').focus({ preventScroll: true });
}

function stepVulnDetail(delta) {
  const order = _vdOrder();
  const next = order[order.indexOf(_vdOpenId) + delta];
  if (_vdMode === 'view' && next) openVulnDetail(next);
}

// force = sin preguntar por cambios sin guardar (tras guardar / al borrar).
function closeVulnDetail(force) {
  if (force !== true && !_vdConfirmDiscard()) return;
  const id = _vdOpenId;
  _vdMode = null;
  _vdOpenId = null;
  _editingVulnId = null;
  _tplClose();
  document.removeEventListener('keydown', _vdOnKey);
  document.getElementById('vd-backdrop')?.classList.remove('open');
  document.getElementById('vd-drw')?.classList.remove('open');
  document.querySelectorAll('.vr-row.is-active').forEach(r => r.classList.remove('is-active'));
  // El foco vuelve a la fila del hallazgo (o a donde estaba al abrir).
  const back = (id && document.getElementById(`vuln-${id}`)) || _vdReturnFocus;
  if (back?.isConnected) back.focus({ preventScroll: true });
  _vdReturnFocus = null;
}

function _vdRefresh() {
  if (_vdMode !== 'view') return; // en edición no se pisa el formulario
  if (state.customVulns.some(v => v.id === _vdOpenId)) _vdRenderView(true);
  else closeVulnDetail(true);
}

function _vdToggleProof(i) {
  if (_vdOpenProofs.has(i)) _vdOpenProofs.delete(i); else _vdOpenProofs.add(i);
  const el = document.getElementById(`http-proof-${_vdOpenId}-${i}`);
  el?.classList.toggle('is-open', _vdOpenProofs.has(i));
  el?.querySelector('.http-proof-body')?.classList.toggle('open', _vdOpenProofs.has(i));
}

function _vdFormState() {
  const root = document.getElementById('vd-edit');
  if (!root) return '';
  const vals = [...root.querySelectorAll('input:not([type=checkbox]):not(#tpl-search-input),textarea,select')].map(el => el.value);
  const cvss = _cvssModified ? (_cvssCleared ? 'cleared' : buildCVSSVector(_cvss)) : '';
  return JSON.stringify([vals, [..._selectedComplianceIds].sort(), cvss]);
}

function _vdConfirmDiscard() {
  if (_vdMode !== 'edit' || _vdFormState() === _vdSnapshot) return true;
  return confirm('Hay cambios sin guardar. ¿Descartarlos?');
}

function _vdOnKey(e) {
  if (!_vdMode || e.defaultPrevented) return;
  // Con el lightbox o el editor de proofs abiertos, las teclas son suyas.
  if (document.getElementById('img-lb') || document.querySelector('.hp-edit-ovl')) return;
  if (_vdMode === 'edit') {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); saveVuln(); }
    else if (e.key === 'Escape') { e.preventDefault(); closeVulnModal(); }
    return;
  }
  if (e.altKey || e.ctrlKey || e.metaKey) return;
  if (e.target.closest?.('input,textarea,select,[contenteditable="true"]')) return;
  if (e.key === 'Escape') { e.preventDefault(); closeVulnDetail(); }
  else if (e.key === 'ArrowLeft')  { e.preventDefault(); stepVulnDetail(-1); }
  else if (e.key === 'ArrowRight') { e.preventDefault(); stepVulnDetail(1); }
}

async function cycleVulnStatus(id, e) {
  e.stopPropagation();
  const v = state.customVulns.find(x => x.id === id);
  if (!v) return;
  const next = v.status === 'done' ? 'fail' : v.status === 'fail' ? null : 'done';
  try {
    const updated = await api.vulns.update(state.currentProject.id, id, { status: next });
    Object.assign(v, updated);
    renderCustomVulns();
    if (typeof updateDashboard === 'function') updateDashboard();
  } catch(err) { showToast(err.message, 'error'); }
}

// Publish / unpublish a finding to the client portal. Findings are hidden by
// default (opt-in): the client only ever sees what the pentester has explicitly
// published here. Mirrors cycleVulnStatus — optimistic re-render off the row
// the PATCH returns.
async function toggleVulnPublish(id, e) {
  e.stopPropagation();
  const v = state.customVulns.find(x => x.id === id);
  if (!v) return;
  try {
    const updated = await api.vulns.update(state.currentProject.id, id, { client_visible: !v.client_visible });
    Object.assign(v, updated);
    renderCustomVulns();
    showToast(updated.client_visible ? 'Hallazgo publicado en el portal del cliente' : 'Hallazgo ocultado del portal del cliente', 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

async function setRemediationStatus(vulnId, status) {
  const v = state.customVulns.find(x => x.id === vulnId);
  if (!v) return;
  try {
    const updated = await api.vulns.setRemediation(state.currentProject.id, vulnId, { remediation_status: status });
    updated.verifier_username     = status === 'verified_closed' ? state.user.username : null;
    updated.verifier_display_name = status === 'verified_closed' ? (state.user.display_name || null) : null;
    Object.assign(v, updated);
    renderCustomVulns();
    if (typeof updateDashboard === 'function') updateDashboard();
    const msg = status === 'verified_closed' ? 'Verificado y cerrado' : status === 'remediated' ? 'Marcado como remediado' : status === 'not_remediated' ? 'Marcado como no remediado' : 'Reabierto';
    showToast(msg, 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

async function setRetestDate(vulnId, date) {
  const v = state.customVulns.find(x => x.id === vulnId);
  if (!v) return;
  try {
    const updated = await api.vulns.setRemediation(state.currentProject.id, vulnId, {
      remediation_status: v.remediation_status || 'open', retest_date: date || null, retest_notes: v.retest_notes || null,
    });
    Object.assign(v, updated);
    renderCustomVulns();
    showToast('Fecha de retest guardada', 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

async function setRetestNotes(vulnId, notes) {
  const v = state.customVulns.find(x => x.id === vulnId);
  if (!v) return;
  try {
    const updated = await api.vulns.setRemediation(state.currentProject.id, vulnId, {
      remediation_status: v.remediation_status || 'open', retest_date: v.retest_date || null, retest_notes: notes,
    });
    Object.assign(v, updated);
    renderCustomVulns();
    showToast('Nota de retest guardada', 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

async function toggleCustomItem(vulnId, idx, el) {
  const v = state.customVulns.find(x => x.id === vulnId);
  if (!v) return;
  const cur = v.checked_items?.[idx] || false;
  const newChecked = { ...v.checked_items, [idx]: !cur };
  try {
    await api.vulns.update(state.currentProject.id, vulnId, { checked_items: newChecked });
    v.checked_items = newChecked;
    el.classList.toggle('checked', !cur);
    el.innerHTML = !cur ? icon('check',{size:11}) : '';
    el.nextElementSibling?.classList.toggle('done', !cur);
    renderCustomVulns(); // contador x/y de la fila y del drawer
  } catch(err) { showToast(err.message, 'error'); }
}

// ── Alta / edición (modo edición del drawer) ─────────────────────────
function openAddVulnModal() {
  _editingVulnId = null;
  document.getElementById('modal-title').textContent       = 'Nuevo hallazgo';
  document.getElementById('vd-edit-kind').textContent      = 'Nuevo hallazgo';
  document.getElementById('modal-vuln-name').value         = '';
  document.getElementById('modal-vuln-cat').value          = '';
  document.getElementById('modal-vuln-cwe').value          = '';
  document.getElementById('modal-vuln-sev').value          = 'medium';
  document.getElementById('modal-vuln-notes').value        = '';
  document.getElementById('modal-vuln-desc').value         = '';
  document.getElementById('modal-vuln-rem').value          = '';
  document.getElementById('tpl-search-input').value        = '';
  populateTargetSelect(null);
  document.getElementById('modal-items-list').innerHTML    = '';
  document.getElementById('modal-payloads-list').innerHTML = '';
  document.getElementById('vuln-error').style.display      = 'none';
  addModalRow('modal-items-list', 'Check item...');
  addModalRow('modal-payloads-list', 'Payload...', true);
  _initCVSS(null);
  renderCompliancePicker([]);
  _vdEnterEdit(null);
}

function openEditVuln(id, e) {
  e?.stopPropagation();
  const v = state.customVulns.find(x => x.id === id);
  if (!v) return;
  _editingVulnId = id;
  document.getElementById('modal-title').textContent      = v.name;
  document.getElementById('vd-edit-kind').textContent     = 'Editando hallazgo';
  document.getElementById('modal-vuln-name').value        = v.name;
  document.getElementById('modal-vuln-cat').value         = v.category || '';
  document.getElementById('modal-vuln-cwe').value         = v.cwe || '';
  document.getElementById('modal-vuln-sev').value         = v.severity || 'medium';
  document.getElementById('modal-vuln-notes').value       = v.notes || '';
  document.getElementById('modal-vuln-desc').value        = v.description || '';
  document.getElementById('modal-vuln-rem').value         = v.remediation || '';
  populateTargetSelect(v.target_id || null);
  document.getElementById('vuln-error').style.display     = 'none';
  const iList = document.getElementById('modal-items-list');
  const pList = document.getElementById('modal-payloads-list');
  iList.innerHTML = ''; pList.innerHTML = '';
  (v.items||[]).forEach(item => { addModalRow('modal-items-list','Check item...'); iList.lastChild.querySelector('input').value = item; });
  if (!v.items?.length) addModalRow('modal-items-list','Check item...');
  (v.payloads||[]).forEach(p => { addModalRow('modal-payloads-list','Payload...',true); pList.lastChild.querySelector('textarea').value = p; });
  if (!v.payloads?.length) addModalRow('modal-payloads-list','Payload...',true);
  _initCVSS(v.cvss_vector || null);
  renderCompliancePicker((v.compliance_tags || []).map(t => t.control_id));
  _vdEnterEdit(id);
}

function addModalRow(containerId, ph, isTextarea = false) {
  const row = document.createElement('div');
  row.className = 'dynamic-row';
  const field = isTextarea
    ? `<textarea class="dynamic-textarea" placeholder="${esc(ph)}"></textarea>`
    : `<input type="text" class="dynamic-input" placeholder="${esc(ph)}">`;
  row.innerHTML = `${field}<button class="btn-remove" onclick="this.parentElement.remove()">${icon('x',{size:11})}</button>`;
  document.getElementById(containerId).appendChild(row);
}

// Cancelar: vuelve al detalle del hallazgo que se editaba (o cierra el
// drawer si era un alta). Avisa si hay cambios sin guardar.
function closeVulnModal() {
  if (!_vdConfirmDiscard()) return false;
  const id = _editingVulnId;
  _editingVulnId = null;
  _tplClose();
  if (id && state.customVulns.some(v => v.id === id)) openVulnDetail(id);
  else closeVulnDetail(true);
  return true;
}

async function saveVuln() {
  const name     = document.getElementById('modal-vuln-name').value.trim();
  const category = document.getElementById('modal-vuln-cat').value.trim();
  const cwe      = document.getElementById('modal-vuln-cwe').value.trim();
  const severity = document.getElementById('modal-vuln-sev').value;
  const notes    = document.getElementById('modal-vuln-notes').value;
  const err      = document.getElementById('vuln-error');
  const btn      = document.getElementById('vuln-save-btn');
  if (btn.disabled) return; // Ctrl+Enter repetido mientras se guarda
  if (!name) { err.textContent = 'Name is required'; err.style.display = 'block'; return; }
  const description = document.getElementById('modal-vuln-desc').value;
  const remediation = document.getElementById('modal-vuln-rem').value;
  const items    = [...document.querySelectorAll('#modal-items-list .dynamic-input')].map(i => i.value.trim()).filter(Boolean);
  const payloads = [...document.querySelectorAll('#modal-payloads-list .dynamic-textarea')].map(i => i.value.trim()).filter(Boolean);
  btn.disabled = true;
  try {
    const target_id = document.getElementById('modal-vuln-target')?.value || null;
    const payload = { name, category: category||'Custom', severity, items, payloads, notes, description, remediation, target_id: target_id||null, cwe: cwe||null, compliance_tags: collectComplianceTags() };
    if (_cvssModified) {
      if (_cvssCleared) {
        payload.cvss_vector = null;
        payload.cvss_score  = null;
      } else {
        payload.cvss_vector = buildCVSSVector(_cvss);
        payload.cvss_score  = calcCVSSScore(_cvss);
      }
    }
    let savedId = _editingVulnId;
    if (_editingVulnId) {
      const updated = await api.vulns.update(state.currentProject.id, _editingVulnId, payload);
      const idx = state.customVulns.findIndex(v => v.id === _editingVulnId);
      if (idx > -1) state.customVulns[idx] = { ...state.customVulns[idx], ...updated };
    } else {
      const created = await api.vulns.create(state.currentProject.id, payload);
      state.customVulns.push(created);
      savedId = created?.id || null;
    }
    // Guardado: se vuelve al detalle de ese hallazgo (también tras un alta).
    _editingVulnId = null;
    _tplClose();
    renderCustomVulns();
    if (savedId && state.customVulns.some(v => v.id === savedId)) openVulnDetail(savedId);
    else closeVulnDetail(true);
    if (typeof updateDashboard === 'function') updateDashboard();
    showToast('Saved', 'success');
  } catch(e) { err.textContent = e.message; err.style.display = 'block'; }
  finally { btn.disabled = false; }
}

// ── AI helpers ───────────────────────────────────────────────────────
async function _aiGenerate(type, context, btnId, btnLabel) {
  const btn = document.getElementById(btnId);
  if (btn) { btn.disabled = true; btn.classList.add('loading'); btn.textContent = '…'; }
  try {
    return await request('POST', `/projects/${state.currentProject.id}/ai/generate`, { type, context });
  } finally {
    if (btn) { btn.disabled = false; btn.classList.remove('loading'); btn.innerHTML = `${icon('sparkles',{size:11})} ${btnLabel}`.trim(); }
  }
}

function _collectVulnContext() {
  const targetSel = document.getElementById('modal-vuln-target');
  const targetHost = targetSel?.selectedOptions?.[0]?.text?.replace(/^[^\s]+\s/, '') || '';
  const payloads = [...document.querySelectorAll('#modal-payloads-list .dynamic-textarea')]
    .map(i => i.value.trim()).filter(Boolean);
  return {
    name:        document.getElementById('modal-vuln-name').value.trim(),
    category:    document.getElementById('modal-vuln-cat').value.trim(),
    notes:       document.getElementById('modal-vuln-notes').value.trim(),
    description: document.getElementById('modal-vuln-desc').value.trim(),
    target:      targetHost === '— No target —' ? '' : targetHost,
    payloads,
  };
}

async function aiDraft() {
  const ctx = _collectVulnContext();
  if (!ctx.name) { showToast('Enter a name first', 'error'); return; }
  try {
    const result = await _aiGenerate('vuln-draft', ctx, 'ai-draft-btn', 'Draft');
    if (result.name)        document.getElementById('modal-vuln-name').value = result.name;
    if (result.category)    document.getElementById('modal-vuln-cat').value  = result.category;
    if (result.severity)    { document.getElementById('modal-vuln-sev').value  = result.severity; }
    if (result.description) document.getElementById('modal-vuln-desc').value = result.description;
    if (result.remediation) document.getElementById('modal-vuln-rem').value  = result.remediation;
    showToast('Draft generated', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function aiRemediation() {
  const ctx = _collectVulnContext();
  if (!ctx.name && !ctx.description) { showToast('Add a name or description first', 'error'); return; }
  try {
    const result = await _aiGenerate('remediation', ctx, 'ai-rem-btn', 'Suggest');
    if (result.remediation) document.getElementById('modal-vuln-rem').value = result.remediation;
    showToast('Remediation generated', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function aiSeverity() {
  const ctx = _collectVulnContext();
  if (!ctx.name) { showToast('Enter a name first', 'error'); return; }
  try {
    const result = await _aiGenerate('severity-suggest', { name: ctx.name, category: ctx.category }, 'ai-sev-btn', 'Suggest');
    if (result.severity) {
      document.getElementById('modal-vuln-sev').value = result.severity;
      showToast(`${result.severity.charAt(0).toUpperCase() + result.severity.slice(1)}${result.reason ? ' — ' + result.reason : ''}`, 'success');
    }
  } catch(e) { showToast(e.message, 'error'); }
}

async function aiCWE() {
  const ctx = _collectVulnContext();
  if (!ctx.name) { showToast('Enter a name first', 'error'); return; }
  try {
    const result = await _aiGenerate('cwe', ctx, 'ai-cwe-btn', '');
    if (result.cwe) {
      document.getElementById('modal-vuln-cwe').value = result.cwe;
      showToast(`${result.cwe}${result.cwe_name ? ' — ' + result.cwe_name : ''}`, 'success');
    }
  } catch(e) { showToast(e.message, 'error'); }
}

async function deleteVuln(id, e) {
  e?.stopPropagation();
  if (!confirm('Delete this vulnerability?')) return;
  try {
    await api.vulns.delete(state.currentProject.id, id);
    state.customVulns = state.customVulns.filter(v => v.id !== id);
    renderCustomVulns();
    if (typeof updateDashboard === 'function') updateDashboard();
    showToast('Deleted', 'error');
  } catch(err) { showToast(err.message, 'error'); }
}

function populateTargetSelect(selectedId) {
  const sel = document.getElementById('modal-vuln-target');
  if (!sel) return;
  const inScope = (state.targets||[]).filter(t => t.scope==='in');
  sel.innerHTML = '<option value="">— No target —</option>' +
    inScope.map(t => `<option value="${t.id}" ${t.id===selectedId?'selected':''}>${esc(t.host)}</option>`).join('');
}

// ── Import Scan ─────────────────────────────────────────────────────────
let _importFile = null;

function openImportModal() {
  _importFile = null;
  document.getElementById('import-filename').textContent     = '';
  document.getElementById('import-error').textContent        = '';
  document.getElementById('import-file-input').value         = '';
  document.getElementById('import-submit-btn').style.display = 'none';
  document.getElementById('import-idle').style.display       = '';
  document.getElementById('import-loading').style.display    = 'none';
  document.getElementById('import-result').style.display     = 'none';
  document.getElementById('import-modal').classList.add('open');
}

function closeImportModal() {
  document.getElementById('import-modal').classList.remove('open');
}

function handleImportFile(file) {
  if (!file) return;
  const ext = file.name.toLowerCase();
  if (!ext.endsWith('.xml') && !ext.endsWith('.nessus')) {
    document.getElementById('import-error').textContent = 'Please select an XML or .nessus file.';
    return;
  }
  _importFile = file;
  document.getElementById('import-filename').textContent    = file.name;
  document.getElementById('import-error').textContent       = '';
  document.getElementById('import-submit-btn').style.display = '';
}

function handleImportDrop(e) {
  e.preventDefault();
  document.getElementById('import-drop-zone').style.borderColor = 'var(--br1)';
  const file = e.dataTransfer?.files?.[0];
  if (file) handleImportFile(file);
}

async function submitImport() {
  if (!_importFile) return;
  const pid = state.currentProject?.id;
  document.getElementById('import-idle').style.display       = 'none';
  document.getElementById('import-loading').style.display    = '';
  document.getElementById('import-submit-btn').style.display = 'none';

  try {
    const res = await api.import.scan(pid, _importFile);
    document.getElementById('import-loading').style.display  = 'none';
    document.getElementById('import-result').style.display   = '';

    const toolName = { burp: 'Burp Suite', nessus: 'Nessus', zap: 'OWASP ZAP', nmap: 'Nmap' }[res.format] || 'scanner';
    // Nmap no reporta vulnerabilidades — a diferencia de los otros 3
    // formatos, puebla puertos/servicios directamente (ver import.js
    // parseNmap), así que "imported" cuenta puertos, no findings.
    const unit = res.format === 'nmap' ? 'port' : 'finding';
    let text = `Imported <strong>${res.imported}</strong> ${unit}${res.imported !== 1 ? 's' : ''} from ${toolName}`;
    if (res.targets_created > 0)
      text += ` · Created <strong>${res.targets_created}</strong> new target${res.targets_created !== 1 ? 's' : ''}`;
    document.getElementById('import-result-msg').innerHTML = text;

    // Reportado tarde en revisión: un import podía crear targets nuevos
    // (cualquiera de los 4 formatos) sin que state.targets se enterara —
    // quedaban invisibles en el resto de la app (selector de la AI Agent,
    // conteos del dashboard, etc.) hasta un reload completo de la página.
    const [freshVulns, freshTargets] = await Promise.all([api.vulns.list(pid), api.targets.list(pid)]);
    state.customVulns = freshVulns.vulns || freshVulns;
    state.targets = freshTargets;
    renderCustomVulns();
    showToast(`Imported ${res.imported} ${unit}${res.imported !== 1 ? 's' : ''} from ${toolName}`, 'success');
  } catch (err) {
    document.getElementById('import-loading').style.display    = 'none';
    document.getElementById('import-idle').style.display       = '';
    document.getElementById('import-error').textContent        = err.message || 'Import failed';
    document.getElementById('import-submit-btn').style.display = '';
  }
}

async function addEvidenceFile(vulnId, input, phase) {
  const file = input.files?.[0];
  if (!file) return;
  if (file.size > 3 * 1024 * 1024) { showToast('Imagen demasiado grande (max 3 MB)', 'error'); input.value = ''; return; }
  const v = state.customVulns.find(x => x.id === vulnId);
  if (!v) return;
  const reader = new FileReader();
  reader.onload = async (e) => {
    const evidence = [...(v.evidence||[]), { data: e.target.result, name: file.name, phase: phase || 'original' }];
    try {
      const updated = await api.vulns.update(state.currentProject.id, vulnId, { evidence });
      Object.assign(v, updated);
      renderCustomVulns();
      showToast('Evidencia agregada', 'success');
    } catch(err) { showToast(err.message, 'error'); }
  };
  reader.readAsDataURL(file);
}

async function toggleHttpProofInclude(vulnId, idx, checked) {
  const v = state.customVulns.find(x => x.id === vulnId);
  if (!v) return;
  const prev   = v.http_proofs;
  const proofs = (v.http_proofs || []).map((p, i) => i === idx ? { ...p, include: checked } : p);
  v.http_proofs = proofs;
  try {
    await api.vulns.update(state.currentProject.id, vulnId, { http_proofs: proofs });
  } catch (err) {
    v.http_proofs = prev;
    showToast(err.message, 'error');
  }
  renderCustomVulns();
}

function editHttpProof(vulnId, idx) {
  const v = state.customVulns.find(x => x.id === vulnId);
  if (!v) return;
  const proof = (v.http_proofs || [])[idx];
  if (!proof) return;

  const overlay = document.createElement('div');
  overlay.className = 'hp-edit-ovl'; // el drawer no toma Esc/flechas mientras está abierto
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:9999;display:flex;align-items:center;justify-content:center';

  const modal = document.createElement('div');
  modal.style.cssText = 'background:var(--bg2);border:1px solid var(--b2);border-radius:10px;padding:20px;width:700px;max-width:95vw;max-height:90vh;display:flex;flex-direction:column;gap:12px';

  const taStyle = 'width:100%;font-family:var(--mono);font-size:11px;background:var(--bg);border:1px solid var(--b2);border-radius:6px;color:var(--t1);padding:8px;resize:vertical;line-height:1.5;box-sizing:border-box';

  const reqTA = document.createElement('textarea');
  reqTA.style.cssText = taStyle; reqTA.style.height = '180px';
  reqTA.value = proof.request || '';

  const resTA = document.createElement('textarea');
  resTA.style.cssText = taStyle; resTA.style.height = '180px';
  resTA.value = proof.response || '';

  const annTA = document.createElement('textarea');
  annTA.style.cssText = taStyle; annTA.style.height = '80px'; annTA.style.fontFamily = 'inherit';
  annTA.placeholder = 'Ej: El parámetro `name` en la línea 3 se refleja sin sanitizar. Payload: `<script>alert(1)</script>`';
  annTA.value = proof.annotation || '';

  modal.innerHTML = `
    <div style="font-size:13px;font-weight:600;color:var(--t1)">
      Editar HTTP Proof #${idx+1}
      <span style="font-family:var(--mono);font-size:10px;color:var(--t3);margin-left:8px">${esc(proof.method||'HTTP')}</span>
    </div>
    <div style="overflow-y:auto;flex:1;display:flex;flex-direction:column;gap:10px;min-height:0">
      <div>
        <div class="http-proof-section-label" style="margin-bottom:4px">Request</div>
        <div id="hp-req-slot"></div>
      </div>
      <div>
        <div class="http-proof-section-label" style="margin-bottom:4px">Response</div>
        <div id="hp-res-slot"></div>
      </div>
      <div>
        <div class="http-proof-section-label" style="margin-bottom:4px">Anotación <span style="text-transform:none;letter-spacing:0;font-size:9px;color:var(--t3)">(markdown)</span></div>
        <div id="hp-ann-slot"></div>
      </div>
    </div>
    <div style="display:flex;gap:8px;justify-content:flex-end;flex-shrink:0">
      <button id="hp-cancel" style="padding:6px 14px;background:var(--bg3);border:1px solid var(--b2);border-radius:6px;color:var(--t2);font-size:12px;cursor:pointer">Cancelar</button>
      <button id="hp-save"   style="padding:6px 14px;background:var(--a);border:none;border-radius:6px;color:#fff;font-size:12px;cursor:pointer;font-weight:600">Guardar</button>
    </div>`;

  modal.querySelector('#hp-req-slot').appendChild(reqTA);
  modal.querySelector('#hp-res-slot').appendChild(resTA);
  modal.querySelector('#hp-ann-slot').appendChild(annTA);
  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  modal.querySelector('#hp-cancel').onclick = () => overlay.remove();
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };

  modal.querySelector('#hp-save').onclick = async () => {
    const proofs = (v.http_proofs || []).map((p, i) =>
      i === idx ? { ...p, request: reqTA.value, response: resTA.value, annotation: annTA.value } : p
    );
    try {
      await api.vulns.update(state.currentProject.id, vulnId, { http_proofs: proofs });
    } catch (err) { showToast(err.message, 'error'); return; }
    v.http_proofs = proofs;
    overlay.remove();
    renderCustomVulns();
  };
}

window.setCVSSMetric      = setCVSSMetric;
window.toggleCVSSSection  = toggleCVSSSection;
window.copyCVSSVector     = copyCVSSVector;
window.clearCVSS          = clearCVSS;
window.renderCustomVulns  = renderCustomVulns;
window.openVulnDetail     = openVulnDetail;
window.closeVulnDetail    = closeVulnDetail;
window.stepVulnDetail     = stepVulnDetail;
window.toggleVulnPublish  = toggleVulnPublish;
window.buildVulnCard      = buildVulnCard;
window.openEvidenceViewer = openEvidenceViewer;
window.openImageLightbox  = openImageLightbox;
window.cycleVulnStatus    = cycleVulnStatus;
window.toggleCustomItem   = toggleCustomItem;
window.setRemediationStatus = setRemediationStatus;
window.setRetestDate         = setRetestDate;
window.setRetestNotes        = setRetestNotes;
window.openAddVulnModal   = openAddVulnModal;
window.openEditVuln       = openEditVuln;
window.addModalRow        = addModalRow;
window.closeVulnModal     = closeVulnModal;
window.saveVuln           = saveVuln;
window.deleteVuln         = deleteVuln;
window.severityBadge      = severityBadge;
window.SEVERITY_ORDER     = SEVERITY_ORDER;
window.SEVERITY_LABELS    = SEVERITY_LABELS;
window.aiDraft            = aiDraft;
window.aiRemediation      = aiRemediation;
window.aiCWE              = aiCWE;
window.aiSeverity         = aiSeverity;
window.openImportModal        = openImportModal;
window.closeImportModal       = closeImportModal;
window.handleImportFile       = handleImportFile;
window.handleImportDrop       = handleImportDrop;
window.submitImport           = submitImport;
window.toggleHttpProofInclude = toggleHttpProofInclude;
window.editHttpProof          = editHttpProof;
window.ensurePciControls      = ensurePciControls;
window.complianceBadge        = complianceBadge;
window.renderCompliancePicker = renderCompliancePicker;
window.toggleComplianceTag    = toggleComplianceTag;
window.collectComplianceTags  = collectComplianceTags;
// ── PROPUESTAS DE CLAUDE CODE ─────────────────────────────────────────
// Hallazgos, cambios a hallazgos existentes ('finding_update'), notas y
// targets que Claude Code propuso vía MCP. Las de contenido del informe
// ('report_section') se revisan en el editor del informe (export.html), no
// acá: este inbox las excluye. Viven aparte
// (mcp_proposals), no en custom_vulns: no cuentan en el dashboard ni llegan
// al reporte/portal hasta que un writer los aprueba acá. Aprobar un hallazgo
// lo crea como cualquier otro, sin publicar al cliente.
//
// El inbox es una lista compacta; la revisión se hace en un drawer lateral
// que permite pasar de una propuesta a la siguiente sin cerrarlo.
let _ccProposals  = [];
let _ccpOpenId    = null;  // propuesta abierta en el drawer
let _ccpBusy      = false; // aprobación/rechazo en curso desde el drawer
const _ccpEvidence = {};   // capturas ya descargadas, por id de propuesta
// Scope elegido para cada propuesta de TARGET. Sin valor por defecto a
// propósito: Claude Code no decide el alcance y aprobar sin elegir no se
// puede (el backend también lo exige).
const _ccpScope = {};
const CCP_SCOPE_LABELS = { in: 'In scope', out: 'Out of scope' };

const CCP_IMG_RE = /^data:image\/(png|jpeg|webp);base64,/;

function _ccpCanReview() {
  return ['owner', 'editor', 'pentester'].includes(state.currentProject?.member_role);
}

function _ccpTitle(pr) {
  const pl = pr.payload || {};
  if (pr.kind === 'finding') return esc(pl.title || 'Hallazgo sin título');
  if (pr.kind === 'target')  return esc(pl.host || 'Target sin host');
  if (pr.kind === 'finding_update') return `Cambios en ${esc(pl.entity_name || 'hallazgo')}`;
  return `Nota en ${esc(pl.entity_name || pr.entity_type)}`;
}

function _ccpKindLabel(pr) {
  if (pr.kind === 'finding') return 'Hallazgo';
  if (pr.kind === 'target')  return `Target (${esc(pr.payload?.type || 'domain')})`;
  if (pr.kind === 'finding_update') {
    const n = _ccpUpdateCount(pr);
    return `Cambio de hallazgo (${n} campo${n === 1 ? '' : 's'})`;
  }
  return `Nota (${esc(pr.entity_type)})`;
}

// ── Cambios propuestos a un hallazgo existente (finding_update) ───────
// El payload trae SOLO los campos que cambian (+ entity_name); el listado
// trae además current_finding con los valores actuales para el antes/después.
const CCP_UPDATE_FIELDS = [
  ['title', 'Título'], ['severity', 'Severidad'], ['category', 'Categoría'],
  ['cvss_score', 'CVSS score'], ['cvss_vector', 'Vector CVSS'], ['cwe', 'CWE'],
  ['description', 'Descripción'], ['remediation', 'Remediación'], ['http_proofs', 'HTTP proofs'],
];

function _ccpUpdateFields(pr) {
  const pl = pr.payload || {};
  return CCP_UPDATE_FIELDS.filter(([k]) => pl[k] !== undefined);
}

// Las capturas cuentan como un campo más del cambio.
function _ccpUpdateCount(pr) {
  return _ccpUpdateFields(pr).length + ((pr.evidence_uploads || []).length ? 1 : 0);
}

function _ccpUpdateValue(field, v, cls) {
  if (v == null || v === '' || (Array.isArray(v) && !v.length)) return `<span class="ccp-muted">(vacío)</span>`;
  if (field === 'severity') return severityBadge(v);
  if (field === 'description' || field === 'remediation') return `<div class="drw-prose md-body">${renderMd(v)}</div>`;
  if (field === 'http_proofs') return _ccpProofsHtml(v);
  return `<code class="ccp-vector ${cls}">${esc(String(v))}</code>`;
}

function _ccpUpdateHtml(pr) {
  const pl = pr.payload || {};
  const cur = pr.current_finding;
  const gone = !cur ? `<div class="ccp-diff-gone">${icon('triangle-alert', { size: 12 })} El hallazgo ya no existe: esta propuesta no se puede aprobar.</div>` : '';
  const shots = (pr.evidence_uploads || []).length;
  // 'replace' reemplaza solo las capturas de fase original; las de retest
  // quedan (ver approveProposal en el backend).
  const orig = Number(cur?.original_evidence_count) || 0;
  const mode = pl.evidence_mode === 'replace'
    ? `reemplazan ${orig === 1 ? 'la captura original actual' : `las ${orig} capturas originales actuales`}`
    : `se suman a ${Number(cur?.evidence_count) === 1 ? 'la captura actual' : `las ${Number(cur?.evidence_count) || 0} capturas actuales`}`;
  return gone + _ccpUpdateFields(pr).map(([k, label]) => _ccpSection(label, `
    <div class="ccp-diff">
      ${cur ? `<div class="ccp-diff-side is-old"><div class="ccp-diff-tag">Actual</div>${_ccpUpdateValue(k, cur[k], 'is-old')}</div>` : ''}
      <div class="ccp-diff-side is-new"><div class="ccp-diff-tag">Propuesto</div>${_ccpUpdateValue(k, pl[k], 'is-new')}</div>
    </div>`)).join('') +
    _ccpSection(`Capturas (${shots}) <span class="ccp-sec-hint">· al aprobar ${mode}</span>`,
      shots ? `<div class="ccp-shots" id="ccp-shots"><span class="ccp-muted">Cargando capturas…</span></div>` : '');
}

async function renderClaudeProposals() {
  const el = document.getElementById('cc-proposals');
  const p  = state.currentProject;
  if (!el || !p) return;
  try {
    _ccProposals = await api.mcpProposals.list(p.id, 'pending', { exclude_kind: 'report_section' });
  } catch {
    _ccProposals = [];
  }
  if (!_ccProposals.length) { el.innerHTML = ''; return; }

  const canReview = _ccpCanReview();
  el.innerHTML = `
    <div class="vuln-severity-section">
      <div class="vuln-severity-header">
        <span class="ccp-inbox-title">${icon('sparkles', { size: 13 })} Propuestas de Claude Code</span>
        <span class="vuln-severity-count">${_ccProposals.length} pendiente${_ccProposals.length > 1 ? 's' : ''} de revisión</span>
      </div>
      ${canReview ? `<div class="ccp-shortcuts">Atajos con una propuesta enfocada:
        <kbd class="ccp-kbd">↑</kbd><kbd class="ccp-kbd">↓</kbd> moverse ·
        <kbd class="ccp-kbd">A</kbd> aprobar ·
        <kbd class="ccp-kbd">I</kbd> in scope ·
        <kbd class="ccp-kbd">O</kbd> out of scope ·
        <kbd class="ccp-kbd">R</kbd> rechazar ·
        <kbd class="ccp-kbd">Enter</kbd> abrir</div>` : ''}
      ${_ccProposals.map(pr => {
        const pl = pr.payload || {};
        const isFinding = pr.kind === 'finding';
        const id = esc(pr.id);
        const shots  = (pr.evidence_uploads || []).length;
        const proofs = isFinding ? (pl.http_proofs || []).length : 0;
        const isTarget = pr.kind === 'target';
        const isUpdate = pr.kind === 'finding_update';
        const meta = [
          _ccpKindLabel(pr),
          pr.target_host ? esc(pr.target_host) : '',
          `por ${esc(displayName(pr, 'proposed_by_'))}`,
          esc(timeAgo(pr.created_at)),
        ].filter(Boolean).join(' · ');
        return `
        <div class="vuln-card ccp-row" id="ccp-${id}" tabindex="0" role="button"
          onclick="openClaudeProposal('${id}')"
          onkeydown="_ccpRowKey(event,'${id}')">
          <div class="ccp-row-main">
            ${isFinding ? severityBadge(pl.severity)
              : isTarget ? `<span class="ccp-kind-note">${icon('circle-plus', { size: 11 })} Target</span>`
              : isUpdate ? `<span class="ccp-kind-note">${icon('pencil', { size: 11 })} Cambio</span>`
              : `<span class="ccp-kind-note">${icon('sticky-note', { size: 11 })} Nota</span>`}
            <div class="ccp-row-text">
              <div class="ccp-row-title">${_ccpTitle(pr)}</div>
              <div class="ccp-row-meta">
                <span>${meta}</span>
                ${shots  ? `<span class="ccp-count" title="Capturas">${icon('image', { size: 10 })}${shots}</span>` : ''}
                ${proofs ? `<span class="ccp-count" title="HTTP proofs">${icon('terminal', { size: 10 })}${proofs}</span>` : ''}
              </div>
            </div>
          </div>
          ${canReview ? `
          <div class="ccp-row-actions" onclick="event.stopPropagation()" onkeydown="event.stopPropagation()">
            <button class="btn btn-ghost ccp-btn ccp-btn-reject" onclick="reviewClaudeProposal('${id}','reject')">Rechazar</button>
            ${isTarget
              // Elegir el botón ES elegir el scope: un clic aprueba con ese
              // scope, sin default ni paso previo por el drawer.
              ? _ccpScopeButtons(id, 'ccp-btn')
              : `<button class="btn btn-prim ccp-btn" onclick="reviewClaudeProposal('${id}','approve')" title="Aprobar (A)">Aprobar</button>`}
          </div>` : ''}
        </div>`;
      }).join('')}
    </div>`;
}

// ── Drawer de revisión ────────────────────────────────────────────────
function _mountClaudeProposalDrawer() {
  if (document.getElementById('ccp-drw')) return;
  const bd = document.createElement('div');
  bd.className = 'drw-backdrop';
  bd.id = 'ccp-drw-backdrop';
  bd.onclick = closeClaudeProposal;

  const drw = document.createElement('div');
  drw.className = 'drw ccp-drw';
  drw.id = 'ccp-drw';
  drw.setAttribute('role', 'dialog');
  drw.setAttribute('aria-modal', 'true');
  drw.innerHTML = `
    <div class="drw-head" id="ccp-drw-head"></div>
    <div class="drw-body" id="ccp-drw-body"></div>
    <div class="ccp-drw-foot" id="ccp-drw-foot"></div>
  `;
  document.body.appendChild(bd);
  document.body.appendChild(drw);
}

function _ccpSection(label, html) {
  return html ? `<div class="drw-sec"><div class="drw-sec-label">${label}</div>${html}</div>` : '';
}

function _ccpProofsHtml(proofs) {
  return proofs.map((hp, i) => `
    <div class="http-proof">
      <div class="http-proof-head ccp-proof-head" onclick="this.closest('.http-proof').querySelector('.http-proof-body').classList.toggle('open')">
        <span class="http-proof-method">${esc(hp.method || 'HTTP')}</span>
        <span class="http-proof-label">Proof #${i + 1}</span>
        <span class="http-proof-toggle">${icon('chevron-down', { size: 11 })}</span>
      </div>
      <div class="http-proof-body${i === 0 ? ' open' : ''}">
        ${hp.request  ? `<div class="http-proof-section-label">Request</div><pre class="http-proof-code">${numberedCode(hp.request)}</pre>` : ''}
        ${hp.response ? `<div class="http-proof-section-label">Response</div><pre class="http-proof-code">${numberedCode(hp.response)}</pre>` : ''}
        ${hp.annotation ? `<div class="http-proof-section-label">Anotación</div><div class="http-proof-annotation md-body">${renderMd(hp.annotation)}</div>` : ''}
      </div>
    </div>`).join('');
}

function openClaudeProposal(id) {
  const idx = _ccProposals.findIndex(x => x.id === id);
  if (idx < 0) return;
  const pr = _ccProposals[idx];
  const pl = pr.payload || {};
  const isFinding = pr.kind === 'finding';
  _mountClaudeProposalDrawer();
  _ccpOpenId = id;

  const score = pl.cvss_score != null && pl.cvss_score !== '' ? +pl.cvss_score : null;
  const chips = [
    pr.target_host ? `<span class="ccp-chip ccp-chip-target">${esc(pr.target_host)}</span>` : '',
    isFinding && pl.category ? `<span class="ccp-chip">${esc(pl.category)}</span>` : '',
    isFinding && score != null && !isNaN(score)
      ? `<span class="ccp-chip ccp-chip-cvss" style="--ccp-cvss:${_cvssColor(score)}">CVSS ${score.toFixed(1)}</span>` : '',
    isFinding && pl.cwe ? `<span class="ccp-chip">${esc(pl.cwe)}</span>` : '',
  ].join('');

  document.getElementById('ccp-drw-head').innerHTML = `
    <button class="drw-close" onclick="closeClaudeProposal()" title="Cerrar (Esc)">${icon('x', { size: 16 })}</button>
    <div class="drw-id">
      <span class="ccp-drw-kind">${icon('sparkles', { size: 11 })} ${isFinding ? 'Hallazgo propuesto'
        : pr.kind === 'target' ? `Target propuesto (${esc(pl.type || 'domain')})`
        : pr.kind === 'finding_update' ? 'Cambio propuesto a un hallazgo · se aplica al aprobar'
        : `Nota propuesta (${esc(pr.entity_type)})`}</span>
      ${isFinding ? severityBadge(pl.severity) : ''}
    </div>
    <div class="drw-title">${_ccpTitle(pr)}</div>
    ${chips ? `<div class="drw-meta">${chips}</div>` : ''}
    <div class="ccp-drw-by">por ${esc(displayName(pr, 'proposed_by_'))} · ${esc(timeAgo(pr.created_at))}</div>
  `;

  const shots  = (pr.evidence_uploads || []).length;
  const proofs = isFinding ? (pl.http_proofs || []) : [];
  let html;
  if (isFinding) {
    html =
      _ccpSection('Descripción', pl.description ? `<div class="drw-prose md-body">${renderMd(pl.description)}</div>` : '') +
      _ccpSection('Evidencia / pasos', pl.evidence ? `<pre class="drw-code ccp-pre">${esc(pl.evidence)}</pre>` : '') +
      _ccpSection(`HTTP proofs (${proofs.length}) <span class="ccp-sec-hint">· se adjuntan al aprobar</span>`,
        proofs.length ? _ccpProofsHtml(proofs) : '') +
      _ccpSection(`Capturas (${shots}) <span class="ccp-sec-hint">· se adjuntan al aprobar</span>`,
        shots ? `<div class="ccp-shots" id="ccp-shots"><span class="ccp-muted">Cargando capturas…</span></div>` : '') +
      _ccpSection('Remediación', pl.remediation ? `<div class="drw-prose md-body">${renderMd(pl.remediation)}</div>` : '') +
      _ccpSection('Vector CVSS', pl.cvss_vector ? `<code class="ccp-vector">${esc(pl.cvss_vector)}</code>` : '');
  } else if (pr.kind === 'finding_update') {
    html = _ccpUpdateHtml(pr);
  } else if (pr.kind === 'target') {
    html =
      _ccpSection('Host', `<code class="ccp-vector">${esc(pl.host || '')}</code>`) +
      _ccpSection('Tipo', `<span class="ccp-chip">${esc(pl.type || 'domain')}</span>`) +
      _ccpSection('Notas', pl.notes ? `<div class="drw-prose md-body">${renderMd(pl.notes)}</div>` : '') +
      (_ccpCanReview() ? _ccpSection('Scope al aprobar <span class="ccp-sec-hint">· obligatorio, lo decidís vos</span>', `
        <div class="ccp-scope">
          <div class="ccp-scope-help is-in">${icon('circle-check', { size: 13 })}<span><strong>In scope</strong> — autorizado: el AI Agent y Claude Code pueden trabajar sobre él.</span></div>
          <div class="ccp-scope-help is-out">${icon('eye-off', { size: 13 })}<span><strong>Out of scope</strong> — queda registrado, pero no se ataca.</span></div>
        </div>`) : '');
  } else {
    html =
      _ccpSection('Aplica a', `<div class="ccp-entity"><span class="ccp-chip">${esc(pr.entity_type)}</span> ${esc(pl.entity_name || '')}</div>`) +
      _ccpSection('Nota', pl.text ? `<div class="drw-prose md-body">${renderMd(pl.text)}</div>` : '');
  }
  if (!html) html = `<div class="ccp-muted ccp-empty">La propuesta no trae contenido.</div>`;
  const body = document.getElementById('ccp-drw-body');
  body.innerHTML = html;
  body.scrollTop = 0;

  _ccpRenderFoot();
  if (shots) _ccpLoadEvidence(id);

  const bd  = document.getElementById('ccp-drw-backdrop');
  const drw = document.getElementById('ccp-drw');
  if (!drw.classList.contains('open')) {
    drw.offsetHeight; // reflow para que se pinte primero el translateX(100%)
    bd.classList.add('open');
    drw.classList.add('open');
    document.addEventListener('keydown', _ccpOnKey);
  }
}

function _ccpRenderFoot() {
  const foot = document.getElementById('ccp-drw-foot');
  if (!foot) return;
  const idx = _ccProposals.findIndex(x => x.id === _ccpOpenId);
  const n = _ccProposals.length;
  const dis = _ccpBusy ? 'disabled' : '';
  const id = esc(_ccpOpenId);
  const pr = _ccProposals[idx];
  foot.innerHTML = `
    <div class="ccp-foot-nav">
      <button class="btn btn-ghost ccp-btn" onclick="stepClaudeProposal(-1)" ${idx <= 0 ? 'disabled' : ''} title="Anterior (←)">‹ anterior</button>
      <span class="ccp-pos">${idx + 1} de ${n}</span>
      <button class="btn btn-ghost ccp-btn" onclick="stepClaudeProposal(1)" ${idx >= n - 1 ? 'disabled' : ''} title="Siguiente (→)">siguiente ›</button>
    </div>
    ${_ccpCanReview() ? `
    <div class="ccp-foot-actions">
      <button class="btn btn-ghost ccp-btn-reject" ${dis} onclick="reviewClaudeProposal('${id}','reject')" title="Rechazar (R)">Rechazar <kbd class="ccp-kbd">R</kbd></button>
      ${pr?.kind === 'target'
        ? _ccpScopeButtons(id, '', dis, true)
        : `<button class="btn btn-prim" ${dis} onclick="reviewClaudeProposal('${id}','approve')" title="Aprobar (A)">Aprobar <kbd class="ccp-kbd">A</kbd></button>`}
    </div>` : ''}`;
}

// Los dos botones de aprobación de un target: cada uno aprueba con su scope.
function _ccpScopeButtons(id, cls = '', dis = '', withKbd = false) {
  return ['in', 'out'].map(v => `
    <button class="btn ${cls} ccp-scope-btn is-${v}" ${dis}
      onclick="approveTargetProposal('${id}','${v}')" title="Aprobar como ${CCP_SCOPE_LABELS[v]} (${v === 'in' ? 'I' : 'O'})">
      ${icon(v === 'in' ? 'circle-check' : 'eye-off', { size: 12 })} ${CCP_SCOPE_LABELS[v]}${withKbd ? ` <kbd class="ccp-kbd">${v === 'in' ? 'I' : 'O'}</kbd>` : ''}
    </button>`).join('');
}

function approveTargetProposal(id, scope) {
  if (!CCP_SCOPE_LABELS[scope]) return;
  _ccpScope[id] = scope;
  reviewClaudeProposal(id, 'approve');
}

// Atajo de teclado compartido por la fila enfocada y el drawer. Devuelve
// true si la tecla era una acción de revisión (y la ejecutó).
function _ccpReviewKey(e, id) {
  if (!_ccpCanReview() || _ccpBusy) return false;
  const pr = _ccProposals.find(x => x.id === id);
  if (!pr) return false;
  const k = e.key.toLowerCase();
  if (pr.kind === 'target' && (k === 'i' || k === 'o')) approveTargetProposal(id, k === 'i' ? 'in' : 'out');
  else if (pr.kind !== 'target' && k === 'a') reviewClaudeProposal(id, 'approve');
  else if (k === 'r') reviewClaudeProposal(id, 'reject');
  else return false;
  e.preventDefault();
  return true;
}

function _ccpRowKey(e, id) {
  // Con el drawer abierto, la fila que lo abrió sigue enfocada: las teclas
  // son del drawer (_ccpOnKey), si no la acción se ejecutaría dos veces.
  if (_ccpOpenId || e.target !== e.currentTarget || e.altKey || e.ctrlKey || e.metaKey) return;
  if (e.key === 'Enter') { e.preventDefault(); openClaudeProposal(id); return; }
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault();
    const rows = [...document.querySelectorAll('#cc-proposals .ccp-row')];
    rows[rows.indexOf(e.currentTarget) + (e.key === 'ArrowDown' ? 1 : -1)]?.focus();
    return;
  }
  _ccpReviewKey(e, id);
}

function stepClaudeProposal(delta) {
  const idx = _ccProposals.findIndex(x => x.id === _ccpOpenId);
  const next = _ccProposals[idx + delta];
  if (idx >= 0 && next) openClaudeProposal(next.id);
}

function closeClaudeProposal() {
  _ccpOpenId = null;
  document.removeEventListener('keydown', _ccpOnKey);
  document.getElementById('ccp-drw-backdrop')?.classList.remove('open');
  document.getElementById('ccp-drw')?.classList.remove('open');
}

function _ccpOnKey(e) {
  // Con el lightbox abierto, las teclas son suyas (él las captura antes).
  if (document.getElementById('img-lb')) return;
  if (e.altKey || e.ctrlKey || e.metaKey) return;
  if (e.target.closest?.('input,textarea,select,[contenteditable="true"]')) return;
  if (e.key === 'Escape') { e.preventDefault(); closeClaudeProposal(); }
  else if (e.key === 'ArrowLeft'  || e.key === 'k') { e.preventDefault(); stepClaudeProposal(-1); }
  else if (e.key === 'ArrowRight' || e.key === 'j') { e.preventDefault(); stepClaudeProposal(1); }
  else if (_ccpOpenId) _ccpReviewKey(e, _ccpOpenId);
}

// Las capturas se piden recién al abrir la propuesta: pueden ser varias
// imágenes de MB y el inbox no tiene por qué bajarlas todas al cargar.
async function _ccpLoadEvidence(id) {
  if (!_ccpEvidence[id]) {
    try {
      const imgs = await api.mcpProposals.evidence(state.currentProject.id, id);
      // Solo data URLs de imagen: es lo que guarda el backend, pero el src
      // termina en el DOM y no se confía en nada que no lo sea.
      _ccpEvidence[id] = (imgs || []).filter(img => CCP_IMG_RE.test(img?.data || ''));
    } catch {
      if (_ccpOpenId === id) {
        const box = document.getElementById('ccp-shots');
        if (box) box.innerHTML = `<span class="ccp-muted">No se pudieron cargar las capturas</span>`;
      }
      return;
    }
  }
  // El usuario pudo haber pasado a otra propuesta mientras se descargaban.
  if (_ccpOpenId !== id) return;
  const box = document.getElementById('ccp-shots');
  if (!box) return;
  const imgs = _ccpEvidence[id];
  box.innerHTML = imgs.length
    ? imgs.map((img, i) => `
      <button class="ccp-shot" onclick="openClaudeProposalShot(${i})" title="${esc(img.name || '')}">
        <img src="${esc(img.data)}" alt="${esc(img.name || '')}" loading="lazy">
        <span class="ccp-shot-name">${esc(img.name || `captura ${i + 1}`)}</span>
      </button>`).join('')
    : `<span class="ccp-muted">Sin capturas válidas</span>`;
}

function openClaudeProposalShot(idx) {
  const imgs = _ccpEvidence[_ccpOpenId];
  if (imgs?.length) openImageLightbox(imgs, idx);
}

async function reviewClaudeProposal(id, action) {
  const pr = _ccProposals.find(x => x.id === id);
  if (!pr || _ccpBusy) return;
  if (action === 'reject' && !confirm('¿Rechazar esta propuesta?')) return;
  if (action === 'approve' && pr.kind === 'target' && !_ccpScope[id]) {
    showToast('Elegí el scope del target antes de aprobar', 'error');
    openClaudeProposal(id);
    return;
  }
  const pid = state.currentProject.id;
  // Si se revisa desde el drawer, después se avanza a la siguiente pendiente.
  const fromDrawer = _ccpOpenId === id;
  const fromRow = !fromDrawer && !!document.activeElement?.closest?.('#cc-proposals');
  const oldIdx = _ccProposals.findIndex(x => x.id === id);
  const nextId = (_ccProposals[oldIdx + 1] || _ccProposals[oldIdx - 1])?.id || null;
  let ok = false;
  _ccpBusy = true;
  if (fromDrawer) _ccpRenderFoot();
  try {
    if (action === 'approve') {
      await api.mcpProposals.approve(pid, id, pr.kind === 'target' ? { scope: _ccpScope[id] } : undefined);
      if (pr.kind === 'finding' || pr.kind === 'finding_update') {
        const fresh = await api.vulns.list(pid);
        state.customVulns = fresh.vulns || fresh;
        renderCustomVulns();
      } else if (pr.kind === 'target') {
        // El selector de target del formulario de hallazgos lee state.targets.
        state.targets = await api.targets.list(pid).catch(() => state.targets);
      }
      showToast(pr.kind === 'finding' ? 'Hallazgo creado (sin publicar al cliente)'
        : pr.kind === 'target' ? `Target creado (${CCP_SCOPE_LABELS[_ccpScope[id]]})`
        : pr.kind === 'finding_update' ? 'Cambios aplicados al hallazgo'
        : 'Nota agregada', 'success');
      delete _ccpScope[id];
    } else {
      await api.mcpProposals.reject(pid, id);
      showToast('Propuesta rechazada', 'success');
    }
    ok = true;
  } catch (e) { showToast(e.message, 'error'); }
  // Aun si falló (ej. otro la aprobó primero, 409) se recarga: el inbox
  // tiene que reflejar el estado real, no lo que se veía al cargar la página.
  await renderClaudeProposals();
  _ccpBusy = false;
  delete _ccpEvidence[id];
  if (!_ccpOpenId) {
    // Revisión desde la lista: el foco pasa a la siguiente fila para poder
    // seguir aprobando con el teclado sin volver al mouse.
    const row = document.getElementById(`ccp-${ok ? nextId : id}`) || document.querySelector('#cc-proposals .ccp-row');
    if (fromRow) row?.focus();
    return;
  }
  if (!_ccProposals.length) { closeClaudeProposal(); return; }
  const has = x => x && _ccProposals.some(p => p.id === x);
  if (_ccpOpenId !== id) {
    // Se navegó a otra mientras tanto: solo se refresca su posición.
    if (has(_ccpOpenId)) _ccpRenderFoot(); else openClaudeProposal(_ccProposals[0].id);
    return;
  }
  // Si falló pero sigue pendiente, se queda en la misma para reintentar.
  const target = !ok && has(id) ? id
    : has(nextId) ? nextId
    : _ccProposals[Math.min(Math.max(oldIdx, 0), _ccProposals.length - 1)].id;
  openClaudeProposal(target);
}

window.renderClaudeProposals  = renderClaudeProposals;
window.openClaudeProposal     = openClaudeProposal;
window.closeClaudeProposal    = closeClaudeProposal;
window.stepClaudeProposal     = stepClaudeProposal;
window.openClaudeProposalShot = openClaudeProposalShot;
window.reviewClaudeProposal   = reviewClaudeProposal;
window.approveTargetProposal  = approveTargetProposal;
window._ccpRowKey             = _ccpRowKey;
