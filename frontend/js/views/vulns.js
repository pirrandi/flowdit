// ── views/vulns.js ───────────────────────────────────────────────────
let _editingVulnId = null;

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
  return 'var(--text3)';
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
  if (btn) btn.textContent = opening ? '▾ close' : '▸ open';
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
  if (btn)  btn.textContent    = vector ? '▾ close' : '▸ open';
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
  if (btn)    btn.textContent       = '▸ open';
  if (clrBtn) clrBtn.style.display  = 'none';
  if (hp)     { hp.style.color = ''; hp.textContent = 'not scored'; }
}

async function copyCVSSVector() {
  await navigator.clipboard.writeText(buildCVSSVector(_cvss)).catch(()=>{});
  showToast('CVSS vector copied', 'info');
}

const SEVERITY_ORDER  = ['critical','high','medium','low','info'];

const SEVERITY_LABELS = { critical:'Critical', high:'High', medium:'Medium', low:'Low', info:'Info' };

function severityBadge(sev) {
  const s = sev || 'medium';
  return `<span class="sev-badge sev-${s}">${SEVERITY_LABELS[s]||s}</span>`;
}

function renderCustomVulns() {
  const container = document.getElementById('custom-content');
  if (!state.customVulns.length) {
    container.innerHTML = '<div class="empty-state"><div class="empty-icon">◌</div><div class="empty-title">No custom vulnerabilities</div><div class="empty-sub">Add findings, then write descriptions & export from the Export page</div></div>';
    return;
  }
  const bySev = {};
  SEVERITY_ORDER.forEach(s => bySev[s] = []);
  state.customVulns.forEach(v => { const s = v.severity||'medium'; (bySev[s]||bySev['medium']).push(v); });

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
}

function buildVulnCard(v) {
  const isDone = v.status === 'done';
  const isFail = v.status === 'fail';
  const card   = document.createElement('div');
  card.className = `vuln-card ${isDone?'completed':''} ${isFail?'failed':''}`;
  card.id = `vuln-${v.id}`;

  const itemsH = (v.items||[]).length ? `<div class="items-section"><div class="items-label">Checklist</div>` +
    v.items.map((item, idx) => {
      const chk = v.checked_items?.[idx] || false;
      return `<div class="item-row">
        <div class="item-checkbox ${chk?'checked':''}" onclick="toggleCustomItem('${v.id}',${idx},this)">${chk?'✓':''}</div>
        <span class="item-text ${chk?'done':''}">${esc(item)}</span>
      </div>`;
    }).join('') + '</div>' : '';

  const payH = (v.payloads||[]).length ? `<div class="payload-section"><div class="items-label">Payloads</div>` +
    v.payloads.map(p => `<div class="payload-row">
      <div class="payload-code">${esc(p)}</div>
      <button class="copy-btn" onclick="copyText(this,'${btoa(encodeURIComponent(p))}')">copy</button>
    </div>`).join('') + '</div>' : '';

  const noteH = v.notes ? `<div class="items-section"><div class="items-label">Notes</div>
    <div class="payload-code" style="color:var(--text2);white-space:pre-wrap">${esc(v.notes)}</div></div>` : '';

  const descH = v.description ? `<div class="items-section"><div class="items-label">Description</div>
    <div class="md-body" style="color:var(--text2)">${renderMd(v.description)}</div></div>` : '';
  const remH  = v.remediation ? `<div class="items-section"><div class="items-label">Remediation</div>
    <div class="md-body" style="color:var(--green)">${renderMd(v.remediation)}</div></div>` : '';
  const evidH = (v.evidence||[]).length ? `<div class="items-section">
    <div class="items-label">Evidence (${v.evidence.length})</div>
    <div class="evidence-thumbs">${v.evidence.map((img,i) =>
      `<img src="${img.data}" class="evidence-thumb" alt="${esc(img.name||'')}" onclick="openEvidenceViewer('${v.id}',${i})">`
    ).join('')}</div></div>` : '';

  const editorBadge = v.editor_username ? `
    <div class="last-editor" style="margin-left:auto">
      ${avatarHtml(v.editor_username, memberRoleColor(v.updated_by, v.editor_color||'#7c3aed'), 20, v.editor_avatar_url||null)}
      <span class="last-editor-name">${esc(v.editor_username)}</span>
      <span class="last-editor-time">${timeAgo(v.updated_at)}</span>
    </div>` : '';

  card.innerHTML = `
    <div class="vuln-header" onclick="toggleVulnBody('${v.id}',event)">
      <div class="test-check"
        style="${isDone?'background:var(--green);border-color:var(--green);color:var(--bg)':isFail?'background:var(--red);border-color:var(--red);color:#fff':''}"
        onclick="cycleVulnStatus('${v.id}',event)">${isDone?'✓':isFail?'✕':''}</div>
      <span class="vuln-tag">${esc(v.category||'Custom')}</span>
      ${severityBadge(v.severity)}
      ${v.cvss_score != null ? `<span style="font-family:var(--mono);font-size:10px;font-weight:700;color:${_cvssColor(+v.cvss_score)};background:${_cvssColor(+v.cvss_score)}15;border:1px solid ${_cvssColor(+v.cvss_score)}33;border-radius:4px;padding:1px 7px;flex-shrink:0">CVSS ${(+v.cvss_score).toFixed(1)}</span>` : ''}
      ${v.cwe ? `<span style="font-family:var(--mono);font-size:10px;font-weight:600;color:var(--text3);background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:1px 7px;flex-shrink:0">${esc(v.cwe)}</span>` : ''}
      ${v.target_host ? `<span class="vuln-tag" style="color:var(--a);border-color:var(--a)33">${esc(v.target_host)}</span>` : ''}
      <span class="vuln-name">${esc(v.name)}</span>
      ${editorBadge}
      <div class="vuln-actions">
        <button class="btn-icon edit" onclick="openEditVuln('${v.id}',event)">✎</button>
        <button class="btn-icon delete" onclick="deleteVuln('${v.id}',event)">✕</button>
      </div>
    </div>
    <div class="vuln-body" id="vbody-${v.id}">${descH}${itemsH}${payH}${noteH}${remH}${evidH}</div>`;
  return card;
}

function openEvidenceViewer(vulnId, idx) {
  const v = state.customVulns.find(x => x.id === vulnId);
  if (!v?.evidence?.[idx]) return;
  const img = v.evidence[idx];
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;background:#000d;z-index:9999;display:flex;align-items:center;justify-content:center;cursor:zoom-out';
  overlay.innerHTML = `<div style="max-width:90vw;max-height:90vh;display:flex;flex-direction:column;gap:8px" onclick="event.stopPropagation()">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <span style="color:#fff;font-family:var(--mono);font-size:11px">${esc(img.name||'evidence')}</span>
      <button onclick="this.closest('[style*=fixed]').remove()"
        style="background:none;border:none;color:#fff;font-size:20px;cursor:pointer;padding:4px 8px">✕</button>
    </div>
    <img src="${img.data}" style="max-width:88vw;max-height:85vh;object-fit:contain;border-radius:8px">
  </div>`;
  overlay.addEventListener('click', () => overlay.remove());
  document.body.appendChild(overlay);
}

function toggleVulnBody(id, e) {
  if (e.target.closest('.vuln-actions,.test-check')) return;
  document.getElementById(`vbody-${id}`)?.classList.toggle('open');
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

async function toggleCustomItem(vulnId, idx, el) {
  const v = state.customVulns.find(x => x.id === vulnId);
  if (!v) return;
  const cur = v.checked_items?.[idx] || false;
  const newChecked = { ...v.checked_items, [idx]: !cur };
  try {
    await api.vulns.update(state.currentProject.id, vulnId, { checked_items: newChecked });
    v.checked_items = newChecked;
    el.classList.toggle('checked', !cur);
    el.textContent = !cur ? '✓' : '';
    el.nextElementSibling?.classList.toggle('done', !cur);
  } catch(err) { showToast(err.message, 'error'); }
}

// ── Modal (operational data only) ───────────────────────────────────
function openAddVulnModal() {
  _editingVulnId = null;
  document.getElementById('modal-title').textContent       = 'Add Vulnerability';
  document.getElementById('modal-vuln-name').value         = '';
  document.getElementById('modal-vuln-cat').value          = '';
  document.getElementById('modal-vuln-cwe').value          = '';
  document.getElementById('modal-vuln-sev').value          = 'medium';
  document.getElementById('modal-vuln-notes').value        = '';
  document.getElementById('modal-vuln-desc').value         = '';
  document.getElementById('modal-vuln-rem').value          = '';
  populateTargetSelect(null);
  document.getElementById('modal-items-list').innerHTML    = '';
  document.getElementById('modal-payloads-list').innerHTML = '';
  document.getElementById('vuln-error').style.display      = 'none';
  addModalRow('modal-items-list', 'Check item...');
  addModalRow('modal-payloads-list', 'Payload...', true);
  _initCVSS(null);
  document.getElementById('vuln-modal').classList.add('open');
}

function openEditVuln(id, e) {
  e.stopPropagation();
  const v = state.customVulns.find(x => x.id === id);
  if (!v) return;
  _editingVulnId = id;
  document.getElementById('modal-title').textContent      = 'Edit Vulnerability';
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
  document.getElementById('vuln-modal').classList.add('open');
}

function addModalRow(containerId, ph, isTextarea = false) {
  const row = document.createElement('div');
  row.className = 'dynamic-row';
  const field = isTextarea
    ? `<textarea class="dynamic-textarea" placeholder="${esc(ph)}"></textarea>`
    : `<input type="text" class="dynamic-input" placeholder="${esc(ph)}">`;
  row.innerHTML = `${field}<button class="btn-remove" onclick="this.parentElement.remove()">✕</button>`;
  document.getElementById(containerId).appendChild(row);
}

function closeVulnModal() {
  document.getElementById('vuln-modal').classList.remove('open');
  _editingVulnId = null;
}

async function saveVuln() {
  const name     = document.getElementById('modal-vuln-name').value.trim();
  const category = document.getElementById('modal-vuln-cat').value.trim();
  const cwe      = document.getElementById('modal-vuln-cwe').value.trim();
  const severity = document.getElementById('modal-vuln-sev').value;
  const notes    = document.getElementById('modal-vuln-notes').value;
  const err      = document.getElementById('vuln-error');
  const btn      = document.getElementById('vuln-save-btn');
  if (!name) { err.textContent = 'Name is required'; err.style.display = 'block'; return; }
  const description = document.getElementById('modal-vuln-desc').value;
  const remediation = document.getElementById('modal-vuln-rem').value;
  const items    = [...document.querySelectorAll('#modal-items-list .dynamic-input')].map(i => i.value.trim()).filter(Boolean);
  const payloads = [...document.querySelectorAll('#modal-payloads-list .dynamic-textarea')].map(i => i.value.trim()).filter(Boolean);
  btn.disabled = true;
  try {
    const target_id = document.getElementById('modal-vuln-target')?.value || null;
    const payload = { name, category: category||'Custom', severity, items, payloads, notes, description, remediation, target_id: target_id||null, cwe: cwe||null };
    if (_cvssModified) {
      if (_cvssCleared) {
        payload.cvss_vector = null;
        payload.cvss_score  = null;
      } else {
        payload.cvss_vector = buildCVSSVector(_cvss);
        payload.cvss_score  = calcCVSSScore(_cvss);
      }
    }
    if (_editingVulnId) {
      const updated = await api.vulns.update(state.currentProject.id, _editingVulnId, payload);
      const idx = state.customVulns.findIndex(v => v.id === _editingVulnId);
      if (idx > -1) state.customVulns[idx] = { ...state.customVulns[idx], ...updated };
    } else {
      const created = await api.vulns.create(state.currentProject.id, payload);
      state.customVulns.push(created);
    }
    closeVulnModal();
    renderCustomVulns();
    if (typeof updateDashboard === 'function') updateDashboard();
    showToast('✓ Saved', 'success');
  } catch(e) { err.textContent = e.message; err.style.display = 'block'; }
  finally { btn.disabled = false; }
}

// ── AI helpers ───────────────────────────────────────────────────────
async function _aiGenerate(type, context, btnId, btnLabel) {
  const btn = document.getElementById(btnId);
  if (btn) { btn.disabled = true; btn.classList.add('loading'); btn.textContent = '…'; }
  try {
    return await request('POST', '/ai/generate', { type, context });
  } finally {
    if (btn) { btn.disabled = false; btn.classList.remove('loading'); btn.textContent = btnLabel; }
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
    const result = await _aiGenerate('vuln-draft', ctx, 'ai-draft-btn', '✦ Draft');
    if (result.name)        document.getElementById('modal-vuln-name').value = result.name;
    if (result.category)    document.getElementById('modal-vuln-cat').value  = result.category;
    if (result.severity)    document.getElementById('modal-vuln-sev').value  = result.severity;
    if (result.description) document.getElementById('modal-vuln-desc').value = result.description;
    if (result.remediation) document.getElementById('modal-vuln-rem').value  = result.remediation;
    showToast('✦ Draft generated', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function aiRemediation() {
  const ctx = _collectVulnContext();
  if (!ctx.name && !ctx.description) { showToast('Add a name or description first', 'error'); return; }
  try {
    const result = await _aiGenerate('remediation', ctx, 'ai-rem-btn', '✦ Suggest');
    if (result.remediation) document.getElementById('modal-vuln-rem').value = result.remediation;
    showToast('✦ Remediation generated', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function aiCWE() {
  const ctx = _collectVulnContext();
  if (!ctx.name) { showToast('Enter a name first', 'error'); return; }
  try {
    const result = await _aiGenerate('cwe', ctx, 'ai-cwe-btn', '✦');
    if (result.cwe) {
      document.getElementById('modal-vuln-cwe').value = result.cwe;
      showToast(`✦ ${result.cwe}${result.cwe_name ? ' — ' + result.cwe_name : ''}`, 'success');
    }
  } catch(e) { showToast(e.message, 'error'); }
}

async function deleteVuln(id, e) {
  e.stopPropagation();
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

window.setCVSSMetric      = setCVSSMetric;
window.toggleCVSSSection  = toggleCVSSSection;
window.copyCVSSVector     = copyCVSSVector;
window.clearCVSS          = clearCVSS;
window.renderCustomVulns  = renderCustomVulns;
window.buildVulnCard      = buildVulnCard;
window.openEvidenceViewer = openEvidenceViewer;
window.toggleVulnBody     = toggleVulnBody;
window.cycleVulnStatus    = cycleVulnStatus;
window.toggleCustomItem   = toggleCustomItem;
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