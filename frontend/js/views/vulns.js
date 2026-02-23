// ── views/vulns.js ───────────────────────────────────────────────────
let _editingVulnId = null;

const SEVERITY_ORDER  = ['critical','high','medium','low','info'];
const SEVERITY_LABELS = { critical:'Critical', high:'High', medium:'Medium', low:'Low', info:'Info' };

function severityBadge(sev) {
  const s = sev || 'medium';
  return `<span class="sev-badge sev-${s}">${SEVERITY_LABELS[s]||s}</span>`;
}

function renderCustomVulns() {
  const container = document.getElementById('custom-content');
  if (!state.customVulns.length) {
    container.innerHTML = '<div class="empty-state"><div class="empty-icon">🛠</div><div class="empty-title">No custom vulnerabilities</div><div class="empty-sub">Add your own findings with custom payloads</div></div>';
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

  const descH = v.description ? `<div class="items-section"><div class="items-label">Description</div>
    <div class="payload-code" style="color:var(--text2);white-space:pre-wrap">${esc(v.description)}</div></div>` : '';

  const remH = v.remediation ? `<div class="items-section"><div class="items-label">Remediation</div>
    <div class="payload-code" style="color:var(--green);white-space:pre-wrap">${esc(v.remediation)}</div></div>` : '';

  const noteH = v.notes ? `<div class="items-section"><div class="items-label">Notes</div>
    <div class="payload-code" style="color:var(--text2);white-space:pre-wrap">${esc(v.notes)}</div></div>` : '';

  const evidH = (v.evidence||[]).length ? `<div class="items-section"><div class="items-label">Evidence (${v.evidence.length})</div>
    <div class="evidence-thumbs">${v.evidence.map((img,i) =>
      `<img src="${img.data}" alt="${esc(img.name||'evidence')}"
        class="evidence-thumb" onclick="openEvidenceModal('${v.id}',${i})">`
    ).join('')}</div></div>` : '';

  const editorBadge = v.editor_username ? `
    <div class="last-editor" style="margin-left:auto">
      <div class="last-editor-avatar" style="background:${esc(v.editor_color||'#7c3aed')}">${v.editor_username[0].toUpperCase()}</div>
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

// ── Evidence lightbox ────────────────────────────────────────────────
function openEvidenceModal(vulnId, idx) {
  const v = state.customVulns.find(x => x.id === vulnId);
  if (!v || !v.evidence?.[idx]) return;
  const img = v.evidence[idx];
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;background:#000c;z-index:9999;display:flex;align-items:center;justify-content:center;cursor:zoom-out';
  overlay.innerHTML = `<div style="max-width:90vw;max-height:90vh;display:flex;flex-direction:column;gap:8px">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <span style="color:#fff;font-family:var(--mono);font-size:11px">${esc(img.name||'evidence')}</span>
      <button onclick="this.closest('[style*=fixed]').remove()"
        style="background:none;border:none;color:#fff;font-size:20px;cursor:pointer;padding:4px 8px">✕</button>
    </div>
    <img src="${img.data}" style="max-width:88vw;max-height:85vh;object-fit:contain;border-radius:8px">
  </div>`;
  overlay.addEventListener('click', e => { if(e.target===overlay) overlay.remove(); });
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
    if(typeof updateDashboard==='function') updateDashboard();
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

// ── Modal ────────────────────────────────────────────────────────────
let _pendingEvidence = []; // { name, data } objects staged before save

function openAddVulnModal() {
  _editingVulnId = null;
  _pendingEvidence = [];
  document.getElementById('modal-title').textContent      = 'Add Vulnerability';
  document.getElementById('modal-vuln-name').value        = '';
  document.getElementById('modal-vuln-cat').value         = '';
  document.getElementById('modal-vuln-sev').value         = 'medium';
  document.getElementById('modal-vuln-desc').value        = '';
  document.getElementById('modal-vuln-notes').value       = '';
  document.getElementById('modal-vuln-rem').value         = '';
  document.getElementById('modal-items-list').innerHTML    = '';
  document.getElementById('modal-payloads-list').innerHTML = '';
  document.getElementById('vuln-error').style.display     = 'none';
  renderEvidencePreview();
  addModalRow('modal-items-list', 'Check item...');
  addModalRow('modal-payloads-list', 'Payload...');
  document.getElementById('vuln-modal').classList.add('open');
}

function openEditVuln(id, e) {
  e.stopPropagation();
  const v = state.customVulns.find(x => x.id === id);
  if (!v) return;
  _editingVulnId = id;
  _pendingEvidence = [...(v.evidence||[])];
  document.getElementById('modal-title').textContent   = 'Edit Vulnerability';
  document.getElementById('modal-vuln-name').value     = v.name;
  document.getElementById('modal-vuln-cat').value      = v.category || '';
  document.getElementById('modal-vuln-sev').value      = v.severity || 'medium';
  document.getElementById('modal-vuln-desc').value     = v.description || '';
  document.getElementById('modal-vuln-notes').value    = v.notes || '';
  document.getElementById('modal-vuln-rem').value      = v.remediation || '';
  document.getElementById('vuln-error').style.display  = 'none';
  const iList = document.getElementById('modal-items-list');
  const pList = document.getElementById('modal-payloads-list');
  iList.innerHTML = ''; pList.innerHTML = '';
  (v.items||[]).forEach(item => { addModalRow('modal-items-list','Check item...'); iList.lastChild.querySelector('input').value = item; });
  if (!v.items?.length) addModalRow('modal-items-list','Check item...');
  (v.payloads||[]).forEach(p => { addModalRow('modal-payloads-list','Payload...'); pList.lastChild.querySelector('input').value = p; });
  if (!v.payloads?.length) addModalRow('modal-payloads-list','Payload...');
  renderEvidencePreview();
  document.getElementById('vuln-modal').classList.add('open');
}

function renderEvidencePreview() {
  const container = document.getElementById('modal-evidence-list');
  if (!container) return;
  if (!_pendingEvidence.length) {
    container.innerHTML = '<div style="font-family:var(--mono);font-size:10px;color:var(--text3)">No images attached</div>';
    return;
  }
  container.innerHTML = _pendingEvidence.map((img, i) => `
    <div class="evidence-preview-item">
      <img src="${img.data}" class="evidence-thumb-sm">
      <span class="evidence-name">${esc(img.name||'image')}</span>
      <button class="btn-remove" onclick="removeEvidence(${i})">✕</button>
    </div>`).join('');
}

function removeEvidence(idx) {
  _pendingEvidence.splice(idx, 1);
  renderEvidencePreview();
}

function pickEvidenceFile() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = 'image/*';
  input.multiple = true;
  input.onchange = () => {
    const files = Array.from(input.files);
    let loaded = 0;
    files.forEach(file => {
      if (!file.type.startsWith('image/')) return;
      const reader = new FileReader();
      reader.onload = e => {
        _pendingEvidence.push({ name: file.name, data: e.target.result });
        loaded++;
        if (loaded === files.length) renderEvidencePreview();
      };
      reader.readAsDataURL(file);
    });
  };
  input.click();
}

function addModalRow(containerId, ph) {
  const row = document.createElement('div');
  row.className = 'dynamic-row';
  row.innerHTML = `<input type="text" class="dynamic-input" placeholder="${esc(ph)}">
    <button class="btn-remove" onclick="this.parentElement.remove()">✕</button>`;
  document.getElementById(containerId).appendChild(row);
}

function closeVulnModal() {
  document.getElementById('vuln-modal').classList.remove('open');
  _editingVulnId = null;
  _pendingEvidence = [];
}

async function saveVuln() {
  const name        = document.getElementById('modal-vuln-name').value.trim();
  const category    = document.getElementById('modal-vuln-cat').value.trim();
  const severity    = document.getElementById('modal-vuln-sev').value;
  const description = document.getElementById('modal-vuln-desc').value;
  const notes       = document.getElementById('modal-vuln-notes').value;
  const remediation = document.getElementById('modal-vuln-rem').value;
  const err         = document.getElementById('vuln-error');
  const btn         = document.getElementById('vuln-save-btn');
  if (!name) { err.textContent = 'Name is required'; err.style.display = 'block'; return; }
  const items    = [...document.querySelectorAll('#modal-items-list .dynamic-input')].map(i => i.value.trim()).filter(Boolean);
  const payloads = [...document.querySelectorAll('#modal-payloads-list .dynamic-input')].map(i => i.value.trim()).filter(Boolean);
  const evidence = _pendingEvidence;
  btn.disabled = true;
  try {
    const payload = { name, category:category||'Custom', severity, description, items, payloads, notes, remediation, evidence };
    if (_editingVulnId) {
      const updated = await api.vulns.update(state.currentProject.id, _editingVulnId, payload);
      const idx = state.customVulns.findIndex(v => v.id === _editingVulnId);
      if (idx > -1) state.customVulns[idx] = updated;
    } else {
      const created = await api.vulns.create(state.currentProject.id, payload);
      state.customVulns.push(created);
    }
    closeVulnModal();
    renderCustomVulns();
    if(typeof updateDashboard==='function') updateDashboard();
    showToast('✓ Saved', 'success');
  } catch(e) { err.textContent = e.message; err.style.display = 'block'; }
  finally { btn.disabled = false; }
}

async function deleteVuln(id, e) {
  e.stopPropagation();
  if (!confirm('Delete this vulnerability?')) return;
  try {
    await api.vulns.delete(state.currentProject.id, id);
    state.customVulns = state.customVulns.filter(v => v.id !== id);
    renderCustomVulns();
    if(typeof updateDashboard==='function') updateDashboard();
    showToast('Deleted', 'error');
  } catch(err) { showToast(err.message, 'error'); }
}

window.renderCustomVulns  = renderCustomVulns;
window.buildVulnCard      = buildVulnCard;
window.openEvidenceModal  = openEvidenceModal;
window.toggleVulnBody     = toggleVulnBody;
window.cycleVulnStatus    = cycleVulnStatus;
window.toggleCustomItem   = toggleCustomItem;
window.openAddVulnModal   = openAddVulnModal;
window.openEditVuln       = openEditVuln;
window.removeEvidence     = removeEvidence;
window.pickEvidenceFile   = pickEvidenceFile;
window.renderEvidencePreview = renderEvidencePreview;
window.addModalRow        = addModalRow;
window.closeVulnModal     = closeVulnModal;
window.saveVuln           = saveVuln;
window.deleteVuln         = deleteVuln;
window.severityBadge      = severityBadge;
window.SEVERITY_ORDER     = SEVERITY_ORDER;
window.SEVERITY_LABELS    = SEVERITY_LABELS;