// ── views/vulns.js ───────────────────────────────────────────────────
let _editingVulnId = null;

function renderCustomVulns() {
  const container = document.getElementById('custom-content');
  if (!state.customVulns.length) {
    container.innerHTML = '<div class="empty-state"><div class="empty-icon">🛠</div><div class="empty-title">No custom vulnerabilities</div><div class="empty-sub">Add your own findings with custom payloads</div></div>';
    return;
  }
  container.innerHTML = '';
  state.customVulns.forEach(v => {
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

    const noteH = v.notes ? `<div class="items-section"><div class="items-label">Notes</div><div class="payload-code" style="color:var(--text2)">${esc(v.notes)}</div></div>` : '';

    // Last editor
    const editorBadge = v.editor_username ? `
      <div class="last-editor" style="margin-left:auto">
        <div class="last-editor-avatar" style="background:${esc(v.editor_color||'#7c3aed')}">${v.editor_username[0].toUpperCase()}</div>
        <span class="last-editor-name">${esc(v.editor_username)}</span>
        <span class="last-editor-time">${timeAgo(v.updated_at)}</span>
      </div>` : '';

    card.innerHTML = `
      <div class="vuln-header" onclick="toggleVulnBody('${v.id}',event)">
        <div class="test-check" style="${isDone?'background:var(--green);border-color:var(--green);color:var(--bg)':isFail?'background:var(--red);border-color:var(--red);color:#fff':''}"
          onclick="cycleVulnStatus('${v.id}',event)">${isDone?'✓':isFail?'✕':''}</div>
        <span class="vuln-tag">${esc(v.category||'Custom')}</span>
        <span class="vuln-name">${esc(v.name)}</span>
        ${editorBadge}
        <div class="vuln-actions">
          <button class="btn-icon edit" onclick="openEditVuln('${v.id}',event)">✎</button>
          <button class="btn-icon delete" onclick="deleteVuln('${v.id}',event)">✕</button>
        </div>
      </div>
      <div class="vuln-body" id="vbody-${v.id}">${itemsH}${payH}${noteH}</div>`;
    container.appendChild(card);
  });
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
    updateDashboard();
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
function openAddVulnModal() {
  _editingVulnId = null;
  document.getElementById('modal-title').textContent = 'Add Vulnerability';
  document.getElementById('modal-vuln-name').value   = '';
  document.getElementById('modal-vuln-cat').value    = '';
  document.getElementById('modal-vuln-notes').value  = '';
  document.getElementById('modal-items-list').innerHTML    = '';
  document.getElementById('modal-payloads-list').innerHTML = '';
  document.getElementById('vuln-error').style.display = 'none';
  addModalRow('modal-items-list', 'Check item...');
  addModalRow('modal-payloads-list', 'Payload...');
  document.getElementById('vuln-modal').classList.add('open');
}

function openEditVuln(id, e) {
  e.stopPropagation();
  const v = state.customVulns.find(x => x.id === id);
  if (!v) return;
  _editingVulnId = id;
  document.getElementById('modal-title').textContent  = 'Edit Vulnerability';
  document.getElementById('modal-vuln-name').value    = v.name;
  document.getElementById('modal-vuln-cat').value     = v.category || '';
  document.getElementById('modal-vuln-notes').value   = v.notes || '';
  document.getElementById('vuln-error').style.display = 'none';

  const iList = document.getElementById('modal-items-list');
  const pList = document.getElementById('modal-payloads-list');
  iList.innerHTML = ''; pList.innerHTML = '';
  (v.items||[]).forEach(item => { addModalRow('modal-items-list', 'Check item...'); iList.lastChild.querySelector('input').value = item; });
  if (!v.items?.length) addModalRow('modal-items-list', 'Check item...');
  (v.payloads||[]).forEach(p => { addModalRow('modal-payloads-list', 'Payload...'); pList.lastChild.querySelector('input').value = p; });
  if (!v.payloads?.length) addModalRow('modal-payloads-list', 'Payload...');
  document.getElementById('vuln-modal').classList.add('open');
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
}

async function saveVuln() {
  const name    = document.getElementById('modal-vuln-name').value.trim();
  const category = document.getElementById('modal-vuln-cat').value.trim();
  const notes   = document.getElementById('modal-vuln-notes').value;
  const err     = document.getElementById('vuln-error');
  const btn     = document.getElementById('vuln-save-btn');
  if (!name) { err.textContent = 'Name is required'; err.style.display = 'block'; return; }
  const items    = [...document.querySelectorAll('#modal-items-list .dynamic-input')].map(i => i.value.trim()).filter(Boolean);
  const payloads = [...document.querySelectorAll('#modal-payloads-list .dynamic-input')].map(i => i.value.trim()).filter(Boolean);
  btn.disabled = true;
  try {
    if (_editingVulnId) {
      const updated = await api.vulns.update(state.currentProject.id, _editingVulnId, { name, category:category||'Custom', items, payloads, notes });
      const idx = state.customVulns.findIndex(v => v.id === _editingVulnId);
      if (idx > -1) state.customVulns[idx] = updated;
    } else {
      const created = await api.vulns.create(state.currentProject.id, { name, category:category||'Custom', items, payloads, notes });
      state.customVulns.push(created);
    }
    closeVulnModal();
    renderCustomVulns();
    updateDashboard();
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
    updateDashboard();
    showToast('Deleted', 'error');
  } catch(err) { showToast(err.message, 'error'); }
}

window.renderCustomVulns = renderCustomVulns;
window.toggleVulnBody    = toggleVulnBody;
window.cycleVulnStatus   = cycleVulnStatus;
window.toggleCustomItem  = toggleCustomItem;
window.openAddVulnModal  = openAddVulnModal;
window.openEditVuln      = openEditVuln;
window.addModalRow       = addModalRow;
window.closeVulnModal    = closeVulnModal;
window.saveVuln          = saveVuln;
window.deleteVuln        = deleteVuln;
