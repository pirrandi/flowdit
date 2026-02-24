// ── views/targets.js ─────────────────────────────────────────────────

const TARGET_TYPES  = ['domain','ip','cidr','url','other'];
const TARGET_ICONS  = { domain:'🌐', ip:'🖥', cidr:'🔲', url:'🔗', other:'📌' };
const TARGET_SCOPE_COLORS = { in:'var(--green)', out:'var(--text3)' };
const TARGET_STATUS_COLORS = { active:'var(--accent)', completed:'var(--green)', 'out-of-scope':'var(--text3)' };

function renderTargets() {
  const container = document.getElementById('targets-content');
  if (!container) return;

  if (!state.targets.length) {
    container.innerHTML = `<div class="empty-state">
      <div class="empty-icon">🎯</div>
      <div class="empty-title">No targets defined</div>
      <div class="empty-sub">Add IPs, domains, URLs and CIDRs in scope for this engagement</div>
    </div>`;
    return;
  }

  // Group by scope: in-scope first
  const inScope  = state.targets.filter(t => t.scope === 'in');
  const outScope = state.targets.filter(t => t.scope === 'out');

  container.innerHTML = '';

  if (inScope.length) {
    container.appendChild(buildTargetGroup('In Scope', inScope, 'var(--green)'));
  }
  if (outScope.length) {
    container.appendChild(buildTargetGroup('Out of Scope', outScope, 'var(--text3)'));
  }
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

  const statusColor = TARGET_STATUS_COLORS[t.status] || 'var(--text3)';
  const statusLabel = t.status === 'out-of-scope' ? 'Out of Scope' : t.status.charAt(0).toUpperCase() + t.status.slice(1);

  // Vulns linked to this target
  const linkedVulns = state.customVulns.filter(v => v.target_id === t.id);

  const vulnsH = linkedVulns.length ? `
    <div class="items-section">
      <div class="items-label">Linked Findings (${linkedVulns.length})</div>
      ${linkedVulns.map(v => `
        <div class="item-row" style="gap:8px">
          <span class="sev-badge sev-${v.severity||'medium'}" style="font-size:9px">${v.severity||'medium'}</span>
          <span class="item-text">${esc(v.name)}</span>
        </div>`).join('')}
    </div>` : '';

  const notesH = t.notes ? `
    <div class="items-section">
      <div class="items-label">Notes</div>
      <div class="payload-code" style="color:var(--text2);white-space:pre-wrap">${esc(t.notes)}</div>
    </div>` : '';

  card.innerHTML = `
    <div class="vuln-header" onclick="toggleTargetBody('${t.id}',event)">
      <span style="font-size:16px;flex-shrink:0">${TARGET_ICONS[t.type]||'📌'}</span>
      <span class="vuln-tag" style="text-transform:uppercase">${t.type}</span>
      <span class="vuln-name" style="font-family:var(--mono);font-size:12px">${esc(t.host)}</span>
      <span style="font-family:var(--mono);font-size:10px;color:${statusColor};margin-left:auto;flex-shrink:0">${statusLabel}</span>
      ${linkedVulns.length ? `<span style="font-family:var(--mono);font-size:10px;color:var(--red);margin-left:8px">${linkedVulns.length} finding${linkedVulns.length>1?'s':''}</span>` : ''}
      <div class="vuln-actions">
        <button class="btn-icon edit"   onclick="openEditTarget('${t.id}',event)">✎</button>
        <button class="btn-icon delete" onclick="deleteTarget('${t.id}',event)">✕</button>
      </div>
    </div>
    <div class="vuln-body" id="tbody-${t.id}">${vulnsH}${notesH}</div>`;
  return card;
}

function toggleTargetBody(id, e) {
  if (e.target.closest('.vuln-actions')) return;
  document.getElementById(`tbody-${id}`)?.classList.toggle('open');
}

// ── Modal ────────────────────────────────────────────────────────────
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
    } else {
      const created = await api.targets.create(state.currentProject.id, { host, type, scope, status, notes });
      state.targets.push(created);
    }
    closeTargetModal();
    renderTargets();
    updateTargetsSidebar();
    showToast('✓ Saved', 'success');
  } catch(e) { errEl.textContent = e.message; errEl.style.display = 'block'; }
  finally { btn.disabled = false; }
}

async function deleteTarget(id, e) {
  e.stopPropagation();
  if (!confirm('Delete this target?')) return;
  try {
    await api.targets.delete(state.currentProject.id, id);
    state.targets = state.targets.filter(t => t.id !== id);
    renderTargets();
    updateTargetsSidebar();
    showToast('Deleted', 'error');
  } catch(err) { showToast(err.message, 'error'); }
}

function updateTargetsSidebar() {
  const sidebar = document.getElementById('sidebar');
  if (!sidebar) return;
  const inScope = state.targets.filter(t => t.scope === 'in');
  let html = `<div class="sidebar-section-label">Scope (${inScope.length})</div>`;
  inScope.forEach(t => {
    const vulnCount = state.customVulns.filter(v => v.target_id === t.id).length;
    html += `<div class="sidebar-item" onclick="scrollToTarget('${t.id}')">
      <span style="font-size:12px">${TARGET_ICONS[t.type]||'📌'}</span>
      <span class="sidebar-item-text" style="font-family:var(--mono);font-size:11px">${esc(t.host)}</span>
      ${vulnCount ? `<span class="sidebar-item-badge" style="background:var(--red)22;color:var(--red)">${vulnCount}</span>` : ''}
    </div>`;
  });
  sidebar.innerHTML = html;
}

function scrollToTarget(id) {
  document.getElementById(`target-${id}`)?.scrollIntoView({ behavior:'smooth', block:'start' });
}

window.renderTargets       = renderTargets;
window.buildTargetCard     = buildTargetCard;
window.toggleTargetBody    = toggleTargetBody;
window.openAddTargetModal  = openAddTargetModal;
window.openEditTarget      = openEditTarget;
window.closeTargetModal    = closeTargetModal;
window.saveTarget          = saveTarget;
window.deleteTarget        = deleteTarget;
window.updateTargetsSidebar = updateTargetsSidebar;
window.scrollToTarget      = scrollToTarget;