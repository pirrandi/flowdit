// ── views/methodology.js ─────────────────────────────────────────────

let _activeMethodId   = null;
let _activeMethodData = null; // full methodology object
let _editingMethodId  = null;
let _editingTestIdx   = null;

// ── LIBRARY LIST ─────────────────────────────────────────────────────
function renderMethodologyList() {
  const list = document.getElementById('method-list');
  if (!list) return;
  const methods = state.methodologies || [];
  if (!methods.length) {
    list.innerHTML = `<div class="empty-state" style="padding:20px 0">
      
      <div class="empty-title">No methodologies yet</div>
      <div class="empty-sub">Create your first custom checklist</div>
    </div>`;
    return;
  }
  list.innerHTML = methods.map(m => {
    const tests   = m.tests || [];
    const isOwner = m.owner_id === state.user?.id;
    const prog    = state.methodProgress[m.id] || {};
    const done    = Object.values(prog).filter(p => p.status === 'done').length;
    const fail    = Object.values(prog).filter(p => p.status === 'fail').length;
    const pct     = tests.length ? Math.round((done+fail)/tests.length*100) : 0;
    const active  = m.id === _activeMethodId;
    return `<div class="method-list-item ${active?'active':''}" onclick="openMethodology('${m.id}')">
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
        <span class="method-list-name">${esc(m.name)}</span>
        ${m.is_shared ? '<span class="method-badge-shared">shared</span>' : ''}
        ${!isOwner ? `<span class="method-badge-owner">${esc(m.owner_username)}</span>` : ''}
      </div>
      <div style="display:flex;align-items:center;gap:8px">
        <div class="progress-bar" style="flex:1;height:3px">
          <div class="progress-bar-fill" style="width:${pct}%;${fail?'background:var(--c-crit)':''}"></div>
        </div>
        <span style="font-family:var(--mono);font-size:10px;color:var(--t3)">${tests.length} tests</span>
        ${fail ? `<span style="color:var(--c-crit);display:inline-flex;align-items:center;gap:2px">${icon('triangle-alert',{size:10})}${fail}</span>` : ''}
      </div>
    </div>`;
  }).join('');
}

// ── OPEN & RUN METHODOLOGY ────────────────────────────────────────────
async function openMethodology(id) {
  _activeMethodId   = id;
  _activeMethodData = state.methodologies.find(m => m.id === id);
  if (!_activeMethodData) return;
  renderMethodologyList(); // re-render to highlight active

  // Load progress for this methodology in current project
  try {
    const prog = await api.methodologies.getProgress(id, state.currentProject.id);
    state.methodProgress[id] = prog;
  } catch { state.methodProgress[id] = {}; }

  renderMethodologyRunner();
}

function renderMethodologyRunner() {
  const runner = document.getElementById('method-runner');
  if (!runner || !_activeMethodData) return;
  const m     = _activeMethodData;
  const tests = m.tests || [];
  const prog  = state.methodProgress[m.id] || {};
  const done  = Object.values(prog).filter(p => p.status === 'done').length;
  const fail  = Object.values(prog).filter(p => p.status === 'fail').length;
  const pct   = tests.length ? Math.round((done+fail)/tests.length*100) : 0;
  const isOwner = m.owner_id === state.user?.id;

  runner.innerHTML = `
    <div class="method-runner-header">
      <div style="flex:1;min-width:0">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:2px">
          <span style="font-size:16px;font-weight:700">${esc(m.name)}</span>
          ${m.is_shared ? '<span class="method-badge-shared">shared</span>' : ''}
        </div>
        ${m.description ? `<div style="font-size:12px;color:var(--t3);margin-bottom:6px">${esc(m.description)}</div>` : ''}
        <div style="display:flex;align-items:center;gap:10px">
          <div class="progress-bar" style="flex:1;max-width:300px">
            <div class="progress-bar-fill" style="width:${pct}%"></div>
          </div>
          <span style="font-family:var(--mono);font-size:11px;color:var(--t3)">${done+fail}/${tests.length} · ${pct}%</span>
          ${fail ? `<span style="color:var(--c-crit);display:inline-flex;align-items:center;gap:3px">${icon('triangle-alert',{size:11})} ${fail} vuln</span>` : ''}
        </div>
      </div>
      <div style="display:flex;gap:6px;flex-shrink:0">
        ${buildActivateBtn(m.id)}
        ${isOwner ? `<button class="btn-secondary" style="font-size:11px;padding:5px 10px" onclick="openEditMethodModal('${m.id}')">${icon('square-pen',{size:11})} Edit</button><button class="btn-secondary" style="font-size:11px;padding:5px 10px;color:var(--c-crit);border-color:var(--c-crit)" onclick="deleteMethodology('${m.id}')">${icon('x',{size:11})} Delete</button>` : ''}
        <button class="btn-secondary" style="font-size:11px;padding:5px 10px" onclick="closeMethodRunner()">${icon('x',{size:11})} Close</button>
      </div>
    </div>
    ${!tests.length
      ? `<div class="empty-state" style="padding:24px 0"><div class="empty-title">No tests defined</div><div class="empty-sub">${isOwner?'Edit this methodology to add tests':''}</div></div>`
      : `<div id="method-tests">${tests.map((t,i) => buildMethodTestItem(m.id, t, i, prog[i])).join('')}</div>`
    }`;
}

function buildMethodTestItem(methodId, test, idx, prog) {
  const status = prog?.status || null;
  const target_host = prog?.target_host || null;
  const inScope = (state.targets||[]).filter(t => t.scope === 'in');
  const targetOpts = inScope.map(t =>
    `<option value="${t.id}" ${t.id===prog?.target_id?'selected':''}>${esc(t.host)}</option>`
  ).join('');

  const targetRow = status === 'fail' && inScope.length ? `
    <div class="wstg-target-row" id="mtr-${methodId}-${idx}">
      <span style="font-family:var(--mono);font-size:10px;color:var(--c-crit);flex-shrink:0">Affected target</span>
      <select class="wstg-target-select" onchange="saveMethodTarget('${methodId}',${idx},this.value)">
        <option value="">— Unassigned —</option>
        ${targetOpts}
      </select>
    </div>` : '';

  return `<div class="test-item ${status==='done'?'completed':''} ${status==='fail'?'failed':''}" id="mtest-${methodId}-${idx}">
    <div class="test-header" onclick="toggleMethodTestBody('${methodId}',${idx},event)">
      <div class="test-check"
        style="${status==='done'?'background:var(--c-low);border-color:var(--c-low);color:var(--bg)':status==='fail'?'background:var(--c-crit);border-color:var(--c-crit);color:#fff':''}"
        onclick="cycleMethodStatus('${methodId}',${idx},event)">${status==='done'?icon('check',{size:12}):status==='fail'?icon('x',{size:12}):''}</div>
      <span class="test-name">${esc(test.name)}</span>
      ${target_host && status==='fail' ? `<span class="wstg-target-badge">${esc(target_host)}</span>` : ''}
      <div class="test-actions">
        <button class="test-action-btn pass" onclick="setMethodStatus('${methodId}',${idx},'done',event)">${icon('check',{size:12})}</button>
        <button class="test-action-btn vuln" onclick="setMethodStatus('${methodId}',${idx},'fail',event)">${icon('x',{size:12})} vuln</button>
        <button class="test-action-btn"      onclick="setMethodStatus('${methodId}',${idx},null,event)">${icon('rotate-ccw',{size:12})}</button>
      </div>
    </div>
    ${targetRow}
    <div class="test-body" id="mbody-${methodId}-${idx}">
      ${test.description ? `<div class="items-section"><div class="items-label">Description</div><div class="payload-code" style="color:var(--t2);white-space:pre-wrap">${esc(test.description)}</div></div>` : ''}
      ${(test.references||[]).length ? `<div class="items-section"><div class="items-label">References</div>${test.references.map(r=>`<a href="${esc(r)}" target="_blank" style="display:block;font-family:var(--mono);font-size:11px;color:var(--a);margin:2px 0">${esc(r)}</a>`).join('')}</div>` : ''}
      <textarea class="note-textarea" placeholder="// Notes, findings, POC..."
        onblur="saveMethodNote('${methodId}',${idx},this.value)">${esc(prog?.note||'')}</textarea>
    </div>
  </div>`;
}

function toggleMethodTestBody(methodId, idx, e) {
  if (e.target.closest('.test-check,.test-actions,.wstg-target-row')) return;
  document.getElementById(`mbody-${methodId}-${idx}`)?.classList.toggle('open');
}

async function cycleMethodStatus(methodId, idx, e) {
  e.stopPropagation();
  const cur  = state.methodProgress[methodId]?.[idx]?.status;
  const next = cur === 'done' ? 'fail' : cur === 'fail' ? null : 'done';
  await _applyMethodStatus(methodId, idx, next);
}

async function setMethodStatus(methodId, idx, status, e) {
  e.stopPropagation();
  await _applyMethodStatus(methodId, idx, status);
}

async function _applyMethodStatus(methodId, idx, status) {
  try {
    await api.methodologies.setProgress(methodId, state.currentProject.id, idx, { status });
    if (!state.methodProgress[methodId]) state.methodProgress[methodId] = {};
    if (!state.methodProgress[methodId][idx]) state.methodProgress[methodId][idx] = {};
    state.methodProgress[methodId][idx].status = status;
    if (!status) state.methodProgress[methodId][idx].target_id = null;

    const el = document.getElementById(`mtest-${methodId}-${idx}`);
    if (el) {
      el.className = `test-item ${status==='done'?'completed':''} ${status==='fail'?'failed':''}`;
      const chk = el.querySelector('.test-check');
      chk.innerHTML         = status==='done'?icon('check',{size:12}):status==='fail'?icon('x',{size:12}):'';
      chk.style.background  = status==='done'?'var(--c-low)':status==='fail'?'var(--c-crit)':'';
      chk.style.borderColor = status==='done'?'var(--c-low)':status==='fail'?'var(--c-crit)':'';
      chk.style.color       = status ? (status==='done'?'var(--bg)':'#fff') : '';

      // Toggle target row
      const existingRow = el.querySelector('.wstg-target-row');
      const inScope = (state.targets||[]).filter(t => t.scope === 'in');
      if (status === 'fail' && !existingRow && inScope.length) {
        const targetOpts = inScope.map(t => `<option value="${t.id}">${esc(t.host)}</option>`).join('');
        el.querySelector('.test-header').insertAdjacentHTML('afterend', `
          <div class="wstg-target-row" id="mtr-${methodId}-${idx}">
            <span style="font-family:var(--mono);font-size:10px;color:var(--c-crit);flex-shrink:0">Affected target</span>
            <select class="wstg-target-select" onchange="saveMethodTarget('${methodId}',${idx},this.value)">
              <option value="">— Unassigned —</option>${targetOpts}
            </select>
          </div>`);
      } else if (status !== 'fail' && existingRow) {
        existingRow.remove();
        el.querySelector('.wstg-target-badge')?.remove();
      }
    }
    const label = status==='done'?'Complete':status==='fail'?'Vuln logged':'Cleared';
    showToast(label, status==='fail'?'error':'success');
    renderMethodologyList();
  } catch(err) { showToast(err.message, 'error'); }
}

async function saveMethodNote(methodId, idx, note) {
  try {
    await api.methodologies.setProgress(methodId, state.currentProject.id, idx, { note });
    if (!state.methodProgress[methodId]) state.methodProgress[methodId] = {};
    if (!state.methodProgress[methodId][idx]) state.methodProgress[methodId][idx] = {};
    state.methodProgress[methodId][idx].note = note;
  } catch {}
}

async function saveMethodTarget(methodId, idx, targetId) {
  try {
    await api.methodologies.setProgress(methodId, state.currentProject.id, idx, { target_id: targetId||null });
    if (!state.methodProgress[methodId]) state.methodProgress[methodId] = {};
    if (!state.methodProgress[methodId][idx]) state.methodProgress[methodId][idx] = {};
    state.methodProgress[methodId][idx].target_id = targetId||null;
    // Update badge
    const el = document.getElementById(`mtest-${methodId}-${idx}`);
    const host = (state.targets||[]).find(t=>t.id===targetId)?.host||'';
    const existing = el?.querySelector('.wstg-target-badge');
    if (targetId && host) {
      const badge = `<span class="wstg-target-badge">${esc(host)}</span>`;
      if (existing) existing.outerHTML = badge;
      else el?.querySelector('.test-name')?.insertAdjacentHTML('afterend', badge);
    } else { existing?.remove(); }
    showToast('Target assigned', 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

function closeMethodRunner() {
  _activeMethodId   = null;
  _activeMethodData = null;
  document.getElementById('method-runner').innerHTML = `
    <div class="empty-state" style="padding:48px 0">
      
      <div class="empty-title">Select a methodology</div>
      <div class="empty-sub">Choose from your library on the left</div>
    </div>`;
  renderMethodologyList();
}

// ── CREATE / EDIT MODAL ───────────────────────────────────────────────
function openCreateMethodModal() {
  _editingMethodId = null;
  document.getElementById('method-modal-title').textContent = 'New Methodology';
  document.getElementById('modal-method-name').value        = '';
  document.getElementById('modal-method-desc').value        = '';
  document.getElementById('modal-method-shared').checked    = false;
  document.getElementById('method-tests-editor').innerHTML  = '';
  document.getElementById('method-modal-error').style.display = 'none';
  addMethodTestRow();
  document.getElementById('method-modal').classList.add('open');
}

function openEditMethodModal(id) {
  const m = state.methodologies.find(x => x.id === id);
  if (!m || m.owner_id !== state.user?.id) return;
  _editingMethodId = id;
  document.getElementById('method-modal-title').textContent = 'Edit Methodology';
  document.getElementById('modal-method-name').value        = m.name;
  document.getElementById('modal-method-desc').value        = m.description || '';
  document.getElementById('modal-method-shared').checked    = m.is_shared;
  document.getElementById('method-modal-error').style.display = 'none';

  const editor = document.getElementById('method-tests-editor');
  editor.innerHTML = '';
  (m.tests||[]).forEach(t => addMethodTestRow(t));
  if (!m.tests?.length) addMethodTestRow();
  document.getElementById('method-modal').classList.add('open');
}

function addMethodTestRow(test={}) {
  const row = document.createElement('div');
  row.className = 'method-test-row';
  row.innerHTML = `
    <div style="display:flex;gap:6px;align-items:flex-start">
      <div style="flex:1;display:flex;flex-direction:column;gap:5px">
        <input type="text" class="method-test-name dynamic-input" placeholder="Test name *" value="${esc(test.name||'')}">
        <input type="text" class="method-test-desc dynamic-input" placeholder="Description (optional)" value="${esc(test.description||'')}">
        <input type="text" class="method-test-refs dynamic-input" placeholder="References (comma-separated URLs)" value="${esc((test.references||[]).join(', '))}">
      </div>
      <button class="btn-remove" onclick="this.closest('.method-test-row').remove()" style="margin-top:2px;flex-shrink:0">${icon('x',{size:11})}</button>
    </div>`;
  document.getElementById('method-tests-editor').appendChild(row);
}

function closeMethodModal() {
  document.getElementById('method-modal').classList.remove('open');
  _editingMethodId = null;
}

async function saveMethodology() {
  const name      = document.getElementById('modal-method-name').value.trim();
  const desc      = document.getElementById('modal-method-desc').value.trim();
  const is_shared = document.getElementById('modal-method-shared').checked;
  const errEl     = document.getElementById('method-modal-error');
  const btn       = document.getElementById('method-modal-save');

  if (!name) { errEl.textContent = 'Name is required'; errEl.style.display = 'block'; return; }

  const tests = [...document.querySelectorAll('.method-test-row')].map(row => {
    const n = row.querySelector('.method-test-name').value.trim();
    const d = row.querySelector('.method-test-desc').value.trim();
    const r = row.querySelector('.method-test-refs').value.trim();
    return n ? {
      name: n,
      description: d || undefined,
      references: r ? r.split(',').map(x=>x.trim()).filter(Boolean) : [],
    } : null;
  }).filter(Boolean);

  if (!tests.length) { errEl.textContent = 'Add at least one test'; errEl.style.display = 'block'; return; }

  btn.disabled = true;
  try {
    if (_editingMethodId) {
      const updated = await api.methodologies.update(_editingMethodId, { name, description:desc, is_shared, tests });
      const idx = state.methodologies.findIndex(m => m.id === _editingMethodId);
      if (idx > -1) state.methodologies[idx] = updated;
      if (_activeMethodId === _editingMethodId) {
        _activeMethodData = updated;
        renderMethodologyRunner();
      }
    } else {
      const created = await api.methodologies.create({ name, description:desc, is_shared, tests });
      state.methodologies.unshift(created);
    }
    closeMethodModal();
    renderMethodologyList();
    showToast('Saved', 'success');
  } catch(e) { errEl.textContent = e.message; errEl.style.display = 'block'; }
  finally { btn.disabled = false; }
}

async function deleteMethodology(id) {
  if (!confirm('Delete this methodology? Progress in all projects will be lost.')) return;
  try {
    await api.methodologies.delete(id);
    state.methodologies = state.methodologies.filter(m => m.id !== id);
    if (_activeMethodId === id) closeMethodRunner();
    renderMethodologyList();
    showToast('Deleted', 'error');
  } catch(err) { showToast(err.message, 'error'); }
}

function buildActivateBtn(methodId) {
  if (!state.currentProject) return '';
  const active = (state.currentProject.active_methodology_ids || []).includes(methodId);
  return `<button class="btn-secondary" style="font-size:11px;padding:5px 10px;${active?'border-color:var(--c-low);color:var(--c-low)':''}"
    onclick="toggleActivate('${methodId}')">${active ? icon('check',{size:11}) + ' Active' : '+ Activate'}</button>`;
}

async function toggleActivate(methodId) {
  if (!state.currentProject) return;
  const ids   = state.currentProject.active_methodology_ids || [];
  const active = !ids.includes(methodId);
  try {
    await api.methodologies.activate(methodId, state.currentProject.id, active);
    // Update local state
    if (active) {
      state.currentProject.active_methodology_ids = [...ids, methodId];
    } else {
      state.currentProject.active_methodology_ids = ids.filter(x => x !== methodId);
    }
    // Reload progress for dashboard
    state.activeMethodProgress = await api.methodologies.projectProgress(state.currentProject.id).catch(() => ({}));
    // Re-render runner header to update button
    if (_activeMethodId === methodId) renderMethodologyRunner();
    showToast(active ? 'Activated for this project' : 'Deactivated', active ? 'success' : 'error');
  } catch(err) { showToast(err.message, 'error'); }
}

window.renderMethodologyList  = renderMethodologyList;
window.openMethodology        = openMethodology;
window.renderMethodologyRunner = renderMethodologyRunner;
window.toggleMethodTestBody   = toggleMethodTestBody;
window.cycleMethodStatus      = cycleMethodStatus;
window.setMethodStatus        = setMethodStatus;
window.saveMethodNote         = saveMethodNote;
window.saveMethodTarget       = saveMethodTarget;
window.closeMethodRunner      = closeMethodRunner;
window.openCreateMethodModal  = openCreateMethodModal;
window.openEditMethodModal    = openEditMethodModal;
window.addMethodTestRow       = addMethodTestRow;
window.closeMethodModal       = closeMethodModal;
window.saveMethodology        = saveMethodology;
window.deleteMethodology      = deleteMethodology;
window.toggleActivate         = toggleActivate;