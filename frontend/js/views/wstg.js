// ── views/wstg.js ────────────────────────────────────────────────────

function filterWSTG(f, el) {
  state.wstgFilter = f;
  document.querySelectorAll('#wstg-filters .filter-chip').forEach(c => c.classList.remove('active'));
  el.classList.add('active');
  renderWSTG();
}

function renderWSTG() {
  const container = document.getElementById('wstg-content');
  container.innerHTML = '';
  if (!state.currentProject) return;

  WSTG_DATA.forEach(cat => {
    let tests = [...cat.tests];
    const f   = state.wstgFilter;
    if (f === 'pending')   tests = tests.filter(t => !state.wstgProgress[t.id]?.status);
    if (f === 'completed') tests = tests.filter(t => state.wstgProgress[t.id]?.status === 'done');
    if (f === 'failed')    tests = tests.filter(t => state.wstgProgress[t.id]?.status === 'fail');
    if (f === 'na')        tests = tests.filter(t => state.wstgProgress[t.id]?.status === 'na');
    if (!tests.length && f !== 'all') return;

    const total    = cat.tests.length;
    const done     = cat.tests.filter(t => state.wstgProgress[t.id]?.status === 'done').length;
    const fail     = cat.tests.filter(t => state.wstgProgress[t.id]?.status === 'fail').length;
    const na       = cat.tests.filter(t => state.wstgProgress[t.id]?.status === 'na').length;
    const reviewed = done + fail + na;
    const donePct  = total ? Math.round(done/total*100) : 0;
    const failPct  = total ? Math.round(fail/total*100) : 0;

    const block = document.createElement('div');
    block.className = 'category-block';
    block.id = `cat-${cat.id}`;

    const hdr = document.createElement('div');
    hdr.className = 'category-header';
    hdr.innerHTML = `
      <span class="category-chevron">▶</span>
      <span class="category-badge">${esc(cat.id)}</span>
      <span class="category-name">${esc(cat.name)}</span>
      <div class="cat-meta">
        <span class="cat-count">${reviewed}/${total}</span>
        <div class="cat-mini-bar"><div class="cat-mini-fill" id="catbar-done-${cat.id}" style="width:${donePct}%"></div><div class="cat-mini-fail" id="catbar-fail-${cat.id}" style="width:${failPct}%"></div></div>
      </div>`;
    hdr.onclick = () => { hdr.classList.toggle('open'); list.classList.toggle('open'); };

    const list = document.createElement('div');
    list.className = 'test-list';

    tests.forEach(t => list.appendChild(buildTestItem(t)));

    block.appendChild(hdr);
    block.appendChild(list);
    container.appendChild(block);
  });
}



function buildTargetSelector(testId, currentTargetId) {
  const inScope = (state.targets||[]).filter(t => t.scope === 'in');
  if (!inScope.length) return '';

  const options = inScope.map(t =>
    `<option value="${t.id}" ${t.id === currentTargetId ? 'selected' : ''}>${esc(t.host)}</option>`
  ).join('');

  return `<div class="wstg-target-row" id="target-row-${testId}">
    <span style="font-family:var(--mono);font-size:10px;color:var(--c-crit);flex-shrink:0">Affected target</span>
    <select class="wstg-target-select" onchange="saveWSTGTarget('${testId}',this.value)">
      <option value="">— Unassigned —</option>
      ${options}
    </select>
  </div>`;
}

function buildTestItem(test) {
  const td      = state.wstgProgress[test.id] || {};
  const status  = td.status || null;
  const editor  = td.last_editor;
  const payloads = PAYLOADS[test.id] || {};
  const pKeys   = Object.keys(payloads);

  // Items checklist
  let itemsHTML = '';
  if (test.items?.length) {
    itemsHTML = `<div class="items-section"><div class="items-label">Checklist</div>` +
      test.items.map((item, idx) => {
        const chk = td.items?.[idx] || false;
        return `<div class="item-row">
          <div class="item-checkbox ${chk?'checked':''}" onclick="toggleWSTGItem('${test.id}',${idx},this)">${chk?'✓':''}</div>
          <span class="item-text ${chk?'done':''}">${esc(item)}</span>
        </div>`;
      }).join('') + '</div>';
  }

  // Payload tabs
  let payloadsHTML = '';
  if (pKeys.length) {
    const tabs   = pKeys.map((k,i) => `<button class="payload-tab ${i===0?'active':''}" onclick="switchPayloadTab('${test.id}','${k}',this)">${esc(k)}</button>`).join('');
    const panels = pKeys.map((k,i) => `<div class="payload-panel ${i===0?'active':''}" data-tab="${k}">` +
      payloads[k].map(p => `<div class="payload-row">
        <div class="payload-code">${esc(p)}</div>
        <button class="copy-btn" onclick="copyText(this,'${btoa(encodeURIComponent(p))}')">copy</button>
      </div>`).join('') + '</div>').join('');
    payloadsHTML = `<div class="payload-section"><div class="items-label">Payloads</div><div class="payload-tabs">${tabs}</div>${panels}</div>`;
  }

  // Last editor badge
  const editorBadge = editor ? `
    <div class="last-editor" title="${esc(editor.username)} · ${relativeDate(td.updated_at)}">
      ${avatarHtml(editor.username, memberRoleColor(editor.id, editor.avatar_color), 20, editor.avatar_url || null)}
      <span class="last-editor-name">${esc(editor.username)}</span>
      <span class="last-editor-time">${timeAgo(td.updated_at)}</span>
    </div>` : '';

  // Target selector + link selector — only shown when status is fail
  const targetSel = status === 'fail' ? buildTargetSelector(test.id, td.target_id) : '';
  const linkSel   = status === 'fail' ? buildVulnLinkSelector(test.id, td.linked_vuln_id) : '';

  // Badges in header (only when fail + assigned)
  const targetBadge = (status === 'fail' && td.target_id)
    ? `<span class="wstg-target-badge">${esc(_getTargetHost(td.target_id))}</span>`
    : '';
  const linkBadge = (status === 'fail' && td.linked_vuln_id)
    ? `<span class="wstg-link-badge">${esc(_getVulnName(td.linked_vuln_id))}</span>`
    : '';

  const statusClass = status==='done'?'completed':status==='fail'?'failed':status==='na'?'na':'';
  const el = document.createElement('div');
  el.className = `test-item${statusClass?' '+statusClass:''}`;
  el.id = `test-${test.id}`;

  el.innerHTML = `
    <div class="test-header" onclick="toggleTestBody('${test.id}',event)">
      <div class="test-check" onclick="cycleWSTGStatus('${test.id}',event)">${status==='done'?'✓':status==='fail'?'✕':status==='na'?'—':''}</div>
      <span class="test-id">${esc(test.id)}</span>
      <span class="test-name">${esc(test.name)}</span>
      ${targetBadge}
      ${linkBadge}
      ${editorBadge}
      <div class="test-actions">
        <button class="test-action-btn pass" onclick="setWSTGStatus('${test.id}','done','${esc(test.name)}',event)">✓</button>
        <button class="test-action-btn vuln" onclick="setWSTGStatus('${test.id}','fail','${esc(test.name)}',event)">✕ vuln</button>
        <button class="test-action-btn" onclick="setWSTGStatus('${test.id}','na','${esc(test.name)}',event)">N/A</button>
        <button class="test-action-btn" onclick="setWSTGStatus('${test.id}',null,'${esc(test.name)}',event)">↺</button>
      </div>
    </div>
    ${targetSel}
    ${linkSel}
    <div class="test-body" id="body-${test.id}">
      ${itemsHTML}${payloadsHTML}
      <textarea class="note-textarea" placeholder="// Notes, findings, POC..."
        onblur="saveWSTGNote('${test.id}','${esc(test.name)}',this.value)">${esc(td.note||'')}</textarea>
    </div>`;
  return el;
}

function _getTargetHost(targetId) {
  return (state.targets||[]).find(t => t.id === targetId)?.host || targetId;
}

function _getVulnName(vulnId) {
  return (state.customVulns||[]).find(v => v.id === vulnId)?.name || vulnId;
}

function buildVulnLinkSelector(testId, currentLinkedId) {
  const vulns = (state.customVulns || []);
  if (!vulns.length) return '';
  const options = vulns.map(v =>
    `<option value="${esc(v.id)}" ${v.id === currentLinkedId ? 'selected' : ''}>${esc(v.name)}</option>`
  ).join('');
  return `<div class="wstg-link-row" id="link-row-${testId}">
    <span style="font-family:var(--mono);font-size:10px;color:var(--a);flex-shrink:0">→ Link to finding</span>
    <select class="wstg-link-select" onchange="saveWSTGLink('${testId}',this.value)">
      <option value="">— Not linked —</option>
      ${options}
    </select>
  </div>`;
}

function toggleTestBody(id, e) {
  if (e.target.closest('.test-check,.test-actions,.wstg-target-row')) return;
  document.getElementById(`body-${id}`)?.classList.toggle('open');
}

function switchPayloadTab(testId, tab, btn) {
  const body = document.getElementById(`body-${testId}`);
  if (!body) return;
  body.querySelectorAll('.payload-tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  body.querySelectorAll('.payload-panel').forEach(p => p.classList.toggle('active', p.dataset.tab === tab));
}

async function cycleWSTGStatus(id, e) {
  e.stopPropagation();
  const cur  = state.wstgProgress[id]?.status;
  const next = cur === 'done' ? 'fail' : cur === 'fail' ? 'na' : cur === 'na' ? null : 'done';
  const test = WSTG_DATA.flatMap(c => c.tests).find(t => t.id === id);
  await _applyWSTGStatus(id, next, test?.name || id);
}

async function setWSTGStatus(id, status, testName, e) {
  e.stopPropagation();
  await _applyWSTGStatus(id, status, testName);
}

async function _applyWSTGStatus(id, status, testName) {
  try {
    const res = await api.wstg.setStatus(state.currentProject.id, id, status, testName);
    if (!state.wstgProgress[id]) state.wstgProgress[id] = {};
    state.wstgProgress[id].status     = status;
    state.wstgProgress[id].updated_at = res.updated_at;
    state.wstgProgress[id].last_editor = res.editor;

    // If leaving fail status, also clear target and link
    if (status !== 'fail') {
      state.wstgProgress[id].target_id      = null;
      state.wstgProgress[id].linked_vuln_id = null;
    }

    const el = document.getElementById(`test-${id}`);
    if (el) {
      const sc = status==='done'?'completed':status==='fail'?'failed':status==='na'?'na':'';
      el.className = `test-item${sc?' '+sc:''}`;
      const chk = el.querySelector('.test-check');
      chk.textContent       = status==='done'?'✓':status==='fail'?'✕':status==='na'?'—':'';
      chk.style.background  = status==='done'?'var(--c-low)':status==='fail'?'var(--c-crit)':status==='na'?'var(--b2)':'';
      chk.style.borderColor = status==='done'?'var(--c-low)':status==='fail'?'var(--c-crit)':status==='na'?'var(--b2)':'';
      chk.style.color       = (status==='done'||status==='fail') ? 'var(--bg)' : status==='na' ? 'var(--t3)' : '';

      // Toggle target selector row + link row
      const existingTargetRow = el.querySelector('.wstg-target-row');
      const existingLinkRow   = el.querySelector('.wstg-link-row');
      if (status === 'fail') {
        const header = el.querySelector('.test-header');
        if (!existingTargetRow) {
          header.insertAdjacentHTML('afterend', buildTargetSelector(id, state.wstgProgress[id].target_id));
        }
        if (!existingLinkRow) {
          const targetRow = el.querySelector('.wstg-target-row');
          targetRow.insertAdjacentHTML('afterend', buildVulnLinkSelector(id, state.wstgProgress[id].linked_vuln_id));
        }
      } else {
        existingTargetRow?.remove();
        existingLinkRow?.remove();
      }

      // Update target + link badges in header
      el.querySelector('.wstg-target-badge')?.remove();
      el.querySelector('.wstg-link-badge')?.remove();

      // Update editor badge
      const editor = res.editor;
      if (editor) {
        const html = `<div class="last-editor" title="${esc(editor.username)} · just now">
          ${avatarHtml(editor.username, memberRoleColor(editor.id, editor.avatar_color), 20, editor.avatar_url || null)}
          <span class="last-editor-name">${esc(editor.username)}</span>
          <span class="last-editor-time">just now</span>
        </div>`;
        const badge = el.querySelector('.last-editor');
        if (badge) badge.outerHTML = html;
        else el.querySelector('.test-actions')?.insertAdjacentHTML('beforebegin', html);
      }
    }

    updateCatBar(id);
    if (typeof updateDashboard === 'function') updateDashboard();

    const label = status==='done'?'✓ Marked complete':status==='fail'?'⚠ Vuln logged — assign a target below':status==='na'?'— Marked as N/A':'↺ Cleared';
    showToast(label, status==='fail'?'error':status==='na'?'info':'success');
  } catch(err) { showToast(err.message, 'error'); }
}

async function saveWSTGTarget(testId, targetId) {
  try {
    await api.wstg.setTarget(state.currentProject.id, testId, targetId||null);
    if (!state.wstgProgress[testId]) state.wstgProgress[testId] = {};
    state.wstgProgress[testId].target_id = targetId || null;

    // Update badge in header
    const el = document.getElementById(`test-${testId}`);
    if (!el) return;
    const existing = el.querySelector('.wstg-target-badge');
    if (targetId) {
      const badge = `<span class="wstg-target-badge">${esc(_getTargetHost(targetId))}</span>`;
      if (existing) existing.outerHTML = badge;
      else el.querySelector('.test-id')?.insertAdjacentHTML('afterend', badge);
    } else {
      existing?.remove();
    }
    showToast('✓ Target assigned', 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

async function toggleWSTGItem(testId, idx, el) {
  const cur = state.wstgProgress[testId]?.items?.[idx] || false;
  try {
    await api.wstg.setItem(state.currentProject.id, testId, idx, !cur);
    if (!state.wstgProgress[testId]) state.wstgProgress[testId] = {};
    if (!state.wstgProgress[testId].items) state.wstgProgress[testId].items = {};
    state.wstgProgress[testId].items[idx] = !cur;
    el.classList.toggle('checked', !cur);
    el.textContent = !cur ? '✓' : '';
    el.nextElementSibling?.classList.toggle('done', !cur);
  } catch(err) { showToast(err.message, 'error'); }
}

let _noteTimers = {};
function saveWSTGNote(testId, testName, val) {
  clearTimeout(_noteTimers[testId]);
  _noteTimers[testId] = setTimeout(async () => {
    try {
      await api.wstg.setNote(state.currentProject.id, testId, val, testName);
      if (!state.wstgProgress[testId]) state.wstgProgress[testId] = {};
      state.wstgProgress[testId].note = val;
    } catch {}
  }, 900);
}

function updateCatBar(testId) {
  const cat = WSTG_DATA.find(c => c.tests.some(t => t.id === testId));
  if (!cat) return;
  const total    = cat.tests.length;
  const done     = cat.tests.filter(t => state.wstgProgress[t.id]?.status === 'done').length;
  const fail     = cat.tests.filter(t => state.wstgProgress[t.id]?.status === 'fail').length;
  const na       = cat.tests.filter(t => state.wstgProgress[t.id]?.status === 'na').length;
  const reviewed = done + fail + na;
  const donePct  = total ? Math.round(done/total*100) : 0;
  const failPct  = total ? Math.round(fail/total*100) : 0;
  const doneBar  = document.getElementById(`catbar-done-${cat.id}`);
  const failBar  = document.getElementById(`catbar-fail-${cat.id}`);
  if (doneBar) doneBar.style.width = `${donePct}%`;
  if (failBar) failBar.style.width = `${failPct}%`;
  const cnt = document.querySelector(`#cat-${cat.id} .cat-count`);
  if (cnt) cnt.textContent = `${reviewed}/${total}`;
}

function scrollToCat(catId) {
  document.getElementById(`cat-${catId}`)?.scrollIntoView({ behavior:'smooth', block:'start' });
}

function patchWSTGTestDOM(testId, progress) {
  const el = document.getElementById(`test-${testId}`);
  if (!el) return;

  const status = progress.status || null;
  const editor = progress.last_editor;

  const sc = status==='done'?'completed':status==='fail'?'failed':status==='na'?'na':'';
  el.className = `test-item${sc?' '+sc:''}`;

  const chk = el.querySelector('.test-check');
  if (chk) {
    chk.textContent       = status==='done'?'✓':status==='fail'?'✕':status==='na'?'—':'';
    chk.style.background  = status==='done'?'var(--c-low)':status==='fail'?'var(--c-crit)':status==='na'?'var(--b2)':'';
    chk.style.borderColor = status==='done'?'var(--c-low)':status==='fail'?'var(--c-crit)':status==='na'?'var(--b2)':'';
    chk.style.color       = (status==='done'||status==='fail') ? 'var(--bg)' : status==='na' ? 'var(--t3)' : '';
  }

  const name = el.querySelector('.test-name');
  if (name) name.style.textDecoration = status==='done' ? 'line-through' : '';

  // Toggle target selector + link row
  const existingTargetRow = el.querySelector('.wstg-target-row');
  const existingLinkRow   = el.querySelector('.wstg-link-row');
  if (status === 'fail') {
    if (!existingTargetRow) {
      el.querySelector('.test-header')?.insertAdjacentHTML('afterend', buildTargetSelector(testId, progress.target_id));
    }
    if (!existingLinkRow) {
      const targetRow = el.querySelector('.wstg-target-row');
      targetRow?.insertAdjacentHTML('afterend', buildVulnLinkSelector(testId, progress.linked_vuln_id));
    }
  } else {
    existingTargetRow?.remove();
    existingLinkRow?.remove();
  }

  if (editor) {
    const badgeHTML = `<div class="last-editor" title="${esc(editor.username)} · just now">
      ${avatarHtml(editor.username, memberRoleColor(editor.id, editor.avatar_color), 20, editor.avatar_url || null)}
      <span class="last-editor-name">${esc(editor.username)}</span>
      <span class="last-editor-time">just now</span>
    </div>`;
    const existing = el.querySelector('.last-editor');
    if (existing) existing.outerHTML = badgeHTML;
    else el.querySelector('.test-actions')?.insertAdjacentHTML('beforebegin', badgeHTML);
  }

  updateCatBar(testId);
}

async function saveWSTGLink(testId, vulnId) {
  try {
    await api.wstg.setLink(state.currentProject.id, testId, vulnId || null);
    if (!state.wstgProgress[testId]) state.wstgProgress[testId] = {};
    state.wstgProgress[testId].linked_vuln_id = vulnId || null;

    const el = document.getElementById(`test-${testId}`);
    if (!el) return;
    const existing = el.querySelector('.wstg-link-badge');
    if (vulnId) {
      const vulnName = _getVulnName(vulnId);
      const badge = `<span class="wstg-link-badge">→ ${esc(vulnName)}</span>`;
      if (existing) existing.outerHTML = badge;
      else el.querySelector('.wstg-target-badge')?.insertAdjacentHTML('afterend', badge)
        || el.querySelector('.test-id')?.insertAdjacentHTML('afterend', badge);
    } else {
      existing?.remove();
    }
    showToast(vulnId ? '✓ Linked to finding' : '↺ Link removed', 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

window.filterWSTG        = filterWSTG;
window.renderWSTG        = renderWSTG;
window.buildTestItem     = buildTestItem;
window.toggleTestBody    = toggleTestBody;
window.switchPayloadTab  = switchPayloadTab;
window.cycleWSTGStatus   = cycleWSTGStatus;
window.setWSTGStatus     = setWSTGStatus;
window.saveWSTGTarget    = saveWSTGTarget;
window.toggleWSTGItem    = toggleWSTGItem;
window.saveWSTGNote      = saveWSTGNote;
window.scrollToCat       = scrollToCat;
window.patchWSTGTestDOM  = patchWSTGTestDOM;
window.saveWSTGLink      = saveWSTGLink;