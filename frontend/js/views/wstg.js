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
    if (!tests.length && f !== 'all') return;

    const total = cat.tests.length;
    const done  = cat.tests.filter(t => state.wstgProgress[t.id]?.status === 'done').length;
    const pct   = total ? Math.round(done/total*100) : 0;

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
        <span class="cat-count">${done}/${total}</span>
        <div class="cat-mini-bar"><div class="cat-mini-fill" id="catbar-${cat.id}" style="width:${pct}%"></div></div>
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

const TARGET_ICONS = { domain:'🌐', ip:'🖥', cidr:'🔲', url:'🔗', other:'📌' };

function buildTargetSelector(testId, currentTargetId) {
  const inScope = (state.targets||[]).filter(t => t.scope === 'in');
  if (!inScope.length) return '';

  const options = inScope.map(t =>
    `<option value="${t.id}" ${t.id === currentTargetId ? 'selected' : ''}>${TARGET_ICONS[t.type]||'📌'} ${esc(t.host)}</option>`
  ).join('');

  return `<div class="wstg-target-row" id="target-row-${testId}">
    <span style="font-family:var(--mono);font-size:10px;color:var(--red);flex-shrink:0">🎯 Affected target</span>
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

  // Target selector — only shown when status is fail
  const targetSel = status === 'fail' ? buildTargetSelector(test.id, td.target_id) : '';

  // Target badge in header if assigned
  const targetBadge = (status === 'fail' && td.target_id)
    ? `<span class="wstg-target-badge">🎯 ${esc(_getTargetHost(td.target_id))}</span>`
    : '';

  const el = document.createElement('div');
  el.className = `test-item ${status==='done'?'completed':''} ${status==='fail'?'failed':''}`;
  el.id = `test-${test.id}`;

  el.innerHTML = `
    <div class="test-header" onclick="toggleTestBody('${test.id}',event)">
      <div class="test-check" onclick="cycleWSTGStatus('${test.id}',event)">${status==='done'?'✓':status==='fail'?'✕':''}</div>
      <span class="test-id">${esc(test.id)}</span>
      <span class="test-name">${esc(test.name)}</span>
      ${targetBadge}
      ${editorBadge}
      <div class="test-actions">
        <button class="test-action-btn pass" onclick="setWSTGStatus('${test.id}','done','${esc(test.name)}',event)">✓</button>
        <button class="test-action-btn vuln" onclick="setWSTGStatus('${test.id}','fail','${esc(test.name)}',event)">✕ vuln</button>
        <button class="test-action-btn" onclick="setWSTGStatus('${test.id}',null,'${esc(test.name)}',event)">↺</button>
      </div>
    </div>
    ${targetSel}
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
  const next = cur === 'done' ? 'fail' : cur === 'fail' ? null : 'done';
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

    // If clearing vuln status, also clear target
    if (!status) state.wstgProgress[id].target_id = null;

    const el = document.getElementById(`test-${id}`);
    if (el) {
      el.className = `test-item ${status==='done'?'completed':''} ${status==='fail'?'failed':''}`;
      const chk = el.querySelector('.test-check');
      chk.textContent       = status==='done'?'✓':status==='fail'?'✕':'';
      chk.style.background  = status==='done'?'var(--green)':status==='fail'?'var(--red)':'';
      chk.style.borderColor = status==='done'?'var(--green)':status==='fail'?'var(--red)':'';
      chk.style.color       = status ? 'var(--bg)' : '';

      // Toggle target selector row
      const existingRow = el.querySelector('.wstg-target-row');
      if (status === 'fail' && !existingRow) {
        const header = el.querySelector('.test-header');
        header.insertAdjacentHTML('afterend', buildTargetSelector(id, state.wstgProgress[id].target_id));
      } else if (status !== 'fail' && existingRow) {
        existingRow.remove();
      }

      // Update target badge in header
      const existingBadge = el.querySelector('.wstg-target-badge');
      if (existingBadge) existingBadge.remove();

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

    const label = status==='done'?'✓ Marked complete':status==='fail'?'⚠ Vuln logged — assign a target below':'↺ Cleared';
    showToast(label, status==='fail'?'error':'success');
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
      const badge = `<span class="wstg-target-badge">🎯 ${esc(_getTargetHost(targetId))}</span>`;
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
  const tested = cat.tests.filter(t => !!state.wstgProgress[t.id]?.status).length;
  const pct    = cat.tests.length ? Math.round(tested/cat.tests.length*100) : 0;
  const bar    = document.getElementById(`catbar-${cat.id}`);
  if (bar) bar.style.width = `${pct}%`;
  const cnt    = document.querySelector(`#cat-${cat.id} .cat-count`);
  if (cnt) cnt.textContent = `${tested}/${cat.tests.length}`;
}

function scrollToCat(catId) {
  document.getElementById(`cat-${catId}`)?.scrollIntoView({ behavior:'smooth', block:'start' });
}

function patchWSTGTestDOM(testId, progress) {
  const el = document.getElementById(`test-${testId}`);
  if (!el) return;

  const status = progress.status || null;
  const editor = progress.last_editor;

  el.className = `test-item ${status==='done'?'completed':''} ${status==='fail'?'failed':''}`.trim();

  const chk = el.querySelector('.test-check');
  if (chk) {
    chk.textContent      = status==='done'?'✓':status==='fail'?'✕':'';
    chk.style.background  = status==='done'?'var(--green)':status==='fail'?'var(--red)':'';
    chk.style.borderColor = status==='done'?'var(--green)':status==='fail'?'var(--red)':'';
    chk.style.color       = status ? 'var(--bg)' : '';
  }

  const name = el.querySelector('.test-name');
  if (name) name.style.textDecoration = status==='done' ? 'line-through' : '';

  // Toggle target selector
  const existingRow = el.querySelector('.wstg-target-row');
  if (status === 'fail' && !existingRow) {
    el.querySelector('.test-header')?.insertAdjacentHTML('afterend', buildTargetSelector(testId, progress.target_id));
  } else if (status !== 'fail' && existingRow) {
    existingRow.remove();
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