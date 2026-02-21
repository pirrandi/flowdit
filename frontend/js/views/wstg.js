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
    const tabs  = pKeys.map((k,i) => `<button class="payload-tab ${i===0?'active':''}" onclick="switchPayloadTab('${test.id}','${k}',this)">${esc(k)}</button>`).join('');
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
      <div class="last-editor-avatar" style="background:${esc(editor.avatar_color)}">${editor.username[0].toUpperCase()}</div>
      <span class="last-editor-name">${esc(editor.username)}</span>
      <span class="last-editor-time">${timeAgo(td.updated_at)}</span>
    </div>` : '';

  const el = document.createElement('div');
  el.className = `test-item ${status==='done'?'completed':''} ${status==='fail'?'failed':''}`;
  el.id = `test-${test.id}`;

  el.innerHTML = `
    <div class="test-header" onclick="toggleTestBody('${test.id}',event)">
      <div class="test-check" onclick="cycleWSTGStatus('${test.id}',event)">${status==='done'?'✓':status==='fail'?'✕':''}</div>
      <span class="test-id">${esc(test.id)}</span>
      <span class="test-name">${esc(test.name)}</span>
      ${editorBadge}
      <div class="test-actions">
        <button class="test-action-btn pass" onclick="setWSTGStatus('${test.id}','done','${esc(test.name)}',event)">✓</button>
        <button class="test-action-btn vuln" onclick="setWSTGStatus('${test.id}','fail','${esc(test.name)}',event)">✕ vuln</button>
        <button class="test-action-btn" onclick="setWSTGStatus('${test.id}',null,'${esc(test.name)}',event)">↺</button>
      </div>
    </div>
    <div class="test-body" id="body-${test.id}">
      ${itemsHTML}${payloadsHTML}
      <textarea class="note-textarea" placeholder="// Notes, findings, POC..."
        onblur="saveWSTGNote('${test.id}','${esc(test.name)}',this.value)">${esc(td.note||'')}</textarea>
    </div>`;
  return el;
}

function toggleTestBody(id, e) {
  if (e.target.closest('.test-check,.test-actions')) return;
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

    // Refresh item UI
    const el = document.getElementById(`test-${id}`);
    if (el) {
      el.className = `test-item ${status==='done'?'completed':''} ${status==='fail'?'failed':''}`;
      const chk = el.querySelector('.test-check');
      chk.textContent  = status==='done'?'✓':status==='fail'?'✕':'';
      chk.style.background  = status==='done'?'var(--green)':status==='fail'?'var(--red)':'';
      chk.style.borderColor = status==='done'?'var(--green)':status==='fail'?'var(--red)':'';
      chk.style.color       = status ? 'var(--bg)' : '';

      // Update editor badge
      const editor = res.editor;
      let badge = el.querySelector('.last-editor');
      if (editor) {
        const html = `<div class="last-editor" title="${esc(editor.username)} · just now">
          <div class="last-editor-avatar" style="background:${esc(editor.avatar_color)}">${editor.username[0].toUpperCase()}</div>
          <span class="last-editor-name">${esc(editor.username)}</span>
          <span class="last-editor-time">just now</span>
        </div>`;
        if (badge) badge.outerHTML = html;
        else {
          const actions = el.querySelector('.test-actions');
          actions?.insertAdjacentHTML('beforebegin', html);
        }
      }
    }

    updateCatBar(id);
    updateDashboard();

    const label = status==='done'?'✓ Marked complete':status==='fail'?'⚠ Vuln logged':'↺ Cleared';
    showToast(label, status==='fail'?'error':'success');
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
  const done = cat.tests.filter(t => state.wstgProgress[t.id]?.status === 'done').length;
  const pct  = cat.tests.length ? Math.round(done/cat.tests.length*100) : 0;
  const bar  = document.getElementById(`catbar-${cat.id}`);
  if (bar) bar.style.width = `${pct}%`;
  const cnt  = document.querySelector(`#cat-${cat.id} .cat-count`);
  if (cnt) cnt.textContent = `${done}/${cat.tests.length}`;
}

function scrollToCat(catId) {
  document.getElementById(`cat-${catId}`)?.scrollIntoView({ behavior:'smooth', block:'start' });
}

window.filterWSTG      = filterWSTG;
window.renderWSTG      = renderWSTG;
window.toggleTestBody  = toggleTestBody;
window.switchPayloadTab = switchPayloadTab;
window.cycleWSTGStatus = cycleWSTGStatus;
window.setWSTGStatus   = setWSTGStatus;
window.toggleWSTGItem  = toggleWSTGItem;
window.saveWSTGNote    = saveWSTGNote;
window.scrollToCat     = scrollToCat;
