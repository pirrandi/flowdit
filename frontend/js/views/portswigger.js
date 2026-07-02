// ── views/portswigger.js ─────────────────────────────────────────────

function filterPS(f, el) {
  state.psFilter = f;
  document.querySelectorAll('#ps-filters .filter-chip').forEach(c => c.classList.remove('active'));
  el.classList.add('active');
  renderPS();
}

function _psLabDone(key) {
  const v = state.psProgress[key];
  return v === true || v?.done === true;
}

function _psLabNote(key) {
  const v = state.psProgress[key];
  return (v && typeof v === 'object') ? (v.note || '') : '';
}

function renderPS() {
  const container = document.getElementById('ps-content');
  container.innerHTML = '';
  if (!state.currentProject) return;

  PS_DATA.forEach(cat => {
    const f = state.psFilter;

    // Decide which labs to show (filter), but keep original index
    const visible = cat.labs.map((lab, i) => ({ lab, i })).filter(({ lab, i }) => {
      const key  = `${cat.id}_${i}`;
      const done = _psLabDone(key);
      if (['Apprentice','Practitioner','Expert'].includes(f) && lab.difficulty !== f) return false;
      if (f === 'done'    && !done) return false;
      if (f === 'pending' && done)  return false;
      return true;
    });

    if (!visible.length && f !== 'all') return;

    const total = cat.labs.length;
    const done  = cat.labs.filter((_, i) => _psLabDone(`${cat.id}_${i}`)).length;

    const labsHTML = visible.map(({ lab, i }) => {
      const key  = `${cat.id}_${i}`;
      const chk  = _psLabDone(key);
      const note = _psLabNote(key);
      return `
        <div class="ps-lab-item" id="pslab-${cat.id}-${i}">
          <div class="ps-lab-row" onclick="togglePSLabBody('${cat.id}',${i},event)">
            <div class="ps-lab-check ${chk?'done':''}"
              onclick="togglePSLab('${cat.id}',${i},'${esc(lab.title)}',this);event.stopPropagation()"
            >${chk?icon('check',{size:11}):''}</div>
            <span class="ps-lab-title ${chk?'done':''}">${esc(lab.title)}</span>
            <span class="diff-badge diff-${lab.difficulty}">${lab.difficulty}</span>
            <span class="ps-note-indicator" id="psnote-ind-${cat.id}-${i}" style="${note?'':'display:none'}"
              title="Has notes">${icon('square-pen',{size:10})}</span>
          </div>
          <div class="ps-lab-body" id="pslab-body-${cat.id}-${i}">
            <textarea
              class="note-textarea"
              placeholder="// Approach, payload that worked, concept learned..."
              onblur="savePSNote('${cat.id}',${i},this.value)"
            >${esc(note)}</textarea>
          </div>
        </div>`;
    }).join('');

    const wrap = document.createElement('div');
    wrap.className = 'ps-category';
    wrap.id = `ps-cat-${cat.id}`;
    wrap.innerHTML = `
      <div class="ps-cat-header" onclick="this.classList.toggle('open');this.nextElementSibling.classList.toggle('open')">
        <span class="ps-cat-name">${esc(cat.name)}</span>
        <span class="ps-cat-count" id="pscount-${cat.id}">${done}/${total}</span>
        <span class="category-chevron">${icon('chevron-right',{size:12})}</span>
      </div>
      <div class="ps-labs">${labsHTML}</div>`;
    container.appendChild(wrap);
  });
}

function togglePSLabBody(catId, idx, e) {
  if (e.target.closest('.ps-lab-check')) return;
  document.getElementById(`pslab-body-${catId}-${idx}`)?.classList.toggle('open');
}

async function togglePSLab(catId, idx, labTitle, el) {
  const key = `${catId}_${idx}`;
  const cur = _psLabDone(key);
  try {
    await api.ps.toggle(state.currentProject.id, catId, idx, !cur, labTitle);
    if (!state.psProgress[key] || typeof state.psProgress[key] !== 'object')
      state.psProgress[key] = { done: false, note: '' };
    state.psProgress[key].done = !cur;
    el.classList.toggle('done', !cur);
    el.innerHTML = !cur ? icon('check',{size:11}) : '';
    const titleEl = el.nextElementSibling;
    if (titleEl) titleEl.classList.toggle('done', !cur);
    updatePSCatCount(catId);
    if (typeof updateDashboard  === 'function') updateDashboard();
    if (typeof updatePSProgress === 'function') updatePSProgress();
  } catch(err) { showToast(err.message, 'error'); }
}

let _psNoteTimers = {};
function savePSNote(catId, idx, val) {
  const key = `${catId}_${idx}`;
  clearTimeout(_psNoteTimers[key]);
  _psNoteTimers[key] = setTimeout(async () => {
    try {
      await api.ps.saveNote(state.currentProject.id, catId, idx, val);
      if (!state.psProgress[key] || typeof state.psProgress[key] !== 'object')
        state.psProgress[key] = { done: false, note: '' };
      state.psProgress[key].note = val;
      // Show/hide note indicator
      const ind = document.getElementById(`psnote-ind-${catId}-${idx}`);
      if (ind) ind.style.display = val ? '' : 'none';
    } catch {}
  }, 800);
}

function updatePSCatCount(catId) {
  const cat = PS_DATA.find(c => c.id === catId);
  if (!cat) return;
  const done = cat.labs.filter((_, i) => _psLabDone(`${catId}_${i}`)).length;
  const el   = document.getElementById(`pscount-${catId}`);
  if (el) el.textContent = `${done}/${cat.labs.length}`;
}

function scrollToPS(catId) {
  document.getElementById(`ps-cat-${catId}`)?.scrollIntoView({ behavior:'smooth', block:'start' });
}

window.filterPS         = filterPS;
window.renderPS         = renderPS;
window.togglePSLabBody  = togglePSLabBody;
window.togglePSLab      = togglePSLab;
window.savePSNote       = savePSNote;
window.updatePSCatCount = updatePSCatCount;
window.scrollToPS       = scrollToPS;