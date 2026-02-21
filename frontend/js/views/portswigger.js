// ── views/portswigger.js ─────────────────────────────────────────────

function filterPS(f, el) {
  state.psFilter = f;
  document.querySelectorAll('#ps-filters .filter-chip').forEach(c => c.classList.remove('active'));
  el.classList.add('active');
  renderPS();
}

function renderPS() {
  const container = document.getElementById('ps-content');
  container.innerHTML = '';
  if (!state.currentProject) return;

  PS_DATA.forEach(cat => {
    let labs = [...cat.labs];
    const f  = state.psFilter;
    if (['Apprentice','Practitioner','Expert'].includes(f)) labs = labs.filter(l => l.difficulty === f);
    else if (f === 'done')    labs = cat.labs.filter((_,i) => state.psProgress[`${cat.id}_${i}`]);
    else if (f === 'pending') labs = cat.labs.filter((_,i) => !state.psProgress[`${cat.id}_${i}`]);
    if (!labs.length && f !== 'all') return;

    const total = cat.labs.length;
    const done  = cat.labs.filter((_,i) => state.psProgress[`${cat.id}_${i}`]).length;

    // Build lab rows using original indices
    const labsHTML = cat.labs.map((lab, i) => {
      const f2 = state.psFilter;
      if (['Apprentice','Practitioner','Expert'].includes(f2) && lab.difficulty !== f2) return '';
      if (f2 === 'done'    && !state.psProgress[`${cat.id}_${i}`]) return '';
      if (f2 === 'pending' && state.psProgress[`${cat.id}_${i}`])  return '';
      const chk = state.psProgress[`${cat.id}_${i}`] || false;
      return `<div class="ps-lab-row">
        <div class="ps-lab-check ${chk?'done':''}" onclick="togglePSLab('${cat.id}',${i},'${esc(lab.title)}',this)">${chk?'✓':''}</div>
        <span class="ps-lab-title">${esc(lab.title)}</span>
        <span class="diff-badge diff-${lab.difficulty}">${lab.difficulty}</span>
      </div>`;
    }).join('');

    const wrap = document.createElement('div');
    wrap.className = 'ps-category';
    wrap.id = `ps-cat-${cat.id}`;
    wrap.innerHTML = `
      <div class="ps-cat-header" onclick="this.classList.toggle('open');this.nextElementSibling.classList.toggle('open')">
        <span class="ps-cat-name">${esc(cat.name)}</span>
        <span class="ps-cat-count">${done}/${total}</span>
        <span class="category-chevron">▶</span>
      </div>
      <div class="ps-labs">${labsHTML}</div>`;
    container.appendChild(wrap);
  });
}

async function togglePSLab(catId, idx, labTitle, el) {
  const key = `${catId}_${idx}`;
  const cur = state.psProgress[key] || false;
  try {
    await api.ps.toggle(state.currentProject.id, catId, idx, !cur, labTitle);
    state.psProgress[key] = !cur;
    el.classList.toggle('done', !cur);
    el.textContent = !cur ? '✓' : '';
    el.nextElementSibling?.classList.toggle('checked-text', !cur);
    updateDashboard();
    updateSidebar();
  } catch(err) { showToast(err.message, 'error'); }
}

function scrollToPS(catId) {
  document.getElementById(`ps-cat-${catId}`)?.scrollIntoView({ behavior:'smooth', block:'start' });
}

window.filterPS     = filterPS;
window.renderPS     = renderPS;
window.togglePSLab  = togglePSLab;
window.scrollToPS   = scrollToPS;
