// ── views/dashboard.js ───────────────────────────────────────────────

function updateDashboard() {
  if (!state.currentProject) return;

  let wDone=0, wFail=0, wTotal=0;
  WSTG_DATA.forEach(cat => cat.tests.forEach(t => {
    wTotal++;
    const s = state.wstgProgress[t.id]?.status;
    if (s === 'done') wDone++;
    if (s === 'fail') wFail++;
  }));
  let psDone=0, psTotal=0;
  PS_DATA.forEach(cat => cat.labs.forEach((_,i) => {
    psTotal++;
    if (state.psProgress[`${cat.id}_${i}`]) psDone++;
  }));

  const wPct = wTotal ? Math.round(wDone/wTotal*100) : 0;
  const pPct = psTotal ? Math.round(psDone/psTotal*100) : 0;

  const setVal = (id, v) => { const el = document.getElementById(id); if(el) el.textContent = v; };
  const setW   = (id, v) => { const el = document.getElementById(id); if(el) el.style.width = v; };

  setVal('stat-completed', wDone);
  setVal('stat-remaining', wTotal - wDone);
  setVal('stat-failed',    wFail);
  setVal('stat-members',   state.members.length);
  setVal('dash-wstg-pct',  `${wPct}%`);
  setW('dash-wstg-bar',  `${wPct}%`);
  setVal('dash-ps-pct',   `${pPct}%`);
  setW('dash-ps-bar',    `${pPct}%`);
  setVal('dash-subtitle', `// ${state.currentProject.name} — ${wPct}% WSTG complete`);

  // Category breakdown
  const grid = document.getElementById('dash-cat-grid');
  if (grid) {
    grid.innerHTML = WSTG_DATA.map(cat => {
      const t = cat.tests.length;
      const d = cat.tests.filter(test => state.wstgProgress[test.id]?.status === 'done').length;
      const p = t ? Math.round(d/t*100) : 0;
      return `<div class="progress-section" style="margin:0">
        <div class="progress-label-row">
          <span class="progress-label" style="font-size:9px">${esc(cat.name)}</span>
          <span class="progress-pct" style="font-size:11px">${p}%</span>
        </div>
        <div class="progress-bar"><div class="progress-bar-fill" style="width:${p}%"></div></div>
      </div>`;
    }).join('');
  }

  updateTopbarProgress(wDone + psDone, wTotal + psTotal);
}

function updateTopbarProgress(done, total) {
  const pct = total ? Math.round(done/total*100) : 0;
  const el  = document.getElementById('topbar-pct');
  const bar = document.getElementById('topbar-bar');
  if (el)  el.textContent   = `${pct}%`;
  if (bar) bar.style.width  = `${pct}%`;
}

window.updateDashboard       = updateDashboard;
window.updateTopbarProgress  = updateTopbarProgress;
