// ── page.js — shared controller for all internal pages ──────────────
// Loaded by dashboard.html, wstg.html, portswigger.html, vulns.html, members.html

// ── AUTH GUARD ────────────────────────────────────────────────────
window.addEventListener('fd:logout', () => { window.location.href = 'index.html'; });

async function bootPage(viewName) {
  if (!api.auth.hasSession()) { window.location.href = 'index.html'; return; }
  try { state.user = await api.auth.me(); }
  catch { window.location.href = 'index.html'; return; }

  state.currentView = viewName;
  renderTopbar();

  state.projects = await api.projects.list();
  state.currentProject = state.projects[0] || null;

  const saved = localStorage.getItem('fd_project');
  if (saved) {
    const found = state.projects.find(p => p.id === saved);
    if (found) state.currentProject = found;
  }

  if (state.currentProject) await loadProjectData(state.currentProject.id);

  hide('loading-overlay');
  if (typeof pageInit === 'function') pageInit();
  refreshTopbarProgress();
}

// ── PROJECT LOADING ───────────────────────────────────────────────
async function loadProjectData(pid) {
  wsClient.connect(pid);
  [state.wstgProgress, state.psProgress, state.customVulns, state.members, state.targets] = await Promise.all([
    api.wstg.getAll(pid),
    api.ps.getAll(pid),
    api.vulns.list(pid),
    api.members.list(pid),
    api.targets.list(pid),
  ]);
  await loadActivity(pid);
}

async function switchProject(id) {
  const proj = state.projects.find(p => p.id === id);
  if (!proj) return;
  state.currentProject = proj;
  localStorage.setItem('fd_project', id);
  wsClient.disconnect();
  show('loading-overlay');
  await loadProjectData(id);
  hide('loading-overlay');
  if (typeof pageInit === 'function') pageInit();
  refreshTopbarProgress();
  if (typeof updateDashboard === 'function') updateDashboard();
}

// ── PROGRESS — always computed from full WSTG+PS totals ──────────
function calcOverallProgress() {
  let done = 0, total = 0;
  if (typeof WSTG_DATA !== 'undefined') {
    WSTG_DATA.forEach(cat => cat.tests.forEach(t => {
      total++;
      if (state.wstgProgress[t.id]?.status === 'done') done++;
    }));
  }
  if (typeof PS_DATA !== 'undefined') {
    PS_DATA.forEach(cat => cat.labs.forEach((_, i) => {
      total++;
      const v = state.psProgress[`${cat.id}_${i}`];
      if (v === true || v?.done === true) done++;
    }));
  }
  return { done, total };
}

function refreshTopbarProgress() {
  const { done, total } = calcOverallProgress();
  updateTopbarProgress(done, total);
}

function updateTopbarProgress(done, total) {
  const pct = total ? Math.round(done / total * 100) : 0;
  const el  = document.getElementById('topbar-pct');
  const bar = document.getElementById('topbar-bar');
  if (el)  el.textContent  = `${pct}%`;
  if (bar) bar.style.width = `${pct}%`;
}

// ── TOPBAR ────────────────────────────────────────────────────────
function renderTopbar() {
  const u = state.user;
  const pages = [
    { href:'dashboard.html',   label:'Dashboard' },
    { href:'owstg.html',        label:'OWASP WSTG' },
    { href:'portswigger.html', label:'PortSwigger' },
    { href:'vulns.html',       label:'Vulnerabilities' },
    { href:'members.html',     label:'Team' },
    { href:'targets.html',     label:'Targets' },
    { href:'export.html',      label:'↓ Export' },
  ];
  const current = window.location.pathname.split('/').pop() || 'dashboard.html';
  const nav = pages.map(p =>
    `<a href="${p.href}" class="nav-btn ${current === p.href ? 'active' : ''}">${p.label}</a>`
  ).join('');

  document.getElementById('topbar').innerHTML = `
    <div class="topbar-logo">
      <div class="topbar-logo-icon">🎯</div>
      <span class="topbar-logo-text">Flowdit</span>
    </div>
    <nav style="display:flex;gap:2px;margin-left:8px">${nav}</nav>
    <div class="topbar-spacer"></div>
    <div class="online-avatars" id="online-presence"></div>
    <div id="live-dot" class="live-badge" title="Connecting..."></div>
    <div class="search-wrap">
      <span class="search-icon">🔍</span>
      <input type="text" class="search-input" placeholder="Search..." oninput="handleSearch(this.value)">
    </div>
    <div class="progress-pill">
      <span id="topbar-pct">0%</span>
      <div class="progress-bar-mini"><div class="progress-bar-mini-fill" id="topbar-bar" style="width:0%"></div></div>
    </div>
    <div class="user-pill" onclick="toggleUserMenu()">
      <div class="avatar-sm" style="background:${u.avatar_color||'#7c3aed'}">${u.username[0].toUpperCase()}</div>
      <span>${esc(u.username)}</span>
      <div class="user-dropdown" id="user-dropdown">
        <a href="members.html"   class="dropdown-item">👥 Team</a>
        <a href="dashboard.html" class="dropdown-item">📁 New Project</a>
        <button class="dropdown-item danger" onclick="doLogout()">↪ Logout</button>
      </div>
    </div>`;
}

// ── SEARCH ────────────────────────────────────────────────────────
function handleSearch(q) {
  const ql = q.toLowerCase();
  if (state.currentView === 'wstg') {
    document.querySelectorAll('.test-item').forEach(el => {
      el.style.display = !q || el.textContent.toLowerCase().includes(ql) ? '' : 'none';
    });
  } else if (state.currentView === 'portswigger') {
    document.querySelectorAll('.ps-lab-row').forEach(el => {
      el.style.display = !q || el.textContent.toLowerCase().includes(ql) ? '' : 'none';
    });
  }
}

// ── USER MENU ─────────────────────────────────────────────────────
function toggleUserMenu() { document.getElementById('user-dropdown')?.classList.toggle('open'); }
function closeUserMenu()  { document.getElementById('user-dropdown')?.classList.remove('open'); }
document.addEventListener('click', e => { if (!e.target.closest('.user-pill')) closeUserMenu(); });

async function doLogout() {
  wsClient.disconnect();
  await api.auth.logout().catch(() => {});
  localStorage.removeItem('fd_project');
  window.location.href = 'index.html';
}

// ── WEBSOCKET EVENTS ──────────────────────────────────────────────
wsClient.on('activity', (event) => {
  prependActivity(event);
  if (event.user?.id !== state.user?.id) {
    const label = actionLabel(event.action, event.entity_type, event.entity_name, event.meta)
      .replace(/<[^>]+>/g, '');
    showToast(`${event.user?.username}: ${label}`, 'info');
    if (event.entity_type === 'wstg_test' && state.currentView === 'wstg') {
      // Update only the affected test — preserve open/closed state of all categories
      const testId = event.entity_id;
      if (testId) {
        if (!state.wstgProgress[testId]) state.wstgProgress[testId] = {};
        state.wstgProgress[testId].status      = event.meta?.status || null;
        state.wstgProgress[testId].last_editor = event.user;
        state.wstgProgress[testId].updated_at  = event.created_at;
        if (typeof patchWSTGTestDOM === 'function') patchWSTGTestDOM(testId, state.wstgProgress[testId]);
        if (typeof updateDashboard  === 'function') updateDashboard();
        refreshTopbarProgress();
      }
    }
  }
});

wsClient.on('presence',     ({ online }) => renderOnlinePresence(online));
wsClient.on('connected',    () => { const d = document.getElementById('live-dot'); if(d){d.style.background='var(--green)';d.title='Live';} });
wsClient.on('disconnected', () => { const d = document.getElementById('live-dot'); if(d){d.style.background='var(--red)';d.title='Reconnecting...';} });

// ── MODAL: NEW PROJECT ────────────────────────────────────────────
function openNewProjectModal() {
  ['proj-name','proj-target','proj-desc'].forEach(id => { const el=document.getElementById(id); if(el) el.value=''; });
  document.getElementById('project-modal')?.classList.add('open');
}

async function saveProject() {
  const name   = document.getElementById('proj-name')?.value.trim();
  const target = document.getElementById('proj-target')?.value.trim();
  const desc   = document.getElementById('proj-desc')?.value.trim();
  const btn    = document.getElementById('proj-save-btn');
  if (!name) return;
  btn.disabled = true;
  try {
    const proj = await api.projects.create({ name, target, description: desc });
    state.projects.unshift(proj);
    state.currentProject = proj;
    localStorage.setItem('fd_project', proj.id);
    document.getElementById('project-modal')?.classList.remove('open');
    await loadProjectData(proj.id);
    if (typeof pageInit === 'function') pageInit();
    refreshTopbarProgress();
    showToast('✓ Project created', 'success');
  } catch(e) { showToast(e.message, 'error'); }
  finally { btn.disabled = false; }
}

['project-modal','vuln-modal'].forEach(id => {
  document.getElementById(id)?.addEventListener('click', e => {
    if (e.target === e.currentTarget) e.currentTarget.classList.remove('open');
  });
});

window.bootPage             = bootPage;
window.switchProject        = switchProject;
window.calcOverallProgress  = calcOverallProgress;
window.refreshTopbarProgress = refreshTopbarProgress;
window.updateTopbarProgress = updateTopbarProgress;
window.renderTopbar         = renderTopbar;
window.handleSearch         = handleSearch;
window.toggleUserMenu       = toggleUserMenu;
window.closeUserMenu        = closeUserMenu;
window.doLogout             = doLogout;
window.openNewProjectModal  = openNewProjectModal;
window.saveProject          = saveProject;