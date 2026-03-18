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
  renderSidenav();

  state.projects = await api.projects.list();

  // Resolve current project: URL ?pid param > localStorage > first available
  const urlPid = new URLSearchParams(window.location.search).get('pid');
  if (urlPid) {
    const found = state.projects.find(p => p.id === urlPid);
    if (found) { state.currentProject = found; localStorage.setItem('fd_project', urlPid); }
  }
  if (!state.currentProject) {
    const saved = localStorage.getItem('fd_project');
    if (saved) {
      const found = state.projects.find(p => p.id === saved);
      if (found) state.currentProject = found;
    }
  }
  if (!state.currentProject && state.projects.length) state.currentProject = state.projects[0];

  // No project at all → go to project list
  if (!state.currentProject) { window.location.href = 'projects.html'; return; }

  // Viewers always go to the client portal
  if (state.currentProject.member_role === 'viewer') {
    window.location.href = `client.html?pid=${state.currentProject.id}`;
    return;
  }

  await loadProjectData(state.currentProject.id);
  renderSidenav();  // re-render now that currentProject and projects are loaded
  renderTopbar();   // re-render with correct role color
  if (state.onlineUsers?.length) renderOnlinePresence(state.onlineUsers); // restore after topbar rebuild
  hide('loading-overlay');
  if (typeof pageInit === 'function') pageInit();
  refreshTopbarProgress();
}

// ── PROJECT LOADING ───────────────────────────────────────────────
async function loadProjectData(pid) {
  wsClient.connect(pid);
  [state.wstgProgress, state.psProgress, state.customVulns, state.members, state.targets, state.methodologies, state.activeMethodProgress, state.tickets] = await Promise.all([
    api.wstg.getAll(pid),
    api.ps.getAll(pid),
    api.vulns.list(pid),
    api.members.list(pid),
    api.targets.list(pid).catch(() => []),
    api.methodologies.list().catch(() => []),
    api.methodologies.projectProgress(pid).catch(() => ({})),
    api.tickets.list(pid).catch(() => []),
  ]);
  await loadActivity(pid);
}

function switchProject(id) {
  localStorage.setItem('fd_project', id);
  window.location.href = `dashboard.html?pid=${id}`;
}

// ── PROGRESS — always computed from full WSTG+PS totals ──────────
function calcOverallProgress() {
  let done = 0, total = 0;
  if (typeof WSTG_DATA !== 'undefined') {
    WSTG_DATA.forEach(cat => cat.tests.forEach(t => {
      total++;
      const s = state.wstgProgress[t.id]?.status;
      if (s === 'done' || s === 'fail') done++;
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
  // old topbar
  const el  = document.getElementById('topbar-pct');
  const bar = document.getElementById('topbar-bar');
  if (el)  el.textContent  = `${pct}%`;
  if (bar) bar.style.width = `${pct}%`;
  // sidenav
  const spct = document.getElementById('sidenav-pct');
  const sbar = document.getElementById('sidenav-bar');
  if (spct) spct.textContent = `${pct}%`;
  if (sbar) sbar.style.width = `${pct}%`;
}


// ── SIDENAV ───────────────────────────────────────────────────────
function renderSidenav() {
  const current = window.location.pathname.split('/').pop() || 'dashboard.html';
  const proj = state.currentProject;
  const pid  = proj ? `?pid=${proj.id}` : '';

  const navGroups = [
    {
      label: 'Engagement',
      items: [
        { href:`dashboard.html${pid}`,   icon:'◈', label:'Overview'   },
        { href:`targets.html${pid}`,     icon:'⊕', label:'Targets'    },
        { href:`vulns.html${pid}`,       icon:'⚡', label:'Findings'   },
        { href:`export.html${pid}`,      icon:'↓', label:'Report'     },
      ]
    },
    {
      label: 'Testing',
      items: [
        { href:`wstg.html${pid}`,        icon:'◉', label:'OWASP WSTG'    },
        { href:`methodology.html${pid}`, icon:'◧', label:'Methodologies' },
      ]
    },
    {
      label: 'Team',
      items: [
        { href:`members.html${pid}`,     icon:'◎', label:'Members'    },
        ...(proj?.tickets_enabled ? [{ href:`tickets.html${pid}`, icon:'💬', label:'Queries' }] : []),
      ]
    },
    {
      label: 'Practice',
      items: [
        { href:`portswigger.html${pid}`, icon:'◪', label:'PortSwigger' },
      ]
    },
  ];

  const { done, total } = calcOverallProgress();
  const pct = total ? Math.round(done/total*100) : 0;

  let html = `
    <div class="sidenav-logo">
      <img src="img/flowdit-logo.png" class="topbar-logo-img" alt="Flowdit">
      <span class="topbar-logo-text">Flowdit</span>
    </div>
    <a href="projects.html" class="sidenav-back-link">
      <span>←</span><span>All Projects</span>
    </a>`;

  if (proj) {
    html += `
    <div class="sidenav-project">
      ${proj.logo_url ? `<div class="sidenav-project-logo-wrap"><img src="${esc(proj.logo_url)}" class="sidenav-project-logo sidenav-project-logo--${proj.logo_bg||'light'}" alt="Project logo"></div>` : ''}
      <div class="sidenav-project-name">${esc(proj.name)}</div>
      ${proj.description ? `<div class="sidenav-project-desc">${esc(proj.description)}</div>` : ''}
      <div class="sidenav-progress">
        <div class="sidenav-progress-bar">
          <div class="sidenav-progress-fill" id="sidenav-bar" style="width:${pct}%"></div>
        </div>
        <span class="sidenav-progress-pct" id="sidenav-pct">${pct}%</span>
      </div>
    </div>`;
  }

  navGroups.forEach(g => {
    html += `<div class="sidenav-group-label">${g.label}</div>`;
    g.items.forEach(item => {
      const active = current === item.href.split('?')[0];
      html += `<a href="${item.href}" class="sidenav-item ${active?'active':''}">
        <span class="sidenav-item-icon">${item.icon}</span>
        <span class="sidenav-item-label">${item.label}</span>
      </a>`;
    });
  });

  const sidenav = document.getElementById('sidenav');
  if (sidenav) sidenav.innerHTML = html;
}

// ── TOPBAR (slim — project context + user only) ───────────────────
function renderTopbar() {
  const u    = state.user;
  const role = state.currentProject?.member_role;
  const color = roleColor(role);
  const el = document.getElementById('topbar');
  if (!el) return;
  el.innerHTML = `
    <div style="display:flex;align-items:center;gap:8px;flex:1;min-width:0">
      <div class="search-wrap">
        <span class="search-icon">🔍</span>
        <input type="text" class="search-input" placeholder="Search..." oninput="handleSearch(this.value)">
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:10px">
      <div class="online-avatars" id="online-presence"></div>
      <div id="live-dot" class="live-badge" title="Connecting..."></div>
      <div class="user-pill" onclick="toggleUserMenu()">
        ${avatarHtml(u.username, color, 24, u.avatar_url)}
        <span>${esc(u.username)}</span>
        ${role ? `<span style="font-family:var(--mono);font-size:9px;color:${color};opacity:.8">${role}</span>` : ''}
        <div class="user-dropdown" id="user-dropdown">
          <button class="dropdown-item" onclick="openProfileModal();event.stopPropagation()">◎ Edit Profile</button>
          <button class="dropdown-item danger" onclick="doLogout()">↪ Logout</button>
        </div>
      </div>
    </div>`;
}

// ── PROFILE MODAL ─────────────────────────────────────────────────
function _injectProfileModal() {
  if (document.getElementById('profile-modal')) return;
  const div = document.createElement('div');
  div.innerHTML = `
  <div class="modal-overlay" id="profile-modal">
    <div class="modal" style="max-width:420px">
      <div class="modal-title">Edit Profile</div>

      <div style="display:flex;flex-direction:column;align-items:center;gap:10px;margin-bottom:20px">
        <div id="profile-avatar-preview" style="width:72px;height:72px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:28px;font-weight:700;color:#fff;overflow:hidden;flex-shrink:0"></div>
        <label style="font-family:var(--mono);font-size:11px;color:var(--accent);cursor:pointer;display:flex;align-items:center;gap:4px">
          ↑ Change photo
          <input type="file" id="profile-avatar-input" accept="image/*" style="display:none">
        </label>
        <button id="profile-avatar-remove" style="display:none;font-family:var(--mono);font-size:10px;color:var(--text3);background:none;border:none;cursor:pointer;padding:0">✕ Remove photo</button>
      </div>

      <div class="form-group">
        <label class="form-label">Display name</label>
        <input type="text" class="form-input" id="profile-username" maxlength="50" autocomplete="off">
        <div style="font-family:var(--mono);font-size:10px;color:var(--text3);margin-top:4px">Letters, numbers, _ and - only.</div>
      </div>

      <div class="form-error" id="profile-error"></div>

      <div class="modal-footer">
        <button class="btn-secondary" onclick="closeProfileModal()">Cancel</button>
        <button class="btn-save" id="profile-save-btn" onclick="saveProfile()">Save changes</button>
      </div>
    </div>
  </div>`;
  document.body.appendChild(div.firstElementChild);

  document.getElementById('profile-modal').addEventListener('click', e => {
    if (e.target === e.currentTarget) closeProfileModal();
  });
  document.getElementById('profile-avatar-input').addEventListener('change', _onAvatarPick);
  document.getElementById('profile-avatar-remove').addEventListener('click', _removeAvatar);
}

let _pendingAvatarUrl = undefined; // undefined = no change; null = remove; string = new

function openProfileModal() {
  _injectProfileModal();
  closeUserMenu();
  _pendingAvatarUrl = undefined;
  const u = state.user;
  document.getElementById('profile-username').value = u.username;
  document.getElementById('profile-error').textContent = '';
  _refreshAvatarPreview(u.avatar_url || null);
  document.getElementById('profile-modal').classList.add('open');
}

function closeProfileModal() {
  document.getElementById('profile-modal')?.classList.remove('open');
}

function _refreshAvatarPreview(url) {
  const preview = document.getElementById('profile-avatar-preview');
  const removeBtn = document.getElementById('profile-avatar-remove');
  const role  = state.currentProject?.member_role;
  const color = roleColor(role);
  if (url) {
    preview.innerHTML = `<img src="${esc(url)}" style="width:100%;height:100%;object-fit:cover">`;
    preview.style.background = color;
    preview.style.boxShadow = `0 0 0 3px ${color}`;
    removeBtn.style.display = 'block';
  } else {
    preview.innerHTML = (state.user?.username || '?')[0].toUpperCase();
    preview.style.background = color;
    preview.style.boxShadow = 'none';
    removeBtn.style.display = 'none';
  }
}

function _onAvatarPick(e) {
  const file = e.target.files[0];
  if (!file) return;
  if (file.size > 1_500_000) { showToast('Image too large (max 1.5 MB)', 'error'); return; }
  const reader = new FileReader();
  reader.onload = ev => {
    _pendingAvatarUrl = ev.target.result;
    _refreshAvatarPreview(_pendingAvatarUrl);
  };
  reader.readAsDataURL(file);
}

function _removeAvatar() {
  _pendingAvatarUrl = null;
  document.getElementById('profile-avatar-input').value = '';
  _refreshAvatarPreview(null);
}

async function saveProfile() {
  const username = document.getElementById('profile-username').value.trim();
  const errEl = document.getElementById('profile-error');
  const btn   = document.getElementById('profile-save-btn');
  errEl.textContent = '';

  if (!username) { errEl.textContent = 'Display name is required.'; return; }
  if (!/^[a-zA-Z0-9_-]{2,50}$/.test(username)) {
    errEl.textContent = 'Only letters, numbers, _ and - (2–50 chars).';
    return;
  }

  const payload = {};
  if (username !== state.user.username) payload.username = username;
  if (_pendingAvatarUrl !== undefined) payload.avatar_url = _pendingAvatarUrl;

  if (!Object.keys(payload).length) { closeProfileModal(); return; }

  btn.disabled = true;
  try {
    const updated = await api.auth.updateProfile(payload);
    state.user = { ...state.user, ...updated };
    localStorage.setItem('fd_user', JSON.stringify(state.user));
    closeProfileModal();
    renderTopbar();
    showToast('Profile updated', 'success');
  } catch(e) {
    errEl.textContent = e.message;
  } finally {
    btn.disabled = false;
  }
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
    localStorage.setItem('fd_project', proj.id);
    document.getElementById('project-modal')?.classList.remove('open');
    window.location.href = `dashboard.html?pid=${proj.id}`;
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
window.saveProfile          = saveProfile;
window.openProfileModal     = openProfileModal;
window.closeProfileModal    = closeProfileModal;
window.saveProject          = saveProject;