// ── page.js — shared controller for all internal pages ──────────────
// Loaded by dashboard.html, owstg.html, portswigger.html, vulns.html, members.html

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
  mountAiChat();
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
      if (s === 'done' || s === 'fail' || s === 'na') done++;
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
const _NAV_ICONS = {
  'dashboard.html':   `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="1" y="1" width="6" height="6" rx="1"/><rect x="9" y="1" width="6" height="6" rx="1"/><rect x="1" y="9" width="6" height="6" rx="1"/><rect x="9" y="9" width="6" height="6" rx="1"/></svg>`,
  'targets.html':     `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="8" cy="8" r="5.5"/><line x1="8" y1="1" x2="8" y2="4"/><line x1="8" y1="12" x2="8" y2="15"/><line x1="1" y1="8" x2="4" y2="8"/><line x1="12" y1="8" x2="15" y2="8"/></svg>`,
  'vulns.html':       `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 2L14 5v4c0 3.5-2.8 5.5-6 6.5C5.8 14.5 2 12.5 2 9V5z"/><line x1="8" y1="7" x2="8" y2="9.5"/><circle cx="8" cy="11.5" r=".7" fill="currentColor" stroke="none"/></svg>`,
  'export.html':      `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 1h6l4 4v10H4z"/><path d="M10 1v4h4"/><line x1="6" y1="8" x2="11" y2="8"/><line x1="6" y1="11" x2="11" y2="11"/></svg>`,
  'whiteboard.html':  `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="1" y="2" width="14" height="11" rx="1.5"/><path d="M5 10.5L6.5 9l3-3L11 4.5l1 1-1.5 1.5-3 3L6 11.5z"/></svg>`,
  'owstg.html':        `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="1" width="12" height="14" rx="1.5"/><path d="M5.5 5.5L7 7l3.5-3.5"/><line x1="5" y1="10" x2="11" y2="10"/><line x1="5" y1="13" x2="9" y2="13"/></svg>`,
  'methodology.html': `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3.5" y="3" width="9" height="12" rx="1"/><path d="M7 3V1.5a1.5 1.5 0 013 0V3"/><line x1="6.5" y1="8" x2="9.5" y2="8"/><line x1="6.5" y1="11" x2="9.5" y2="11"/></svg>`,
  'members.html':     `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="6" cy="5.5" r="2.5"/><path d="M1 14c0-3 2-4.5 5-4.5s5 1.5 5 4.5"/><circle cx="12.5" cy="5" r="2"/><path d="M12.5 11c2.5.2 3.5 1.5 3.5 3"/></svg>`,
  'settings.html':    `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="8" cy="8" r="2.5"/><path d="M8 1.5V3M8 13v1.5M1.5 8H3M13 8h1.5M3.5 3.5l1 1M11.5 11.5l1 1M3.5 12.5l1-1M11.5 4.5l1-1"/></svg>`,
  'tickets.html':     `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2 2h12v9H9l-2.5 3L4 11H2z"/></svg>`,
  'portswigger.html': `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 1v5L2 14h12L10 6V1"/><line x1="5.5" y1="1" x2="10.5" y2="1"/><circle cx="7" cy="11" r="1" fill="currentColor" stroke="none"/></svg>`,
};

function renderSidenav() {
  const current = window.location.pathname.split('/').pop() || 'dashboard.html';
  const proj = state.currentProject;
  const pid  = proj ? `?pid=${proj.id}` : '';
  const u    = state.user;

  const navGroups = [
    {
      label: 'Engagement',
      items: [
        { href:`dashboard.html${pid}`,   label:'Overview'      },
        { href:`targets.html${pid}`,     label:'Targets'       },
        { href:`vulns.html${pid}`,       label:'Findings'      },
        { href:`export.html${pid}`,      label:'Report'        },
        { href:`whiteboard.html${pid}`,  label:'Whiteboard'    },
      ]
    },
    {
      label: 'Testing',
      items: [
        { href:`owstg.html${pid}`,        label:'OWASP WSTG'    },
        { href:`methodology.html${pid}`, label:'Methodologies' },
      ]
    },
    {
      label: 'Team',
      items: [
        { href:`members.html${pid}`,     label:'Members'       },
        { href:`settings.html${pid}`,    label:'Settings'      },
        ...(proj?.tickets_enabled ? [{ href:`tickets.html${pid}`, label:'Queries' }] : []),
      ]
    },
    {
      label: 'Practice',
      items: [
        { href:`portswigger.html${pid}`, label:'PortSwigger'   },
      ]
    },
  ];

  const { done, total } = calcOverallProgress();
  const pct = total ? Math.round(done/total*100) : 0;

  let html = `
    <div class="brand">
      <img src="img/flowdit-logo.png" class="brand-logo-img" alt="Flowdit">
      <span class="brand-wordmark">Flowdit</span>
      <span class="brand-tag">SELF-HOSTED</span>
    </div>
    <a href="projects.html" class="nav-back-link">${icon('arrow-left', { size: 13 })} All Projects</a>`;

  if (proj) {
    html += `
    <div class="nav-project">
      ${proj.logo_url ? `<div class="nav-project-logo-wrap"><img src="${esc(proj.logo_url)}" class="nav-project-logo nav-project-logo--${proj.logo_bg||'light'}" alt="Project logo"></div>` : ''}
      <div class="nav-project-name">${esc(proj.name)}</div>
      ${proj.description ? `<div class="nav-project-target">${esc(proj.description)}</div>` : ''}
      <div class="nav-progress">
        <div class="nav-progress-bar">
          <div class="nav-progress-fill" id="sidenav-bar" style="width:${pct}%"></div>
        </div>
        <span class="nav-progress-pct" id="sidenav-pct">${pct}%</span>
      </div>
    </div>`;
  }

  html += `<div class="nav-scroll">`;
  navGroups.forEach(g => {
    html += `<div class="nav-group-label">${g.label}</div>`;
    g.items.forEach(item => {
      const active = current === item.href.split('?')[0];
      const navIcon = _NAV_ICONS[item.href.split('?')[0]] || '';
      html += `<a href="${item.href}" class="nav-item ${active?'active':''}">${navIcon}<span>${item.label}</span></a>`;
    });
  });
  html += `</div>`;

  if (u) {
    const role  = proj?.member_role;
    const color = roleColor(role);
    html += `
    <div class="nav-foot">
      ${avatarHtml(u.username, color, 24, u.avatar_url)}
      <div>
        <div class="nav-foot-name">${esc(u.username)}</div>
        ${role ? `<div class="nav-foot-role">${role}</div>` : ''}
      </div>
    </div>`;
  }

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
        <span class="search-icon">${icon('search', { size: 14 })}</span>
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
          <button class="dropdown-item" onclick="openProfileModal();event.stopPropagation()">${icon('user', { size: 13 })} Edit Profile</button>
          <button class="dropdown-item" onclick="window.location.href='orgs.html'">${icon('building-2', { size: 13 })} Organizations</button>
          <button class="dropdown-item danger" onclick="doLogout()">${icon('log-out', { size: 13 })} Logout</button>
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
        <label style="font-family:var(--mono);font-size:11px;color:var(--a);cursor:pointer;display:flex;align-items:center;gap:4px">
          ${icon('upload', { size: 12 })} Change photo
          <input type="file" id="profile-avatar-input" accept="image/*" style="display:none">
        </label>
        <button id="profile-avatar-remove" style="display:none;font-family:var(--mono);font-size:10px;color:var(--t3);background:none;border:none;cursor:pointer;padding:0">${icon('x', { size: 11 })} Remove photo</button>
      </div>

      <div class="form-group">
        <label class="form-label">Display name</label>
        <input type="text" class="form-input" id="profile-username" maxlength="50" autocomplete="off">
        <div style="font-family:var(--mono);font-size:10px;color:var(--t3);margin-top:4px">Letters, numbers, _ and - only.</div>
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
wsClient.on('connected',    () => { const d = document.getElementById('live-dot'); if(d){d.style.background='var(--c-low)';d.title='Live';} });
wsClient.on('disconnected', () => { const d = document.getElementById('live-dot'); if(d){d.style.background='var(--c-crit)';d.title='Reconnecting...';} });

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

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    if (typeof closeVulnDrawer === 'function') closeVulnDrawer();
  }
});

['project-modal','vuln-modal'].forEach(id => {
  document.getElementById(id)?.addEventListener('click', e => {
    if (e.target === e.currentTarget) e.currentTarget.classList.remove('open');
  });
});

// ── AI CHAT BUBBLE ────────────────────────────────────────────────────
let _chatHistory = [];

function _buildProjectContext() {
  const p       = state.currentProject || {};
  const vulns   = state.customVulns   || [];
  const targets = state.targets       || [];

  let wDone=0, wFail=0, wTotal=0;
  if (typeof WSTG_DATA !== 'undefined') {
    WSTG_DATA.forEach(cat => cat.tests.forEach(t => {
      wTotal++;
      const s = state.wstgProgress?.[t.id]?.status;
      if (s === 'done') wDone++;
      if (s === 'fail') wFail++;
    }));
  }

  const activeProg   = state.activeMethodProgress || {};
  const methodologies = Object.values(activeProg).map(m => ({
    name: m.name,
    pct:  m.total ? Math.round((m.done + m.fail) / m.total * 100) : 0,
  }));

  const feed        = state.activityFeed || [];
  const todayStr    = new Date().toDateString();
  const todayCount  = feed.filter(e => new Date(e.created_at).toDateString() === todayStr).length;
  const activity    = feed.slice(0, Math.max(todayCount, 20)).map(e => ({
    who: e.username, action: e.action,
    entity: e.entity_name || e.entity_type || '', when: e.created_at,
  }));

  return {
    project: { name: p.name, target: p.target, description: p.description, status: p.status },
    vulns:   vulns.map(v => ({ name: v.name, severity: v.severity, status: v.status, target_host: v.target_host || null })),
    wstg:    { done: wDone, fail: wFail, pending: wTotal-wDone-wFail, pct: wTotal ? Math.round((wDone+wFail)/wTotal*100) : 0 },
    targets: targets.map(t => ({ host: t.host, type: t.type, scope: t.scope })),
    team:    (state.members || []).map(m => ({ username: m.username, role: m.role })),
    methodologies, activity,
  };
}

function _chatRender() {
  const box = document.getElementById('ai-panel-messages');
  if (!box) return;
  if (!_chatHistory.length) {
    box.innerHTML = `<div class="ai-chat-empty">Pregúntame sobre hallazgos, cobertura, próximos pasos...</div>`;
    return;
  }
  box.innerHTML = _chatHistory.map(msg => {
    const isUser  = msg.role === 'user';
    const content = isUser ? esc(msg.content) : renderMd(msg.content);
    return `<div class="ai-chat-msg ${isUser ? 'user' : 'ai'}"><div class="ai-chat-bubble">${content}</div></div>`;
  }).join('');
  box.scrollTop = box.scrollHeight;
}

function _chatSetLoading(on) {
  const btn    = document.getElementById('ai-panel-send');
  const inp    = document.getElementById('ai-panel-input');
  const typing = document.getElementById('ai-panel-typing');
  if (btn)    btn.disabled    = on;
  if (inp)    inp.disabled    = on;
  if (typing) typing.style.display = on ? 'flex' : 'none';
  const box = document.getElementById('ai-panel-messages');
  if (on && box) box.scrollTop = box.scrollHeight;
}

async function aiChatSend() {
  const inp      = document.getElementById('ai-panel-input');
  const question = inp?.value.trim();
  if (!question) return;
  inp.value = '';
  inp.style.height = '';
  _chatHistory.push({ role: 'user', content: question });
  _chatRender();
  _chatSetLoading(true);
  try {
    const result = await request('POST', `/projects/${state.currentProject.id}/ai/chat`, {
      question,
      history: _chatHistory.slice(-7, -1),
      context: _buildProjectContext(),
    });
    _chatHistory.push({ role: 'assistant', content: result.answer });
    if (_chatHistory.length > 20) _chatHistory = _chatHistory.slice(-20);
  } catch(e) {
    _chatHistory.push({ role: 'assistant', content: `_Error: ${e.message}_` });
  } finally {
    _chatSetLoading(false);
    _chatRender();
  }
}

function aiChatKeydown(e) {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); aiChatSend(); }
}

function aiChatClear() {
  _chatHistory = [];
  _chatRender();
}

function toggleAiPanel() {
  const panel = document.getElementById('ai-panel');
  if (!panel) return;
  const open = panel.classList.toggle('open');
  if (open) {
    _chatRender();
    setTimeout(() => document.getElementById('ai-panel-input')?.focus(), 50);
  }
}

function mountAiChat() {
  if (document.getElementById('ai-fab')) return; // already mounted

  // FAB button
  const fab = document.createElement('button');
  fab.id        = 'ai-fab';
  fab.className = 'no-print';
  fab.innerHTML = icon('sparkles', { size: 20 });
  fab.title     = 'AI Assistant';
  fab.onclick   = toggleAiPanel;
  document.body.appendChild(fab);

  // Floating panel
  const panel = document.createElement('div');
  panel.id        = 'ai-panel';
  panel.className = 'no-print';
  panel.innerHTML = `
    <div class="ai-panel-header">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="color:var(--a)">${icon('sparkles', { size: 14 })}</span>
        <span style="font-size:12px;font-weight:700">AI Assistant</span>
      </div>
      <div style="display:flex;align-items:center;gap:6px">
        <button onclick="aiChatClear()" style="font-family:var(--mono);font-size:10px;color:var(--t3);background:none;border:none;cursor:pointer;padding:2px 6px;border-radius:var(--r)" title="Clear">clear</button>
        <button onclick="toggleAiPanel()" style="font-size:16px;color:var(--t3);background:none;border:none;cursor:pointer;line-height:1;padding:2px 4px" title="Close">×</button>
      </div>
    </div>
    <div class="ai-chat-messages" id="ai-panel-messages">
      <div class="ai-chat-empty">Pregúntame sobre hallazgos, cobertura, próximos pasos...</div>
    </div>
    <div class="ai-chat-typing" id="ai-panel-typing" style="display:none">
      <span></span><span></span><span></span>
    </div>
    <div class="ai-chat-input-row">
      <textarea class="ai-chat-input" id="ai-panel-input"
        placeholder="Ej: ¿qué vulnerabilidades críticas hay?" rows="1"
        onkeydown="aiChatKeydown(event)"
        oninput="this.style.height='';this.style.height=Math.min(this.scrollHeight,80)+'px'"></textarea>
      <button class="ai-chat-send" id="ai-panel-send" onclick="aiChatSend()">${icon('send', { size: 14 })}</button>
    </div>
  `;
  document.body.appendChild(panel);
}

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
window.mountAiChat          = mountAiChat;
window.toggleAiPanel        = toggleAiPanel;
window.aiChatSend           = aiChatSend;
window.aiChatKeydown        = aiChatKeydown;
window.aiChatClear          = aiChatClear;