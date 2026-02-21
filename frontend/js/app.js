// ── app.js — main controller ─────────────────────────────────────────

// ── BOOT ──────────────────────────────────────────────────────────
window.addEventListener('fd:logout', () => showLogin());

async function boot() {
  if (api.auth.hasSession()) {
    try {
      state.user = await api.auth.me();
      await enterApp();
    } catch { showLogin(); }
  } else {
    showLogin();
  }
}

function showLogin() {
  hide('loading-overlay');
  document.getElementById('login-screen').classList.add('active');
  document.getElementById('app-screen').classList.remove('active');
}

async function enterApp() {
  hide('loading-overlay');
  document.getElementById('login-screen').classList.remove('active');
  document.getElementById('app-screen').classList.add('active');

  const u = state.user;
  document.getElementById('user-name-top').textContent  = u.username;
  document.getElementById('user-avatar-top').style.background = u.avatar_color || '#7c3aed';
  document.getElementById('user-avatar-top').textContent = u.username[0].toUpperCase();

  state.projects = await api.projects.list();
  state.currentProject = state.projects[0] || null;
  populateProjectSelect();
  await loadProjectData();
  renderApp();
  showView('dashboard');
}

// ── AUTH ──────────────────────────────────────────────────────────
function switchAuthTab(tab, btn) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('login-form').style.display    = tab === 'login'    ? '' : 'none';
  document.getElementById('register-form').style.display = tab === 'register' ? '' : 'none';
}

async function doLogin() {
  const login = document.getElementById('login-user').value.trim();
  const pass  = document.getElementById('login-pass').value;
  const err   = document.getElementById('login-error');
  const btn   = document.getElementById('login-btn');
  err.style.display = 'none'; btn.disabled = true; btn.textContent = 'Connecting...';
  try {
    const data = await api.auth.login(login, pass);
    api.auth.setTokens(data.accessToken, data.refreshToken);
    state.user = data.user;
    await enterApp();
  } catch(e) { err.textContent = e.message; err.style.display = 'block'; }
  finally { btn.disabled = false; btn.textContent = 'Access Terminal'; }
}

async function doRegister() {
  const user  = document.getElementById('reg-user').value.trim();
  const email = document.getElementById('reg-email').value.trim();
  const pass  = document.getElementById('reg-pass').value;
  const pass2 = document.getElementById('reg-pass2').value;
  const err   = document.getElementById('reg-error');
  const btn   = document.getElementById('reg-btn');
  err.style.display = 'none';
  if (pass !== pass2) { err.textContent = 'Passwords do not match'; err.style.display = 'block'; return; }
  btn.disabled = true; btn.textContent = 'Creating...';
  try {
    const data = await api.auth.register(user, email, pass);
    api.auth.setTokens(data.accessToken, data.refreshToken);
    state.user = data.user;
    await enterApp();
  } catch(e) { err.textContent = e.message; err.style.display = 'block'; }
  finally { btn.disabled = false; btn.textContent = 'Create Account'; }
}

async function doLogout() {
  closeUserMenu();
  wsClient.disconnect();
  await api.auth.logout().catch(() => {});
  Object.assign(state, { user:null, currentProject:null, projects:[], wstgProgress:{}, psProgress:{}, customVulns:[], members:[], activityFeed:[], onlineUsers:[] });
  showLogin();
}

// ── PROJECTS ──────────────────────────────────────────────────────
function populateProjectSelect() {
  const sel = document.getElementById('project-select');
  if (!sel) return;
  sel.innerHTML = state.projects.map(p =>
    `<option value="${p.id}">${esc(p.name)}</option>`
  ).join('');
  if (state.currentProject) sel.value = state.currentProject.id;
}

async function switchProject(id) {
  state.currentProject = state.projects.find(p => p.id === id);
  show('loading-overlay');
  await loadProjectData();
  hide('loading-overlay');
  renderApp();
  updateDashboard();
  showView(state.currentView);
}

async function loadProjectData() {
  if (!state.currentProject) return;
  const pid = state.currentProject.id;
  wsClient.connect(pid);

  [state.wstgProgress, state.psProgress, state.customVulns, state.members] = await Promise.all([
    api.wstg.getAll(pid),
    api.ps.getAll(pid),
    api.vulns.list(pid),
    api.members.list(pid),
  ]);
  await loadActivity(pid);
}

function openNewProjectModal() {
  document.getElementById('proj-name').value   = '';
  document.getElementById('proj-target').value = '';
  document.getElementById('proj-desc').value   = '';
  document.getElementById('project-modal').classList.add('open');
}

async function saveProject() {
  const name   = document.getElementById('proj-name').value.trim();
  const target = document.getElementById('proj-target').value.trim();
  const desc   = document.getElementById('proj-desc').value.trim();
  const btn    = document.getElementById('proj-save-btn');
  if (!name) return;
  btn.disabled = true;
  try {
    const proj = await api.projects.create({ name, target, description: desc });
    state.projects.unshift(proj);
    state.currentProject = proj;
    populateProjectSelect();
    await loadProjectData();
    renderApp();
    updateDashboard();
    document.getElementById('project-modal').classList.remove('open');
    showToast('✓ Project created', 'success');
  } catch(e) { showToast(e.message, 'error'); }
  finally { btn.disabled = false; }
}

// ── VIEWS ─────────────────────────────────────────────────────────
const NAV_ORDER = ['dashboard','wstg','portswigger','custom','members'];

function showView(name) {
  state.currentView = name;
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById(`view-${name}`)?.classList.add('active');
  document.querySelectorAll('.nav-btn').forEach((b, i) => b.classList.toggle('active', NAV_ORDER[i] === name));
  updateSidebar();

  if (name === 'dashboard')    updateDashboard();
  if (name === 'custom')       renderCustomVulns();
  if (name === 'members')      renderMembers();
}

// ── SIDEBAR ───────────────────────────────────────────────────────
function updateSidebar() {
  const sidebar = document.getElementById('sidebar');
  const view    = state.currentView;
  let html      = '';

  if (state.currentProject) {
    html += `<div class="sidebar-section-label">Project</div>
      <div class="sidebar-item" onclick="showView('members')">
        <span class="sidebar-item-text">📁 ${esc(state.currentProject.name)}</span>
        <span class="role-badge role-${state.currentProject.member_role}" style="font-size:8px">${state.currentProject.member_role}</span>
      </div>
      <div class="sidebar-divider"></div>`;
  }

  if (view === 'wstg') {
    html += '<div class="sidebar-section-label">Categories</div>';
    WSTG_DATA.forEach(cat => {
      const t = cat.tests.length;
      const d = cat.tests.filter(test => state.wstgProgress[test.id]?.status === 'done').length;
      const p = t ? Math.round(d/t*100) : 0;
      html += `<div class="sidebar-item" onclick="scrollToCat('${cat.id}')">
        <div class="sidebar-mini-bar"><div class="sidebar-mini-fill" style="width:${p}%"></div></div>
        <span class="sidebar-item-text">${esc(cat.name)}</span>
        <span class="sidebar-item-badge">${d}/${t}</span>
      </div>`;
    });
  } else if (view === 'portswigger') {
    html += '<div class="sidebar-section-label">Categories</div>';
    PS_DATA.forEach(cat => {
      const t = cat.labs.length;
      const d = cat.labs.filter((_,i) => state.psProgress[`${cat.id}_${i}`]).length;
      html += `<div class="sidebar-item" onclick="scrollToPS('${cat.id}')">
        <span class="sidebar-item-text">${esc(cat.name)}</span>
        <span class="sidebar-item-badge">${d}/${t}</span>
      </div>`;
    });
  } else {
    html += '<div class="sidebar-section-label">Projects</div>';
    state.projects.forEach(p => {
      const active = p.id === state.currentProject?.id;
      html += `<div class="sidebar-item ${active?'active':''}" onclick="switchProject('${p.id}')">
        <span class="sidebar-item-text">${esc(p.name)}</span>
        <span class="sidebar-item-badge">${p.member_role}</span>
      </div>`;
    });
    html += `<div class="sidebar-item" onclick="showView('members')">
      <span class="sidebar-item-text" style="color:var(--text3)">+ Join / manage</span>
    </div>`;
  }

  sidebar.innerHTML = html;
}

// ── RENDER ALL ────────────────────────────────────────────────────
function renderApp() {
  renderWSTG();
  renderPS();
  renderCustomVulns();
  updateSidebar();
  updateDashboard();
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
function toggleUserMenu() { document.getElementById('user-dropdown').classList.toggle('open'); }
function closeUserMenu()  { document.getElementById('user-dropdown').classList.remove('open'); }

document.addEventListener('click', e => {
  if (!e.target.closest('.user-pill')) closeUserMenu();
});

// ── WebSocket event handlers ──────────────────────────────────────
wsClient.on('activity', (event) => {
  // Only show if it's not from us
  if (event.user?.id !== state.user?.id) {
    prependActivity(event);
    showToast(`${event.user?.username}: ${actionLabel(event.action, event.entity_type, event.entity_name, event.meta).replace(/<[^>]+>/g, '')}`, 'info');

    // Refresh WSTG data if someone updated a test
    if (event.entity_type === 'wstg_test' && state.currentView === 'wstg') {
      api.wstg.getAll(state.currentProject.id).then(p => {
        state.wstgProgress = p;
        renderWSTG();
        updateDashboard();
      }).catch(() => {});
    }
  } else {
    prependActivity(event);
  }
});

wsClient.on('presence', ({ online }) => {
  renderOnlinePresence(online);
});

wsClient.on('connected', () => {
  const dot = document.getElementById('live-dot');
  if (dot) { dot.style.background = 'var(--green)'; dot.title = 'Live'; }
});

wsClient.on('disconnected', () => {
  const dot = document.getElementById('live-dot');
  if (dot) { dot.style.background = 'var(--red)'; dot.title = 'Reconnecting...'; }
});

// ── CLOSE MODALS on backdrop click ───────────────────────────────
['vuln-modal','project-modal'].forEach(id => {
  document.getElementById(id)?.addEventListener('click', e => {
    if (e.target === e.currentTarget) e.currentTarget.classList.remove('open');
  });
});

// ── BOOT ──────────────────────────────────────────────────────────
boot();
