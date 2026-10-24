// ── page.js — shared controller for all internal pages ──────────────
// Loaded by dashboard.html, owstg.html, portswigger.html, vulns.html, members.html

// ── AUTH GUARD ────────────────────────────────────────────────────
window.addEventListener('fd:logout', () => { clearShellSnapshot(); window.location.href = '/'; });

// ── SHELL SNAPSHOT — instant sidenav/topbar paint between pages ──────
// Every section is its own HTML page, so each navigation used to paint an
// empty sidenav, then a partial one, then the full one once the API calls
// returned. The last rendered shell (project header, progress, AI badge) is
// kept in sessionStorage and painted synchronously at the start of
// bootPage(), so the new page's first frame already shows the full sidebar
// (which is also what lets the cross-document view transition keep it still).
//
// It holds only display data for the current project. The user part is
// never stored here: it is read from localStorage `fd_user`, which already
// holds it. No tokens. Cleared on logout, on 401 (tokens.clear() in api.js)
// and when switching project. The client portal does not load page.js.
const SHELL_SNAPSHOT_KEY = 'fd_shell';
const SHELL_SNAPSHOT_VERSION = 1;
let _shellSnap = null;          // snapshot painted on this page, until real data replaces it
let _projectDataLoaded = false; // true once loadProjectData() has filled state

function clearShellSnapshot() {
  _shellSnap = null;
  try { sessionStorage.removeItem(SHELL_SNAPSHOT_KEY); } catch {}
}

function _storedUser() {
  try {
    const u = JSON.parse(localStorage.getItem('fd_user') || 'null');
    return u && u.id ? u : null;
  } catch { return null; }
}

function _readShellSnapshot() {
  try {
    const snap = JSON.parse(sessionStorage.getItem(SHELL_SNAPSHOT_KEY) || 'null');
    if (!snap || snap.v !== SHELL_SNAPSHOT_VERSION || !snap.project?.id) return null;
    return snap;
  } catch { return null; }
}

function _saveShellSnapshot() {
  const p = state.currentProject;
  if (!_projectDataLoaded || !state.user?.id || !p?.id || p.member_role === 'viewer') return;
  const { done, total } = calcOverallProgress();
  const snap = {
    v: SHELL_SNAPSHOT_VERSION,
    uid: state.user.id,
    project: {
      id: p.id, name: p.name, description: p.description || '',
      logo_url: p.logo_url || null, logo_bg: p.logo_bg || null,
      member_role: p.member_role, tickets_enabled: !!p.tickets_enabled,
    },
    pct: total ? Math.round(done / total * 100) : 0,
    aiBadge: state.navAiBadge || null,
    proposalsBadge: !!state.navProposalsBadge,
  };
  try { sessionStorage.setItem(SHELL_SNAPSHOT_KEY, JSON.stringify(snap)); } catch {}
}

// Synchronous: must run before the first await of bootPage().
function _paintShellFromSnapshot() {
  const snap = _readShellSnapshot();
  const user = _storedUser();
  if (!snap || !user || snap.uid !== user.id) return false;
  // Only when this page will resolve to the same project as the snapshot.
  const urlPid = new URLSearchParams(window.location.search).get('pid');
  let wantedPid = urlPid;
  if (!wantedPid) { try { wantedPid = localStorage.getItem('fd_project'); } catch {} }
  if (wantedPid !== snap.project.id) return false;
  _shellSnap = { user, project: snap.project, pct: snap.pct };
  if (state.navAiBadge == null) state.navAiBadge = snap.aiBadge || null;
  if (state.navProposalsBadge == null) state.navProposalsBadge = !!snap.proposalsBadge;
  renderTopbar();
  renderSidenav();
  mountAiChat();
  return true;
}

// Only touch the DOM when the markup really changed, so re-rendering with
// fresh data after the cached paint does not flash (or wipe the search box).
function _setShellHtml(el, html) {
  if (el._fdShellHtml === html) return false;
  el.innerHTML = html;
  el._fdShellHtml = html;
  return true;
}

async function bootPage(viewName) {
  if (!api.auth.hasSession()) { window.location.href = '/'; return; }
  state.currentView = viewName;
  _paintShellFromSnapshot();
  _initNavSpeculation();

  try { state.user = await api.auth.me(); }
  catch (err) {
    if (err.status === 401) { clearShellSnapshot(); window.location.href = '/'; return; }
    showToast('Could not reach the server, please retry', 'error');
    return;
  }

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

  // The cached shell belongs to another project (or none) → drop it.
  if (_shellSnap && _shellSnap.project.id !== state.currentProject?.id) {
    clearShellSnapshot();
    renderSidenav();
  }

  // No project at all → go to project list
  if (!state.currentProject) { window.location.href = 'projects'; return; }

  // Viewers always go to the client portal
  if (state.currentProject.member_role === 'viewer') {
    clearShellSnapshot();
    window.location.href = `client?pid=${state.currentProject.id}`;
    return;
  }

  await loadProjectData(state.currentProject.id);
  _projectDataLoaded = true;
  _shellSnap = null; // real data from here on
  renderSidenav();  // re-render now that currentProject and projects are loaded
  renderTopbar();   // re-render with correct role color
  if (state.onlineUsers?.length) renderOnlinePresence(state.onlineUsers); // restore after topbar rebuild
  hide('loading-overlay');
  mountAiChat();
  if (typeof pageInit === 'function') pageInit();
  refreshTopbarProgress();
  initNavAiBadge(); // no await — punto vivo en "AI Agent" del nav, visible desde cualquier página
  initNavProposalsBadge(); // no await — punto en "Findings" si hay propuestas de IA pendientes
  if (typeof initNotifications === 'function') initNotifications(); // no await — badge de la campana
}

// ── Badge del AI Agent en el nav — "que se complemente con el ecosistema" ─
// Un scan puede quedar corriendo mientras el pentester trabaja en Targets,
// Findings, etc. — sin esto, no había ninguna señal de que el agente
// seguía activo fuera de la propia página de AI Agent. Chequeo inicial
// liviano (reusa GET /sessions, lo mismo que ya pide ai-agent.html) +
// actualización en vivo por WS, disponible en TODAS las páginas porque
// page.js se carga en todas.
async function initNavAiBadge() {
  if (!state.currentProject) return;
  try {
    const sessions = await api.aiScan.listSessions(state.currentProject.id);
    const active = sessions.find(s => ['running', 'waiting_approval'].includes(s.status));
    setNavAiBadge(active ? active.status : null);
  } catch {}
}

function setNavAiBadge(status) {
  // Persistido en `state` (no solo en el DOM) para que sobreviva a un
  // renderSidenav() disparado por otra razón (ej. settings.js guardando el
  // nombre del proyecto) — sin esto, ese re-render pisaba el badge con el
  // template oculto por defecto y quedaba invisible hasta el próximo evento WS.
  state.navAiBadge = ['running', 'waiting_approval'].includes(status) ? status : null;
  _saveShellSnapshot();
  const badge = document.getElementById('nav-ai-badge');
  if (!badge) return;
  if (status === 'running') {
    badge.style.display = 'inline-block';
    badge.className = 'nav-ai-badge running';
    badge.title = 'El AI Agent está trabajando';
  } else if (status === 'waiting_approval') {
    badge.style.display = 'inline-block';
    badge.className = 'nav-ai-badge waiting';
    badge.title = 'El AI Agent espera tu aprobación';
  } else {
    badge.style.display = 'none';
  }
}

// Room-scoped por proyecto (ver ws.js backend) — cualquier ai_scan:event
// que llega acá ya es de ESTE proyecto, no hace falta filtrar por
// session_id. Simplificación deliberada: asume una sola sesión realmente
// activa a la vez por proyecto (mismo supuesto que ya usa ai-agent.js al
// elegir qué sesión mostrar al entrar) — si hubiera varias en paralelo, el
// badge refleja la última que emitió un evento, no un agregado de todas.
wsClient.on('ai_scan:event', (msg) => {
  setNavAiBadge(['running', 'waiting_approval'].includes(msg.status) ? msg.status : null);
});

// ── Punto de propuestas en "Findings" ─────────────────────────────
// Claude Code deja hallazgos como propuestas pendientes (mcp_proposals) que
// solo se ven en el inbox de la página de Findings: sin este punto nadie se
// entera hasta entrar ahí. Mismo esquema que el badge del AI Agent: chequeo
// inicial por REST + vivo por WS (mcp_proposals:changed trae la cantidad
// pendiente), persistido en state y en el snapshot del shell.
async function initNavProposalsBadge() {
  if (!state.currentProject) return;
  try {
    const pending = await api.mcpProposals.list(state.currentProject.id);
    setNavProposalsBadge(pending.length);
  } catch {}
}

function setNavProposalsBadge(pending) {
  state.navProposalsBadge = pending > 0;
  _saveShellSnapshot();
  const badge = document.getElementById('nav-proposals-badge');
  if (!badge) return;
  badge.style.display = state.navProposalsBadge ? 'inline-block' : 'none';
  badge.title = state.navProposalsBadge
    ? `${pending} propuesta${pending > 1 ? 's' : ''} de IA pendiente${pending > 1 ? 's' : ''} de revisión`
    : '';
}

wsClient.on('mcp_proposals:changed', (msg) => {
  setNavProposalsBadge(Number(msg.pending) || 0);
  // Con la página de Findings abierta, el inbox se refresca solo.
  if (typeof renderClaudeProposals === 'function') renderClaudeProposals();
});

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
  clearShellSnapshot();
  localStorage.setItem('fd_project', id);
  window.location.href = `dashboard?pid=${id}`;
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
  _saveShellSnapshot();
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
  'dashboard':   `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="1" y="1" width="6" height="6" rx="1"/><rect x="9" y="1" width="6" height="6" rx="1"/><rect x="1" y="9" width="6" height="6" rx="1"/><rect x="9" y="9" width="6" height="6" rx="1"/></svg>`,
  'targets':     `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="8" cy="8" r="5.5"/><line x1="8" y1="1" x2="8" y2="4"/><line x1="8" y1="12" x2="8" y2="15"/><line x1="1" y1="8" x2="4" y2="8"/><line x1="12" y1="8" x2="15" y2="8"/></svg>`,
  'vulns':       `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 2L14 5v4c0 3.5-2.8 5.5-6 6.5C5.8 14.5 2 12.5 2 9V5z"/><line x1="8" y1="7" x2="8" y2="9.5"/><circle cx="8" cy="11.5" r=".7" fill="currentColor" stroke="none"/></svg>`,
  'export':      `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 1h6l4 4v10H4z"/><path d="M10 1v4h4"/><line x1="6" y1="8" x2="11" y2="8"/><line x1="6" y1="11" x2="11" y2="11"/></svg>`,
  'whiteboard':  `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="1" y="2" width="14" height="11" rx="1.5"/><path d="M5 10.5L6.5 9l3-3L11 4.5l1 1-1.5 1.5-3 3L6 11.5z"/></svg>`,
  'ai-agent':    `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="5.5" width="10" height="8" rx="2"/><line x1="8" y1="5.5" x2="8" y2="2.5"/><circle cx="8" cy="1.5" r="1" fill="currentColor" stroke="none"/><circle cx="6" cy="9.5" r=".8" fill="currentColor" stroke="none"/><circle cx="10" cy="9.5" r=".8" fill="currentColor" stroke="none"/><line x1="5.5" y1="12.5" x2="10.5" y2="12.5"/></svg>`,
  'owstg':        `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="1" width="12" height="14" rx="1.5"/><path d="M5.5 5.5L7 7l3.5-3.5"/><line x1="5" y1="10" x2="11" y2="10"/><line x1="5" y1="13" x2="9" y2="13"/></svg>`,
  'methodology': `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3.5" y="3" width="9" height="12" rx="1"/><path d="M7 3V1.5a1.5 1.5 0 013 0V3"/><line x1="6.5" y1="8" x2="9.5" y2="8"/><line x1="6.5" y1="11" x2="9.5" y2="11"/></svg>`,
  'members':     `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="6" cy="5.5" r="2.5"/><path d="M1 14c0-3 2-4.5 5-4.5s5 1.5 5 4.5"/><circle cx="12.5" cy="5" r="2"/><path d="M12.5 11c2.5.2 3.5 1.5 3.5 3"/></svg>`,
  'settings':    `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="8" cy="8" r="2.5"/><path d="M8 1.5V3M8 13v1.5M1.5 8H3M13 8h1.5M3.5 3.5l1 1M11.5 11.5l1 1M3.5 12.5l1-1M11.5 4.5l1-1"/></svg>`,
  'tickets':     `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2 2h12v9H9l-2.5 3L4 11H2z"/></svg>`,
  'tasks':       icon('list-checks', { size: 14, strokeWidth: 1.75 }),
  'my-tasks':    icon('user', { size: 14, strokeWidth: 1.75 }),
  'portswigger': `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 1v5L2 14h12L10 6V1"/><line x1="5.5" y1="1" x2="10.5" y2="1"/><circle cx="7" cy="11" r="1" fill="currentColor" stroke="none"/></svg>`,
};

function renderSidenav() {
  const current = window.location.pathname.split('/').pop() || 'dashboard';
  // Before the project data arrives, fall back to the cached shell snapshot.
  const proj = state.currentProject || _shellSnap?.project || null;
  const pid  = proj ? `?pid=${proj.id}` : '';
  const u    = state.user || _shellSnap?.user || null;

  const navGroups = [
    {
      label: 'Engagement',
      items: [
        { href:`dashboard${pid}`,   label:'Overview'      },
        { href:`targets${pid}`,     label:'Targets'       },
        { href:`vulns${pid}`,       label:'Findings'      },
        { href:`tasks${pid}`,       label:'Tareas'        },
        { href:`export${pid}`,      label:'Report'        },
        { href:`whiteboard${pid}`,  label:'Whiteboard'    },
        { href:`ai-agent${pid}`,    label:'AI Agent'      },
      ]
    },
    {
      label: 'Testing',
      items: [
        { href:`owstg${pid}`,        label:'OWASP WSTG'    },
        { href:`methodology${pid}`, label:'Methodologies' },
      ]
    },
    {
      label: 'Team',
      items: [
        { href:`my-tasks${pid}`,    label:'Mis tareas'    },
        { href:`members${pid}`,     label:'Members'       },
        { href:`settings${pid}`,    label:'Settings'      },
        ...(proj?.tickets_enabled ? [{ href:`tickets${pid}`, label:'Queries' }] : []),
      ]
    },
    {
      label: 'Practice',
      items: [
        { href:`portswigger${pid}`, label:'PortSwigger'   },
      ]
    },
  ];

  let pct;
  if (!_projectDataLoaded && _shellSnap) pct = _shellSnap.pct || 0;
  else { const { done, total } = calcOverallProgress(); pct = total ? Math.round(done/total*100) : 0; }

  let html = `
    <div class="brand">
      <img src="img/flowdit-logo.png" class="brand-logo-img" alt="Flowdit">
      <span class="brand-wordmark">Flowdit</span>
      <span class="brand-tag">SELF-HOSTED</span>
    </div>
    <a href="projects" class="nav-back-link">${icon('arrow-left', { size: 13 })} All Projects</a>`;

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
      // Badge del AI Agent — punto vivo cuando hay un scan corriendo o
      // esperando aprobación en ESTE proyecto, visible desde cualquier
      // página (no solo estando en ai-agent.html). Vacío/oculto por
      // default, `initNavAiBadge()` lo llena después del render inicial —
      // ver ese comentario para el porqué (no bloquea el render del nav).
      // Arranca con el último estado conocido (state.navAiBadge) en vez de
      // siempre oculto — así un renderSidenav() disparado por otra vista
      // (ej. saveGeneral() en settings.js) no apaga el punto de un scan
      // que sigue corriendo; setNavAiBadge() mantiene ese estado al día.
      const badgeStatus = state.navAiBadge;
      const aiBadge = item.href.split('?')[0] === 'ai-agent'
        ? `<span class="nav-ai-badge${badgeStatus ? ' '+badgeStatus : ''}" id="nav-ai-badge" style="${badgeStatus ? '' : 'display:none'}"></span>` : '';
      // Punto de propuestas de IA pendientes — ver setNavProposalsBadge().
      const proposalsBadge = item.href.split('?')[0] === 'vulns'
        ? `<span class="nav-ai-badge waiting" id="nav-proposals-badge" style="${state.navProposalsBadge ? '' : 'display:none'}"></span>` : '';
      html += `<a href="${item.href}" class="nav-item ${active?'active':''}">${navIcon}<span>${item.label}</span>${aiBadge}${proposalsBadge}</a>`;
    });
  });
  html += `</div>`;

  if (u) {
    const role  = proj?.member_role;
    const color = roleColor(role);
    html += `
    <div class="nav-foot nav-foot-user" onclick="toggleUserMenu()" title="Account">
      ${avatarHtml(displayName(u), color, 24, u.avatar_url)}
      <div style="flex:1;min-width:0">
        <div class="nav-foot-name" title="@${esc(u.username)}">${esc(displayName(u))}</div>
        ${role ? `<div class="nav-foot-role">${role}</div>` : ''}
      </div>
      <span class="nav-foot-chevron">${icon('chevron-up', { size: 13 })}</span>
      <div class="user-dropdown user-dropdown-up" id="user-dropdown">
        <button class="dropdown-item" onclick="openProfileModal();event.stopPropagation()">${icon('user', { size: 13 })} Edit Profile</button>
        <button class="dropdown-item" onclick="window.location.href='orgs'">${icon('building-2', { size: 13 })} Organizations</button>
        <button class="dropdown-item danger" onclick="doLogout()">${icon('log-out', { size: 13 })} Logout</button>
      </div>
    </div>`;
  }

  const sidenav = document.getElementById('sidenav');
  if (sidenav && _setShellHtml(sidenav, html)) _saveShellSnapshot();
}

// ── SIDENAV NAVIGATION — instant highlight + prefetch ────────────
// Move the active highlight as soon as a section is clicked, instead of
// waiting for the next page to render it.
document.addEventListener('click', e => {
  const link = e.target.closest?.('#sidenav a.nav-item');
  if (!link || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  document.querySelectorAll('#sidenav a.nav-item.active').forEach(a => a.classList.remove('active'));
  link.classList.add('active');
});

// Back/forward cache restores the page as it was left, with the highlight
// already moved to the section we navigated to: put it back.
window.addEventListener('pageshow', e => {
  if (!e.persisted) return;
  const current = window.location.pathname.split('/').pop() || 'dashboard';
  document.querySelectorAll('#sidenav a.nav-item').forEach(a => {
    a.classList.toggle('active', (a.getAttribute('href') || '').split('?')[0] === current);
  });
});

// Cross-document view transitions (css/transitions.css): only the pages
// that link transitions.css opt in. When the next page does not (login,
// project list, report export...), Chrome would start the transition here
// and then abort it with an "opt-in disabled" InvalidStateError in the
// console, so skip it up front. Keep in sync with the pages linking it.
const _VT_PAGES = new Set(['dashboard', 'targets', 'vulns', 'tasks', 'whiteboard', 'ai-agent',
  'owstg', 'methodology', 'my-tasks', 'members', 'settings', 'tickets', 'portswigger']);
window.addEventListener('pageswap', e => {
  const vt = e.viewTransition;
  if (!vt) return;
  [vt.ready, vt.finished, vt.updateCallbackDone].forEach(pr => pr?.catch?.(() => {}));
  let target = '';
  try {
    const url = new URL(e.activation?.entry?.url || '', location.href);
    if (url.origin === location.origin) target = url.pathname.split('/').pop().replace(/\.html$/, '');
  } catch {}
  if (!_VT_PAGES.has(target)) vt.skipTransition();
});

// Prefetch (document only, no prerender: these pages open a WebSocket,
// announce presence and call APIs on load) the sidenav sections on hover.
// Speculation Rules where supported; <link rel=prefetch> on hover otherwise.
// CSP note: script-src has 'unsafe-inline', which also covers inline
// speculation rules, so no nginx change is needed.
let _navSpeculationReady = false;
function _initNavSpeculation() {
  if (_navSpeculationReady) return;
  _navSpeculationReady = true;
  try {
    if (HTMLScriptElement.supports?.('speculationrules')) {
      const s = document.createElement('script');
      s.type = 'speculationrules';
      s.textContent = JSON.stringify({
        prefetch: [{
          source: 'document',
          where: { and: [
            { selector_matches: '#sidenav a.nav-item' },
            { not: { selector_matches: '#sidenav a.nav-item.active' } },
          ] },
          eagerness: 'moderate',
        }],
      });
      document.head.appendChild(s);
      return;
    }
  } catch {}
  const done = new Set();
  const prefetch = e => {
    const link = e.target.closest?.('#sidenav a.nav-item');
    if (!link || link.classList.contains('active') || link.origin !== location.origin) return;
    const href = link.href;
    if (done.has(href)) return;
    done.add(href);
    const l = document.createElement('link');
    l.rel = 'prefetch';
    l.href = href;
    document.head.appendChild(l);
  };
  document.addEventListener('pointerover', prefetch);
  document.addEventListener('pointerdown', prefetch);
}

// ── TOPBAR (slim — search, presence, notifications) ──────────────
// The account menu (profile, orgs, logout) lives in the sidenav foot.
function renderTopbar() {
  const el = document.getElementById('topbar');
  if (!el) return;
  _setShellHtml(el, `
    <div style="display:flex;align-items:center;gap:8px;flex:1;min-width:0">
      <div class="search-wrap">
        <span class="search-icon">${icon('search', { size: 14 })}</span>
        <input type="text" class="search-input" placeholder="Search..." oninput="handleSearch(this.value)">
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:10px">
      <div class="online-avatars" id="online-presence"></div>
      <div id="live-dot" class="live-badge" title="Connecting..."></div>
      ${typeof notifBellHtml === 'function' ? notifBellHtml() : ''}
    </div>`);
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
        <label class="form-label" for="profile-display-name">Display name</label>
        <input type="text" class="form-input" id="profile-display-name" maxlength="50" autocomplete="name" placeholder="e.g. Juan Pérez">
        <div style="font-family:var(--mono);font-size:10px;color:var(--t3);margin-top:4px">Optional. Shown to your team instead of your username.</div>
      </div>

      <div class="form-group">
        <label class="form-label" for="profile-username">Username</label>
        <input type="text" class="form-input" id="profile-username" maxlength="50" autocomplete="username" spellcheck="false">
        <div style="font-family:var(--mono);font-size:10px;color:var(--t3);margin-top:4px">Used to sign in. Letters, numbers, _ and - only.</div>
      </div>

      <div class="form-error" id="profile-error"></div>

      <div style="border-top:1px solid var(--b1);margin:18px 0 4px;padding-top:16px">
        <div style="font-family:var(--mono);font-size:11px;color:var(--t3);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px">Security</div>
        <div id="profile-mfa-section"></div>
      </div>

      <div style="border-top:1px solid var(--b1);margin:18px 0 4px;padding-top:16px">
        <div style="font-family:var(--mono);font-size:11px;color:var(--t3);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px">Claude Code</div>
        <div id="profile-cc-section"></div>
      </div>

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
  document.getElementById('profile-display-name').value = u.display_name || '';
  document.getElementById('profile-username').value = u.username;
  document.getElementById('profile-error').textContent = '';
  _refreshAvatarPreview(u.avatar_url || null);
  document.getElementById('profile-modal').classList.add('open');
  _loadMfaStatus();
  _loadApiTokens();
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
    preview.innerHTML = nameInitial(displayName(state.user));
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
  const username    = document.getElementById('profile-username').value.trim();
  // Same normalisation the server applies (whitespace collapsed, trimmed), so
  // an unchanged name with stray spaces is not sent as a change.
  const displayNm   = document.getElementById('profile-display-name').value.replace(/\s+/g, ' ').trim();
  const errEl = document.getElementById('profile-error');
  const btn   = document.getElementById('profile-save-btn');
  errEl.textContent = '';

  if (!username) { errEl.textContent = 'Username is required.'; return; }
  if (!/^[a-zA-Z0-9_-]{2,50}$/.test(username)) {
    errEl.textContent = 'Username: only letters, numbers, _ and - (2–50 chars).';
    return;
  }
  if ([...displayNm].length > 50) {
    errEl.textContent = 'Display name: 50 characters max.';
    return;
  }

  const payload = {};
  if (username !== state.user.username) payload.username = username;
  if (displayNm !== (state.user.display_name || '')) payload.display_name = displayNm;
  if (_pendingAvatarUrl !== undefined) payload.avatar_url = _pendingAvatarUrl;

  if (!Object.keys(payload).length) { closeProfileModal(); return; }

  btn.disabled = true;
  try {
    const updated = await api.auth.updateProfile(payload);
    state.user = { ...state.user, ...updated };
    localStorage.setItem('fd_user', JSON.stringify(state.user));
    closeProfileModal();
    // Keep the cached members list in step so views that resolve people via
    // state.members (presence, activity avatars, assignee labels) pick it up.
    const me = (state.members || []).find(m => m.id === state.user.id);
    if (me) Object.assign(me, { username: state.user.username, display_name: state.user.display_name ?? me.display_name, avatar_url: state.user.avatar_url ?? me.avatar_url });
    // The name and avatar are shown in the sidenav foot, not the topbar.
    renderSidenav();
    if (state.onlineUsers && typeof renderOnlinePresence === 'function') renderOnlinePresence(state.onlineUsers);
    if (typeof renderMembers === 'function' && state.currentView === 'members') renderMembers();
    // A server that predates display names ignores the field and omits it
    // from the response: say so instead of silently dropping the edit.
    if ('display_name' in payload && !('display_name' in updated)) {
      showToast('Display name is not supported by the server yet', 'error');
    } else {
      showToast('Profile updated', 'success');
    }
  } catch(e) {
    errEl.textContent = e.message;
  } finally {
    btn.disabled = false;
  }
}

// ── PROFILE MODAL — 2FA (TOTP) ───────────────────────────────────────
// Sub-states rendered inside #profile-mfa-section: idle (toggle row) ->
// setup (QR + confirm code) -> backup-codes (shown once) back to idle,
// or idle -> disable (password re-entry) -> idle.
let _mfaSetup = null; // { secret, qrCodeDataUrl } while a setup is in flight

async function _loadMfaStatus() {
  _renderMfaSection('idle', { enabled: null }); // loading placeholder
  try {
    const { enabled } = await api.auth.mfa.status();
    _renderMfaSection('idle', { enabled });
  } catch {
    _renderMfaSection('idle', { enabled: false });
  }
}

function _renderMfaSection(view, ctx = {}) {
  const el = document.getElementById('profile-mfa-section');
  if (!el) return;

  if (view === 'idle') {
    if (ctx.enabled === null) { el.innerHTML = `<div style="font-family:var(--mono);font-size:11px;color:var(--t3)">Checking...</div>`; return; }
    el.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;gap:10px">
        <div>
          <div style="font-size:13px;font-weight:600">Two-factor authentication</div>
          <div style="font-family:var(--mono);font-size:10px;color:var(--t3)">${ctx.enabled ? 'Enabled — an authenticator app is required at login.' : 'Off — add an extra step to your login.'}</div>
        </div>
        <button class="setting-toggle ${ctx.enabled ? 'on' : ''}" onclick="${ctx.enabled ? 'mfaPromptDisable()' : 'mfaStartSetup()'}">
          <span class="setting-toggle-knob"></span>
        </button>
      </div>`;
    return;
  }

  if (view === 'setup') {
    el.innerHTML = `
      <div style="display:flex;flex-direction:column;align-items:center;gap:10px;text-align:center">
        <div style="font-family:var(--mono);font-size:10px;color:var(--t3)">Scan with Google Authenticator, Authy, or similar.</div>
        <img src="${ctx.qrCodeDataUrl}" alt="2FA QR code" style="width:160px;height:160px;border-radius:8px;background:#fff;padding:8px">
        <div style="font-family:var(--mono);font-size:11px;color:var(--t2);word-break:break-all;background:var(--bg3);border:1px solid var(--b1);border-radius:6px;padding:6px 10px">${esc(ctx.secret)}</div>
        <input type="text" class="form-input" id="mfa-setup-code" placeholder="123456" inputmode="numeric" maxlength="6"
          style="text-align:center;letter-spacing:2px" onkeydown="if(event.key==='Enter')mfaConfirmEnable()">
        <div class="form-error" id="mfa-setup-error" style="display:none"></div>
        <div style="display:flex;gap:8px;width:100%">
          <button class="btn-secondary" style="flex:1" onclick="mfaCancelSetup()">Cancel</button>
          <button class="btn-primary" style="flex:1" id="mfa-setup-confirm-btn" onclick="mfaConfirmEnable()">Confirm</button>
        </div>
      </div>`;
    document.getElementById('mfa-setup-code').focus();
    return;
  }

  if (view === 'backup-codes') {
    el.innerHTML = `
      <div style="display:flex;flex-direction:column;gap:8px">
        <div style="font-size:13px;font-weight:600;color:var(--green)">${icon('check', { size: 13 })} Two-factor authentication enabled</div>
        <div style="font-family:var(--mono);font-size:10px;color:var(--t3)">Save these one-time backup codes — each works once if you lose access to your authenticator app. They won't be shown again.</div>
        <div style="font-family:var(--mono);font-size:12px;background:var(--bg3);border:1px solid var(--b1);border-radius:6px;padding:10px;display:grid;grid-template-columns:1fr 1fr;gap:4px">
          ${ctx.codes.map(c => `<span>${esc(c)}</span>`).join('')}
        </div>
        <button class="btn-primary" onclick="mfaAcknowledgeBackupCodes()">I've saved these codes</button>
      </div>`;
    return;
  }

  if (view === 'disable') {
    el.innerHTML = `
      <div style="display:flex;flex-direction:column;gap:8px">
        <div style="font-family:var(--mono);font-size:10px;color:var(--t3)">Enter your password to turn off two-factor authentication.</div>
        <input type="password" class="form-input" id="mfa-disable-password" placeholder="••••••••"
          onkeydown="if(event.key==='Enter')mfaConfirmDisable()">
        <div class="form-error" id="mfa-disable-error" style="display:none"></div>
        <div style="display:flex;gap:8px">
          <button class="btn-secondary" style="flex:1" onclick="_loadMfaStatus()">Cancel</button>
          <button class="btn-primary" style="flex:1" id="mfa-disable-confirm-btn" onclick="mfaConfirmDisable()">Disable</button>
        </div>
      </div>`;
    document.getElementById('mfa-disable-password').focus();
    return;
  }
}

async function mfaStartSetup() {
  _renderMfaSection('idle', { enabled: null });
  try {
    _mfaSetup = await api.auth.mfa.setup();
    _renderMfaSection('setup', _mfaSetup);
  } catch (e) {
    showToast(e.message, 'error');
    _loadMfaStatus();
  }
}

function mfaCancelSetup() {
  _mfaSetup = null;
  _loadMfaStatus();
}

async function mfaConfirmEnable() {
  const code = document.getElementById('mfa-setup-code').value.trim();
  const errEl = document.getElementById('mfa-setup-error');
  const btn = document.getElementById('mfa-setup-confirm-btn');
  errEl.style.display = 'none';
  if (!code) return;
  btn.disabled = true;
  try {
    const { backupCodes } = await api.auth.mfa.enable(code);
    _mfaSetup = null;
    _renderMfaSection('backup-codes', { codes: backupCodes });
  } catch (e) {
    errEl.textContent = e.message;
    errEl.style.display = 'block';
  } finally {
    btn.disabled = false;
  }
}

function mfaAcknowledgeBackupCodes() {
  _loadMfaStatus();
  showToast('Two-factor authentication enabled', 'success');
}

function mfaPromptDisable() {
  _renderMfaSection('disable');
}

async function mfaConfirmDisable() {
  const password = document.getElementById('mfa-disable-password').value;
  const errEl = document.getElementById('mfa-disable-error');
  const btn = document.getElementById('mfa-disable-confirm-btn');
  errEl.style.display = 'none';
  if (!password) return;
  btn.disabled = true;
  try {
    await api.auth.mfa.disable(password);
    _loadMfaStatus();
    showToast('Two-factor authentication disabled', 'success');
  } catch (e) {
    errEl.textContent = e.message;
    errEl.style.display = 'block';
    btn.disabled = false;
  }
}

// ── PROFILE MODAL — tokens de Claude Code (MCP) ──────────────────────
// Tokens personales para conectar Claude Code al servidor MCP (/mcp). El
// token en claro llega una sola vez (respuesta del create): se muestra con
// el comando listo para pegar y, al cerrar ese aviso, ya no se puede
// recuperar — solo revocarlo y crear otro.
let _newApiToken = null; // { token, name } mientras se muestra el aviso

// /mcp cuelga del mismo host que /api: en prod es el mismo origen (nginx),
// en dev el backend está en :4000 (ver config.js).
function _mcpUrl() {
  const base = window.FLOWDIT_API || '/api';
  const origin = /^https?:\/\//.test(base) ? new URL(base).origin : window.location.origin;
  return `${origin}/mcp`;
}

function _mcpAddCommand(token) {
  return `claude mcp add --transport http flowdit ${_mcpUrl()} --header "Authorization: Bearer ${token}"`;
}

async function _loadApiTokens() {
  const el = document.getElementById('profile-cc-section');
  if (!el) return;
  if (_newApiToken) { _renderNewApiToken(); return; }
  el.innerHTML = `<div style="font-family:var(--mono);font-size:11px;color:var(--t3)">Cargando...</div>`;
  try {
    _renderApiTokens(await api.me.apiTokens.list());
  } catch (e) {
    el.innerHTML = `<div class="form-error" style="display:block">${esc(e.message)}</div>`;
  }
}

function _renderApiTokens(list) {
  const el = document.getElementById('profile-cc-section');
  if (!el) return;
  const scopeLabel = s => s === 'read_propose' ? 'lectura + propuestas' : 'solo lectura';
  const statusLabel = { active: 'activo', revoked: 'revocado', expired: 'vencido' };
  const rows = list.map(t => `
    <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;padding:6px 0;border-bottom:1px solid var(--b1);${t.status === 'active' ? '' : 'opacity:.5'}">
      <div style="min-width:0">
        <div style="font-size:12px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(t.name)}</div>
        <div style="font-family:var(--mono);font-size:10px;color:var(--t3)">
          ${esc(t.token_prefix)}… · ${scopeLabel(t.scopes)} · ${statusLabel[t.status] || t.status}
          · ${t.last_used_at ? 'usado ' + esc(timeAgo(t.last_used_at)) : 'sin usar'}
          ${t.expires_at && t.status === 'active' ? ` · vence ${esc(new Date(t.expires_at).toLocaleDateString())}` : ''}
        </div>
      </div>
      ${t.status === 'active' ? `<button class="btn btn-ghost" style="font-size:10px;padding:3px 8px;color:var(--c-crit);flex-shrink:0" onclick="revokeApiToken('${t.id}')">Revocar</button>` : ''}
    </div>`).join('');

  el.innerHTML = `
    <div style="font-family:var(--mono);font-size:10px;color:var(--t3);margin-bottom:10px;line-height:1.5">
      Tokens para conectar Claude Code a Flowdit (MCP). Claude Code puede leer los proyectos que tengan habilitado el acceso y proponer hallazgos/notas, que quedan pendientes de revisión. No sirven para la API web.
    </div>
    ${rows || `<div style="font-family:var(--mono);font-size:11px;color:var(--t3);margin-bottom:8px">Todavía no creaste ningún token.</div>`}
    <div style="display:flex;flex-direction:column;gap:6px;margin-top:10px">
      <input type="text" class="form-input" id="cc-token-name" maxlength="100" placeholder="Nombre (ej. laptop trabajo)" style="font-size:12px">
      <div style="display:flex;gap:6px">
        <select class="form-input" id="cc-token-scope" style="font-size:12px;flex:1">
          <option value="read_propose">Lectura + propuestas</option>
          <option value="read">Solo lectura</option>
        </select>
        <select class="form-input" id="cc-token-expiry" style="font-size:12px;flex:1">
          <option value="30">Vence en 30 días</option>
          <option value="90" selected>Vence en 90 días</option>
          <option value="365">Vence en 1 año</option>
          <option value="">Sin vencimiento</option>
        </select>
      </div>
      <div class="form-error" id="cc-token-error" style="display:none"></div>
      <button class="btn btn-prim" id="cc-token-create-btn" onclick="createApiToken()">Crear token</button>
    </div>`;
}

function _renderNewApiToken() {
  const el = document.getElementById('profile-cc-section');
  if (!el || !_newApiToken) return;
  const cmd = _mcpAddCommand(_newApiToken.token);
  el.innerHTML = `
    <div style="display:flex;flex-direction:column;gap:8px">
      <div style="font-size:13px;font-weight:600;color:var(--green)">${icon('check', { size: 13 })} Token "${esc(_newApiToken.name)}" creado</div>
      <div style="font-family:var(--mono);font-size:10px;color:var(--t3)">Copialo ahora: no se va a volver a mostrar.</div>
      <div style="display:flex;gap:6px;align-items:flex-start">
        <div style="flex:1;font-family:var(--mono);font-size:11px;word-break:break-all;background:var(--bg3);border:1px solid var(--b1);border-radius:6px;padding:6px 10px">${esc(_newApiToken.token)}</div>
        <button class="copy-btn" onclick="copyText(this,'${btoa(encodeURIComponent(_newApiToken.token))}')">copy</button>
      </div>
      <div style="font-family:var(--mono);font-size:10px;color:var(--t3)">Comando para Claude Code:</div>
      <div style="display:flex;gap:6px;align-items:flex-start">
        <div style="flex:1;font-family:var(--mono);font-size:11px;word-break:break-all;background:var(--bg3);border:1px solid var(--b1);border-radius:6px;padding:6px 10px">${esc(cmd)}</div>
        <button class="copy-btn" onclick="copyText(this,'${btoa(encodeURIComponent(cmd))}')">copy</button>
      </div>
      <button class="btn btn-prim" onclick="ackNewApiToken()">Listo, ya lo copié</button>
    </div>`;
}

async function createApiToken() {
  const name   = document.getElementById('cc-token-name').value.trim();
  const scopes = document.getElementById('cc-token-scope').value;
  const expiry = document.getElementById('cc-token-expiry').value;
  const errEl  = document.getElementById('cc-token-error');
  const btn    = document.getElementById('cc-token-create-btn');
  errEl.style.display = 'none';
  if (!name) { errEl.textContent = 'Poné un nombre para reconocer el token'; errEl.style.display = 'block'; return; }
  btn.disabled = true;
  try {
    const created = await api.me.apiTokens.create({ name, scopes, expires_in_days: expiry ? Number(expiry) : null });
    _newApiToken = { token: created.token, name: created.name };
    _renderNewApiToken();
  } catch (e) {
    errEl.textContent = e.message;
    errEl.style.display = 'block';
    btn.disabled = false;
  }
}

function ackNewApiToken() {
  _newApiToken = null;
  _loadApiTokens();
}

async function revokeApiToken(id) {
  if (!confirm('¿Revocar este token? Claude Code va a perder el acceso de inmediato.')) return;
  try {
    await api.me.apiTokens.revoke(id);
    showToast('Token revocado', 'success');
    _loadApiTokens();
  } catch (e) { showToast(e.message, 'error'); }
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
document.addEventListener('click', e => { if (!e.target.closest('.user-pill, .nav-foot-user')) closeUserMenu(); });

async function doLogout() {
  wsClient.disconnect();
  clearShellSnapshot();
  await api.auth.logout().catch(() => {});
  localStorage.removeItem('fd_project');
  window.location.href = '/';
}

// ── WEBSOCKET EVENTS ──────────────────────────────────────────────
// Lista de hallazgos en vivo: cualquier alta/cambio/baja de un custom_vuln
// (de otro miembro, de una propuesta de Claude Code aprobada o del AI
// Agent) re-pide GET /vulns. Llega por dos lados: el evento de Activity
// (entity_type 'custom_vuln') y 'vulns:changed' para los caminos que no van
// al feed. Debounce porque un mismo cambio puede disparar los dos, o el
// agente crear varios seguidos. Incluye eventos propios: un hallazgo del
// agente aprobado por mí tampoco existe todavía en esta pestaña.
let _vulnsRefreshTimer = null;
function scheduleVulnsRefresh() {
  if (!state.currentProject) return;
  clearTimeout(_vulnsRefreshTimer);
  _vulnsRefreshTimer = setTimeout(async () => {
    const pid = state.currentProject?.id;
    if (!pid) return;
    try {
      const vulns = await api.vulns.list(pid);
      if (state.currentProject?.id !== pid) return;
      state.customVulns = vulns;
    } catch { return; }
    // renderCustomVulns() conserva el drawer: en vista lo redibuja con los
    // datos nuevos (scroll y borrador de notas incluidos), en edición no lo toca.
    if (state.currentView === 'custom' && typeof renderCustomVulns === 'function') renderCustomVulns();
    if (typeof updateDashboard === 'function') updateDashboard();
    // Whiteboard: finding rows of target nodes and finding cards.
    if (typeof wbRefreshFindings === 'function') wbRefreshFindings();
  }, 300);
}

wsClient.on('vulns:changed', scheduleVulnsRefresh);

// Lo mismo para targets / puertos / endpoints. Eventos propios se ignoran
// (esta pestaña ya se actualizó sola) salvo los de Claude Code, que actúa
// con la cuenta del dueño del token pero no pasó por esta pestaña.
const _targetsRefreshIds = new Set();
let _targetsRefreshTimer = null;
function scheduleTargetsRefresh(targetId) {
  if (!state.currentProject) return;
  if (targetId) _targetsRefreshIds.add(targetId);
  clearTimeout(_targetsRefreshTimer);
  _targetsRefreshTimer = setTimeout(async () => {
    const pid = state.currentProject?.id;
    const ids = [..._targetsRefreshIds];
    _targetsRefreshIds.clear();
    if (!pid) return;
    try {
      const targets = await api.targets.list(pid);
      if (state.currentProject?.id !== pid) return;
      state.targets = targets;
    } catch { return; }
    if (state.currentView === 'targets' && typeof refreshTargetsLive === 'function') {
      if (!ids.length) refreshTargetsLive(null);
      else ids.forEach(id => refreshTargetsLive(id));
    }
    if (typeof updateDashboard === 'function') updateDashboard();
  }, 300);
}

wsClient.on('activity', (event) => {
  prependActivity(event);
  if (event.entity_type === 'custom_vuln') scheduleVulnsRefresh();
  if (['target', 'port', 'endpoint'].includes(event.entity_type)
      && (event.user?.id !== state.user?.id || event.meta?.via === 'claude-code')) {
    scheduleTargetsRefresh(event.entity_type === 'target' ? event.entity_id : event.meta?.target_id);
  }
  if (event.user?.id !== state.user?.id) {
    const label = actionLabel(event.action, event.entity_type, event.entity_name, event.meta)
      .replace(/<[^>]+>/g, '');
    showToast(`${displayName(event.user)}: ${label}`, 'info');
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
    window.location.href = `dashboard?pid=${proj.id}`;
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
    who: displayName(e), action: e.action,
    entity: e.entity_name || e.entity_type || '', when: e.created_at,
  }));

  return {
    project: { name: p.name, target: p.target, description: p.description, status: p.status },
    vulns:   vulns.map(v => ({ name: v.name, severity: v.severity, status: v.status, target_host: v.target_host || null })),
    wstg:    { done: wDone, fail: wFail, pending: wTotal-wDone-wFail, pct: wTotal ? Math.round((wDone+wFail)/wTotal*100) : 0 },
    targets: targets.map(t => ({ host: t.host, type: t.type, scope: t.scope })),
    team:    (state.members || []).map(m => ({ username: m.username, display_name: m.display_name || null, role: m.role })),
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
window.mfaStartSetup            = mfaStartSetup;
window.mfaCancelSetup           = mfaCancelSetup;
window.mfaConfirmEnable         = mfaConfirmEnable;
window.mfaAcknowledgeBackupCodes = mfaAcknowledgeBackupCodes;
window.mfaPromptDisable         = mfaPromptDisable;
window.mfaConfirmDisable        = mfaConfirmDisable;
window._loadMfaStatus           = _loadMfaStatus;
window.createApiToken           = createApiToken;
window.ackNewApiToken           = ackNewApiToken;
window.revokeApiToken           = revokeApiToken;
window.saveProject          = saveProject;
window.mountAiChat          = mountAiChat;
window.toggleAiPanel        = toggleAiPanel;
window.aiChatSend           = aiChatSend;
window.aiChatKeydown        = aiChatKeydown;
window.aiChatClear          = aiChatClear;