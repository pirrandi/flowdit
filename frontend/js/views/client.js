// ── views/client.js — Client portal (read-only) ──────────────────────

const SEV_ORDER  = ['critical','high','medium','low','info'];
const SEV_COLORS = { critical:'#dc2626', high:'#f97316', medium:'#f59e0b', low:'#059669', info:'#64748b' };
const SEV_LABELS = { critical:'Critical', high:'High', medium:'Medium', low:'Low', info:'Info' };

// ── BOOT ─────────────────────────────────────────────────────────────
async function bootClient() {
  const isPortal = api.portal.session.has();

  if (!isPortal && !api.auth.hasSession()) {
    window.location.href = 'client-login.html';
    return;
  }

  if (isPortal) {
    state.user = { id: null, username: 'client', role: 'viewer' };
    const pid  = api.portal.session.projectId;
    if (!pid) { window.location.href = 'client-login.html'; return; }
    const projectData = await api.projects.get(pid).catch(() => null);
    if (!projectData) { api.portal.session.clear(); window.location.href = 'client-login.html'; return; }
    state.projects       = [{ ...projectData, member_role: 'viewer' }];
    state.currentProject = state.projects[0];
    await loadClientProject(pid);
    hide('loading-overlay');
    renderClientTopbar();
    return;
  }

  // Regular user session
  try {
    state.user = await api.auth.me();
  } catch {
    api.auth.clearTokens();
    window.location.href = 'client-login.html';
    return;
  }

  const allProjects  = await api.projects.list().catch(() => []);
  state.projects     = allProjects.filter(p => p.member_role === 'viewer');
  state.hasOwnProjects = allProjects.some(p => p.member_role !== 'viewer');

  if (!state.projects.length) {
    hide('loading-overlay');
    document.getElementById('client-main').innerHTML = `
      <div style="max-width:400px;margin:80px auto;text-align:center">
        <div style="font-size:20px;font-weight:800;margin-bottom:8px">No projects yet</div>
        <div style="font-family:var(--mono);font-size:12px;color:var(--t3);margin-bottom:28px;line-height:1.6">
          Paste the invite code you received to join your project.
        </div>
        <div style="display:flex;gap:8px">
          <input type="text" id="client-join-input" class="form-input"
            placeholder="FD-XXXXXXXXXXXXXXXX"
            style="flex:1;text-transform:uppercase;letter-spacing:.08em;font-family:var(--mono)"
            onkeydown="if(event.key==='Enter')clientJoinProject()">
          <button class="btn-accent" onclick="clientJoinProject()">Join</button>
        </div>
        <div class="form-error" id="client-join-error" style="margin-top:8px"></div>
      </div>`;
    renderClientTopbar();
    return;
  }

  const urlPid = new URLSearchParams(window.location.search).get('pid');
  let resolved = null;
  if (urlPid) resolved = state.projects.find(p => p.id === urlPid);
  if (!resolved) {
    const saved = localStorage.getItem('fd_project');
    resolved = state.projects.find(p => p.id === saved) || state.projects[0];
  }
  state.currentProject = resolved;

  await loadClientProject(state.currentProject.id);
  hide('loading-overlay');
  renderClientTopbar();
}

async function loadClientProject(pid) {
  wsClient.connect(pid);
  [state.customVulns, state.targets, state.wstgProgress, state.members] = await Promise.all([
    api.vulns.list(pid).catch(() => []),
    api.targets.list(pid).catch(() => []),
    api.wstg.getAll(pid).catch(() => {}),
    api.members.list(pid).catch(() => []),
  ]);
  state.tickets = state.currentProject?.tickets_enabled
    ? await api.tickets.list(pid).catch(() => [])
    : [];
  state.clientActivity = state.currentProject?.show_activity
    ? await api.activity.list(pid).catch(() => [])
    : [];
  renderClientDashboard();
}

async function switchClientProject(id) {
  const proj = state.projects.find(p => p.id === id);
  if (!proj) return;
  state.currentProject = proj;
  localStorage.setItem('fd_project', id);
  wsClient.disconnect();
  show('loading-overlay');
  await loadClientProject(id);
  hide('loading-overlay');
  renderClientTopbar();
}

// ── TOPBAR ────────────────────────────────────────────────────────────
function renderClientTopbar() {
  const proj = state.currentProject;
  const el   = document.getElementById('client-topbar');
  if (!el) return;

  const isPortal = api.portal.session.has();

  // Logo: project logo if available, else Flowdit mark
  const logoEl = proj?.logo_url
    ? `<img src="${esc(proj.logo_url)}" style="height:24px;max-width:80px;object-fit:contain;flex-shrink:0" alt="">`
    : `<img src="img/flowdit-logo.png" class="topbar-logo-img" alt="Flowdit">`;

  const projName = proj
    ? `<span style="font-family:var(--mono);font-size:12px;color:var(--t2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:260px">${esc(proj.name)}</span>`
    : '';

  el.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;flex:1;min-width:0;overflow:hidden">
      ${logoEl}
      <span style="font-size:13px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--t1);flex-shrink:0">Flowdit</span>
      <span style="font-family:var(--mono);font-size:9px;color:var(--a);border:1px solid rgba(245,158,11,.25);border-radius:var(--r-sm);padding:2px 6px;text-transform:uppercase;letter-spacing:.08em;flex-shrink:0">portal</span>
      <div style="width:1px;height:16px;background:var(--b1);flex-shrink:0;margin:0 2px"></div>
      ${projName}
    </div>
    <div style="display:flex;align-items:center;gap:10px;flex-shrink:0">
      <div style="display:flex;align-items:center;gap:5px">
        <div id="client-live" class="live-badge" title="Connecting..."></div>
        <span style="font-family:var(--mono);font-size:9px;color:var(--t3)">live</span>
      </div>
      <div style="width:1px;height:16px;background:var(--b1)"></div>
      ${!isPortal ? `<a href="projects.html" class="btn btn-ghost" style="font-size:11px;padding:5px 10px;text-decoration:none">← Projects</a>` : ''}
      <button class="btn btn-ghost" style="font-size:11px;padding:5px 10px" onclick="doClientLogout()">Logout</button>
    </div>`;
}

// ── MAIN DASHBOARD ────────────────────────────────────────────────────
function renderClientDashboard() {
  const proj = state.currentProject;
  if (!proj) return;
  const main     = document.getElementById('client-main');
  const workarea = document.getElementById('client-workarea');
  const actCol   = document.getElementById('client-activity-col');
  if (!main) return;

  if (!proj.client_view_enabled) {
    main.innerHTML = `
      <div style="max-width:420px;margin:80px auto;text-align:center">
        <div class="page-title" style="margin-bottom:8px">Portal not yet available</div>
        <div style="font-family:var(--mono);font-size:12px;color:var(--t3);line-height:1.8">
          The project team hasn't opened the client portal yet.<br>Check back soon.
        </div>
      </div>`;
    if (workarea) workarea.classList.add('no-activity');
    if (actCol)   actCol.style.display = 'none';
    return;
  }

  // Toggle activity sidebar
  if (proj.show_activity) {
    if (workarea) workarea.classList.remove('no-activity');
    if (actCol)   actCol.style.display = '';
    renderClientActivity();
  } else {
    if (workarea) workarea.classList.add('no-activity');
    if (actCol)   actCol.style.display = 'none';
  }

  const vulns   = state.customVulns || [];
  const targets = state.targets.filter(t => t.scope === 'in');

  const wstgTotal = WSTG_DATA.reduce((s, c) => s + c.tests.length, 0);
  const wstgDone  = Object.values(state.wstgProgress || {}).filter(v => v.status === 'done').length;
  const wstgFail  = Object.values(state.wstgProgress || {}).filter(v => v.status === 'fail').length;
  const wstgPct   = wstgTotal ? Math.round((wstgDone + wstgFail) / wstgTotal * 100) : 0;

  const sections = [
    proj.show_findings      ? buildFindingsSection(vulns)                              : '',
    proj.show_wstg_progress ? buildWSTGSection(wstgPct, wstgDone, wstgFail, wstgTotal) : '',
    proj.show_targets       ? buildTargetsSection(targets)                             : '',
    proj.tickets_enabled    ? buildTicketsSection(state.tickets || [])                 : '',
  ].filter(Boolean).join('');

  // Date range display
  const dateRange = (() => {
    const fmt = d => d ? new Date(d).toLocaleDateString('en', { year:'numeric', month:'short', day:'numeric' }) : null;
    const s = fmt(proj.date_start), e = fmt(proj.date_end);
    if (s && e) return `${s} → ${e}`;
    if (s) return `Started ${s}`;
    return new Date(proj.created_at).toLocaleDateString('en', { year:'numeric', month:'short' });
  })();

  main.innerHTML = `
    <div class="page-header">
      <div style="flex:1;min-width:0">
        <div class="page-title">${esc(proj.name)}</div>
        <div class="page-subtitle">${dateRange}</div>
      </div>
      ${proj.logo_url ? `
        <div style="background:${proj.logo_bg==='dark'?'#1a1a1a':'#fff'};border:1px solid var(--b1);border-radius:var(--r);padding:6px 12px;display:flex;align-items:center;flex-shrink:0">
          <img src="${esc(proj.logo_url)}" style="height:32px;max-width:110px;object-fit:contain" alt="">
        </div>` : ''}
    </div>

    ${buildStatsRow(proj, vulns, targets, wstgPct)}

    <div style="display:flex;flex-direction:column;gap:12px">
      ${sections || `<div class="members-card" style="text-align:center;padding:40px">
        <div style="font-family:var(--mono);font-size:12px;color:var(--t3)">No sections enabled by the project team yet.</div>
      </div>`}
    </div>`;
}

// ── STAT ROW ─────────────────────────────────────────────────────────
function buildStatsRow(proj, vulns, targets, wstgPct) {
  const cells = [];
  const push = (label, val, sub, barClass) => cells.push({ label, val, sub, barClass });

  if (proj.show_findings) {
    const crit = vulns.filter(v => v.severity === 'critical').length;
    const high = vulns.filter(v => v.severity === 'high').length;
    push('Findings', vulns.length,
      crit ? `<span class="stat-crit">${crit} critical</span>` : high ? `<span style="color:#f97316">${high} high</span>` : 'no critical',
      crit ? 'crit' : high ? 'high' : '');
  }
  if (proj.show_wstg_progress) {
    push('Coverage', `${wstgPct}%`,
      `OWASP WSTG`, wstgPct >= 70 ? 'low' : '');
  }
  if (proj.show_targets) {
    push('In Scope', targets.length, 'targets', '');
  }
  if (proj.tickets_enabled) {
    const open = (state.tickets || []).filter(t => t.status === 'open').length;
    push('Queries', open, open ? 'awaiting response' : 'all resolved', open ? '' : 'low');
  }

  if (!cells.length) return '';

  return `<div class="stat-row" style="margin-bottom:16px;grid-template-columns:repeat(${cells.length},1fr)">
    ${cells.map(c => `
      <div class="stat-cell">
        <div class="stat-label">${c.label}</div>
        <div class="stat-val">${c.val}</div>
        <div class="stat-sub">${c.sub}</div>
        ${c.barClass ? `<div class="stat-bar"><div class="stat-bar-fill ${c.barClass}" style="width:100%"></div></div>` : ''}
      </div>`).join('')}
  </div>`;
}

// ── FINDINGS ──────────────────────────────────────────────────────────
function buildFindingsSection(vulns) {
  const sorted = [...vulns].sort((a,b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));

  const cards = sorted.map(v => {
    const target     = state.targets.find(t => t.id === v.target_id);
    const color      = SEV_COLORS[v.severity] || 'var(--t3)';
    const isDone     = v.status === 'done';
    const isFail     = v.status === 'fail';
    const statusColor = isDone ? 'var(--c-low)' : isFail ? 'var(--c-crit)' : 'var(--t3)';
    const statusText  = isDone ? '✓ resolved' : isFail ? '⚠ open' : '— pending';

    return `
      <div class="client-finding-card" onclick="toggleClientFinding('${v.id}')" style="border-left:2px solid ${color}">
        <div class="client-finding-header">
          <span class="sev-badge sev-${v.severity||'medium'}">${SEV_LABELS[v.severity]||v.severity}</span>
          ${v.cvss_score != null ? `<span style="font-family:var(--mono);font-size:10px;font-weight:700;color:${color};flex-shrink:0">${(+v.cvss_score).toFixed(1)}</span>` : ''}
          <span class="client-finding-name">${esc(v.name)}</span>
          ${target ? `<span class="client-finding-target">${esc(target.host)}</span>` : ''}
          <span style="font-family:var(--mono);font-size:10px;color:${statusColor};margin-left:auto;flex-shrink:0">${statusText}</span>
          <span class="client-finding-chevron" id="chev-${v.id}">▸</span>
        </div>
        <div class="client-finding-body" id="cfbody-${v.id}">
          <div style="height:1px;background:var(--b1);margin-bottom:12px"></div>
          ${v.description
            ? `<div class="client-finding-desc">${esc(v.description)}</div>`
            : `<div class="client-finding-desc" style="color:var(--t3);font-style:italic">Description not yet written.</div>`}
          ${v.remediation ? `
            <div style="margin-top:12px;padding:10px 12px;background:rgba(5,150,105,.06);border:1px solid rgba(5,150,105,.18);border-radius:var(--r)">
              <div style="font-family:var(--mono);font-size:9px;text-transform:uppercase;color:var(--c-low);margin-bottom:5px;letter-spacing:.08em">Remediation</div>
              <div class="client-finding-desc">${esc(v.remediation)}</div>
            </div>` : ''}
          ${v.category ? `<div style="margin-top:10px;font-family:var(--mono);font-size:10px;color:var(--t3)">Category: ${esc(v.category)}</div>` : ''}
        </div>
      </div>`;
  }).join('');

  return `
    <div class="members-card">
      <div class="members-card-title">
        Findings
        ${vulns.length ? `<span style="font-family:var(--mono);font-size:11px;color:var(--t3);font-weight:400">${vulns.length} total</span>` : ''}
      </div>
      ${vulns.length ? cards : `
        <div style="text-align:center;padding:28px 0;color:var(--t3)">
          <div style="font-size:20px;margin-bottom:6px;color:var(--c-low)">✓</div>
          <div style="font-size:13px;font-weight:600;color:var(--t2);margin-bottom:2px">No findings reported yet</div>
          <div style="font-family:var(--mono);font-size:11px">The team is actively testing</div>
        </div>`}
    </div>`;
}

function toggleClientFinding(id) {
  const body  = document.getElementById(`cfbody-${id}`);
  const chev  = document.getElementById(`chev-${id}`);
  const open  = body?.classList.toggle('open');
  if (chev) chev.style.transform = open ? 'rotate(90deg)' : '';
}

// ── WSTG ──────────────────────────────────────────────────────────────
function buildWSTGSection(pct, done, fail, total) {
  const showNotes = state.currentProject?.show_wstg_notes;
  const prog      = state.wstgProgress || {};

  const categories = WSTG_DATA.map(cat => {
    const catDone = cat.tests.filter(t => prog[t.id]?.status === 'done').length;
    const catFail = cat.tests.filter(t => prog[t.id]?.status === 'fail').length;
    const catPct  = cat.tests.length ? Math.round((catDone + catFail) / cat.tests.length * 100) : 0;

    const notableTests = cat.tests.filter(t => {
      const p = prog[t.id];
      if (!p) return false;
      return p.status === 'done' || p.status === 'fail' || (showNotes && p.note);
    });

    const testRows = notableTests.map(t => {
      const p      = prog[t.id];
      const isDone = p.status === 'done';
      const isFail = p.status === 'fail';
      const color  = isDone ? 'var(--c-low)' : isFail ? 'var(--c-crit)' : 'var(--t3)';
      const icon   = isDone ? '✓' : isFail ? '⚠' : '○';
      return `
        <div class="wstg-client-test">
          <span style="font-family:var(--mono);font-size:11px;color:${color};flex-shrink:0;width:14px">${icon}</span>
          <div style="flex:1;min-width:0">
            <div style="font-size:12px;color:var(--t2)">${esc(t.name)}</div>
            ${showNotes && p.note ? `<div style="font-family:var(--mono);font-size:11px;color:var(--t3);margin-top:3px;white-space:pre-wrap">${esc(p.note)}</div>` : ''}
          </div>
        </div>`;
    }).join('');

    const barColor = catFail ? 'var(--c-crit)' : 'var(--a)';
    return `
      <div class="wstg-client-cat" onclick="this.classList.toggle('open')">
        <div class="wstg-client-cat-header">
          <span style="flex:1;font-size:12px;font-weight:600;color:var(--t1)">${esc(cat.name)}</span>
          ${catFail ? `<span style="font-family:var(--mono);font-size:10px;color:var(--c-crit)">⚠ ${catFail}</span>` : ''}
          <span style="font-family:var(--mono);font-size:10px;color:var(--t3)">${catDone+catFail}/${cat.tests.length}</span>
          <div style="width:60px;height:3px;background:var(--bg3);border-radius:2px;overflow:hidden;flex-shrink:0">
            <div style="height:100%;width:${catPct}%;background:${barColor};border-radius:2px"></div>
          </div>
          <span style="font-family:var(--mono);font-size:10px;color:var(--t3)">▸</span>
        </div>
        ${notableTests.length ? `<div class="wstg-client-tests">${testRows}</div>` : ''}
      </div>`;
  }).join('');

  return `
    <div class="members-card">
      <div class="members-card-title">
        OWASP WSTG Progress
        <span style="font-family:var(--mono);font-size:11px;font-weight:700;color:var(--a)">${pct}%</span>
      </div>
      <div style="height:3px;background:var(--bg3);border-radius:2px;overflow:hidden;margin-bottom:6px">
        <div style="height:100%;width:${pct}%;background:var(--a);border-radius:2px;transition:width .6s ease"></div>
      </div>
      <div style="font-family:var(--mono);font-size:10px;color:var(--t3);margin-bottom:14px">${done+fail} / ${total} tests covered · ${fail} with findings</div>
      <div style="display:flex;flex-direction:column;gap:2px">${categories}</div>
    </div>`;
}

// ── TARGETS ───────────────────────────────────────────────────────────
function buildTargetsSection(targets) {
  const STATUS_COL   = { active:'var(--a)', completed:'var(--c-low)', 'out-of-scope':'var(--t3)' };
  const STATUS_LABEL = { active:'active', completed:'done', 'out-of-scope':'oos' };

  const rows = targets.map(t => {
    const findingCount = (state.customVulns || []).filter(v => v.target_id === t.id).length;
    const critCount    = (state.customVulns || []).filter(v => v.target_id === t.id && v.severity === 'critical').length;
    const statusColor  = STATUS_COL[t.status] || 'var(--t3)';
    return `
      <div class="client-target-row">
        <span style="font-family:var(--mono);font-size:9px;color:var(--t3);text-transform:uppercase;flex-shrink:0;min-width:34px">${t.type}</span>
        <span style="font-family:var(--mono);font-size:11px;color:var(--t1);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(t.host)}</span>
        ${findingCount ? `<span style="font-family:var(--mono);font-size:10px;background:${critCount?'rgba(220,38,38,.1)':'var(--bg3)'};color:${critCount?'var(--c-crit)':'var(--t3)'};border:1px solid ${critCount?'rgba(220,38,38,.25)':'var(--b1)'};border-radius:var(--r-sm);padding:1px 6px;flex-shrink:0">${findingCount} finding${findingCount!==1?'s':''}</span>` : ''}
        <span style="font-family:var(--mono);font-size:9px;color:${statusColor};flex-shrink:0;text-transform:uppercase;letter-spacing:.04em">${STATUS_LABEL[t.status]||t.status}</span>
      </div>`;
  }).join('');

  return `
    <div class="members-card">
      <div class="members-card-title">
        Scope
        <span style="font-family:var(--mono);font-size:11px;color:var(--t3);font-weight:400">${targets.length} target${targets.length!==1?'s':''}</span>
      </div>
      ${targets.length ? rows : `<div style="font-family:var(--mono);font-size:11px;color:var(--t3)">No targets defined</div>`}
    </div>`;
}

// ── ACTIVITY SIDEBAR ─────────────────────────────────────────────────
function renderClientActivity() {
  const list   = document.getElementById('client-activity-list');
  const events = state.clientActivity || [];
  if (!list) return;

  if (!events.length) {
    list.innerHTML = '<div class="activity-empty">No activity yet</div>';
    return;
  }

  list.innerHTML = events.slice(0, 50).map(e => {
    const member = (state.members || []).find(m => m.username === e.username);
    const color  = member ? roleColor(member.role) : roleColor('editor');
    const label  = actionLabel(e.action, e.entity_type, e.entity_name, e.meta);
    return `
      <div class="activity-item">
        ${avatarHtml(e.username, color, 24, member?.avatar_url || null)}
        <div class="activity-content">
          <div class="activity-text"><strong>${esc(e.username || '?')}</strong> ${label}</div>
          <div class="activity-time">${timeAgo(e.created_at)}</div>
        </div>
      </div>`;
  }).join('');
}

// ── TICKETS ───────────────────────────────────────────────────────────
function buildTicketsSection(tickets) {
  const STATUS_COL   = { open:'var(--a)', in_review:'#f59e0b', closed:'var(--c-low)' };
  const STATUS_LABEL = { open:'open', in_review:'in review', closed:'closed' };

  const rows = tickets.map(t => {
    const author = t.opened_by_username || t.client_name || 'Client';
    return `
    <div class="client-ticket-row" onclick="openTicketDetail('${t.id}')">
      <div style="width:5px;height:5px;border-radius:50%;background:${STATUS_COL[t.status]||'var(--t3)'};flex-shrink:0;margin-top:4px"></div>
      <div style="flex:1;min-width:0">
        <div style="font-size:12px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--t1)">${esc(t.title)}</div>
        <div style="font-family:var(--mono);font-size:10px;color:var(--t3);margin-top:2px">${esc(author)}${t.vuln_name ? ` · re: ${esc(t.vuln_name)}` : ''}</div>
      </div>
      <div style="display:flex;flex-direction:column;align-items:flex-end;gap:2px;flex-shrink:0">
        <span style="font-family:var(--mono);font-size:9px;color:${STATUS_COL[t.status]||'var(--t3)'};text-transform:uppercase;letter-spacing:.04em">${STATUS_LABEL[t.status]||t.status}</span>
        <span style="font-family:var(--mono);font-size:10px;color:var(--t3)">${t.reply_count} repl${t.reply_count===1?'y':'ies'}</span>
      </div>
    </div>`;
  }).join('');

  return `
    <div class="members-card">
      <div class="members-card-title">
        Queries
        ${tickets.length ? `<span style="font-family:var(--mono);font-size:11px;color:var(--t3);font-weight:400">${tickets.length} total</span>` : ''}
        <button class="btn btn-ghost" style="font-size:11px;padding:4px 10px;margin-left:auto" onclick="openNewTicketModal()">+ New</button>
      </div>
      ${tickets.length ? rows : `
        <div style="text-align:center;padding:24px 0;border:1px dashed var(--b2);border-radius:var(--r);color:var(--t3)">
          <div style="font-family:var(--mono);font-size:11px;margin-bottom:10px">No queries yet</div>
          <button class="btn btn-prim" style="font-size:11px;padding:5px 14px" onclick="openNewTicketModal()">Open a query</button>
        </div>`}
    </div>`;
}

// ── TICKET MODALS ─────────────────────────────────────────────────────
function openNewTicketModal() {
  document.getElementById('ct-title').value = '';
  document.getElementById('ct-desc').value  = '';
  document.getElementById('ct-vuln').innerHTML =
    `<option value="">— Not linked to a specific finding —</option>` +
    (state.customVulns||[]).map(v => `<option value="${v.id}">[${v.severity}] ${esc(v.name)}</option>`).join('');
  if (window.reinitCsel) window.reinitCsel('ct-vuln');
  document.getElementById('ct-error').style.display = 'none';
  document.getElementById('client-ticket-modal').classList.add('open');
}

function closeTicketModal() {
  document.getElementById('client-ticket-modal').classList.remove('open');
}

async function submitTicket() {
  const title   = document.getElementById('ct-title').value.trim();
  const desc    = document.getElementById('ct-desc').value.trim();
  const vuln_id = document.getElementById('ct-vuln').value || null;
  const errEl   = document.getElementById('ct-error');
  const btn     = document.getElementById('ct-save-btn');
  if (!title) { errEl.textContent = 'Title is required'; errEl.style.display = 'block'; return; }
  btn.disabled = true;
  try {
    const payload = { title, description: desc, vuln_id };
    // Portal sessions attach identity from sessionStorage
    const isPortal = api.portal.session.has();
    if (isPortal) {
      if (api.portal.session.name)  payload.client_name  = api.portal.session.name;
      if (api.portal.session.email) payload.client_email = api.portal.session.email;
    }
    const ticket = await api.tickets.create(state.currentProject.id, payload);
    state.tickets = [ticket, ...(state.tickets||[])];
    closeTicketModal();
    renderClientDashboard();
    showToast('✓ Query submitted', 'success');
  } catch(e) { errEl.textContent = e.message; errEl.style.display = 'block'; }
  finally { btn.disabled = false; }
}

async function openTicketDetail(ticketId) {
  try {
    const ticket = await api.tickets.get(state.currentProject.id, ticketId);
    const STATUS_COL   = { open:'var(--a)', in_review:'#f59e0b', closed:'var(--c-low)' };
    const STATUS_LABEL = { open:'Open', in_review:'In Review', closed:'Closed' };

    // Portal session name for "is this mine" detection
    const myPortalName = api.portal.session.name || null;
    const replies = (ticket.replies||[]).map(r => {
      // A reply is "mine" if it came from this portal session (matched by name) or same user id
      const displayName = r.author_username || r.client_name || 'Client';
      const isTeam  = !!r.author_id;
      const isMe    = !isTeam && (myPortalName ? displayName === myPortalName : true);
      const color   = isTeam ? roleColor('editor') : roleColor('viewer');
      return `
        <div style="display:flex;gap:8px;${isMe?'flex-direction:row-reverse':''}">
          ${avatarHtml(displayName, color, 24, null)}
          <div style="max-width:80%;display:flex;flex-direction:column;gap:2px;${isMe?'align-items:flex-end':''}">
            <div style="font-family:var(--mono);font-size:10px;color:var(--t3)">${esc(displayName)}${isTeam ? ' <span style="color:var(--a)">· team</span>' : ''} · ${relativeDate(r.created_at)}</div>
            <div style="background:${isTeam?'var(--a-dim)':isMe?'var(--bg3)':'var(--bg2)'};border:1px solid ${isTeam?'rgba(245,158,11,.2)':'var(--b1)'};border-radius:8px;padding:8px 12px;font-size:12px;line-height:1.6;white-space:pre-wrap">${esc(r.body)}</div>
          </div>
        </div>`;
    }).join('');

    document.getElementById('ctd-content').innerHTML = `
      <div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:16px;padding-bottom:16px;border-bottom:1px solid var(--b1)">
        <div style="flex:1">
          <h3 style="margin:0 0 4px;font-size:16px">${esc(ticket.title)}</h3>
          ${ticket.vuln_name ? `<div style="font-family:var(--mono);font-size:11px;color:var(--t3)">re: ${esc(ticket.vuln_name)}</div>` : ''}
        </div>
        <span style="font-family:var(--mono);font-size:10px;color:${STATUS_COL[ticket.status]};background:${STATUS_COL[ticket.status]}18;border:1px solid ${STATUS_COL[ticket.status]}44;border-radius:4px;padding:3px 8px;flex-shrink:0">${STATUS_LABEL[ticket.status]||ticket.status}</span>
      </div>
      ${ticket.description ? `<div style="color:var(--t2);font-size:13px;margin-bottom:16px;line-height:1.6">${esc(ticket.description)}</div>` : ''}
      <div style="display:flex;flex-direction:column;gap:10px;margin-bottom:16px;max-height:280px;overflow-y:auto">
        ${replies || `<div style="font-family:var(--mono);font-size:11px;color:var(--t3);padding:8px 0;text-align:center">No replies yet — the team will respond soon.</div>`}
      </div>
      ${ticket.status !== 'closed' ? `
        <div style="border-top:1px solid var(--b1);padding-top:12px;display:flex;gap:8px">
          <textarea class="form-input note-textarea" id="ctd-reply" placeholder="Write a reply..." style="flex:1;min-height:56px;resize:none" onkeydown="if(event.key==='Enter'&&(event.ctrlKey||event.metaKey))submitReply('${ticket.id}')"></textarea>
          <button class="btn btn-prim" style="align-self:flex-end;padding:8px 16px" onclick="submitReply('${ticket.id}')">Send</button>
        </div>` : `<div style="font-family:var(--mono);font-size:11px;color:var(--t3);text-align:center;padding:8px 0;border-top:1px solid var(--b1)">This query is closed</div>`}`;

    document.getElementById('client-ticket-detail').classList.add('open');
  } catch(err) { showToast(err.message, 'error'); }
}

function closeTicketDetail() {
  document.getElementById('client-ticket-detail').classList.remove('open');
}

async function submitReply(ticketId) {
  const body = document.getElementById('ctd-reply')?.value.trim();
  if (!body) return;
  try {
    const extra = {};
    if (api.portal.session.has() && api.portal.session.name) extra.client_name = api.portal.session.name;
    await api.tickets.reply(state.currentProject.id, ticketId, body, extra);
    showToast('✓ Reply sent', 'success');
    closeTicketDetail();
    await openTicketDetail(ticketId);
  } catch(err) { showToast(err.message, 'error'); }
}

// ── JOIN PROJECT ──────────────────────────────────────────────────────
async function clientJoinProject() {
  const input = document.getElementById('client-join-input');
  const errEl = document.getElementById('client-join-error');
  const code  = (input?.value || '').trim().toUpperCase();
  if (!code) return;
  errEl.style.display = 'none';
  try {
    await api.projects.join(code);
    show('loading-overlay');
    await bootClient();
  } catch(e) {
    errEl.textContent = e.message;
    errEl.style.display = 'block';
  }
}

// ── AUTH ──────────────────────────────────────────────────────────────
async function doClientLogout() {
  wsClient.disconnect();
  if (api.portal.session.has()) {
    api.portal.session.clear();
  } else {
    await api.auth.logout().catch(() => {});
    localStorage.removeItem('fd_project');
  }
  window.location.href = 'client-login.html';
}

// ── WEBSOCKET ─────────────────────────────────────────────────────────
wsClient.on('connected',    () => { const d = document.getElementById('client-live'); if(d){ d.style.background='var(--c-low)'; d.title='Live'; }});
wsClient.on('disconnected', () => { const d = document.getElementById('client-live'); if(d){ d.style.background='var(--c-crit)'; d.title='Reconnecting...'; }});
wsClient.on('activity', async () => {
  if (!state.currentProject?.id) return;
  state.clientActivity = await api.activity.list(state.currentProject.id).catch(() => []);
  renderClientActivity();
});

// ── EXPORTS ───────────────────────────────────────────────────────────
window.clientJoinProject   = clientJoinProject;
window.switchClientProject = switchClientProject;
window.toggleClientFinding = toggleClientFinding;
window.openNewTicketModal  = openNewTicketModal;
window.closeTicketModal    = closeTicketModal;
window.submitTicket        = submitTicket;
window.openTicketDetail    = openTicketDetail;
window.closeTicketDetail   = closeTicketDetail;
window.submitReply         = submitReply;
window.doClientLogout      = doClientLogout;

bootClient();
