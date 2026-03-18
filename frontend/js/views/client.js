// ── views/client.js — Client portal (read-only) ──────────────────────

const SEV_ORDER  = ['critical','high','medium','low','info'];
const SEV_COLORS = { critical:'#dc2626', high:'#f97316', medium:'#f59e0b', low:'#059669', info:'#64748b' };
const SEV_LABELS = { critical:'Critical', high:'High', medium:'Medium', low:'Low', info:'Info' };

// ── BOOT ─────────────────────────────────────────────────────────────
async function bootClient() {
  if (!api.auth.hasSession()) { window.location.href = 'index.html'; return; }
  try {
    state.user = await api.auth.me();
  } catch {
    api.auth.clearTokens();
    window.location.href = 'index.html';
    return;
  }

  const allProjects  = await api.projects.list().catch(() => []);
  state.projects     = allProjects.filter(p => p.member_role === 'viewer');
  state.hasOwnProjects = allProjects.some(p => p.member_role !== 'viewer');

  if (!state.projects.length) {
    hide('loading-overlay');
    document.getElementById('client-main').innerHTML = `
      <div style="max-width:400px;margin:80px auto;text-align:center">
        <div style="font-size:48px;margin-bottom:20px">🔒</div>
        <div style="font-size:20px;font-weight:800;margin-bottom:8px">No projects yet</div>
        <div style="font-family:var(--mono);font-size:12px;color:var(--text3);margin-bottom:28px;line-height:1.6">
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
  const u    = state.user;
  const proj = state.currentProject;
  const el   = document.getElementById('client-topbar');
  if (!el) return;

  const projOptions = state.projects.map(p =>
    `<option value="${p.id}" ${p.id===proj?.id?'selected':''}>${esc(p.name)}</option>`
  ).join('');

  const avatarColor = roleColor('viewer');

  el.innerHTML = `
    <div style="display:flex;align-items:center;gap:12px;flex:1;min-width:0;overflow:hidden">
      <div style="display:flex;align-items:center;gap:8px;flex-shrink:0">
        <img src="img/flowdit-logo.png" style="height:22px;width:auto" alt="Flowdit">
        <span style="font-family:var(--mono);font-size:13px;font-weight:700;color:var(--text)">Flowdit</span>
        <span style="font-family:var(--mono);font-size:10px;color:var(--accent2);border:1px solid var(--accent)44;border-radius:3px;padding:2px 6px">client</span>
      </div>
      <div style="width:1px;height:18px;background:var(--border);flex-shrink:0"></div>
      ${state.projects.length > 1 ? `
        <select onchange="switchClientProject(this.value)"
          style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:5px 10px;color:var(--text);font-family:var(--mono);font-size:12px;outline:none;cursor:pointer;max-width:220px">
          ${projOptions}
        </select>` : proj ? `<span style="font-family:var(--mono);font-size:12px;color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(proj.name)}</span>` : ''}
    </div>
    <div style="display:flex;align-items:center;gap:10px;flex-shrink:0">
      <div style="display:flex;align-items:center;gap:7px">
        ${avatarHtml(u.username, avatarColor, 26, u.avatar_url)}
        <span style="font-size:13px;color:var(--text2)">${esc(u.username)}</span>
      </div>
      <div style="width:1px;height:18px;background:var(--border)"></div>
      <div style="display:flex;align-items:center;gap:5px">
        <div id="client-live" class="live-badge" title="Connecting..."></div>
        <span style="font-family:var(--mono);font-size:9px;color:var(--text3)">live</span>
      </div>
      <div style="width:1px;height:18px;background:var(--border)"></div>
      <a href="projects.html" class="btn-secondary" style="font-size:11px;padding:4px 10px;text-decoration:none">← Projects</a>
      <button class="btn-secondary" style="font-size:11px;padding:4px 10px" onclick="doClientLogout()">Logout</button>
    </div>`;
}

// ── MAIN DASHBOARD ────────────────────────────────────────────────────
function renderClientDashboard() {
  const proj = state.currentProject;
  if (!proj) return;
  const main = document.getElementById('client-main');
  if (!main) return;

  if (!proj.client_view_enabled) {
    main.innerHTML = `
      <div style="max-width:440px;margin:80px auto;text-align:center">
        <div style="font-size:40px;margin-bottom:16px">🔒</div>
        <div style="font-size:18px;font-weight:800;margin-bottom:8px">Portal not yet available</div>
        <div style="font-family:var(--mono);font-size:12px;color:var(--text3);line-height:1.6">
          The project team hasn't opened the client portal yet.<br>You'll be notified when it's ready.
        </div>
      </div>`;
    return;
  }

  const vulns   = state.customVulns || [];
  const targets = state.targets.filter(t => t.scope === 'in');

  const wstgTotal = WSTG_DATA.reduce((s, c) => s + c.tests.length, 0);
  const wstgDone  = Object.values(state.wstgProgress || {}).filter(v => v.status === 'done').length;
  const wstgFail  = Object.values(state.wstgProgress || {}).filter(v => v.status === 'fail').length;
  const wstgPct   = wstgTotal ? Math.round((wstgDone + wstgFail) / wstgTotal * 100) : 0;

  const counts = SEV_ORDER.reduce((acc, s) => { acc[s] = 0; return acc; }, {});
  vulns.forEach(v => { if (counts[v.severity] !== undefined) counts[v.severity]++; });

  const mainCol = `
    ${proj.show_findings      ? buildFindingsSection(vulns)                             : ''}
    ${proj.show_wstg_progress ? buildWSTGSection(wstgPct, wstgDone, wstgFail, wstgTotal) : ''}
    ${proj.tickets_enabled    ? buildTicketsSection(state.tickets || [])                : ''}`;

  const sideCol = `
    ${proj.show_targets  ? buildTargetsSection(targets)                     : ''}
    ${proj.show_activity ? buildActivitySection(state.clientActivity || []) : ''}`;

  main.innerHTML = `
    ${buildHero(proj, vulns, targets, wstgPct)}
    ${proj.show_findings ? buildSeverityBar(counts, vulns.length) : ''}
    <div class="client-grid">
      <div class="client-col-main">${mainCol || '<div style="padding:40px 0;text-align:center;font-family:var(--mono);font-size:12px;color:var(--text3)">No sections enabled by the project team yet.</div>'}</div>
      ${sideCol.trim() ? `<div class="client-col-side">${sideCol}</div>` : ''}
    </div>`;
}

// ── HERO ──────────────────────────────────────────────────────────────
function buildHero(proj, vulns, targets, wstgPct) {
  const STATUS_COLORS = { active:'#059669', completed:'#2563eb', archived:'var(--text3)' };
  const STATUS_BG     = { active:'#05966918', completed:'#2563eb18', archived:'var(--bg3)' };
  const statusColor = STATUS_COLORS[proj.status] || 'var(--text3)';
  const statusBg    = STATUS_BG[proj.status]    || 'var(--bg3)';

  const critCount   = vulns.filter(v => v.severity === 'critical').length;
  const highCount   = vulns.filter(v => v.severity === 'high').length;
  const medCount    = vulns.filter(v => v.severity === 'medium').length;
  const lowCount    = vulns.filter(v => v.severity === 'low').length;
  const openTickets = (state.tickets || []).filter(t => t.status === 'open').length;

  const stats = [
    { label: 'Total',    value: vulns.length,   color: 'var(--text)',  dim: !vulns.length },
    { label: 'Critical', value: critCount,       color: '#dc2626',      dim: !critCount },
    { label: 'High',     value: highCount,       color: '#f97316',      dim: !highCount },
    { label: 'Medium',   value: medCount,        color: '#f59e0b',      dim: !medCount },
    { label: 'Low',      value: lowCount,        color: '#059669',      dim: !lowCount },
    { label: 'In Scope', value: targets.length,  color: 'var(--accent2)', dim: !targets.length },
  ];
  if (proj.tickets_enabled) {
    stats.push({ label: 'Queries', value: openTickets, color: 'var(--accent2)', dim: !openTickets });
  }

  const statsHtml = stats.map((s, i) => `
    <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:3px;padding:14px 8px;${i < stats.length-1 ? 'border-right:1px solid var(--border)' : ''}">
      <span style="font-size:22px;font-weight:800;color:${s.dim ? 'var(--text3)' : s.color};font-family:var(--mono);line-height:1">${s.value}</span>
      <span style="font-family:var(--mono);font-size:9px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;white-space:nowrap">${s.label}</span>
    </div>`).join('');

  const progressBar = proj.show_wstg_progress ? `
    <div style="margin-top:12px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:5px">
        <span style="font-family:var(--mono);font-size:10px;color:var(--text3)">Testing progress</span>
        <span style="font-family:var(--mono);font-size:11px;font-weight:700;color:var(--text)">${wstgPct}%</span>
      </div>
      <div style="height:5px;background:var(--bg3);border-radius:3px;overflow:hidden">
        <div style="height:100%;width:${wstgPct}%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:3px;transition:width .6s ease"></div>
      </div>
    </div>` : '';

  const _logoBg  = proj.logo_bg === 'dark' ? '#1e1e1e' : '#ffffff';
  const _logoBd  = proj.logo_bg === 'dark' ? 'rgba(255,255,255,.08)' : 'rgba(0,0,0,.09)';
  const logoHtml = proj.logo_url ? `
    <div style="position:absolute;top:16px;right:18px;z-index:1;background:${_logoBg};border:1px solid ${_logoBd};border-radius:8px;padding:6px 12px;display:flex;align-items:center">
      <img src="${proj.logo_url}" style="height:40px;max-width:140px;object-fit:contain" alt="Project logo">
    </div>` : '';

  return `
    <div style="background:var(--surface);border:1px solid var(--border2);border-radius:var(--radius-lg);padding:22px 24px;margin-bottom:20px;position:relative;overflow:hidden">
      <div style="position:absolute;inset:0;background:linear-gradient(135deg,var(--accent)06 0%,transparent 55%);pointer-events:none"></div>
      <div style="position:absolute;left:0;top:0;bottom:0;width:3px;background:linear-gradient(180deg,var(--accent),var(--accent2));border-radius:3px 0 0 3px"></div>
      ${logoHtml}
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px;${proj.logo_url ? 'padding-right:170px' : ''}">
        <h1 style="font-size:20px;font-weight:800;margin:0;line-height:1.2">${esc(proj.name)}</h1>
        <span style="font-family:var(--mono);font-size:9px;color:${statusColor};background:${statusBg};border:1px solid ${statusColor}44;border-radius:3px;padding:2px 7px;flex-shrink:0;text-transform:uppercase">${proj.status}</span>
      </div>
      ${proj.description ? `<p style="margin:0 0 3px;color:var(--text3);font-size:13px;line-height:1.5;${proj.logo_url ? 'padding-right:170px' : ''}">${esc(proj.description)}</p>` : ''}
      <div style="font-family:var(--mono);font-size:10px;color:var(--text3)">Started ${new Date(proj.created_at).toLocaleDateString('en', {year:'numeric',month:'short',day:'numeric'})}</div>
      ${progressBar}
      <div style="display:flex;align-items:stretch;margin-top:18px;border:1px solid var(--border);border-radius:8px;overflow:hidden;background:var(--bg2)">
        ${statsHtml}
      </div>
    </div>`;
}

// ── SEVERITY BAR ──────────────────────────────────────────────────────
function buildSeverityBar(counts, total) {
  if (!total) return '';

  const barSegs = SEV_ORDER.map(s => {
    const pct = total ? Math.round(counts[s] / total * 100) : 0;
    if (!pct) return '';
    return `<div style="height:100%;width:${pct}%;background:${SEV_COLORS[s]};transition:width .4s ease" title="${SEV_LABELS[s]}: ${counts[s]}"></div>`;
  }).join('');

  const pills = SEV_ORDER.filter(s => counts[s] > 0).map(s => `
    <div style="display:flex;align-items:center;gap:5px">
      <div style="width:8px;height:8px;border-radius:50%;background:${SEV_COLORS[s]};flex-shrink:0"></div>
      <span style="font-family:var(--mono);font-size:11px;color:var(--text2)">${counts[s]} ${SEV_LABELS[s]}</span>
    </div>`).join('');

  return `
    <div style="background:var(--surface);border:1px solid var(--border2);border-radius:var(--radius-lg);padding:16px 20px;margin-bottom:20px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;flex-wrap:wrap;gap:8px">
        <span style="font-family:var(--mono);font-size:11px;font-weight:700;color:var(--text2)">FINDINGS OVERVIEW</span>
        <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap">${pills}</div>
      </div>
      <div style="height:8px;background:var(--bg3);border-radius:4px;overflow:hidden;display:flex">
        ${barSegs}
      </div>
    </div>`;
}

// ── FINDINGS ──────────────────────────────────────────────────────────
function buildFindingsSection(vulns) {
  if (!vulns.length) return `
    <div class="client-section">
      <div class="client-section-title">Findings</div>
      <div style="text-align:center;padding:32px 0">
        <div style="font-size:28px;margin-bottom:8px">✓</div>
        <div style="font-size:13px;font-weight:600;margin-bottom:4px">No findings reported yet</div>
        <div style="font-family:var(--mono);font-size:11px;color:var(--text3)">The team is actively testing</div>
      </div>
    </div>`;

  const sorted = [...vulns].sort((a,b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  const cards  = sorted.map(v => {
    const target  = state.targets.find(t => t.id === v.target_id);
    const color   = SEV_COLORS[v.severity] || 'var(--text3)';
    const isDone  = v.status === 'done';
    const statusColor = isDone ? '#059669' : v.status === 'fail' ? '#dc2626' : 'var(--text3)';

    return `
      <div class="client-finding-card" onclick="toggleClientFinding('${v.id}')" style="border-left:3px solid ${color}">
        <div class="client-finding-header">
          <span class="sev-badge sev-${v.severity||'medium'}">${SEV_LABELS[v.severity]||v.severity}</span>
          ${v.cvss_score != null ? `<span style="font-family:var(--mono);font-size:10px;font-weight:700;color:${SEV_COLORS[v.severity]||'var(--text3)'};opacity:.85;flex-shrink:0">${(+v.cvss_score).toFixed(1)}</span>` : ''}
          <span class="client-finding-name">${esc(v.name)}</span>
          ${target ? `<span class="client-finding-target">🎯 ${esc(target.host)}</span>` : ''}
          <span style="font-family:var(--mono);font-size:10px;color:${statusColor};margin-left:auto;flex-shrink:0">${isDone ? '✓ resolved' : v.status === 'fail' ? '⚠ open' : '— pending'}</span>
          <span class="client-finding-chevron" id="chev-${v.id}">▸</span>
        </div>
        <div class="client-finding-body" id="cfbody-${v.id}">
          <div style="height:1px;background:var(--border);margin-bottom:12px"></div>
          ${v.description
            ? `<div class="client-finding-desc">${esc(v.description)}</div>`
            : `<div class="client-finding-desc" style="color:var(--text3);font-style:italic">Description not yet written.</div>`}
          ${v.remediation ? `
            <div style="margin-top:12px;padding:10px 12px;background:#05966910;border:1px solid #05966930;border-radius:8px">
              <div style="font-family:var(--mono);font-size:9px;text-transform:uppercase;color:#059669;margin-bottom:5px;letter-spacing:.05em">Remediation</div>
              <div class="client-finding-desc">${esc(v.remediation)}</div>
            </div>` : ''}
          ${v.category ? `<div style="margin-top:10px;font-family:var(--mono);font-size:10px;color:var(--text3)">Category: ${esc(v.category)}</div>` : ''}
        </div>
      </div>`;
  }).join('');

  return `
    <div class="client-section">
      <div class="client-section-title">Findings <span class="client-badge">${vulns.length}</span></div>
      ${cards}
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
      const color  = isDone ? '#059669' : isFail ? '#dc2626' : 'var(--text3)';
      const icon   = isDone ? '✓' : isFail ? '⚠' : '○';
      return `
        <div class="wstg-client-test">
          <span style="font-family:var(--mono);font-size:11px;color:${color};flex-shrink:0;width:14px">${icon}</span>
          <div style="flex:1;min-width:0">
            <div style="font-size:12px;color:var(--text2)">${esc(t.name)}</div>
            ${showNotes && p.note ? `<div style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-top:3px;white-space:pre-wrap">${esc(p.note)}</div>` : ''}
          </div>
        </div>`;
    }).join('');

    const barColor = catFail ? '#dc2626' : 'var(--accent)';
    return `
      <div class="wstg-client-cat" onclick="this.classList.toggle('open')">
        <div class="wstg-client-cat-header">
          <span style="flex:1;font-size:12px;font-weight:600">${esc(cat.name)}</span>
          ${catFail ? `<span style="font-family:var(--mono);font-size:10px;color:#dc2626">⚠ ${catFail}</span>` : ''}
          <span style="font-family:var(--mono);font-size:10px;color:var(--text3)">${catDone+catFail}/${cat.tests.length}</span>
          <div style="width:60px;height:4px;background:var(--bg3);border-radius:2px;overflow:hidden;flex-shrink:0">
            <div style="height:100%;width:${catPct}%;background:${barColor};border-radius:2px"></div>
          </div>
          <span style="font-family:var(--mono);font-size:10px;color:var(--text3)">▸</span>
        </div>
        ${notableTests.length ? `<div class="wstg-client-tests">${testRows}</div>` : ''}
      </div>`;
  }).join('');

  return `
    <div class="client-section">
      <div class="client-section-title">
        OWASP WSTG Progress
        <span style="margin-left:auto;font-family:var(--mono);font-size:12px;font-weight:700;color:var(--text)">${pct}%</span>
      </div>
      <div style="height:6px;background:var(--bg3);border-radius:3px;overflow:hidden;margin-bottom:6px">
        <div style="height:100%;width:${pct}%;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:3px;transition:width .6s ease"></div>
      </div>
      <div style="font-family:var(--mono);font-size:10px;color:var(--text3);margin-bottom:14px">${done+fail} / ${total} tests covered · ${fail} with findings</div>
      <div style="display:flex;flex-direction:column;gap:2px">${categories}</div>
    </div>`;
}

// ── TARGETS ───────────────────────────────────────────────────────────
function buildTargetsSection(targets) {
  if (!targets.length) return `
    <div class="client-section">
      <div class="client-section-title">Scope</div>
      <div style="font-family:var(--mono);font-size:11px;color:var(--text3);padding:8px 0">No targets defined</div>
    </div>`;

  const STATUS_COL  = { active:'var(--accent)', completed:'#059669', 'out-of-scope':'var(--text3)' };
  const STATUS_LABEL= { active:'active', completed:'done', 'out-of-scope':'oos' };
  const TYPE_ICONS  = { domain:'🌐', ip:'🖥', cidr:'🔲', url:'🔗', other:'📌' };

  const rows = targets.map(t => {
    const findingCount = (state.customVulns || []).filter(v => v.target_id === t.id).length;
    const critCount    = (state.customVulns || []).filter(v => v.target_id === t.id && v.severity === 'critical').length;
    const statusColor  = STATUS_COL[t.status] || 'var(--text3)';
    return `
      <div class="client-target-row">
        <span style="font-size:13px;flex-shrink:0">${TYPE_ICONS[t.type]||'📌'}</span>
        <span style="font-family:var(--mono);font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(t.host)}</span>
        ${findingCount ? `<span style="font-family:var(--mono);font-size:10px;background:${critCount?'#dc262618':'var(--bg3)'};color:${critCount?'#dc2626':'var(--text3)'};border:1px solid ${critCount?'#dc262630':'var(--border)'};border-radius:4px;padding:1px 6px;flex-shrink:0">${findingCount}</span>` : ''}
        <span style="font-family:var(--mono);font-size:9px;color:${statusColor};flex-shrink:0;text-transform:uppercase">${STATUS_LABEL[t.status]||t.status}</span>
      </div>`;
  }).join('');

  return `
    <div class="client-section">
      <div class="client-section-title">Scope <span class="client-badge">${targets.length}</span></div>
      ${rows}
    </div>`;
}

// ── ACTIVITY ──────────────────────────────────────────────────────────
function buildActivitySection(events) {
  const rows = events.slice(0, 30).map(e => {
    const member = (state.members || []).find(m => m.username === e.username);
    const color  = member ? roleColor(member.role) : roleColor('editor');
    const label  = actionLabel(e.action, e.entity_type, e.entity_name, e.meta).replace(/<[^>]+>/g, '');
    return `
      <div style="display:flex;align-items:flex-start;gap:8px;padding:7px 0;border-bottom:1px solid var(--border)">
        ${avatarHtml(e.username, color, 22, null)}
        <div style="flex:1;min-width:0">
          <span style="font-size:12px;font-weight:600">${esc(e.username || '?')}</span>
          <span style="font-size:12px;color:var(--text3)"> · ${esc(label)}</span>
          <div style="font-family:var(--mono);font-size:10px;color:var(--text3);margin-top:1px">${relativeDate(e.created_at)}</div>
        </div>
      </div>`;
  }).join('');

  return `
    <div class="client-section">
      <div class="client-section-title">
        Activity
        <div style="display:flex;align-items:center;gap:5px;margin-left:auto">
          <div class="live-badge" style="width:6px;height:6px"></div>
          <span style="font-family:var(--mono);font-size:9px;color:var(--text3)">live</span>
        </div>
      </div>
      <div style="max-height:380px;overflow-y:auto;margin:0 -2px;padding:0 2px">
        ${events.length ? rows : '<div style="font-family:var(--mono);font-size:11px;color:var(--text3);padding:8px 0">No activity yet</div>'}
      </div>
    </div>`;
}

// ── TICKETS ───────────────────────────────────────────────────────────
function buildTicketsSection(tickets) {
  const STATUS_COL   = { open:'var(--accent)', in_review:'#f59e0b', closed:'#059669' };
  const STATUS_LABEL = { open:'open', in_review:'in review', closed:'closed' };
  const openBtn = `<button class="btn-accent" style="font-size:11px;padding:4px 12px;margin-left:auto" onclick="openNewTicketModal()">+ New Query</button>`;

  const rows = tickets.map(t => `
    <div style="display:flex;align-items:center;gap:10px;padding:10px;border:1px solid var(--border);border-radius:8px;cursor:pointer;transition:background .15s;margin-bottom:6px" onclick="openTicketDetail('${t.id}')" onmouseenter="this.style.background='var(--bg3)'" onmouseleave="this.style.background=''">
      <div style="width:6px;height:6px;border-radius:50%;background:${STATUS_COL[t.status]||'var(--text3)'};flex-shrink:0"></div>
      <div style="flex:1;min-width:0">
        <div style="font-size:12px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(t.title)}</div>
        ${t.vuln_name ? `<div style="font-family:var(--mono);font-size:10px;color:var(--text3);margin-top:2px">re: ${esc(t.vuln_name)}</div>` : ''}
      </div>
      <div style="display:flex;flex-direction:column;align-items:flex-end;gap:2px;flex-shrink:0">
        <span style="font-family:var(--mono);font-size:9px;color:${STATUS_COL[t.status]};text-transform:uppercase">${STATUS_LABEL[t.status]||t.status}</span>
        <span style="font-family:var(--mono);font-size:10px;color:var(--text3)">${t.reply_count} repl${t.reply_count===1?'y':'ies'}</span>
      </div>
    </div>`).join('');

  return `
    <div class="client-section">
      <div class="client-section-title" style="display:flex;align-items:center">
        Queries ${tickets.length ? `<span class="client-badge">${tickets.length}</span>` : ''}
        ${openBtn}
      </div>
      ${tickets.length
        ? rows
        : `<div style="text-align:center;padding:24px 0;border:1px dashed var(--border);border-radius:10px;margin-top:4px">
            <div style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-bottom:10px">No queries yet</div>
            <button class="btn-accent" style="font-size:11px;padding:5px 14px" onclick="openNewTicketModal()">Open a query</button>
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
    const ticket = await api.tickets.create(state.currentProject.id, { title, description: desc, vuln_id });
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
    const STATUS_COL   = { open:'var(--accent)', in_review:'#f59e0b', closed:'#059669' };
    const STATUS_LABEL = { open:'Open', in_review:'In Review', closed:'Closed' };

    const replies = (ticket.replies||[]).map(r => {
      const isMe  = r.author_id === state.user?.id;
      const color = isMe ? roleColor('viewer') : roleColor('editor');
      return `
        <div style="display:flex;gap:8px;${isMe?'flex-direction:row-reverse':''}">
          ${avatarHtml(r.author_username, color, 24, null)}
          <div style="max-width:80%;display:flex;flex-direction:column;gap:2px;${isMe?'align-items:flex-end':''}">
            <div style="font-family:var(--mono);font-size:10px;color:var(--text3)">${esc(r.author_username)} · ${relativeDate(r.created_at)}</div>
            <div style="background:${isMe?'#2563eb18':'var(--bg3)'};border:1px solid ${isMe?'#2563eb33':'var(--border)'};border-radius:8px;padding:8px 12px;font-size:12px;line-height:1.6;white-space:pre-wrap">${esc(r.body)}</div>
          </div>
        </div>`;
    }).join('');

    document.getElementById('ctd-content').innerHTML = `
      <div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:16px;padding-bottom:16px;border-bottom:1px solid var(--border)">
        <div style="flex:1">
          <h3 style="margin:0 0 4px;font-size:16px">${esc(ticket.title)}</h3>
          ${ticket.vuln_name ? `<div style="font-family:var(--mono);font-size:11px;color:var(--text3)">re: ${esc(ticket.vuln_name)}</div>` : ''}
        </div>
        <span style="font-family:var(--mono);font-size:10px;color:${STATUS_COL[ticket.status]};background:${STATUS_COL[ticket.status]}18;border:1px solid ${STATUS_COL[ticket.status]}44;border-radius:4px;padding:3px 8px;flex-shrink:0">${STATUS_LABEL[ticket.status]||ticket.status}</span>
      </div>
      ${ticket.description ? `<div style="color:var(--text2);font-size:13px;margin-bottom:16px;line-height:1.6">${esc(ticket.description)}</div>` : ''}
      <div style="display:flex;flex-direction:column;gap:10px;margin-bottom:16px;max-height:280px;overflow-y:auto">
        ${replies || `<div style="font-family:var(--mono);font-size:11px;color:var(--text3);padding:8px 0;text-align:center">No replies yet — the team will respond soon.</div>`}
      </div>
      ${ticket.status !== 'closed' ? `
        <div style="border-top:1px solid var(--border);padding-top:12px;display:flex;gap:8px">
          <textarea class="form-input note-textarea" id="ctd-reply" placeholder="Write a reply..." style="flex:1;min-height:56px;resize:none" onkeydown="if(event.key==='Enter'&&(event.ctrlKey||event.metaKey))submitReply('${ticket.id}')"></textarea>
          <button class="btn-save" style="align-self:flex-end;padding:8px 16px" onclick="submitReply('${ticket.id}')">Send</button>
        </div>` : `<div style="font-family:var(--mono);font-size:11px;color:var(--text3);text-align:center;padding:8px 0;border-top:1px solid var(--border)">This query is closed</div>`}`;

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
    await api.tickets.reply(state.currentProject.id, ticketId, body);
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
  await api.auth.logout().catch(() => {});
  localStorage.removeItem('fd_project');
  window.location.href = 'index.html';
}

// ── WEBSOCKET ─────────────────────────────────────────────────────────
wsClient.on('connected',    () => { const d = document.getElementById('client-live'); if(d){ d.style.background='var(--green)'; d.title='Live'; }});
wsClient.on('disconnected', () => { const d = document.getElementById('client-live'); if(d){ d.style.background='var(--red)'; d.title='Reconnecting...'; }});
wsClient.on('activity', () => { loadClientProject(state.currentProject?.id); });

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
