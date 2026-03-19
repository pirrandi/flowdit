// ── views/members.js ─────────────────────────────────────────────────

async function renderMembers() {
  const container = document.getElementById('view-members');
  if (!state.currentProject) {
    container.innerHTML = '<div class="empty-state"><div class="empty-icon">📁</div><div class="empty-title">No project selected</div></div>';
    return;
  }

  const isOwner = state.currentProject.member_role === 'owner';
  let invites   = [];
  if (isOwner) {
    try { invites = await api.invites.list(state.currentProject.id); } catch {}
  }

  container.innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title">Team Members</div>
        <div class="page-subtitle">// ${esc(state.currentProject.name)}</div>
      </div>
    </div>

    <div class="members-card">
      <div class="members-card-title">
        Members
        <span style="font-family:var(--mono);font-size:11px;color:var(--text3);font-weight:400">${state.members.length} total</span>
      </div>
      ${state.members.map(m => `
        <div class="member-row">
          <div class="member-avatar-lg" style="background:${roleColor(m.role)};overflow:hidden;padding:0${m.avatar_url ? `;box-shadow:0 0 0 2px ${roleColor(m.role)}` : ''}">${m.avatar_url ? `<img src="${esc(m.avatar_url)}" style="width:100%;height:100%;object-fit:cover;border-radius:50%">` : `<span style="display:flex;align-items:center;justify-content:center;width:100%;height:100%">${m.username[0].toUpperCase()}</span>`}</div>
          <div class="member-info">
            <div class="member-username">${esc(m.username)}</div>
            <div class="member-meta">
              ${m.invited_by_username ? `Invited by ${esc(m.invited_by_username)} · ` : ''}
              Joined ${relativeDate(m.joined_at)}
            </div>
          </div>
          <span class="role-badge role-${m.role}">${m.role}</span>
          ${isOwner && m.role !== 'owner' ? `<button class="btn-icon delete" onclick="removeMember('${m.id}')">✕</button>` : ''}
        </div>`).join('')}
    </div>

    ${isOwner ? `
    <div class="members-card">
      <div class="members-card-title">
        Invite Links
        <button class="btn-accent" style="padding:5px 12px;font-size:12px" onclick="createInvite()">+ Generate Code</button>
      </div>
      <p style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-bottom:12px">
        Share these codes with teammates. They paste the code below to get access.
      </p>
      ${invites.length ? `
        <div class="invite-list">
          ${invites.map(inv => {
            const expired = new Date(inv.expires_at) < new Date();
            const used    = !!inv.accepted_at;
            const cls     = (expired || used) ? 'invite-item invite-used' : 'invite-item';
            return `<div class="${cls}">
              <div class="invite-token-display">${esc(inv.token)}</div>
              <span class="invite-role-tag role-badge role-${inv.role}">${inv.role}</span>
              <span class="invite-expires">
                ${used ? `Used by ${esc(inv.accepted_by_username||'?')}` : expired ? 'Expired' : `Expires ${relativeDate(inv.expires_at)}`}
              </span>
              ${!used && !expired ? `
                <button class="btn-icon" onclick="copyInviteCode('${esc(inv.token)}')" title="Copy">📋</button>
                <button class="btn-icon delete" onclick="revokeInvite('${inv.id}')" title="Revoke">✕</button>` : ''}
            </div>`;
          }).join('')}
        </div>` : '<div style="font-family:var(--mono);font-size:11px;color:var(--text3)">No invite codes yet.</div>'}
    </div>

    <div class="members-card">
      <div class="members-card-title">Client Portal</div>
      <p style="font-family:var(--mono);font-size:11px;color:var(--text3);margin:0 0 14px">
        Control what the client sees in their read-only portal.
      </p>
      ${buildClientSettings(state.currentProject)}
    </div>

    <div class="members-card" style="border-color:#7c3aed22">
      <div class="members-card-title" style="color:var(--text3);font-size:12px">
        // extras
        <span style="font-family:var(--mono);font-size:9px;color:var(--text3);opacity:.5;font-weight:400;margin-left:6px">completely optional nonsense</span>
      </div>
      <div style="display:flex;flex-direction:column;gap:2px">
        ${buildFunSettings()}
      </div>
    </div>

    <div class="members-card">
      <div class="members-card-title">Danger Zone</div>
      <button class="btn-danger" onclick="deleteProject()">🗑 Delete Project</button>
    </div>` : ''}

    <div class="members-card">
      <div class="members-card-title">Join Another Project</div>
      <div style="display:flex;gap:8px">
        <input type="text" id="join-code-input" class="form-input"
          placeholder="Enter code e.g. FD-ABC123DEF456"
          style="flex:1;text-transform:uppercase;letter-spacing:.1em"
          onkeydown="if(event.key==='Enter')joinWithCode()">
        <button class="btn-accent" onclick="joinWithCode()">Join</button>
      </div>
      <div class="form-error" id="join-code-error"></div>
    </div>
  `;
}

const INVITE_ROLE_HINTS = {
  editor: 'Can create findings, update methodology and manage the project.',
  viewer: 'Read-only access via the client portal.',
};

function createInvite() {
  // Reset modal state
  document.getElementById('invite-label').value = '';
  selectInviteRole('editor');
  document.getElementById('invite-modal').classList.add('open');
}

function selectInviteRole(role) {
  document.querySelectorAll('.invite-role-btn').forEach(b => b.classList.toggle('active', b.dataset.role === role));
  document.getElementById('invite-role-hint').textContent = INVITE_ROLE_HINTS[role] || '';
}

async function submitCreateInvite() {
  const role  = document.querySelector('.invite-role-btn.active')?.dataset.role || 'editor';
  const label = document.getElementById('invite-label').value.trim();
  const btn   = document.getElementById('invite-save-btn');
  btn.disabled = true;
  try {
    const inv = await api.invites.create(state.currentProject.id, role, label);
    navigator.clipboard.writeText(inv.token).catch(() => {});
    document.getElementById('invite-modal').classList.remove('open');
    showToast(`✓ Code copied: ${inv.token}`, 'success');
    renderMembers();
  } catch(e) {
    showToast(e.message, 'error');
  } finally {
    btn.disabled = false;
  }
}

async function copyInviteCode(token) {
  await navigator.clipboard.writeText(token);
  showToast(`📋 Copied: ${token}`, 'info');
}

async function revokeInvite(id) {
  if (!confirm("Revoke this invite code?")) return;
  try {
    await api.invites.revoke(state.currentProject.id, id);
    showToast('Invite revoked', 'success');
    renderMembers();
  } catch(e) { showToast(e.message, 'error'); }
}

async function removeMember(userId) {
  if (!confirm('Remove this member from the project?')) return;
  try {
    await api.members.remove(state.currentProject.id, userId);
    state.members = state.members.filter(m => m.id !== userId);
    showToast('Member removed', 'success');
    renderMembers();
  } catch(e) { showToast(e.message, 'error'); }
}

async function joinWithCode() {
  const input = document.getElementById('join-code-input');
  const err   = document.getElementById('join-code-error');
  const code  = (input?.value || '').trim().toUpperCase();
  if (!code) return;
  err.style.display = 'none';
  try {
    const res = await api.projects.join(code);
    state.projects = await api.projects.list();
    state.currentProject = state.projects.find(p => p.id === res.projectId) || state.projects[0];
    localStorage.setItem('fd_project', state.currentProject.id);

    if (state.currentProject.member_role === 'viewer') {
      window.location.href = 'client.html';
      return;
    }

    await loadProjectData(state.currentProject.id);
    if (typeof pageInit === 'function') pageInit();
    refreshTopbarProgress();
    showToast('✓ Joined project!', 'success');
  } catch(e) {
    err.textContent = e.message;
    err.style.display = 'block';
  }
}

async function deleteProject() {
  if (!confirm(`Delete "${state.currentProject.name}"? This cannot be undone.`)) return;
  try {
    await api.projects.delete(state.currentProject.id);
    state.projects = state.projects.filter(p => p.id !== state.currentProject.id);
    state.currentProject = state.projects[0] || null;
    localStorage.setItem('fd_project', state.currentProject?.id || '');
    if (state.currentProject) {
      await loadProjectData(state.currentProject.id);
    } else {
      state.wstgProgress = {}; state.psProgress = {}; state.customVulns = []; state.members = [];
    }
    if (typeof pageInit === 'function') pageInit();
    refreshTopbarProgress();
    showToast('Project deleted', 'error');
  } catch(e) { showToast(e.message, 'error'); }
}

function buildClientSettings(p) {
  const toggle = (flag, label, desc) => {
    const on = !!p[flag];
    return `
      <div class="client-setting-row">
        <div>
          <div style="font-size:13px;font-weight:600;margin-bottom:2px">${label}</div>
          <div style="font-family:var(--mono);font-size:11px;color:var(--text3)">${desc}</div>
        </div>
        <button class="setting-toggle ${on?'on':''}" onclick="toggleProjectFlag('${flag}',${!on})">
          <span class="setting-toggle-knob"></span>
        </button>
      </div>`;
  };

  const logoBg    = p.logo_bg || 'light';
  const previewBg = logoBg === 'dark' ? '#1e1e1e' : '#ffffff';
  const previewBd = logoBg === 'dark' ? 'rgba(255,255,255,.08)' : 'rgba(0,0,0,.09)';

  const logoPreview = p.logo_url
    ? `<div style="background:${previewBg};border:1px solid ${previewBd};border-radius:8px;padding:8px 14px;display:flex;align-items:center;justify-content:center;min-width:80px">
         <img src="${esc(p.logo_url)}" style="height:36px;max-width:120px;object-fit:contain">
       </div>`
    : `<div style="height:52px;width:90px;border-radius:8px;background:var(--bg3);border:1px dashed var(--border);display:flex;align-items:center;justify-content:center">
         <span style="font-family:var(--mono);font-size:10px;color:var(--text3)">no logo</span>
       </div>`;

  const bgToggle = p.logo_url ? `
    <div style="display:flex;gap:4px;margin-top:4px">
      <button onclick="setLogoBg('light')" style="font-family:var(--mono);font-size:10px;padding:3px 8px;border-radius:5px;border:1px solid ${logoBg==='light'?'var(--accent)':'var(--border)'};background:${logoBg==='light'?'var(--accent)18':'transparent'};color:${logoBg==='light'?'var(--accent)':'var(--text3)'};cursor:pointer">☀ Light</button>
      <button onclick="setLogoBg('dark')"  style="font-family:var(--mono);font-size:10px;padding:3px 8px;border-radius:5px;border:1px solid ${logoBg==='dark' ?'var(--accent)':'var(--border)'};background:${logoBg==='dark' ?'var(--accent)18':'transparent'};color:${logoBg==='dark' ?'var(--accent)':'var(--text3)'};cursor:pointer">◑ Dark</button>
    </div>` : '';

  const logoSection = `
    <div style="padding:14px 0;border-bottom:1px solid var(--border);margin-bottom:4px">
      <div style="font-size:13px;font-weight:600;margin-bottom:10px">Project Logo</div>
      <div style="display:flex;align-items:center;gap:12px">
        ${logoPreview}
        <div style="display:flex;flex-direction:column;gap:6px">
          <label class="btn-secondary" style="font-size:11px;padding:4px 10px;cursor:pointer;display:inline-block;text-align:center">
            ${p.logo_url ? 'Change' : 'Upload'}
            <input type="file" accept="image/*" style="display:none" onchange="onLogoFileChange(this)">
          </label>
          ${p.logo_url ? `<button class="btn-secondary" style="font-size:11px;padding:4px 10px;color:#dc2626;border-color:#dc262644" onclick="removeLogo()">Remove</button>` : ''}
          ${bgToggle}
        </div>
        <span style="font-family:var(--mono);font-size:10px;color:var(--text3);line-height:1.6">Shown in the client<br>portal and sidebar.<br>PNG/JPG, max 1.5 MB.</span>
      </div>
    </div>`;

  return `
    <div style="display:flex;flex-direction:column;gap:2px">
      ${logoSection}
      ${toggle('client_view_enabled', 'Client portal active',    'Allow invited viewers to access the client portal')}
      ${toggle('show_findings',       'Show findings',           'Vulnerabilities with severity, description and remediation')}
      ${toggle('show_wstg_progress',  'Show WSTG progress',      'Testing progress by category in real time')}
      ${toggle('show_wstg_notes',     'Show WSTG notes',         'Notes written by pentesters on each test')}
      ${toggle('show_targets',        'Show targets',            'In-scope hosts and their audit status')}
      ${toggle('show_activity',       'Show activity log',       'Real-time feed of pentester actions on the project')}
      ${toggle('tickets_enabled',     'Enable client queries',   'Client can open questions linked to a finding')}
    </div>`;
}

async function onLogoFileChange(input) {
  const file = input.files?.[0];
  if (!file) return;
  if (file.size > 1.5 * 1024 * 1024) { showToast('Image too large (max 1.5 MB)', 'error'); return; }
  const reader = new FileReader();
  reader.onload = async (e) => {
    const dataUrl = e.target.result;
    try {
      const updated = await api.projects.update(state.currentProject.id, { logo_url: dataUrl });
      state.currentProject = { ...state.currentProject, ...updated };
      const idx = state.projects.findIndex(p => p.id === state.currentProject.id);
      if (idx > -1) state.projects[idx] = state.currentProject;
      showToast('✓ Logo saved', 'success');
      renderMembers();
    } catch(e) { showToast(e.message, 'error'); }
  };
  reader.readAsDataURL(file);
}

async function removeLogo() {
  try {
    const updated = await api.projects.update(state.currentProject.id, { logo_url: null });
    state.currentProject = { ...state.currentProject, ...updated };
    const idx = state.projects.findIndex(p => p.id === state.currentProject.id);
    if (idx > -1) state.projects[idx] = state.currentProject;
    showToast('Logo removed', 'success');
    renderMembers();
  } catch(e) { showToast(e.message, 'error'); }
}

async function setLogoBg(bg) {
  try {
    const updated = await api.projects.update(state.currentProject.id, { logo_bg: bg });
    state.currentProject = { ...state.currentProject, ...updated };
    const idx = state.projects.findIndex(p => p.id === state.currentProject.id);
    if (idx > -1) state.projects[idx] = state.currentProject;
    renderMembers();
  } catch(e) { showToast(e.message, 'error'); }
}

function buildFunSettings() {
  if (!state.currentProject) return '';
  const s = getFunSettings(state.currentProject.id);
  const ft = (key, emoji, label, desc) => {
    const on = !!s[key];
    return `<div class="client-setting-row">
      <div>
        <div style="font-size:13px;font-weight:600;margin-bottom:2px">${emoji} ${label}</div>
        <div style="font-family:var(--mono);font-size:11px;color:var(--text3)">${desc}</div>
      </div>
      <button class="setting-toggle ${on?'on':''}" onclick="toggleFunSetting('${key}',${!on})">
        <span class="setting-toggle-knob"></span>
      </button>
    </div>`;
  };
  return `
    ${ft('confetti', '🎉', 'Confetti at 100%',  'Shoot confetti from both sides when WSTG coverage hits 100%')}
    ${ft('neon',     '🌈', 'Neon mode',          'Add neon glow to severity badges and progress bars')}
    ${ft('hacker',   '💀', 'Hacker vibes',        'Scanline overlay — for maximum credibility in client calls')}
  `;
}

function toggleFunSetting(key, val) {
  if (!state.currentProject) return;
  setFunSetting(state.currentProject.id, key, val);
  renderMembers();
}

async function toggleProjectFlag(flag, value) {
  try {
    const updated = await api.projects.update(state.currentProject.id, { [flag]: value });
    state.currentProject = { ...state.currentProject, ...updated };
    // Update in projects list too
    const idx = state.projects.findIndex(p => p.id === state.currentProject.id);
    if (idx > -1) state.projects[idx] = state.currentProject;
    renderMembers();
    showToast('✓ Saved', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

window.buildFunSettings     = buildFunSettings;
window.toggleFunSetting     = toggleFunSetting;
window.renderMembers        = renderMembers;
window.createInvite         = createInvite;
window.selectInviteRole     = selectInviteRole;
window.submitCreateInvite   = submitCreateInvite;
window.copyInviteCode       = copyInviteCode;
window.revokeInvite         = revokeInvite;
window.removeMember         = removeMember;
window.joinWithCode         = joinWithCode;
window.deleteProject        = deleteProject;
window.toggleProjectFlag    = toggleProjectFlag;
window.onLogoFileChange     = onLogoFileChange;
window.removeLogo           = removeLogo;
window.setLogoBg            = setLogoBg;