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

    <!-- MEMBERS LIST -->
    <div class="members-card">
      <div class="members-card-title">
        Members
        <span style="font-family:var(--mono);font-size:11px;color:var(--text3);font-weight:400">${state.members.length} total</span>
      </div>
      ${state.members.map(m => `
        <div class="member-row">
          <div class="member-avatar-lg" style="background:${esc(m.avatar_color||'#7c3aed')}">${m.username[0].toUpperCase()}</div>
          <div class="member-info">
            <div class="member-username">${esc(m.username)}</div>
            <div class="member-meta">
              ${m.invited_by_username ? `Invited by ${esc(m.invited_by_username)} · ` : ''}
              Joined ${relativeDate(m.joined_at)}
            </div>
          </div>
          <span class="role-badge role-${m.role}">${m.role}</span>
          ${isOwner && m.role !== 'owner' ? `
            <button class="btn-icon delete" onclick="removeMember('${m.id}')">✕</button>` : ''}
        </div>`).join('')}
    </div>

    ${isOwner ? `
    <!-- INVITE LINKS -->
    <div class="members-card">
      <div class="members-card-title">
        Invite Links
        <button class="btn-accent" style="padding:5px 12px;font-size:12px" onclick="createInvite()">+ Generate Code</button>
      </div>
      <p style="font-family:var(--mono);font-size:11px;color:var(--text3);margin-bottom:12px">
        Share these codes with teammates. They enter the code in "Join Project" to get access.
      </p>

      ${invites.length ? `
        <div class="invite-list">
          ${invites.map(inv => {
            const expired  = new Date(inv.expires_at) < new Date();
            const used     = !!inv.accepted_at;
            const cls      = (expired || used) ? 'invite-item invite-used' : 'invite-item';
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

    <!-- PROJECT SETTINGS -->
    <div class="members-card">
      <div class="members-card-title">Project Settings</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn-danger" onclick="deleteProject()">🗑 Delete Project</button>
      </div>
    </div>` : ''}

    <!-- JOIN PROJECT (for non-owners too) -->
    <div class="members-card">
      <div class="members-card-title">Join Another Project</div>
      <div style="display:flex;gap:8px">
        <input type="text" id="join-code-input" class="form-input" placeholder="Enter code e.g. FD-ABC123DEF456" style="flex:1;text-transform:uppercase;letter-spacing:.1em">
        <button class="btn-accent" onclick="joinWithCode()">Join</button>
      </div>
      <div class="form-error" id="join-code-error"></div>
    </div>
  `;
}

// Create a new invite token
async function createInvite() {
  // Show mini modal inline
  const role  = prompt('Role for this invite? (editor / viewer)', 'editor');
  if (!role || !['editor','viewer'].includes(role.trim().toLowerCase())) return;
  const label = prompt('Label for this invite? (optional, e.g. "Alice")', '');

  try {
    const inv = await api.invites.create(state.currentProject.id, role.trim(), label || '');
    showToast(`✓ Code created: ${inv.token}`, 'success');
    // Copy to clipboard automatically
    navigator.clipboard.writeText(inv.token).catch(()=>{});
    renderMembers();
  } catch(e) { showToast(e.message, 'error'); }
}

async function copyInviteCode(token) {
  await navigator.clipboard.writeText(token);
  showToast(`📋 Copied: ${token}`, 'info');
}

async function revokeInvite(id) {
  if (!confirm('Revoke this invite code? Anyone who has it won\'t be able to use it.')) return;
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
    updateDashboard();
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
    showToast('✓ Joined project!', 'success');
    state.projects = await api.projects.list();
    state.currentProject = state.projects.find(p => p.id === res.projectId) || state.projects[0];
    populateProjectSelect();
    await loadProjectData();
    renderApp();
    showView('dashboard');
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
    populateProjectSelect();
    if (state.currentProject) await loadProjectData();
    renderApp();
    showView('dashboard');
    showToast('Project deleted', 'error');
  } catch(e) { showToast(e.message, 'error'); }
}

window.renderMembers   = renderMembers;
window.createInvite    = createInvite;
window.copyInviteCode  = copyInviteCode;
window.revokeInvite    = revokeInvite;
window.removeMember    = removeMember;
window.joinWithCode    = joinWithCode;
window.deleteProject   = deleteProject;
