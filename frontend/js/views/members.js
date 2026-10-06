// ── views/members.js ─────────────────────────────────────────────────

async function renderMembers() {
  const container = document.getElementById('view-members');
  if (!state.currentProject) {
    container.innerHTML = `<div class="empty-state"><div class="empty-icon">${icon('inbox', { size: 28 })}</div><div class="empty-title">No project selected</div></div>`;
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
        <div class="page-title">Team</div>
        <div class="page-subtitle">// ${esc(state.currentProject.name)}</div>
      </div>
    </div>

    <div style="display:flex;flex-direction:column;gap:12px">

      <div class="members-card">
        <div class="members-card-title">
          Members
          <span style="font-family:var(--mono);font-size:11px;color:var(--t3);font-weight:400">${state.members.length} total</span>
        </div>
        ${state.members.map(m => `
          <div class="member-row">
            <div class="member-avatar-lg" style="background:${roleColor(m.role)};overflow:hidden;padding:0${m.avatar_url ? `;box-shadow:0 0 0 2px ${roleColor(m.role)}` : ''}">${m.avatar_url ? `<img src="${esc(m.avatar_url)}" style="width:100%;height:100%;object-fit:cover;border-radius:50%">` : `<span style="display:flex;align-items:center;justify-content:center;width:100%;height:100%">${nameInitial(displayName(m))}</span>`}</div>
            <div class="member-info">
              <div class="member-username">
                ${esc(displayName(m))}
                ${m.display_name ? `<span style="font-family:var(--mono);font-size:10px;color:var(--t3);font-weight:400;margin-left:6px">@${esc(m.username)}</span>` : ''}
                ${m.label ? `<span style="font-family:var(--mono);font-size:10px;color:var(--t3);font-weight:400;margin-left:6px">${esc(m.label)}</span>` : ''}
              </div>
              <div class="member-meta">
                ${m.invited_by_username ? `Invited by ${esc(displayName(m, 'invited_by_'))} · ` : ''}
                Joined ${relativeDate(m.joined_at)}
              </div>
            </div>
            ${isOwner && m.role !== 'owner' && m.id !== state.user?.id ? `
              <select class="form-input" style="width:auto;padding:3px 8px;font-size:11px" title="Cambiar rol"
                onchange="changeMemberRole('${m.id}', this.value)">
                ${ASSIGNABLE_ROLES.map(r => `<option value="${r}" ${r === m.role ? 'selected' : ''}>${ROLE_LABELS[r]}</option>`).join('')}
              </select>` : `<span class="role-badge role-${m.role}">${m.role}</span>`}
            ${isOwner && m.role !== 'owner' ? `<button class="btn-icon delete" onclick="removeMember('${m.id}')">${icon('x',{size:12})}</button>` : ''}
          </div>`).join('')}
      </div>

      ${isOwner ? `
      <div class="members-card">
        <div class="members-card-title">
          Invite Links
          <button class="btn btn-prim" style="padding:4px 12px;font-size:12px" onclick="createInvite()">+ Generate Code</button>
        </div>
        <p style="font-family:var(--mono);font-size:11px;color:var(--t3);margin-bottom:12px">
          Comparte estos códigos con tu equipo. Lo pegan en "Join project" para obtener acceso.
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
                  ${used ? `Used by ${esc(displayName(inv, 'accepted_by_'))}` : expired ? 'Expired' : `Expires ${relativeDate(inv.expires_at)}`}
                </span>
                ${!used && !expired ? `
                  <button class="btn-icon" onclick="copyInviteCode('${esc(inv.token)}')" title="Copy code">copy</button>
                  ${inv.role === 'viewer' ? `<button class="btn-icon" onclick="copyInviteLink('${esc(inv.token)}')" title="Copy client portal link">copy link</button>` : ''}
                  <button class="btn-icon delete" onclick="revokeInvite('${inv.id}')" title="Revoke">${icon('x',{size:12})}</button>` : ''}
              </div>`;
            }).join('')}
          </div>` : '<div style="font-family:var(--mono);font-size:11px;color:var(--t3)">No invite codes yet.</div>'}
      </div>` : ''}

      <div class="members-card">
        <div class="members-card-title">Join Another Project</div>
        <div style="display:flex;gap:8px">
          <input type="text" id="join-code-input" class="form-input"
            placeholder="Enter code e.g. FD-ABC123DEF456"
            style="flex:1;text-transform:uppercase;letter-spacing:.1em"
            onkeydown="if(event.key==='Enter')joinWithCode()">
          <button class="btn btn-prim" onclick="joinWithCode()">Join</button>
        </div>
        <div class="form-error" id="join-code-error"></div>
      </div>

    </div>
  `;
}

// ── invite actions ────────────────────────────────────────────────────

const INVITE_ROLE_HINTS = {
  editor:    'Can create findings, update methodology and manage the project.',
  pentester: 'Trabajo técnico, sin acciones de cara al cliente (publicar, tickets, exportar).',
  viewer:    'Read-only access via the client portal.',
};

// Roles the owner can hand out; matches ASSIGNABLE_ROLES in routes/projects.js.
const ASSIGNABLE_ROLES = ['editor', 'pentester', 'viewer'];
const ROLE_LABELS = { editor: 'Editor', pentester: 'Pentester', viewer: 'Viewer' };

async function changeMemberRole(userId, role) {
  try {
    await api.members.changeRole(state.currentProject.id, userId, role);
    const m = state.members.find(x => x.id === userId);
    if (m) m.role = role;
    showToast('Rol actualizado', 'success');
  } catch(e) { showToast(e.message, 'error'); }
  renderMembers();
}

function createInvite() {
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
    showToast(`Code copied: ${inv.token}`, 'success');
    renderMembers();
  } catch(e) {
    showToast(e.message, 'error');
  } finally {
    btn.disabled = false;
  }
}

async function copyInviteCode(token) {
  await navigator.clipboard.writeText(token);
  showToast(`Copied: ${token}`, 'info');
}

async function copyInviteLink(token) {
  const base = `${window.location.origin}${window.location.pathname.replace(/\/[^/]*$/, '')}/client-login`;
  const link = `${base}?invite=${encodeURIComponent(token)}`;
  await navigator.clipboard.writeText(link);
  showToast('Client portal link copied', 'info');
}

async function revokeInvite(id) {
  if (!confirm('Revoke this invite code?')) return;
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
      window.location.href = 'client';
      return;
    }
    await loadProjectData(state.currentProject.id);
    if (typeof pageInit === 'function') pageInit();
    refreshTopbarProgress();
    showToast('Joined project!', 'success');
  } catch(e) {
    err.textContent = e.message;
    err.style.display = 'block';
  }
}

window.renderMembers      = renderMembers;
window.createInvite       = createInvite;
window.selectInviteRole   = selectInviteRole;
window.submitCreateInvite = submitCreateInvite;
window.copyInviteCode     = copyInviteCode;
window.copyInviteLink     = copyInviteLink;
window.revokeInvite       = revokeInvite;
window.removeMember       = removeMember;
window.changeMemberRole   = changeMemberRole;
window.joinWithCode       = joinWithCode;
