// ── components/activity.js ───────────────────────────────────────────

function _actorColor(username, fallbackColor) {
  const m = (state.members || []).find(m => m.username === username);
  return m ? roleColor(m.role) : (fallbackColor || '#7c3aed');
}

function _actorAvatarUrl(username) {
  const member = (state.members || []).find(m => m.username === username);
  if (member?.avatar_url) return member.avatar_url;
  if (username === state.user?.username) return state.user?.avatar_url || null;
  return null;
}

function renderActivityFeed() {
  const list = document.getElementById('activity-list');
  if (!list) return;

  if (!state.activityFeed.length) {
    list.innerHTML = '<div class="activity-empty">No activity yet</div>';
    return;
  }

  list.innerHTML = state.activityFeed.map(item => {
    // REST rows are flat (username/display_name); WS-pushed rows nest them
    // under `user`. Both shapes end up in state.activityFeed.
    const who  = item.user || item;
    const name = displayName(who);
    return `
    <div class="activity-item" id="act-${item.id}">
      ${avatarHtml(name, _actorColor(who.username, who.avatar_color), 24, _actorAvatarUrl(who.username))}
      <div class="activity-content">
        <div class="activity-text">
          <strong>${esc(name)}</strong>
          ${actionLabel(item.action, item.entity_type, item.entity_name, item.meta)}
        </div>
        <div class="activity-time">${timeAgo(item.created_at)}</div>
      </div>
    </div>`;
  }).join('');
}

function prependActivity(item) {
  state.activityFeed.unshift(item);
  if (state.activityFeed.length > 100) state.activityFeed.pop();

  const list = document.getElementById('activity-list');
  if (!list) return;

  const empty = list.querySelector('.activity-empty');
  if (empty) empty.remove();

  const who      = item.user || item;
  const username = who.username;
  const name     = displayName(who);
  const div = document.createElement('div');
  div.className = 'activity-item';
  div.id = `act-${item.id}`;
  div.innerHTML = `
    ${avatarHtml(name, _actorColor(username, who.avatar_color || item.avatar_color), 24, _actorAvatarUrl(username))}
    <div class="activity-content">
      <div class="activity-text">
        <strong>${esc(name)}</strong>
        ${actionLabel(item.action, item.entity_type, item.entity_name, item.meta)}
      </div>
      <div class="activity-time">${timeAgo(item.created_at)}</div>
    </div>`;
  div.style.animation = 'toastIn .3s ease';
  list.prepend(div);

  while (list.children.length > 50) list.lastChild.remove();
}

function renderOnlinePresence(onlineUsers) {
  state.onlineUsers = onlineUsers;
  const el = document.getElementById('online-presence');
  if (!el) return;

  if (!onlineUsers.length) { el.innerHTML = ''; return; }

  const shown = onlineUsers.slice(0, 5);
  const extra = onlineUsers.length - shown.length;
  el.innerHTML = shown.map(u => {
    const member    = (state.members || []).find(m => m.id === u.id || m.username === u.username);
    const isMe      = u.id === state.user?.id || u.username === state.user?.username;
    // Prefer the freshest source: own profile, then the members list, then
    // what the socket carried at connect time.
    const name      = displayName(isMe ? state.user : (member || u));
    const role      = member?.role || (u.id === state.user?.id ? state.currentProject?.member_role : null);
    const color     = role ? roleColor(role) : '#7c3aed';
    const avatarUrl = isMe
      ? (state.user?.avatar_url || null)
      : (member?.avatar_url || null);
    const size = 26;
    const base = `width:${size}px;height:${size}px;font-size:11px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-weight:700;color:#fff;line-height:1;box-shadow:0 0 0 2px ${color},0 0 0 4px var(--bg2)`;
    const inner = avatarUrl
      ? `<div style="${base};background:${color};overflow:hidden;padding:0"><img src="${esc(avatarUrl)}" style="width:100%;height:100%;object-fit:cover;border-radius:50%"></div>`
      : `<div style="${base};background:${color}">${nameInitial(name)}</div>`;
    return `<div class="online-dot" title="${esc(name)}">${inner}</div>`;
  }).join('') + (extra > 0 ? `<span class="online-count">+${extra}</span>` : '');
}

async function loadActivity(projectId) {
  try {
    const items = await api.activity.list(projectId);
    state.activityFeed = items;
    renderActivityFeed();
  } catch {}
}

window.renderActivityFeed  = renderActivityFeed;
window.prependActivity     = prependActivity;
window.renderOnlinePresence = renderOnlinePresence;
window.loadActivity        = loadActivity;
