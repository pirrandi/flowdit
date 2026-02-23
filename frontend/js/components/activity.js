// ── components/activity.js ───────────────────────────────────────────

function renderActivityFeed() {
  const list = document.getElementById('activity-list');
  if (!list) return;

  if (!state.activityFeed.length) {
    list.innerHTML = '<div class="activity-empty">No activity yet</div>';
    return;
  }

  list.innerHTML = state.activityFeed.map(item => `
    <div class="activity-item" id="act-${item.id}">
      ${avatarHtml(item.username, item.avatar_color, 24)}
      <div class="activity-content">
        <div class="activity-text">
          <strong>${esc(item.username)}</strong>
          ${actionLabel(item.action, item.entity_type, item.entity_name, item.meta)}
        </div>
        <div class="activity-time">${timeAgo(item.created_at)}</div>
      </div>
    </div>`).join('');
}

function prependActivity(item) {
  state.activityFeed.unshift(item);
  if (state.activityFeed.length > 100) state.activityFeed.pop();

  const list = document.getElementById('activity-list');
  if (!list) return;

  // Remove empty state if present
  const empty = list.querySelector('.activity-empty');
  if (empty) empty.remove();

  const div = document.createElement('div');
  div.className = 'activity-item';
  div.id = `act-${item.id}`;
  div.innerHTML = `
    ${avatarHtml(item.user?.username || item.username, item.user?.avatar_color || item.avatar_color, 24)}
    <div class="activity-content">
      <div class="activity-text">
        <strong>${esc(item.user?.username || item.username)}</strong>
        ${actionLabel(item.action, item.entity_type, item.entity_name, item.meta)}
      </div>
      <div class="activity-time">${timeAgo(item.created_at)}</div>
    </div>`;
  div.style.animation = 'toastIn .3s ease';
  list.prepend(div);

  // Keep max 50 visible
  while (list.children.length > 50) list.lastChild.remove();
}

function renderOnlinePresence(onlineUsers) {
  state.onlineUsers = onlineUsers;
  const el = document.getElementById('online-presence');
  if (!el) return;

  if (!onlineUsers.length) { el.innerHTML = ''; return; }

  const shown = onlineUsers.slice(0, 5);
  const extra = onlineUsers.length - shown.length;
  el.innerHTML = shown.map(u =>
    `<div class="online-dot" title="${esc(u.username)}">
      ${avatarHtml(u.username, '#7c3aed', 24)}
    </div>`
  ).join('') + (extra > 0 ? `<span class="online-count">+${extra}</span>` : '');
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
