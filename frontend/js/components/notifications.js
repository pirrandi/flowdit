// ── components/notifications.js — topbar bell + inbox popover ────────
// Loaded on every internal page (before page.js). renderTopbar() embeds
// notifBellHtml(); bootPage() calls initNotifications(). New notifications
// arrive live over the user's WebSocket ('notification' messages are sent
// only to the recipient's own sockets — see backend services/ws.js).

const _notif = { items: [], unread: 0, loaded: false, open: false };

const NOTIF_TEXT = {
  task_assigned: (actor, title) => `<strong>${actor}</strong> te asignó la tarea <span class="hl">${title}</span>`,
  task_comment:  (actor, title) => `<strong>${actor}</strong> comentó en <span class="hl">${title}</span>`,
  task_done:     (actor, title) => `<strong>${actor}</strong> completó <span class="hl">${title}</span>`,
  // Avisos de la IA: no hay actor humano (llegan también a quien inició el
  // trabajo), el "actor" es la fuente fija.
  ai_finding_proposed: (_, title) => `<strong>Claude Code</strong> propuso el hallazgo <span class="hl">${title}</span>`,
  ai_finding_gate:     (_, title) => `<strong>AI Agent</strong> espera aprobación para <span class="hl">${title}</span>`,
  ai_finding_update_proposed: (_, title) => `<strong>Claude Code</strong> propuso cambios al hallazgo <span class="hl">${title}</span>`,
  ai_target_proposed:  (_, title) => `<strong>Claude Code</strong> propuso el target <span class="hl">${title}</span>`,
};

// Every interpolated value is user-controlled (usernames, task titles) and
// goes through esc() before reaching innerHTML.
function notifText(n) {
  const actor = esc(displayName(n, 'actor_', 'Alguien'));
  const title = esc(n.payload?.task_title || n.payload?.finding_title || n.payload?.target_host || '');
  const fn = NOTIF_TEXT[n.type];
  return fn ? fn(actor, title) : `Nueva notificación de <strong>${actor}</strong>`;
}

function notifPlainText(n) {
  const tmp = document.createElement('div');
  tmp.innerHTML = notifText(n);
  return tmp.textContent;
}

function notifHref(n) {
  if (n.entity_type === 'task' && n.project_id && n.entity_id)
    return `tasks?pid=${encodeURIComponent(n.project_id)}&task=${encodeURIComponent(n.entity_id)}`;
  // El inbox de propuestas vive arriba de todo en la página de Findings.
  if (n.entity_type === 'mcp_proposal' && n.project_id)
    return `vulns?pid=${encodeURIComponent(n.project_id)}`;
  if (n.entity_type === 'ai_scan_session' && n.project_id)
    return `ai-agent?pid=${encodeURIComponent(n.project_id)}`;
  return null;
}

function notifBellHtml() {
  const n = _notif.unread;
  return `
    <div class="notif-wrap" id="notif-wrap">
      <button class="notif-bell" onclick="toggleNotifPanel(event)" title="Notificaciones" aria-label="Notificaciones">
        ${icon('bell', { size: 15 })}
        <span class="notif-badge" id="notif-badge" style="${n ? '' : 'display:none'}">${n > 99 ? '99+' : n}</span>
      </button>
      <div class="notif-panel" id="notif-panel" style="${_notif.open ? '' : 'display:none'}"></div>
    </div>`;
}

function _renderNotifBadge() {
  const b = document.getElementById('notif-badge');
  if (!b) return;
  b.textContent = _notif.unread > 99 ? '99+' : String(_notif.unread);
  b.style.display = _notif.unread ? '' : 'none';
}

function _renderNotifPanel() {
  const panel = document.getElementById('notif-panel');
  if (!panel) return;
  const head = `
    <div class="notif-head">
      <span>Notificaciones</span>
      <button class="notif-readall" onclick="markAllNotificationsRead(event)" ${_notif.unread ? '' : 'disabled'}>
        ${icon('check-check', { size: 12 })} Marcar todo como leído
      </button>
    </div>`;
  let body;
  if (!_notif.loaded)          body = `<div class="notif-empty">Cargando…</div>`;
  else if (!_notif.items.length) body = `<div class="notif-empty">Sin notificaciones</div>`;
  else body = _notif.items.map(n => `
    <button class="notif-item ${n.read_at ? '' : 'unread'}" onclick="openNotification('${esc(n.id)}')">
      <span class="notif-dot"></span>
      <span class="notif-body">
        <span class="notif-text">${notifText(n)}</span>
        ${n.payload?.comment ? `<span class="notif-snippet">${esc(n.payload.comment)}</span>` : ''}
        <span class="notif-meta">${esc(n.payload?.project_name || '')}${n.payload?.project_name ? ' · ' : ''}${esc(timeAgo(n.created_at))}</span>
      </span>
    </button>`).join('');
  panel.innerHTML = head + `<div class="notif-list">${body}</div>`;
}

async function initNotifications() {
  try {
    const { count } = await api.notifications.unreadCount();
    _notif.unread = count || 0;
    _renderNotifBadge();
  } catch {}
}

async function toggleNotifPanel(e) {
  e?.stopPropagation();
  _notif.open = !_notif.open;
  const panel = document.getElementById('notif-panel');
  if (!panel) return;
  panel.style.display = _notif.open ? '' : 'none';
  if (!_notif.open) return;
  _renderNotifPanel();
  try {
    _notif.items  = await api.notifications.list({ limit: 20 });
    _notif.loaded = true;
    const { count } = await api.notifications.unreadCount();
    _notif.unread = count || 0;
    _renderNotifBadge();
  } catch (err) { showToast(err.message, 'error'); }
  _renderNotifPanel();
}

function closeNotifPanel() {
  _notif.open = false;
  const panel = document.getElementById('notif-panel');
  if (panel) panel.style.display = 'none';
}

async function openNotification(id) {
  const n = _notif.items.find(x => x.id === id);
  if (!n) return;
  if (!n.read_at) {
    try {
      await api.notifications.markRead(id);
      n.read_at = new Date().toISOString();
      _notif.unread = Math.max(0, _notif.unread - 1);
      _renderNotifBadge();
    } catch {}
  }
  const href = notifHref(n);
  if (!href) { _renderNotifPanel(); return; }
  // Same page and project → open the task in place instead of reloading.
  const params = new URLSearchParams(window.location.search);
  if (state.currentView === 'tasks' && params.get('pid') === n.project_id && typeof openTaskModal === 'function') {
    closeNotifPanel();
    openTaskModal(n.entity_id);
    return;
  }
  window.location.href = href;
}

async function markAllNotificationsRead(e) {
  e?.stopPropagation();
  try {
    await api.notifications.markAllRead();
    const now = new Date().toISOString();
    _notif.items.forEach(n => { if (!n.read_at) n.read_at = now; });
    _notif.unread = 0;
    _renderNotifBadge();
    _renderNotifPanel();
  } catch (err) { showToast(err.message, 'error'); }
}

document.addEventListener('click', e => {
  if (_notif.open && !e.target.closest('.notif-wrap')) closeNotifPanel();
});

wsClient.on('notification', ({ notification: n }) => {
  if (!n || !n.id || _notif.items.some(x => x.id === n.id)) return;
  _notif.items.unshift(n);
  if (_notif.items.length > 50) _notif.items.length = 50;
  _notif.unread += 1;
  _renderNotifBadge();
  if (_notif.open) _renderNotifPanel();
  showToast(notifPlainText(n), 'info');
  window.dispatchEvent(new CustomEvent('fd:notification', { detail: n }));
});

window.notifBellHtml            = notifBellHtml;
window.initNotifications        = initNotifications;
window.toggleNotifPanel         = toggleNotifPanel;
window.closeNotifPanel          = closeNotifPanel;
window.openNotification         = openNotification;
window.markAllNotificationsRead = markAllNotificationsRead;
