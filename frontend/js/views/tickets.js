// ── views/tickets.js — Client Queries page ───────────────────────────

const STATUS_COLOR = { open:'var(--a)', in_review:'var(--c-high)', closed:'var(--c-low)' };
const STATUS_LABEL = { open:'Open', in_review:'In Review', closed:'Closed' };

let _activeFilter  = 'all';
let _openTicketId  = null;

// ── RENDER ────────────────────────────────────────────────────────────
function renderTickets() {
  const tickets = state.tickets || [];
  const main    = document.getElementById('tickets-main');
  if (!main) return;

  const counts = {
    all:       tickets.length,
    open:      tickets.filter(t => t.status === 'open').length,
    in_review: tickets.filter(t => t.status === 'in_review').length,
    closed:    tickets.filter(t => t.status === 'closed').length,
  };

  // Filter tabs
  document.getElementById('tickets-filters').innerHTML = `
    <div style="display:flex;gap:4px;background:var(--bg3);border:1px solid var(--b1);border-radius:8px;padding:3px">
      ${[['all','All'],['open','Open'],['in_review','In Review'],['closed','Closed']].map(([key, label]) => `
        <button onclick="setTicketFilter('${key}')" id="tf-${key}"
          style="font-family:var(--mono);font-size:11px;padding:4px 12px;border-radius:5px;border:none;cursor:pointer;transition:background .15s,color .15s;
                 background:${_activeFilter===key?'var(--surface)':'transparent'};
                 color:${_activeFilter===key?'var(--t1)':'var(--t3)'}">
          ${label}${counts[key] ? ` <span style="opacity:.6">${counts[key]}</span>` : ''}
        </button>`).join('')}
    </div>`;

  const filtered = _activeFilter === 'all'
    ? tickets
    : tickets.filter(t => t.status === _activeFilter);

  if (!tickets.length) {
    main.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">◌</div>
        <div class="empty-title">No queries yet</div>
        <div class="empty-sub">Client queries will appear here once the client opens a question</div>
      </div>`;
    return;
  }

  if (!filtered.length) {
    main.innerHTML = `<div style="font-family:var(--mono);font-size:12px;color:var(--t3);padding:40px 0;text-align:center">No ${STATUS_LABEL[_activeFilter]?.toLowerCase()} queries</div>`;
    return;
  }

  main.innerHTML = `<div class="tickets-list">${filtered.map(ticketRowHtml).join('')}</div>`;
}

function ticketRowHtml(t) {
  const color      = STATUS_COLOR[t.status] || 'var(--t3)';
  const label      = STATUS_LABEL[t.status] || t.status;
  const hasReplies = t.reply_count > 0;
  const author     = t.opened_by_username || t.client_name || 'Client';
  const isPortal   = !t.opened_by_username && t.client_name;

  return `
    <div class="ticket-row" onclick="openTicketModal('${t.id}')">
      <div class="ticket-row-status-dot" style="background:${color}"></div>
      <div class="ticket-row-body">
        <div style="display:flex;align-items:center;gap:8px;min-width:0">
          <span class="ticket-row-title">${esc(t.title)}</span>
          ${t.vuln_name ? `<span class="ticket-row-tag">${esc(t.vuln_name)}</span>` : ''}
          ${isPortal ? `<span style="font-family:var(--mono);font-size:9px;color:var(--a);border:1px solid rgba(245,158,11,.3);border-radius:var(--r-sm);padding:1px 5px">portal</span>` : ''}
        </div>
        <div class="ticket-row-meta">
          <span>opened by <strong>${esc(author)}</strong></span>
          <span>·</span>
          <span>${relativeDate(t.updated_at)}</span>
          ${hasReplies ? `<span>·</span><span>${t.reply_count} repl${t.reply_count === 1 ? 'y' : 'ies'}</span>` : ''}
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:8px;flex-shrink:0">
        <span class="ticket-status-badge" style="color:${color};border-color:${color}44">${label}</span>
        <span style="font-family:var(--mono);font-size:11px;color:var(--t3)">→</span>
      </div>
    </div>`;
}

function setTicketFilter(filter) {
  _activeFilter = filter;
  renderTickets();
}

// ── TICKET MODAL ──────────────────────────────────────────────────────
async function openTicketModal(ticketId) {
  _openTicketId = ticketId;
  const pid = state.currentProject.id;
  const t   = await api.tickets.get(pid, ticketId).catch(() => null);
  if (!t) return;

  document.getElementById('ticket-modal-title').textContent = t.title;
  document.getElementById('ticket-modal-desc').textContent  = t.description || '';
  const openedBy = t.opened_by_username || t.client_name || 'Client';
  const isPortalTicket = !t.opened_by_username && t.client_name;
  document.getElementById('ticket-modal-meta').innerHTML    =
    `Opened by <strong>${esc(openedBy)}</strong>${isPortalTicket ? ' <span style="font-family:var(--mono);font-size:9px;color:var(--a);border:1px solid rgba(245,158,11,.3);border-radius:var(--r-sm);padding:1px 5px">portal</span>' : ''} · ${relativeDate(t.created_at)}` +
    (t.vuln_name ? ` · re: <span style="color:var(--a)">${esc(t.vuln_name)}</span>` : '');

  const color = STATUS_COLOR[t.status] || 'var(--t3)';
  const btns  = ['open','in_review','closed'].filter(s => s !== t.status).map(s =>
    `<button class="btn-secondary" style="font-size:10px;padding:3px 9px;color:${STATUS_COLOR[s]};border-color:${STATUS_COLOR[s]}44"
      onclick="changeTicketStatus('${s}',event)">${STATUS_LABEL[s]}</button>`
  ).join('');

  document.getElementById('ticket-modal-status-btns').innerHTML =
    `<span style="font-family:var(--mono);font-size:10px;font-weight:700;color:${color};background:${color}18;border:1px solid ${color}44;border-radius:4px;padding:2px 8px">${STATUS_LABEL[t.status]}</span>${btns}`;

  renderTicketThread(t.replies || []);
  document.getElementById('ticket-reply-input').value = '';
  document.getElementById('ticket-modal').classList.add('open');
  setTimeout(() => {
    const thread = document.getElementById('ticket-modal-thread');
    if (thread) thread.scrollTop = thread.scrollHeight;
  }, 50);
}

function closeTicketModal() {
  document.getElementById('ticket-modal').classList.remove('open');
  _openTicketId = null;
}

function renderTicketThread(replies) {
  const thread = document.getElementById('ticket-modal-thread');
  if (!replies.length) {
    thread.innerHTML = `<div style="font-family:var(--mono);font-size:11px;color:var(--t3);text-align:center;padding:16px 0">No replies yet — be the first to respond.</div>`;
    return;
  }
  thread.innerHTML = replies.map(r => {
    const isPortal    = !r.author_id;
    const displayName = r.author_username || r.client_name || 'Client';
    const isMe        = !isPortal && r.author_id === state.user?.id;
    const color       = isPortal ? 'var(--a)' : roleColor(isMe ? state.currentProject?.member_role : 'viewer');
    const bgColor     = isPortal ? 'rgba(245,158,11,.08)' : isMe ? color + '18' : 'var(--bg3)';
    const borderColor = isPortal ? 'rgba(245,158,11,.2)'  : isMe ? color + '33' : 'var(--b1)';
    return `
      <div style="display:flex;gap:8px;${isMe ? 'flex-direction:row-reverse' : ''}">
        ${avatarHtml(displayName, color, 26, r.author_avatar_url || null)}
        <div style="max-width:78%;display:flex;flex-direction:column;gap:3px;${isMe ? 'align-items:flex-end' : ''}">
          <div style="font-family:var(--mono);font-size:10px;color:var(--t3)">
            ${esc(displayName)}${isPortal ? ' <span style="color:var(--a)">· client</span>' : ''} · ${relativeDate(r.created_at)}
          </div>
          <div style="background:${bgColor};border:1px solid ${borderColor};border-radius:8px;padding:9px 13px;font-size:13px;line-height:1.6;white-space:pre-wrap;color:var(--t1)">${esc(r.body)}</div>
        </div>
      </div>`;
  }).join('');
}

async function submitTicketReply() {
  const input = document.getElementById('ticket-reply-input');
  const body  = input.value.trim();
  if (!body || !_openTicketId) return;
  try {
    await api.tickets.reply(state.currentProject.id, _openTicketId, body);
    input.value = '';
    const t = await api.tickets.get(state.currentProject.id, _openTicketId);
    renderTicketThread(t.replies || []);
    setTimeout(() => {
      const thread = document.getElementById('ticket-modal-thread');
      if (thread) thread.scrollTop = thread.scrollHeight;
    }, 50);
    state.tickets = await api.tickets.list(state.currentProject.id).catch(() => state.tickets);
    renderTickets();
  } catch(e) { showToast(e.message, 'error'); }
}

async function changeTicketStatus(status, e) {
  e?.stopPropagation();
  if (!_openTicketId) return;
  try {
    await api.tickets.update(state.currentProject.id, _openTicketId, { status });
    state.tickets = await api.tickets.list(state.currentProject.id).catch(() => state.tickets);
    renderTickets();
    openTicketModal(_openTicketId);
  } catch(e) { showToast(e.message, 'error'); }
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('ticket-modal')?.addEventListener('click', e => {
    if (e.target === e.currentTarget) closeTicketModal();
  });
});

window.renderTickets       = renderTickets;
window.setTicketFilter     = setTicketFilter;
window.openTicketModal     = openTicketModal;
window.closeTicketModal    = closeTicketModal;
window.submitTicketReply   = submitTicketReply;
window.changeTicketStatus  = changeTicketStatus;
