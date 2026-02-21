// ── utils.js ─────────────────────────────────────────────────────────

function esc(s) {
  if (typeof s !== 'string') return '';
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function hide(id) { const el = document.getElementById(id); if (el) el.style.display = 'none'; }
function show(id) { const el = document.getElementById(id); if (el) el.style.display = ''; }

function showToast(msg, type = 'success') {
  const c = document.getElementById('toast-container');
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.innerHTML = `<span>${type==='success'?'✓':type==='error'?'✕':'ℹ'}</span> ${esc(msg)}`;
  c.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

function copyText(btn, encoded) {
  navigator.clipboard.writeText(decodeURIComponent(atob(encoded))).then(() => {
    btn.textContent = '✓'; btn.classList.add('copied');
    setTimeout(() => { btn.textContent = 'copy'; btn.classList.remove('copied'); }, 1500);
  });
}

function timeAgo(dateStr) {
  const diff = Date.now() - new Date(dateStr).getTime();
  if (diff < 60000)  return 'just now';
  if (diff < 3600000) return `${Math.floor(diff/60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff/3600000)}h ago`;
  return `${Math.floor(diff/86400000)}d ago`;
}

function relativeDate(dateStr) {
  if (!dateStr) return '';
  return new Date(dateStr).toLocaleDateString(undefined, { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' });
}

function avatarHtml(username, color, size = 24) {
  const letter = (username || '?')[0].toUpperCase();
  return `<div class="avatar-sm" style="width:${size}px;height:${size}px;background:${esc(color||'#7c3aed')};font-size:${Math.round(size*0.42)}px">${letter}</div>`;
}

function actionLabel(action, entityType, entityName, meta) {
  const name = `<span class="hl">${esc(entityName || '')}</span>`;
  switch (action) {
    case 'set_status':
      if (meta?.status === 'done')    return `marked ${name} as <span class="activity-status-pill pill-done">✓ done</span>`;
      if (meta?.status === 'fail')    return `flagged ${name} as <span class="activity-status-pill pill-fail">✕ vuln</span>`;
      return `cleared status on ${name}`;
    case 'add_note':    return `added notes to ${name}`;
    case 'lab_completed': return `completed lab ${name}`;
    case 'vuln_created':  return `added custom vuln ${name}`;
    case 'vuln_deleted':  return `deleted ${name}`;
    case 'invite_created': return `created an invite link`;
    case 'member_joined':  return `<strong>${esc(entityName)}</strong> joined the project`;
    default: return `updated ${name}`;
  }
}

window.esc         = esc;
window.hide        = hide;
window.show        = show;
window.showToast   = showToast;
window.copyText    = copyText;
window.timeAgo     = timeAgo;
window.relativeDate = relativeDate;
window.avatarHtml  = avatarHtml;
window.actionLabel = actionLabel;
