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
  const ic = type === 'success' ? 'circle-check' : type === 'error' ? 'circle-x' : 'info';
  t.innerHTML = `<span>${icon(ic, { size: 14 })}</span> ${esc(msg)}`;
  c.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

function copyText(btn, encoded) {
  navigator.clipboard.writeText(decodeURIComponent(atob(encoded))).then(() => {
    btn.innerHTML = icon('check', { size: 12 }); btn.classList.add('copied');
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

// ── Role-based avatar colors ──────────────────────────────────────
const ROLE_COLOR = { owner:'#dc2626', editor:'#059669', viewer:'#2563eb' };
function roleColor(role) { return ROLE_COLOR[role] || '#7c3aed'; }

// Role color for a user by ID (looks up state.members)
function memberRoleColor(userId, fallback) {
  const m = (typeof state !== 'undefined' ? state.members || [] : []).find(m => m.id === userId);
  return m ? roleColor(m.role) : (fallback || '#7c3aed');
}

function avatarHtml(username, color, size = 24, avatarUrl = null) {
  const s = `width:${size}px;height:${size}px;font-size:${Math.round(size*0.42)}px`;
  const c = esc(color || '#7c3aed');
  if (avatarUrl) {
    return `<div class="avatar-sm" style="${s};background:${c};overflow:hidden;padding:0;box-shadow:0 0 0 2px ${c}"><img src="${esc(avatarUrl)}" style="width:100%;height:100%;object-fit:cover;border-radius:50%"></div>`;
  }
  return `<div class="avatar-sm" style="${s};background:${c}">${(username||'?')[0].toUpperCase()}</div>`;
}

function actionLabel(action, entityType, entityName, meta) {
  const name = `<span class="hl">${esc(entityName || '')}</span>`;
  switch (action) {
    case 'set_status':
      if (meta?.status === 'done')    return `marked ${name} as <span class="activity-status-pill pill-done">${icon('check',{size:10})} done</span>`;
      if (meta?.status === 'fail')    return `flagged ${name} as <span class="activity-status-pill pill-fail">${icon('x',{size:10})} vuln</span>`;
      return `cleared status on ${name}`;
    case 'add_note':    return `added notes to ${name}`;
    case 'remediation_status_changed':
      if (meta?.remediation_status === 'remediated')       return `marked ${name} as <span class="activity-status-pill pill-done">remediated</span>`;
      if (meta?.remediation_status === 'verified_closed')  return `verified ${name} as <span class="activity-status-pill pill-done">closed</span>`;
      if (meta?.remediation_status === 'not_remediated')   return `marked ${name} as <span class="activity-status-pill pill-fail">${icon('x',{size:10})} not remediated</span>`;
      return `reopened ${name}`;
    case 'lab_completed': return `completed lab ${name}`;
    case 'vuln_created':
      // Pedido explícito: en un entorno colaborativo, "dvalencia added
      // custom vuln X" sin más hace parecer que lo escribió a mano — este
      // badge distingue que lo encontró el AI Agent (dvalencia solo
      // aprobó), sin sacarle el crédito de la aprobación al actor. Mismo
      // estilo que el badge "AI" ya usado en la lista de Findings (vulns.js).
      return `added custom vuln ${name}` + (meta?.ai_generated
        ? `<span style="font-family:var(--mono);font-size:10px;font-weight:600;color:var(--a);background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.3);border-radius:4px;padding:1px 7px;margin-left:6px;display:inline-flex;align-items:center;gap:3px" title="Propuesto por el AI Agent">${icon('sparkles',{size:10})}AI</span>`
        : '');
    case 'vuln_deleted':  return `deleted ${name}`;
    case 'target_added': return `added target ${name}`
    case 'target_removed': return `deleted target ${name}`
    case 'target_updated': return `updated target ${name}`
    case 'invite_created': return `created an invite link`;
    case 'member_joined':  return `joined the project`;
    case 'ai_scan_started':  return `started an AI Agent scan`;
    case 'ai_scan_deleted':  return `deleted an AI Agent scan session`;
    // El único aviso real que dispara el modo autónomo del agente (ver
    // AI_PENTEST_AGENT.md § Notificaciones) — se frenó de verdad y
    // necesita que alguien mire. `meta.message` trae el motivo puntual
    // (gate pendiente, o se acabó el presupuesto de auto-continues).
    case 'ai_scan_needs_attention':
      return `<span style="color:var(--a)">${icon('triangle-alert',{size:10})} ${esc(meta?.message || 'El AI Agent necesita tu atención')}</span>`;
    default: return `updated ${name}`;
  }
}

// ── Markdown renderer (subset: code blocks, inline code, bold, italic, headers, lists) ──
function _applyInline(text) {
  return esc(text)
    .replace(/\*\*([^*<>]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*<>]+)\*/g, '<em>$1</em>');
}

function _inlineMd(text) {
  const parts = [];
  const re = /`([^`]+)`/g;
  let last = 0, m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) parts.push(_applyInline(text.slice(last, m.index)));
    parts.push(`<code class="md-ic">${esc(m[1])}</code>`);
    last = m.index + m[0].length;
  }
  if (last < text.length) parts.push(_applyInline(text.slice(last)));
  return parts.join('');
}

function renderMd(raw) {
  if (!raw) return '';
  const lines = raw.split('\n');
  const out = [];
  let inCode = false, codeLines = [], tableRows = [];

  function flushTable() {
    if (!tableRows.length) return;
    // First row = header, second = separator (skip), rest = data
    const [head, , ...body] = tableRows;
    const cols = head.split('|').slice(1,-1).map(c => c.trim());
    let t = `<table class="rpt-table" style="margin:8px 0">`;
    t += `<thead><tr>${cols.map(c => `<th>${_inlineMd(c)}</th>`).join('')}</tr></thead>`;
    t += `<tbody>${body.map(row => {
      const cells = row.split('|').slice(1,-1).map(c => c.trim());
      return `<tr>${cells.map((c,i) => i < cols.length ? `<td>${_inlineMd(c)}</td>` : '').join('')}</tr>`;
    }).join('')}</tbody></table>`;
    out.push(t);
    tableRows = [];
  }

  for (const line of lines) {
    if (!inCode && line.startsWith('```')) { flushTable(); inCode = true; codeLines = []; continue; }
    if (inCode) {
      if (line.startsWith('```')) {
        inCode = false;
        out.push(`<pre class="md-pre"><code>${esc(codeLines.join('\n'))}</code></pre>`);
        codeLines = [];
      } else codeLines.push(line);
      continue;
    }
    // Table rows
    if (/^\|.+\|/.test(line)) { tableRows.push(line); continue; }
    if (tableRows.length) flushTable();

    if (line.startsWith('### ')) { out.push(`<div class="md-h3">${_inlineMd(line.slice(4))}</div>`); continue; }
    if (line.startsWith('## '))  { out.push(`<div class="md-h2">${_inlineMd(line.slice(3))}</div>`); continue; }
    if (line.startsWith('# '))   { out.push(`<div class="md-h2">${_inlineMd(line.slice(2))}</div>`); continue; }
    if (/^[-*] /.test(line))     { out.push(`<div class="md-li">${_inlineMd(line.slice(2))}</div>`); continue; }
    if (line.trim() === '')      { out.push('<div class="md-gap"></div>'); continue; }
    out.push(`<div class="md-line">${_inlineMd(line)}</div>`);
  }
  if (inCode) out.push(`<pre class="md-pre"><code>${esc(codeLines.join('\n'))}</code></pre>`);
  flushTable();
  return out.join('');
}

window.esc             = esc;
window.hide            = hide;
window.show            = show;
window.showToast       = showToast;
window.copyText        = copyText;
window.timeAgo         = timeAgo;
window.relativeDate    = relativeDate;
window.ROLE_COLOR      = ROLE_COLOR;
window.roleColor       = roleColor;
window.avatarHtml      = avatarHtml;
window.actionLabel     = actionLabel;
window.renderMd        = renderMd;
window.memberRoleColor = memberRoleColor;
