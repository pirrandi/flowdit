// ── components/task-ui.js — shared bits of the Tasks / My tasks pages ─
// Every user-supplied value (titles, usernames, hosts, finding names) goes
// through esc() before it reaches innerHTML.

const TASK_STATUSES       = ['pending', 'in_progress', 'done'];
const TASK_STATUS_LABEL   = { pending: 'Pendiente', in_progress: 'En curso', done: 'Hecha' };
const TASK_STATUS_COLOR   = { pending: 'var(--t3)', in_progress: 'var(--a)', done: 'var(--c-low)' };
const TASK_PRIORITY_LABEL = { low: 'Baja', medium: 'Media', high: 'Alta' };
const TASK_PRIORITY_RANK  = { high: 0, medium: 1, low: 2 };

function _todayIso() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function taskIsOverdue(t) {
  return !!t.due_date && t.status !== 'done' && t.due_date < _todayIso();
}

// due_date arrives as a plain 'YYYY-MM-DD' (backend DATE parser), so parse it
// as a local date — new Date('YYYY-MM-DD') would be UTC midnight and can
// show the previous day west of Greenwich.
function taskDueLabel(t) {
  if (!t.due_date) return '';
  const [y, m, d] = t.due_date.split('-').map(Number);
  return new Date(y, m - 1, d).toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
}

function taskPriorityChip(t) {
  const p = TASK_PRIORITY_LABEL[t.priority] ? t.priority : 'medium';
  return `<span class="task-chip task-prio-${p}">${TASK_PRIORITY_LABEL[p]}</span>`;
}

function taskDueChip(t) {
  if (!t.due_date) return '';
  const overdue = taskIsOverdue(t);
  return `<span class="task-chip ${overdue ? 'task-overdue' : ''}" title="${overdue ? 'Vencida' : 'Vencimiento'}">${icon('calendar', { size: 10 })} ${esc(taskDueLabel(t))}</span>`;
}

function taskLinkChips(t) {
  return [
    t.target_host  ? `<span class="task-chip" title="Target">${esc(t.target_host)}</span>` : '',
    t.vuln_name    ? `<span class="task-chip" title="Hallazgo">${esc(t.vuln_name)}</span>` : '',
    t.wstg_test_id ? `<span class="task-chip" title="Prueba WSTG">${esc(t.wstg_test_id)}</span>` : '',
  ].join('');
}

// Status <select>. `handler` is the name of a global function taking
// (projectId, taskId, newStatus) — ids are server UUIDs, still escaped.
function taskStatusSelect(t, handler) {
  return `<select class="task-status-select" onclick="event.stopPropagation()"
      onchange="${handler}('${esc(t.project_id)}','${esc(t.id)}',this.value)">
      ${TASK_STATUSES.map(s => `<option value="${s}" ${s === t.status ? 'selected' : ''}>${TASK_STATUS_LABEL[s]}</option>`).join('')}
    </select>`;
}

function taskStatusBadge(status) {
  const c = TASK_STATUS_COLOR[status] || 'var(--t3)';
  return `<span class="ticket-status-badge" style="color:${c};border-color:${c}">${TASK_STATUS_LABEL[status] || esc(status)}</span>`;
}

window.taskIsOverdue    = taskIsOverdue;
window.taskDueLabel     = taskDueLabel;
window.taskPriorityChip = taskPriorityChip;
window.taskDueChip      = taskDueChip;
window.taskLinkChips    = taskLinkChips;
window.taskStatusSelect = taskStatusSelect;
window.taskStatusBadge  = taskStatusBadge;
