// ── views/my-tasks.js — tasks assigned to me across all my projects ──

let _myTasks       = [];
let _myIncludeDone = false;
let _mySort        = 'due';   // 'due' | 'priority' | 'project'

async function loadMyTasks() {
  try { _myTasks = await api.me.tasks(_myIncludeDone); }
  catch (e) { _myTasks = []; showToast(e.message, 'error'); }
}

function _sortedMyTasks() {
  const due  = t => t.due_date || '9999-12-31';
  const prio = t => TASK_PRIORITY_RANK[t.priority] ?? 1;
  const cmp = {
    due:      (a, b) => due(a).localeCompare(due(b)) || prio(a) - prio(b),
    priority: (a, b) => prio(a) - prio(b) || due(a).localeCompare(due(b)),
    project:  (a, b) => (a.project_name || '').localeCompare(b.project_name || '') || due(a).localeCompare(due(b)),
  }[_mySort];
  return [..._myTasks].sort((a, b) => (a.status === 'done') - (b.status === 'done') || cmp(a, b));
}

async function renderMyTasks(reload = true) {
  if (reload) await loadMyTasks();
  const actions = document.getElementById('my-tasks-actions');
  const main = document.getElementById('my-tasks-main');
  if (!main) return;

  actions.innerHTML = `
    <label style="font-family:var(--mono);font-size:11px;color:var(--t3);display:flex;align-items:center;gap:6px">
      Ordenar por
      <select class="task-status-select" onchange="setMyTasksSort(this.value)">
        ${[['due', 'Vencimiento'], ['priority', 'Prioridad'], ['project', 'Proyecto']].map(([v, l]) =>
          `<option value="${v}" ${v === _mySort ? 'selected' : ''}>${l}</option>`).join('')}
      </select>
    </label>
    <label style="font-family:var(--mono);font-size:11px;color:var(--t3);display:flex;align-items:center;gap:6px;cursor:pointer">
      <input type="checkbox" ${_myIncludeDone ? 'checked' : ''} onchange="toggleMyTasksDone(this.checked)"> Mostrar hechas
    </label>`;

  if (!_myTasks.length) {
    main.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">${icon('list-checks', { size: 28 })}</div>
        <div class="empty-title">No tienes tareas ${_myIncludeDone ? '' : 'pendientes'}</div>
        <div class="empty-sub">Cuando alguien te asigne una tarea aparecerá aquí</div>
      </div>`;
    return;
  }

  main.innerHTML = `<div class="tickets-list">${_sortedMyTasks().map(t => `
    <div class="task-row">
      <div class="ticket-row-status-dot" style="background:${TASK_STATUS_COLOR[t.status] || 'var(--t3)'}"></div>
      <div class="task-row-body" onclick="openMyTask('${esc(t.project_id)}','${esc(t.id)}')">
        <span class="ticket-row-title">${esc(t.title)}</span>
        <div class="task-card-meta">
          <span class="task-chip" title="Proyecto">${esc(t.project_name)}</span>
          ${taskPriorityChip(t)}${taskDueChip(t)}${taskLinkChips(t)}
          ${t.comment_count ? `<span>${icon('message-square', { size: 10 })} ${t.comment_count}</span>` : ''}
          ${t.created_by_username ? `<span>· de ${esc(displayName(t, 'created_by_'))}</span>` : ''}
        </div>
      </div>
      ${taskStatusSelect(t, 'changeMyTaskStatus')}
    </div>`).join('')}</div>`;
}

function setMyTasksSort(v) { _mySort = v; renderMyTasks(false); }
function toggleMyTasksDone(on) { _myIncludeDone = on; renderMyTasks(); }

function openMyTask(projectId, taskId) {
  window.location.href = `tasks?pid=${encodeURIComponent(projectId)}&task=${encodeURIComponent(taskId)}`;
}

async function changeMyTaskStatus(projectId, taskId, status) {
  try {
    await api.tasks.update(projectId, taskId, { status });
    showToast(`Estado: ${TASK_STATUS_LABEL[status]}`, 'success');
  } catch (e) { showToast(e.message, 'error'); }
  renderMyTasks();
}

// A new assignment (or comment) landed → refresh the list.
window.addEventListener('fd:notification', (e) => {
  if (e.detail?.entity_type === 'task') renderMyTasks();
});

window.renderMyTasks      = renderMyTasks;
window.setMyTasksSort     = setMyTasksSort;
window.toggleMyTasksDone  = toggleMyTasksDone;
window.openMyTask         = openMyTask;
window.changeMyTaskStatus = changeMyTaskStatus;
