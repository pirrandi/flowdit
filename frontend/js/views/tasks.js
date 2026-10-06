// ── views/tasks.js — per-project Tasks board ─────────────────────────
// Leads (owner/editor) create, edit, assign and delete; the assignee or a
// lead changes status and comments. These controls are hidden for everyone
// else, but that is cosmetic — the API enforces it.

let _taskFilter  = 'all';   // 'all' | 'mine'
let _openTaskId  = null;
let _editTaskId  = null;    // null = creating
let _tasksLoaded = false;

function _isLead() { return canActForClient(); }
function _canActOn(t) { return _isLead() || (!!t.assignee_id && t.assignee_id === state.user?.id); }

async function loadTasks() {
  try {
    state.tasks = await api.tasks.list(state.currentProject.id);
  } catch (e) {
    state.tasks = [];
    showToast(e.message, 'error');
  }
  _tasksLoaded = true;
}

async function renderTasks() {
  if (!_tasksLoaded) {
    await loadTasks();
    const deepLink = new URLSearchParams(window.location.search).get('task');
    if (deepLink) openTaskModal(deepLink);
  }
  const main = document.getElementById('tasks-main');
  if (!main) return;
  const all   = state.tasks || [];
  const mine  = all.filter(t => t.assignee_id === state.user?.id);
  const tasks = _taskFilter === 'mine' ? mine : all;

  document.getElementById('tasks-actions').innerHTML = `
    <div style="display:flex;gap:4px;background:var(--bg3);border:1px solid var(--b1);border-radius:8px;padding:3px">
      ${[['all', 'Todas', all.length], ['mine', 'Asignadas a mí', mine.length]].map(([key, label, n]) => `
        <button onclick="setTaskFilter('${key}')"
          style="font-family:var(--mono);font-size:11px;padding:4px 12px;border-radius:5px;border:none;cursor:pointer;
                 background:${_taskFilter === key ? 'var(--surface)' : 'transparent'};
                 color:${_taskFilter === key ? 'var(--t1)' : 'var(--t3)'}">
          ${label}${n ? ` <span style="opacity:.6">${n}</span>` : ''}
        </button>`).join('')}
    </div>
    ${_isLead() ? `<button class="btn-primary" onclick="openTaskForm()">${icon('plus', { size: 13 })} Nueva tarea</button>` : ''}`;

  if (!all.length) {
    main.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">${icon('list-checks', { size: 28 })}</div>
        <div class="empty-title">Todavía no hay tareas</div>
        <div class="empty-sub">${_isLead() ? 'Crea una tarea y asígnala a alguien del equipo' : 'Las tareas que te asignen aparecerán aquí'}</div>
      </div>`;
    return;
  }

  main.innerHTML = `<div class="task-board">${TASK_STATUSES.map(s => {
    const col = tasks.filter(t => t.status === s);
    return `
      <div class="task-col">
        <div class="task-col-head"><span style="color:${TASK_STATUS_COLOR[s]}">${TASK_STATUS_LABEL[s]}</span><span>${col.length}</span></div>
        ${col.length ? col.map(taskCardHtml).join('') : `<div style="font-family:var(--mono);font-size:10px;color:var(--t3);padding:8px 2px">Sin tareas</div>`}
      </div>`;
  }).join('')}</div>`;
}

function taskCardHtml(t) {
  const assigneeName = displayName(t, 'assignee_', '');
  const assignee = assigneeName
    ? `<span style="display:inline-flex;align-items:center;gap:4px">${avatarHtml(assigneeName, memberRoleColor(t.assignee_id, t.assignee_color), 16, t.assignee_avatar_url)} ${esc(assigneeName)}</span>`
    : `<span>Sin asignar</span>`;
  return `
    <div class="task-card" onclick="openTaskModal('${esc(t.id)}')">
      <div class="task-card-title">${esc(t.title)}</div>
      <div class="task-card-meta">${taskPriorityChip(t)}${taskDueChip(t)}${taskLinkChips(t)}</div>
      <div class="task-card-meta" style="justify-content:space-between">
        ${assignee}
        <span style="display:inline-flex;align-items:center;gap:6px">
          ${t.comment_count ? `<span>${icon('message-square', { size: 10 })} ${t.comment_count}</span>` : ''}
          ${_canActOn(t) ? taskStatusSelect(t, 'changeTaskStatus') : ''}
        </span>
      </div>
    </div>`;
}

function setTaskFilter(f) { _taskFilter = f; renderTasks(); }

async function changeTaskStatus(projectId, taskId, status) {
  try {
    await api.tasks.update(projectId, taskId, { status });
    await loadTasks();
    renderTasks();
    if (_openTaskId === taskId) openTaskModal(taskId);
  } catch (e) { showToast(e.message, 'error'); renderTasks(); }
}

// ── DETAIL MODAL ──────────────────────────────────────────────────────
async function openTaskModal(taskId) {
  const pid = state.currentProject.id;
  const t = await api.tasks.get(pid, taskId).catch(e => { showToast(e.message, 'error'); return null; });
  if (!t) return;
  _openTaskId = t.id;

  document.getElementById('task-modal-title').textContent = t.title;
  document.getElementById('task-modal-meta').innerHTML = [
    taskStatusBadge(t.status),
    taskPriorityChip(t),
    taskDueChip(t),
    `<span>Asignada a <strong>${esc(displayName(t, 'assignee_', 'nadie'))}</strong></span>`,
    `<span>· creada por ${esc(displayName(t, 'created_by_', '—'))} · ${esc(relativeDate(t.created_at))}</span>`,
    taskLinkChips(t),
  ].join(' ');

  const canAct = _canActOn(t);
  document.getElementById('task-modal-actions').innerHTML = [
    canAct ? taskStatusSelect(t, 'changeTaskStatus') : '',
    _isLead() ? `<button class="btn-icon edit" title="Editar" onclick="openTaskForm('${esc(t.id)}')">${icon('pencil', { size: 13 })}</button>` : '',
    _isLead() ? `<button class="btn-icon delete" title="Eliminar" onclick="deleteTask('${esc(t.id)}')">${icon('trash-2', { size: 13 })}</button>` : '',
  ].join('');

  // renderMd escapes its input (see utils.js) before applying the subset.
  document.getElementById('task-modal-desc').innerHTML = t.description
    ? renderMd(t.description)
    : `<span style="color:var(--t3);font-family:var(--mono);font-size:11px">Sin indicaciones</span>`;
  renderTaskThread(t.comments || []);

  document.getElementById('task-comment-input').value = '';
  document.getElementById('task-comment-box').style.display = canAct ? '' : 'none';
  document.getElementById('task-comment-readonly').style.display = canAct ? 'none' : '';
  document.getElementById('task-modal').classList.add('open');
}

function closeTaskModal() {
  document.getElementById('task-modal').classList.remove('open');
  _openTaskId = null;
}

function renderTaskThread(comments) {
  const thread = document.getElementById('task-modal-thread');
  if (!comments.length) {
    thread.innerHTML = `<div style="font-family:var(--mono);font-size:11px;color:var(--t3);padding:6px 0">Sin comentarios todavía.</div>`;
    return;
  }
  thread.innerHTML = comments.map(c => {
    const name  = displayName(c, 'author_', 'Usuario eliminado');
    const isMe  = c.user_id && c.user_id === state.user?.id;
    const color = memberRoleColor(c.user_id, c.author_color);
    return `
      <div style="display:flex;gap:8px;${isMe ? 'flex-direction:row-reverse' : ''}">
        ${avatarHtml(name, color, 26, c.author_avatar_url || null)}
        <div style="max-width:80%;display:flex;flex-direction:column;gap:3px;${isMe ? 'align-items:flex-end' : ''}">
          <div style="font-family:var(--mono);font-size:10px;color:var(--t3)">${esc(name)} · ${esc(relativeDate(c.created_at))}</div>
          <div style="background:${isMe ? 'var(--a-dim)' : 'var(--bg3)'};border:1px solid var(--b1);border-radius:8px;padding:9px 13px;font-size:13px;line-height:1.6;white-space:pre-wrap;color:var(--t1);word-break:break-word">${esc(c.body)}</div>
        </div>
      </div>`;
  }).join('');
}

async function submitTaskComment() {
  const input = document.getElementById('task-comment-input');
  const body = input.value.trim();
  if (!body || !_openTaskId) return;
  try {
    await api.tasks.comment(state.currentProject.id, _openTaskId, body);
    input.value = '';
    const t = await api.tasks.get(state.currentProject.id, _openTaskId);
    renderTaskThread(t.comments || []);
    await loadTasks();
    renderTasks();
  } catch (e) { showToast(e.message, 'error'); }
}

async function deleteTask(taskId) {
  if (!confirm('¿Eliminar esta tarea? Esta acción no se puede deshacer.')) return;
  try {
    await api.tasks.delete(state.currentProject.id, taskId);
    closeTaskModal();
    await loadTasks();
    renderTasks();
    showToast('Tarea eliminada', 'success');
  } catch (e) { showToast(e.message, 'error'); }
}

// ── CREATE / EDIT FORM (leads) ────────────────────────────────────────
function _options(list, selected, emptyLabel) {
  return `<option value="">${esc(emptyLabel)}</option>` + list.map(([v, label]) =>
    `<option value="${esc(v)}" ${v === selected ? 'selected' : ''}>${esc(label)}</option>`).join('');
}

async function openTaskForm(taskId = null) {
  _editTaskId = taskId;
  let t = {};
  if (taskId) {
    t = await api.tasks.get(state.currentProject.id, taskId).catch(e => { showToast(e.message, 'error'); return null; });
    if (!t) return;
  }
  const assignable = (state.members || []).filter(m => ['owner', 'editor', 'pentester'].includes(m.role));
  const wstgTests = typeof WSTG_DATA !== 'undefined'
    ? WSTG_DATA.flatMap(cat => cat.tests.map(x => [x.id, `${x.id} — ${x.name}`])) : [];

  document.getElementById('task-form-title').textContent = taskId ? 'Editar tarea' : 'Nueva tarea';
  document.getElementById('tf-title').value    = t.title || '';
  document.getElementById('tf-desc').value     = t.description || '';
  document.getElementById('tf-priority').value = t.priority || 'medium';
  document.getElementById('tf-due').value      = t.due_date || '';
  document.getElementById('tf-assignee').innerHTML =
    _options(assignable.map(m => [m.id, `${displayName(m)} (${m.role})`]), t.assignee_id || '', 'Sin asignar');
  document.getElementById('tf-target').innerHTML =
    _options((state.targets || []).map(x => [x.id, x.host]), t.target_id || '', 'Ninguno');
  document.getElementById('tf-vuln').innerHTML =
    _options((state.customVulns || []).map(x => [x.id, x.name]), t.vuln_id || '', 'Ninguno');
  document.getElementById('tf-wstg').innerHTML = _options(wstgTests, t.wstg_test_id || '', 'Ninguna');
  document.getElementById('tf-error').textContent = '';
  document.getElementById('task-form-modal').classList.add('open');
  setTimeout(() => document.getElementById('tf-title').focus(), 50);
}

function closeTaskForm() {
  document.getElementById('task-form-modal').classList.remove('open');
  _editTaskId = null;
}

async function saveTaskForm() {
  const val = id => document.getElementById(id).value;
  const errEl = document.getElementById('tf-error');
  const btn = document.getElementById('tf-save-btn');
  const data = {
    title:        val('tf-title').trim(),
    description:  val('tf-desc'),
    priority:     val('tf-priority'),
    due_date:     val('tf-due') || null,
    assignee_id:  val('tf-assignee') || null,
    target_id:    val('tf-target') || null,
    vuln_id:      val('tf-vuln') || null,
    wstg_test_id: val('tf-wstg') || null,
  };
  errEl.textContent = '';
  if (!data.title) { errEl.textContent = 'El título es obligatorio.'; return; }
  btn.disabled = true;
  try {
    const pid = state.currentProject.id;
    const saved = _editTaskId
      ? await api.tasks.update(pid, _editTaskId, data)
      : await api.tasks.create(pid, data);
    closeTaskForm();
    await loadTasks();
    renderTasks();
    if (_openTaskId === saved.id) openTaskModal(saved.id);
    showToast(_editTaskId ? 'Tarea actualizada' : 'Tarea creada', 'success');
  } catch (e) {
    errEl.textContent = e.message;
  } finally {
    btn.disabled = false;
  }
}

// Another member created/changed a task in this project → refresh the board.
wsClient.on('activity', (event) => {
  if (event.entity_type !== 'task' || state.currentView !== 'tasks') return;
  loadTasks().then(renderTasks);
});

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('task-modal')?.addEventListener('click', e => {
    if (e.target === e.currentTarget) closeTaskModal();
  });
  document.getElementById('task-form-modal')?.addEventListener('click', e => {
    if (e.target === e.currentTarget) closeTaskForm();
  });
});

window.renderTasks       = renderTasks;
window.setTaskFilter     = setTaskFilter;
window.changeTaskStatus  = changeTaskStatus;
window.openTaskModal     = openTaskModal;
window.closeTaskModal    = closeTaskModal;
window.submitTaskComment = submitTaskComment;
window.deleteTask        = deleteTask;
window.openTaskForm      = openTaskForm;
window.closeTaskForm     = closeTaskForm;
window.saveTaskForm      = saveTaskForm;
