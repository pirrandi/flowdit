// Project tasks — a lead assigns work to a team member. The "instructions"
// are the task's description plus its comment thread.
//
// Permissions (server-side; the UI only mirrors them):
//   read            writers only (owner|editor|pentester). A viewer is the client-side
//                   account, so internal instructions never reach it; portal denied too
//   create / edit / assign / delete   lead only (owner|editor)
//   change status / comment           the assignee OR a lead
const router = require('express').Router({ mergeParams: true });
const { body, validationResult } = require('express-validator');
const db       = require('../db');
const activity = require('../services/activity');
const { notify } = require('../services/notifications');
const { requireAuth, requireUser } = require('../middleware/auth');
const { requireProjectAccess, findProjectForUser, requireWriter, requireLead, isLeadRole } = require('../middleware/project');
const { targetBelongsToProject, vulnBelongsToProject } = require('../services/ownership');

const STATUSES   = ['pending', 'in_progress', 'done'];
const PRIORITIES = ['low', 'medium', 'high'];
// Roles that can be handed work. A viewer is the client-side account, so it
// can't be an assignee even though it is a project member.
const ASSIGNABLE_ROLES = ['owner', 'editor', 'pentester'];
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const WSTG_RE = /^WSTG-[A-Z]{2,6}-\d{2}$/;
// Fields only a lead may set. Status is handled separately (assignee or lead).
const LEAD_FIELDS = ['title', 'description', 'priority', 'due_date', 'assignee_id', 'target_id', 'vuln_id', 'wstg_test_id'];

// Portal sessions and viewers are the client side: deny-by-default, before any lookup.
router.use(requireAuth, requireUser, requireProjectAccess, requireWriter);

// A malformed id would otherwise reach Postgres as an invalid uuid cast (500).
router.param('taskId', (req, res, next, id) => {
  if (!UUID_RE.test(id)) return res.status(404).json({ error: 'Task not found' });
  next();
});

const TASK_SELECT = `
  SELECT t.*,
         a.username AS assignee_username, a.display_name AS assignee_display_name, a.avatar_color AS assignee_color, a.avatar_url AS assignee_avatar_url,
         c.username AS created_by_username, c.display_name AS created_by_display_name,
         tg.host AS target_host,
         v.name AS vuln_name,
         (SELECT COUNT(*) FROM task_comments tc WHERE tc.task_id = t.id)::int AS comment_count
  FROM project_tasks t
  LEFT JOIN users a  ON a.id  = t.assignee_id
  LEFT JOIN users c  ON c.id  = t.created_by
  LEFT JOIN targets tg ON tg.id = t.target_id
  LEFT JOIN custom_vulns v ON v.id = t.vuln_id`;

const nullable = { values: 'falsy' };
const fieldValidators = [
  body('description').optional({ values: 'null' }).isString().isLength({ max: 20000 }),
  body('priority').optional().isIn(PRIORITIES),
  body('status').optional().isIn(STATUSES),
  body('assignee_id').optional(nullable).isUUID(),
  body('due_date').optional(nullable).isISO8601({ strict: true }),
  body('target_id').optional(nullable).isUUID(),
  body('vuln_id').optional(nullable).isUUID(),
  body('wstg_test_id').optional(nullable).matches(WSTG_RE),
];

function validationFailed(req, res) {
  const errors = validationResult(req);
  if (errors.isEmpty()) return false;
  res.status(400).json({ errors: errors.array() });
  return true;
}

// Validates the optional links + assignee against THIS project. Returns an
// error message, or null when everything present is valid. Mutates `fields`
// to normalise empty values to null.
async function checkReferences(projectId, fields) {
  for (const k of ['assignee_id', 'due_date', 'target_id', 'vuln_id', 'wstg_test_id']) {
    if (k in fields && !fields[k]) fields[k] = null;
  }
  if (fields.assignee_id) {
    const p = await findProjectForUser(projectId, fields.assignee_id);
    if (!p || !ASSIGNABLE_ROLES.includes(p.member_role))
      return 'Assignee must be a member of the project (owner, editor or pentester)';
  }
  if (fields.target_id && !(await targetBelongsToProject(fields.target_id, projectId)))
    return 'Target does not belong to this project';
  if (fields.vuln_id && !(await vulnBelongsToProject(fields.vuln_id, projectId)))
    return 'Finding does not belong to this project';
  return null;
}

async function loadTask(taskId, projectId) {
  const { rows } = await db.query(`${TASK_SELECT} WHERE t.id = $1 AND t.project_id = $2`, [taskId, projectId]);
  return rows[0] || null;
}

const snippet = (s, n = 140) => (s || '').length > n ? `${s.slice(0, n - 1)}…` : (s || '');

function taskPayload(req, task, extra = {}) {
  return { task_title: snippet(task.title), project_name: req.project?.name || null, ...extra };
}

// GET /projects/:projectId/tasks?status=&assignee=me|<uuid>
router.get('/', async (req, res, next) => {
  const where = ['t.project_id = $1'];
  const values = [req.params.projectId];
  if (req.query.status) {
    if (!STATUSES.includes(req.query.status)) return res.status(400).json({ error: 'Invalid status' });
    values.push(req.query.status);
    where.push(`t.status = $${values.length}`);
  }
  if (req.query.assignee) {
    const who = req.query.assignee === 'me' ? req.user.id : req.query.assignee;
    if (!UUID_RE.test(who)) return res.status(400).json({ error: 'Invalid assignee' });
    values.push(who);
    where.push(`t.assignee_id = $${values.length}`);
  }
  try {
    const { rows } = await db.query(
      `${TASK_SELECT} WHERE ${where.join(' AND ')}
       ORDER BY CASE t.status WHEN 'done' THEN 1 ELSE 0 END,
                t.due_date ASC NULLS LAST,
                CASE t.priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                t.created_at DESC`,
      values
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// GET single task with its comment thread
router.get('/:taskId', async (req, res, next) => {
  try {
    const task = await loadTask(req.params.taskId, req.params.projectId);
    if (!task) return res.status(404).json({ error: 'Task not found' });
    const { rows: comments } = await db.query(
      `SELECT tc.id, tc.task_id, tc.user_id, tc.body, tc.created_at,
              u.username AS author_username, u.display_name AS author_display_name, u.avatar_color AS author_color, u.avatar_url AS author_avatar_url
       FROM task_comments tc
       LEFT JOIN users u ON u.id = tc.user_id
       WHERE tc.task_id = $1
       ORDER BY tc.created_at ASC`,
      [task.id]
    );
    res.json({ ...task, comments });
  } catch (err) { next(err); }
});

// POST create (lead only)
router.post('/', requireLead, [
  body('title').isString().trim().isLength({ min: 1, max: 300 }),
  ...fieldValidators,
], async (req, res, next) => {
  if (validationFailed(req, res)) return;
  const f = {};
  ['title', 'description', 'priority', 'status', ...LEAD_FIELDS].forEach(k => {
    if (req.body[k] !== undefined) f[k] = req.body[k];
  });
  try {
    const refError = await checkReferences(req.params.projectId, f);
    if (refError) return res.status(400).json({ error: refError });

    const status = f.status || 'pending';
    const { rows } = await db.query(
      `INSERT INTO project_tasks
         (project_id, title, description, status, priority, assignee_id, created_by,
          due_date, target_id, vuln_id, wstg_test_id, completed_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       RETURNING id`,
      [req.params.projectId, f.title, f.description || '', status, f.priority || 'medium',
       f.assignee_id || null, req.user.id, f.due_date || null, f.target_id || null,
       f.vuln_id || null, f.wstg_test_id || null, status === 'done' ? new Date() : null]
    );
    const task = await loadTask(rows[0].id, req.params.projectId);

    await activity.log({
      projectId: req.params.projectId, user: req.user, action: 'task_created',
      entityType: 'task', entityId: task.id, entityName: task.title,
      meta: { assignee: task.assignee_username || null },
    });
    if (task.assignee_id) {
      await notify({
        recipients: [task.assignee_id], actor: req.user, projectId: req.params.projectId,
        type: 'task_assigned', entityType: 'task', entityId: task.id,
        payload: taskPayload(req, task, { priority: task.priority, due_date: task.due_date }),
      });
    }
    res.status(201).json(task);
  } catch (err) { next(err); }
});

// PATCH update — lead-only fields need a lead; status needs the assignee or a lead
router.patch('/:taskId', [
  body('title').optional().isString().trim().isLength({ min: 1, max: 300 }),
  ...fieldValidators,
], async (req, res, next) => {
  if (validationFailed(req, res)) return;
  try {
    const task = await loadTask(req.params.taskId, req.params.projectId);
    if (!task) return res.status(404).json({ error: 'Task not found' });

    const lead       = isLeadRole(req.memberRole);
    const isAssignee = !!task.assignee_id && task.assignee_id === req.user.id;

    const f = {};
    LEAD_FIELDS.forEach(k => { if (req.body[k] !== undefined) f[k] = req.body[k]; });
    if (Object.keys(f).length && !lead)
      return res.status(403).json({ error: 'Only the project owner or an editor can edit or reassign a task' });
    if (req.body.status !== undefined) {
      if (!lead && !isAssignee)
        return res.status(403).json({ error: 'Only the assignee or a lead can change the status' });
      f.status = req.body.status;
    }
    if (!Object.keys(f).length) return res.status(400).json({ error: 'Nothing to update' });

    const refError = await checkReferences(req.params.projectId, f);
    if (refError) return res.status(400).json({ error: refError });

    const sets = [], values = [];
    Object.entries(f).forEach(([k, v]) => { values.push(v); sets.push(`${k}=$${values.length}`); });
    if (f.status !== undefined && f.status !== task.status)
      sets.push(f.status === 'done' ? 'completed_at=NOW()' : 'completed_at=NULL');
    sets.push('updated_at=NOW()');
    values.push(task.id, req.params.projectId);
    await db.query(
      `UPDATE project_tasks SET ${sets.join(', ')}
       WHERE id=$${values.length - 1} AND project_id=$${values.length}`,
      values
    );
    const updated = await loadTask(task.id, req.params.projectId);

    const reassigned = 'assignee_id' in f && f.assignee_id !== task.assignee_id;
    if (reassigned) {
      await activity.log({
        projectId: req.params.projectId, user: req.user, action: 'task_assigned',
        entityType: 'task', entityId: task.id, entityName: updated.title,
        meta: { assignee: updated.assignee_username || null },
      });
      if (updated.assignee_id) {
        await notify({
          recipients: [updated.assignee_id], actor: req.user, projectId: req.params.projectId,
          type: 'task_assigned', entityType: 'task', entityId: task.id,
          payload: taskPayload(req, updated, { priority: updated.priority, due_date: updated.due_date }),
        });
      }
    }
    if (f.status !== undefined && f.status !== task.status) {
      await activity.log({
        projectId: req.params.projectId, user: req.user, action: 'task_status_changed',
        entityType: 'task', entityId: task.id, entityName: updated.title,
        meta: { from: task.status, status: f.status },
      });
      if (f.status === 'done' && updated.created_by) {
        await notify({
          recipients: [updated.created_by], actor: req.user, projectId: req.params.projectId,
          type: 'task_done', entityType: 'task', entityId: task.id,
          payload: taskPayload(req, updated),
        });
      }
    }
    res.json(updated);
  } catch (err) { next(err); }
});

// DELETE (lead only) — also drops the inbox entries pointing at it
router.delete('/:taskId', requireLead, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `DELETE FROM project_tasks WHERE id=$1 AND project_id=$2 RETURNING id`,
      [req.params.taskId, req.params.projectId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Task not found' });
    await db.query(
      `DELETE FROM notifications WHERE entity_type='task' AND entity_id=$1`,
      [rows[0].id]
    );
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// POST comment — the assignee or a lead
router.post('/:taskId/comments', [
  body('body').isString().trim().isLength({ min: 1, max: 10000 }),
], async (req, res, next) => {
  if (validationFailed(req, res)) return;
  try {
    const task = await loadTask(req.params.taskId, req.params.projectId);
    if (!task) return res.status(404).json({ error: 'Task not found' });
    const isAssignee = !!task.assignee_id && task.assignee_id === req.user.id;
    if (!isLeadRole(req.memberRole) && !isAssignee)
      return res.status(403).json({ error: 'Only the assignee or a lead can comment on this task' });

    const { rows } = await db.query(
      `INSERT INTO task_comments (task_id, user_id, body) VALUES ($1,$2,$3) RETURNING *`,
      [task.id, req.user.id, req.body.body]
    );
    await db.query(`UPDATE project_tasks SET updated_at=NOW() WHERE id=$1`, [task.id]);

    await notify({
      recipients: [task.assignee_id, task.created_by], actor: req.user, projectId: req.params.projectId,
      type: 'task_comment', entityType: 'task', entityId: task.id,
      payload: taskPayload(req, task, { comment: snippet(req.body.body, 200) }),
    });
    res.status(201).json({
      ...rows[0],
      author_username: req.user.username,
      author_display_name: req.user.display_name || null,
      author_color: req.user.avatar_color,
      author_avatar_url: req.user.avatar_url || null,
    });
  } catch (err) { next(err); }
});

module.exports = router;
