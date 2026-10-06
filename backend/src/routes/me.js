// Cross-project views of the current user's own work.
const router = require('express').Router();
const db = require('../db');
const { requireAuth, requireUser } = require('../middleware/auth');
const { projectAccessSql } = require('../services/ownership');

router.use(requireAuth, requireUser);

// GET /me/tasks?include_done=1 — tasks assigned to me, in every project I can
// still access (an assignment in a project I was removed from is not listed).
router.get('/tasks', async (req, res, next) => {
  const includeDone = req.query.include_done === '1' || req.query.include_done === 'true';
  try {
    const { rows } = await db.query(
      `SELECT t.*, p.name AS project_name,
              c.username AS created_by_username, c.display_name AS created_by_display_name,
              tg.host AS target_host, v.name AS vuln_name,
              (SELECT COUNT(*) FROM task_comments tc WHERE tc.task_id = t.id)::int AS comment_count
       FROM project_tasks t
       JOIN projects p ON p.id = t.project_id
       LEFT JOIN users c ON c.id = t.created_by
       LEFT JOIN targets tg ON tg.id = t.target_id
       LEFT JOIN custom_vulns v ON v.id = t.vuln_id
       WHERE t.assignee_id = $1
         AND ${projectAccessSql('t.project_id', '$1')}
         ${includeDone ? '' : `AND t.status <> 'done'`}
       ORDER BY CASE t.status WHEN 'done' THEN 1 ELSE 0 END,
                t.due_date ASC NULLS LAST,
                CASE t.priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                t.created_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

module.exports = router;
