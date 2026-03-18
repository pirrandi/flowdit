const router = require('express').Router({ mergeParams: true });
const db = require('../db');
const { requireAuth } = require('../middleware/auth');
const { requireProjectAccess } = require('../middleware/project');

router.use(requireAuth, requireProjectAccess);

// GET /projects/:projectId/activity?limit=50&offset=0
router.get('/', async (req, res, next) => {
  const limit  = Math.min(parseInt(req.query.limit)  || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const { rows } = await db.query(
      `SELECT al.id, al.action, al.entity_type, al.entity_id, al.entity_name,
              al.meta, al.created_at,
              u.id AS user_id, u.username, u.avatar_color, u.avatar_url
       FROM activity_log al
       JOIN users u ON u.id = al.user_id
       WHERE al.project_id = $1
       ORDER BY al.created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.params.projectId, limit, offset]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

module.exports = router;
