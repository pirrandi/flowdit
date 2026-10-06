// Per-user notification inbox. Every query is pinned to req.user.id, so a user
// can only ever see or mark their own notifications. Project-scoped entries
// are also hidden once the user loses access to that project.
const router = require('express').Router();
const db = require('../db');
const { requireAuth, requireUser } = require('../middleware/auth');
const { projectAccessSql } = require('../services/ownership');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

router.use(requireAuth, requireUser);

const VISIBLE = `n.user_id = $1 AND (n.project_id IS NULL OR ${projectAccessSql('n.project_id', '$1')})`;

// GET /notifications?limit=20&offset=0&unread=1 — newest first
router.get('/', async (req, res, next) => {
  const limit  = Math.min(Math.max(parseInt(req.query.limit) || 20, 1), 100);
  const offset = Math.max(parseInt(req.query.offset) || 0, 0);
  const unread = req.query.unread === '1' || req.query.unread === 'true';
  try {
    const { rows } = await db.query(
      `SELECT n.*, a.username AS actor_username, a.display_name AS actor_display_name, a.avatar_color AS actor_color
       FROM notifications n
       LEFT JOIN users a ON a.id = n.actor_id
       WHERE ${VISIBLE} ${unread ? 'AND n.read_at IS NULL' : ''}
       ORDER BY n.created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.user.id, limit, offset]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

router.get('/unread-count', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT COUNT(*)::int AS count FROM notifications n WHERE ${VISIBLE} AND n.read_at IS NULL`,
      [req.user.id]
    );
    res.json({ count: rows[0].count });
  } catch (err) { next(err); }
});

router.post('/read-all', async (req, res, next) => {
  try {
    const { rowCount } = await db.query(
      `UPDATE notifications SET read_at = NOW() WHERE user_id = $1 AND read_at IS NULL`,
      [req.user.id]
    );
    res.json({ updated: rowCount });
  } catch (err) { next(err); }
});

// Someone else's id answers 404, same as a missing one — no existence oracle.
router.post('/:id/read', async (req, res, next) => {
  if (!UUID_RE.test(req.params.id)) return res.status(404).json({ error: 'Notification not found' });
  try {
    const { rows } = await db.query(
      `UPDATE notifications SET read_at = COALESCE(read_at, NOW())
       WHERE id = $1 AND user_id = $2 RETURNING *`,
      [req.params.id, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Notification not found' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

module.exports = router;
