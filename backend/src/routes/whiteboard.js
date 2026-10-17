const router  = require('express').Router({ mergeParams: true });
const db      = require('../db');
const { requireAuth, requireUser } = require('../middleware/auth');
const { requireProjectAccess, requireWriter, denyClientSessions } = require('../middleware/project');

// Las cuentas viewer son el cliente (ver isClientSession): igual que el portal,
// no ven este material interno aunque no puedan escribirlo.
router.use(requireAuth, requireUser, requireProjectAccess, denyClientSessions); // internal-only: never exposed to client portal sessions

router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT * FROM whiteboard_state WHERE project_id=$1`,
      [req.params.projectId]
    );
    res.json(rows[0] || { id: null, project_id: req.params.projectId, data: {}, updated_by: null, updated_at: null });
  } catch (err) { next(err); }
});

router.put('/', requireWriter, async (req, res, next) => {
  const data = req.body.data ?? {};
  try {
    const { rows } = await db.query(
      `INSERT INTO whiteboard_state (project_id, data, updated_by)
       VALUES ($1, $2, $3)
       ON CONFLICT (project_id) DO UPDATE
         SET data=$2, updated_by=$3, updated_at=NOW()
       RETURNING *`,
      [req.params.projectId, JSON.stringify(data), req.user.id]
    );
    res.json(rows[0]);
  } catch (err) { next(err); }
});

module.exports = router;
