const router = require('express').Router({ mergeParams: true });
const db     = require('../db');
const { requireAuth } = require('../middleware/auth');
const { requireProjectAccess, requireLead } = require('../middleware/project');

router.use(requireAuth, requireProjectAccess);

// Guard against a runaway payload filling the column: the report config is
// text + layout, never binary evidence (that lives on the vuln rows).
const MAX_BYTES = 2 * 1024 * 1024;

// GET /api/projects/:projectId/report-config
router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT project_id, data, updated_by, updated_at FROM report_config WHERE project_id=$1`,
      [req.params.projectId]
    );
    res.json(rows[0] || { project_id: req.params.projectId, data: null, updated_by: null, updated_at: null });
  } catch (err) { next(err); }
});

// PUT /api/projects/:projectId/report-config
// The report builder shapes the client deliverable — lead only (no pentester).
router.put('/', requireLead, async (req, res, next) => {
  const data = req.body.data;
  if (data === null || typeof data !== 'object' || Array.isArray(data)) {
    return res.status(400).json({ error: 'data must be an object' });
  }
  const serialized = JSON.stringify(data);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_BYTES) {
    return res.status(413).json({ error: 'Report configuration is too large to store' });
  }
  try {
    const { rows } = await db.query(
      `INSERT INTO report_config (project_id, data, updated_by)
       VALUES ($1, $2, $3)
       ON CONFLICT (project_id) DO UPDATE
         SET data=$2, updated_by=$3, updated_at=NOW()
       RETURNING project_id, data, updated_by, updated_at`,
      [req.params.projectId, serialized, req.user.id]
    );
    res.json(rows[0]);
  } catch (err) { next(err); }
});

module.exports = router;
