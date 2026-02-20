const router = require('express').Router({ mergeParams: true });
const db = require('../db');
const { requireAuth } = require('../middleware/auth');
const { requireProjectAccess, requireEditor } = require('../middleware/project');

router.use(requireAuth, requireProjectAccess);

// ── GET /projects/:projectId/ps ───────────────────────────────────────
router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT cat_id, lab_idx, done FROM ps_progress WHERE project_id = $1`,
      [req.params.projectId]
    );
    // Build { "catId_labIdx": bool }
    const progress = {};
    rows.forEach(r => { progress[`${r.cat_id}_${r.lab_idx}`] = r.done; });
    res.json(progress);
  } catch (err) { next(err); }
});

// ── PATCH /projects/:projectId/ps/:catId/:labIdx ──────────────────────
router.patch('/:catId/:labIdx', requireEditor, async (req, res, next) => {
  const labIdx = parseInt(req.params.labIdx);
  if (isNaN(labIdx)) return res.status(400).json({ error: 'Invalid lab index' });
  const { done } = req.body;
  try {
    await db.query(
      `INSERT INTO ps_progress (project_id, cat_id, lab_idx, done, updated_by)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (project_id, cat_id, lab_idx) DO UPDATE
         SET done = EXCLUDED.done, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
      [req.params.projectId, req.params.catId, labIdx, !!done, req.user.id]
    );
    res.json({ ok: true });
  } catch (err) { next(err); }
});

module.exports = router;
