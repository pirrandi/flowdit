const router = require('express').Router({ mergeParams: true });
const db = require('../db');
const { requireAuth } = require('../middleware/auth');
const { requireProjectAccess, requireEditor } = require('../middleware/project');

router.use(requireAuth, requireProjectAccess);

// ── GET /projects/:projectId/wstg ─────────────────────────────────────
// Get all WSTG progress for a project
router.get('/', async (req, res, next) => {
  try {
    const [progressRes, checksRes] = await Promise.all([
      db.query(
        `SELECT test_id, status, note, updated_by, updated_at FROM wstg_progress WHERE project_id = $1`,
        [req.params.projectId]
      ),
      db.query(
        `SELECT test_id, item_idx, checked FROM wstg_item_checks WHERE project_id = $1`,
        [req.params.projectId]
      ),
    ]);

    // Build { testId: { status, note, items: {idx: bool} } }
    const progress = {};
    progressRes.rows.forEach(r => {
      progress[r.test_id] = { status: r.status, note: r.note, items: {} };
    });
    checksRes.rows.forEach(r => {
      if (!progress[r.test_id]) progress[r.test_id] = { status: null, note: '', items: {} };
      progress[r.test_id].items[r.item_idx] = r.checked;
    });

    res.json(progress);
  } catch (err) { next(err); }
});

// ── PATCH /projects/:projectId/wstg/:testId/status ───────────────────
router.patch('/:testId/status', requireEditor, async (req, res, next) => {
  const { status } = req.body;
  if (status !== null && !['done','fail'].includes(status)) {
    return res.status(400).json({ error: 'status must be done, fail, or null' });
  }
  try {
    await db.query(
      `INSERT INTO wstg_progress (project_id, test_id, status, updated_by)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (project_id, test_id) DO UPDATE
         SET status = EXCLUDED.status, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
      [req.params.projectId, req.params.testId, status, req.user.id]
    );
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// ── PATCH /projects/:projectId/wstg/:testId/note ─────────────────────
router.patch('/:testId/note', requireEditor, async (req, res, next) => {
  const { note } = req.body;
  try {
    await db.query(
      `INSERT INTO wstg_progress (project_id, test_id, note, updated_by)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (project_id, test_id) DO UPDATE
         SET note = EXCLUDED.note, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
      [req.params.projectId, req.params.testId, note || '', req.user.id]
    );
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// ── PATCH /projects/:projectId/wstg/:testId/items/:itemIdx ───────────
router.patch('/:testId/items/:itemIdx', requireEditor, async (req, res, next) => {
  const { checked } = req.body;
  const itemIdx = parseInt(req.params.itemIdx);
  if (isNaN(itemIdx)) return res.status(400).json({ error: 'Invalid item index' });
  try {
    await db.query(
      `INSERT INTO wstg_item_checks (project_id, test_id, item_idx, checked, updated_by)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (project_id, test_id, item_idx) DO UPDATE
         SET checked = EXCLUDED.checked, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
      [req.params.projectId, req.params.testId, itemIdx, !!checked, req.user.id]
    );
    res.json({ ok: true });
  } catch (err) { next(err); }
});

module.exports = router;
