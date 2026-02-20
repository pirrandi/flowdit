const router = require('express').Router({ mergeParams: true });
const { body, validationResult } = require('express-validator');
const db = require('../db');
const { requireAuth } = require('../middleware/auth');
const { requireProjectAccess, requireEditor } = require('../middleware/project');

router.use(requireAuth, requireProjectAccess);

// ── GET /projects/:projectId/vulns ────────────────────────────────────
router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT id, name, category, items, payloads, notes, status, checked_items, created_at, updated_at
       FROM custom_vulns WHERE project_id = $1 ORDER BY created_at`,
      [req.params.projectId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// ── POST /projects/:projectId/vulns ───────────────────────────────────
router.post('/', requireEditor, [
  body('name').trim().isLength({ min: 1, max: 300 }),
  body('category').optional().trim().isLength({ max: 100 }),
  body('items').optional().isArray(),
  body('payloads').optional().isArray(),
  body('notes').optional().trim(),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { name, category = 'Custom', items = [], payloads = [], notes = '' } = req.body;
  try {
    const { rows } = await db.query(
      `INSERT INTO custom_vulns (project_id, name, category, items, payloads, notes, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [req.params.projectId, name, category, JSON.stringify(items), JSON.stringify(payloads), notes, req.user.id]
    );
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

// ── PATCH /projects/:projectId/vulns/:vulnId ──────────────────────────
router.patch('/:vulnId', requireEditor, async (req, res, next) => {
  const allowed = ['name','category','items','payloads','notes','status','checked_items'];
  const updates = [];
  const values  = [];
  allowed.forEach(f => {
    if (req.body[f] !== undefined) {
      let val = req.body[f];
      if (['items','payloads','checked_items'].includes(f)) val = JSON.stringify(val);
      updates.push(`${f} = $${values.length + 1}`);
      values.push(val);
    }
  });
  if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });
  values.push(req.params.vulnId, req.params.projectId);

  try {
    const { rows } = await db.query(
      `UPDATE custom_vulns SET ${updates.join(', ')}
       WHERE id = $${values.length - 1} AND project_id = $${values.length} RETURNING *`,
      values
    );
    if (!rows.length) return res.status(404).json({ error: 'Vulnerability not found' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

// ── DELETE /projects/:projectId/vulns/:vulnId ─────────────────────────
router.delete('/:vulnId', requireEditor, async (req, res, next) => {
  try {
    await db.query(
      `DELETE FROM custom_vulns WHERE id = $1 AND project_id = $2`,
      [req.params.vulnId, req.params.projectId]
    );
    res.json({ ok: true });
  } catch (err) { next(err); }
});

module.exports = router;
