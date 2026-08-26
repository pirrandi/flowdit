const router = require('express').Router();
const { body, validationResult } = require('express-validator');
const db = require('../db');
const { requireAuth } = require('../middleware/auth');

router.use(requireAuth);

const MAX_BYTES = 1024 * 1024;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Postgres raises 22P02 on a malformed UUID, which the global handler would
// turn into a 500. A bad id is a client error, so reject it up front.
router.param('id', (req, res, next, id) =>
  UUID_RE.test(id) ? next() : res.status(404).json({ error: 'Not found' }));

function validPayload(data) {
  return data && typeof data === 'object' && !Array.isArray(data)
    && data.meta && typeof data.meta === 'object'
    && Array.isArray(data.sections);
}

// GET /api/report-templates — the caller's own templates
router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT id, name, data, created_at, updated_at
       FROM report_templates
       WHERE created_by=$1
       ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// POST /api/report-templates
router.post('/', [
  body('name').trim().notEmpty().isLength({ max: 200 }),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

  const { name, data } = req.body;
  if (!validPayload(data)) return res.status(400).json({ error: 'data must include meta and sections' });
  const serialized = JSON.stringify(data);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_BYTES) {
    return res.status(413).json({ error: 'Template is too large to store' });
  }
  try {
    const { rows } = await db.query(
      `INSERT INTO report_templates (name, data, created_by)
       VALUES ($1,$2,$3)
       RETURNING id, name, data, created_at, updated_at`,
      [name, serialized, req.user.id]
    );
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

// PUT /api/report-templates/:id — overwrite an existing template in place
router.put('/:id', [
  body('name').optional().trim().notEmpty().isLength({ max: 200 }),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

  const { name, data } = req.body;
  if (!validPayload(data)) return res.status(400).json({ error: 'data must include meta and sections' });
  const serialized = JSON.stringify(data);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_BYTES) {
    return res.status(413).json({ error: 'Template is too large to store' });
  }
  try {
    const { rows } = await db.query(
      `UPDATE report_templates
       SET name = COALESCE($1, name), data = $2, updated_at = NOW()
       WHERE id = $3 AND created_by = $4
       RETURNING id, name, data, created_at, updated_at`,
      [name || null, serialized, req.params.id, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

// DELETE /api/report-templates/:id
router.delete('/:id', async (req, res, next) => {
  try {
    const { rowCount } = await db.query(
      `DELETE FROM report_templates WHERE id=$1 AND created_by=$2`,
      [req.params.id, req.user.id]
    );
    if (rowCount === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

module.exports = router;
