const router = require('express').Router();
const { body, validationResult } = require('express-validator');
const db = require('../db');
const { requireAuth } = require('../middleware/auth');

router.use(requireAuth);

// GET /api/templates?q=search
router.get('/', async (req, res, next) => {
  try {
    const q = (req.query.q || '').trim();
    const userId = req.user.id;

    let rows;
    if (q.length === 0) {
      ({ rows } = await db.query(
        `SELECT id, name, category, severity, cwe, description, remediation, cvss_vector, is_builtin, created_by
         FROM vuln_templates
         WHERE is_builtin = TRUE OR created_by = $1
         ORDER BY is_builtin DESC, LOWER(name)
         LIMIT 30`,
        [userId]
      ));
    } else {
      ({ rows } = await db.query(
        `SELECT id, name, category, severity, cwe, description, remediation, cvss_vector, is_builtin, created_by
         FROM vuln_templates
         WHERE (is_builtin = TRUE OR created_by = $1)
           AND (name ILIKE $2 OR category ILIKE $2)
         ORDER BY
           CASE WHEN LOWER(name) LIKE LOWER($3) THEN 0 ELSE 1 END,
           is_builtin DESC,
           LOWER(name)
         LIMIT 20`,
        [userId, `%${q}%`, `${q}%`]
      ));
    }
    res.json(rows);
  } catch (err) { next(err); }
});

// POST /api/templates — save personal template
router.post('/', [
  body('name').trim().notEmpty().isLength({ max: 200 }),
  body('severity').isIn(['critical','high','medium','low','info']),
  body('category').optional().trim().isLength({ max: 100 }),
  body('cwe').optional().trim().isLength({ max: 50 }),
  body('description').optional().trim(),
  body('remediation').optional().trim(),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });
  try {
    const { name, category, severity, cwe, description, remediation, cvss_vector } = req.body;
    const { rows } = await db.query(
      `INSERT INTO vuln_templates (name, category, severity, cwe, description, remediation, cvss_vector, is_builtin, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,FALSE,$8)
       RETURNING *`,
      [name, category || null, severity, cwe || null, description || null, remediation || null, cvss_vector || null, req.user.id]
    );
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

// DELETE /api/templates/:id — delete own template only
router.delete('/:id', async (req, res, next) => {
  try {
    const { rowCount } = await db.query(
      `DELETE FROM vuln_templates WHERE id = $1 AND created_by = $2 AND is_builtin = FALSE`,
      [req.params.id, req.user.id]
    );
    if (rowCount === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

module.exports = router;
