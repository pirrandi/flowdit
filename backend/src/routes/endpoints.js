const router   = require('express').Router({ mergeParams: true });
const { body, validationResult } = require('express-validator');
const db       = require('../db');
const activity = require('../services/activity');
const { requireAuth } = require('../middleware/auth');
const { requireProjectAccess, requireWriter, requireTargetAccess, portalRequiresFlag } = require('../middleware/project');

router.use(requireAuth, requireProjectAccess, portalRequiresFlag('show_targets'), requireTargetAccess);

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'OTHER'];

// GET all endpoints for a target
router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT e.*, u.username AS added_by_username, u.display_name AS added_by_display_name
       FROM target_endpoints e
       LEFT JOIN users u ON u.id = e.added_by
       WHERE e.target_id = $1
       ORDER BY e.path ASC, e.method ASC`,
      [req.params.targetId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// POST create endpoint
router.post('/', requireWriter, [
  body('path').trim().isLength({ min: 1, max: 1000 }),
  body('method').optional().isIn(METHODS),
  body('status_code').optional().isInt({ min: 100, max: 599 }),
  body('interesting').optional().isBoolean(),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { path, method = 'GET', status_code = null, interesting = false, notes = '' } = req.body;
  try {
    const { rows } = await db.query(
      `INSERT INTO target_endpoints (target_id, path, method, status_code, interesting, notes, added_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [req.params.targetId, path, method, status_code, interesting, notes, req.user.id]
    );
    const { rows: t } = await db.query(`SELECT host FROM targets WHERE id=$1`, [req.params.targetId]);
    await activity.log({
      projectId:  req.params.projectId,
      user:       req.user,
      action:     'endpoint_added',
      entityType: 'endpoint',
      entityId:   rows[0].id,
      entityName: `${method} ${t[0]?.host}${path}`,
      meta:       { interesting, status_code },
    });
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

// PATCH update endpoint
router.patch('/:endpointId', requireWriter, async (req, res, next) => {
  const allowed = ['path', 'method', 'status_code', 'interesting', 'notes'];
  const updates = [], values = [];
  allowed.forEach(f => {
    if (req.body[f] !== undefined) {
      updates.push(`${f}=$${values.length + 1}`);
      values.push(req.body[f]);
    }
  });
  if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });
  values.push(req.params.endpointId, req.params.targetId);
  try {
    const { rows } = await db.query(
      `UPDATE target_endpoints SET ${updates.join(',')}
       WHERE id=$${values.length - 1} AND target_id=$${values.length} RETURNING *`,
      values
    );
    if (!rows.length) return res.status(404).json({ error: 'Endpoint not found' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

// DELETE endpoint
router.delete('/:endpointId', requireWriter, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `DELETE FROM target_endpoints WHERE id=$1 AND target_id=$2 RETURNING path, method`,
      [req.params.endpointId, req.params.targetId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Endpoint not found' });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

module.exports = router;
