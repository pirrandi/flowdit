const router   = require('express').Router({ mergeParams: true });
const { body, validationResult } = require('express-validator');
const db       = require('../db');
const activity = require('../services/activity');
const { requireAuth } = require('../middleware/auth');
const { requireProjectAccess, requireEditor, requireTargetAccess } = require('../middleware/project');

router.use(requireAuth, requireProjectAccess, requireTargetAccess);

// GET all ports for a target
router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT p.*, u.username AS added_by_username
       FROM target_ports p
       LEFT JOIN users u ON u.id = p.added_by
       WHERE p.target_id = $1
       ORDER BY p.port ASC`,
      [req.params.targetId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// POST create port
router.post('/', requireEditor, [
  body('port').isInt({ min: 1, max: 65535 }),
  body('protocol').optional().isIn(['tcp', 'udp']),
  body('state').optional().isIn(['open', 'filtered', 'closed']),
  body('service').optional().trim().isLength({ max: 100 }),
  body('version').optional().trim().isLength({ max: 200 }),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { port, protocol = 'tcp', state = 'open', service = '', version = '', notes = '' } = req.body;
  try {
    const { rows } = await db.query(
      `INSERT INTO target_ports (target_id, port, protocol, state, service, version, notes, added_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [req.params.targetId, port, protocol, state, service, version, notes, req.user.id]
    );
    // Fetch target host for activity log
    const { rows: t } = await db.query(`SELECT host FROM targets WHERE id=$1`, [req.params.targetId]);
    await activity.log({
      projectId:  req.params.projectId,
      user:       req.user,
      action:     'port_added',
      entityType: 'port',
      entityId:   rows[0].id,
      entityName: `${t[0]?.host}:${port}/${protocol}`,
      meta:       { state, service },
    });
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

// PATCH update port
router.patch('/:portId', requireEditor, async (req, res, next) => {
  const allowed = ['port', 'protocol', 'state', 'service', 'version', 'notes'];
  const updates = [], values = [];
  allowed.forEach(f => {
    if (req.body[f] !== undefined) {
      updates.push(`${f}=$${values.length + 1}`);
      values.push(req.body[f]);
    }
  });
  if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });
  values.push(req.params.portId, req.params.targetId);
  try {
    const { rows } = await db.query(
      `UPDATE target_ports SET ${updates.join(',')}
       WHERE id=$${values.length - 1} AND target_id=$${values.length} RETURNING *`,
      values
    );
    if (!rows.length) return res.status(404).json({ error: 'Port not found' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

// DELETE port
router.delete('/:portId', requireEditor, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `DELETE FROM target_ports WHERE id=$1 AND target_id=$2 RETURNING port, protocol`,
      [req.params.portId, req.params.targetId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Port not found' });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

module.exports = router;
