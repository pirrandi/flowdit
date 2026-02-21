const router   = require('express').Router({ mergeParams: true });
const { body, validationResult } = require('express-validator');
const db       = require('../db');
const activity = require('../services/activity');
const { requireAuth } = require('../middleware/auth');
const { requireProjectAccess, requireEditor } = require('../middleware/project');

router.use(requireAuth, requireProjectAccess);

router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT cv.*, u.username AS editor_username, u.avatar_color AS editor_color
       FROM custom_vulns cv
       LEFT JOIN users u ON u.id=cv.updated_by
       WHERE cv.project_id=$1 ORDER BY cv.created_at`,
      [req.params.projectId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

router.post('/', requireEditor, [
  body('name').trim().isLength({ min:1, max:300 }),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { name, category='Custom', items=[], payloads=[], notes='' } = req.body;
  try {
    const { rows } = await db.query(
      `INSERT INTO custom_vulns (project_id, name, category, items, payloads, notes, created_by, updated_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$7) RETURNING *`,
      [req.params.projectId, name, category, JSON.stringify(items), JSON.stringify(payloads), notes, req.user.id]
    );
    await activity.log({
      projectId:  req.params.projectId,
      user:       req.user,
      action:     'vuln_created',
      entityType: 'custom_vuln',
      entityId:   rows[0].id,
      entityName: name,
    });
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

router.patch('/:vulnId', requireEditor, async (req, res, next) => {
  const allowed = ['name','category','items','payloads','notes','status','checked_items'];
  const updates = [], values = [];
  allowed.forEach(f => {
    if (req.body[f] !== undefined) {
      let val = req.body[f];
      if (['items','payloads','checked_items'].includes(f)) val = JSON.stringify(val);
      updates.push(`${f}=$${values.length+1}`);
      values.push(val);
    }
  });
  if (!updates.length) return res.status(400).json({ error:'Nothing to update' });
  updates.push(`updated_by=$${values.length+1}`);
  values.push(req.user.id);
  values.push(req.params.vulnId, req.params.projectId);

  try {
    const { rows } = await db.query(
      `UPDATE custom_vulns SET ${updates.join(',')}
       WHERE id=$${values.length-1} AND project_id=$${values.length} RETURNING *`,
      values
    );
    if (!rows.length) return res.status(404).json({ error:'Vulnerability not found' });
    if (req.body.status !== undefined) {
      await activity.log({
        projectId:  req.params.projectId,
        user:       req.user,
        action:     'set_status',
        entityType: 'custom_vuln',
        entityId:   req.params.vulnId,
        entityName: rows[0].name,
        meta:       { status: req.body.status },
      });
    }
    res.json(rows[0]);
  } catch (err) { next(err); }
});

router.delete('/:vulnId', requireEditor, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `DELETE FROM custom_vulns WHERE id=$1 AND project_id=$2 RETURNING name`,
      [req.params.vulnId, req.params.projectId]
    );
    if (rows.length) {
      await activity.log({
        projectId:  req.params.projectId,
        user:       req.user,
        action:     'vuln_deleted',
        entityType: 'custom_vuln',
        entityName: rows[0].name,
      });
    }
    res.json({ ok:true });
  } catch (err) { next(err); }
});

module.exports = router;
