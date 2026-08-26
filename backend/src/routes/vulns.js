const router   = require('express').Router({ mergeParams: true });
const { body, validationResult } = require('express-validator');
const db       = require('../db');
const activity = require('../services/activity');
const { requireAuth } = require('../middleware/auth');
const { requireProjectAccess, requireEditor } = require('../middleware/project');
const { targetBelongsToProject } = require('../services/ownership');

router.use(requireAuth, requireProjectAccess);

router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT cv.*, u.username AS editor_username, u.avatar_color AS editor_color, u.avatar_url AS editor_avatar_url,
              vu.username AS verifier_username,
              t.host AS target_host, t.type AS target_type
       FROM custom_vulns cv
       LEFT JOIN users u  ON u.id=cv.updated_by
       LEFT JOIN users vu ON vu.id=cv.verified_by
       LEFT JOIN targets t ON t.id=cv.target_id
       WHERE cv.project_id=$1
       ORDER BY
         CASE cv.severity
           WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
           WHEN 'low' THEN 4 WHEN 'info' THEN 5 ELSE 6 END,
         cv.created_at`,
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
  const { name, category='Custom', severity='medium', items=[], payloads=[], notes='', description='', remediation='', evidence=[], target_id=null, cvss_vector=null, cvss_score=null, cwe=null, compliance_tags=[] } = req.body;
  try {
    const validTargetId = await targetBelongsToProject(target_id, req.params.projectId);
    const { rows } = await db.query(
      `INSERT INTO custom_vulns (project_id, name, category, severity, items, payloads, notes, description, remediation, evidence, target_id, cvss_vector, cvss_score, cwe, compliance_tags, created_by, updated_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$16) RETURNING *`,
      [req.params.projectId, name, category, severity, JSON.stringify(items), JSON.stringify(payloads), notes, description, remediation, JSON.stringify(evidence), validTargetId, cvss_vector||null, cvss_score||null, cwe||null, JSON.stringify(compliance_tags), req.user.id]
    );
    await activity.log({
      projectId:  req.params.projectId,
      user:       req.user,
      action:     'vuln_created',
      entityType: 'custom_vuln',
      entityId:   rows[0].id,
      entityName: name,
      meta:       { severity },
    });
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

router.patch('/:vulnId', requireEditor, async (req, res, next) => {
  const allowed = ['name','category','severity','items','payloads','notes','description','remediation','evidence','http_proofs','status','checked_items','cvss_vector','cvss_score','cwe','compliance_tags'];
  const updates = [], values = [];
  allowed.forEach(f => {
    if (req.body[f] !== undefined) {
      let val = req.body[f];
      if (['items','payloads','checked_items','evidence','http_proofs','compliance_tags'].includes(f)) val = JSON.stringify(val);
      updates.push(`${f}=$${values.length+1}`);
      values.push(val);
    }
  });
  if (req.body.target_id !== undefined) {
    const validTargetId = await targetBelongsToProject(req.body.target_id, req.params.projectId);
    updates.push(`target_id=$${values.length+1}`);
    values.push(validTargetId);
  }
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
        projectId:  req.params.projectId, user: req.user,
        action: 'set_status', entityType: 'custom_vuln',
        entityId: req.params.vulnId, entityName: rows[0].name,
        meta: { status: req.body.status },
      });
    }
    res.json(rows[0]);
  } catch (err) { next(err); }
});

// PATCH /:vulnId/remediation — remediation/retest lifecycle (open -> remediated -> verified_closed)
router.patch('/:vulnId/remediation', requireEditor, [
  body('remediation_status').isIn(['open', 'remediated', 'verified_closed']),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { remediation_status, retest_date = null, retest_notes = null } = req.body;
  try {
    const current = await db.query(
      `SELECT remediation_status, name FROM custom_vulns WHERE id=$1 AND project_id=$2`,
      [req.params.vulnId, req.params.projectId]
    );
    if (!current.rows.length) return res.status(404).json({ error: 'Vulnerability not found' });
    const statusChanged = current.rows[0].remediation_status !== remediation_status;

    const updates = ['remediation_status=$1', 'retest_date=$2', 'retest_notes=$3', 'updated_by=$4'];
    const values  = [remediation_status, retest_date, retest_notes, req.user.id];

    // Only touch the audit trail when the status is actually transitioning —
    // editing the retest date/notes on an unchanged status must not reset it.
    if (statusChanged) {
      if (remediation_status === 'remediated') {
        updates.push(`remediated_at=NOW()`, `verified_at=NULL`, `verified_by=NULL`);
      } else if (remediation_status === 'verified_closed') {
        updates.push(`verified_at=NOW()`, `verified_by=$${values.length+1}`);
        values.push(req.user.id);
      } else {
        // Reopened — clear the trail, the finding is being tracked as open again.
        updates.push(`remediated_at=NULL`, `verified_at=NULL`, `verified_by=NULL`);
      }
    }

    values.push(req.params.vulnId, req.params.projectId);
    const { rows } = await db.query(
      `UPDATE custom_vulns SET ${updates.join(',')}
       WHERE id=$${values.length-1} AND project_id=$${values.length} RETURNING *`,
      values
    );
    if (statusChanged) {
      await activity.log({
        projectId:  req.params.projectId,
        user:       req.user,
        action:     'remediation_status_changed',
        entityType: 'custom_vuln',
        entityId:   req.params.vulnId,
        entityName: rows[0].name,
        meta:       { remediation_status },
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
        projectId: req.params.projectId, user: req.user,
        action: 'vuln_deleted', entityType: 'custom_vuln', entityName: rows[0].name,
      });
    }
    res.json({ ok:true });
  } catch (err) { next(err); }
});

module.exports = router;