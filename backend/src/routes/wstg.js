const router   = require('express').Router({ mergeParams: true });
const db       = require('../db');
const activity = require('../services/activity');
const { requireAuth } = require('../middleware/auth');
const { requireProjectAccess, requireEditor } = require('../middleware/project');

router.use(requireAuth, requireProjectAccess);

// GET all progress + last-editor info
router.get('/', async (req, res, next) => {
  try {
    const [progressRes, checksRes] = await Promise.all([
      db.query(
        `SELECT wp.test_id, wp.status, wp.note, wp.description, wp.remediation, wp.target_id, wp.linked_vuln_id, wp.updated_at,
                u.id AS editor_id, u.username AS editor_username, u.avatar_color AS editor_color, u.avatar_url AS editor_avatar_url
         FROM wstg_progress wp
         LEFT JOIN users u ON u.id = wp.updated_by
         WHERE wp.project_id = $1`,
        [req.params.projectId]
      ),
      db.query(
        `SELECT test_id, item_idx, checked FROM wstg_item_checks WHERE project_id=$1`,
        [req.params.projectId]
      ),
    ]);

    const progress = {};
    progressRes.rows.forEach(r => {
      progress[r.test_id] = {
        status:         r.status,
        note:           r.note,
        description:    r.description,
        remediation:    r.remediation,
        target_id:      r.target_id,
        linked_vuln_id: r.linked_vuln_id,
        updated_at:     r.updated_at,
        last_editor: r.editor_id ? {
          id: r.editor_id, username: r.editor_username, avatar_color: r.editor_color, avatar_url: r.editor_avatar_url || null,
        } : null,
        items: {},
      };
    });
    checksRes.rows.forEach(r => {
      if (!progress[r.test_id]) progress[r.test_id] = { status:null, note:'', last_editor:null, items:{} };
      progress[r.test_id].items[r.item_idx] = r.checked;
    });

    res.json(progress);
  } catch (err) { next(err); }
});

// PATCH /:testId/status
router.patch('/:testId/status', requireEditor, async (req, res, next) => {
  const { status, testName } = req.body;
  if (status !== null && !['done','fail','na'].includes(status))
    return res.status(400).json({ error:'status must be done, fail, na, or null' });
  try {
    await db.query(
      `INSERT INTO wstg_progress (project_id, test_id, status, updated_by)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (project_id, test_id) DO UPDATE
         SET status=$3, updated_by=$4, updated_at=NOW()`,
      [req.params.projectId, req.params.testId, status, req.user.id]
    );

    await activity.log({
      projectId:  req.params.projectId,
      user:       req.user,
      action:     'set_status',
      entityType: 'wstg_test',
      entityId:   req.params.testId,
      entityName: testName || req.params.testId,
      meta:       { status },
    });

    res.json({ ok:true, editor: { id:req.user.id, username:req.user.username, avatar_color:req.user.avatar_color, avatar_url: req.user.avatar_url||null }, updated_at: new Date() });
  } catch (err) { next(err); }
});

// PATCH /:testId/note
router.patch('/:testId/note', requireEditor, async (req, res, next) => {
  const { note, testName } = req.body;
  try {
    await db.query(
      `INSERT INTO wstg_progress (project_id, test_id, note, updated_by)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (project_id, test_id) DO UPDATE
         SET note=$3, updated_by=$4, updated_at=NOW()`,
      [req.params.projectId, req.params.testId, note||'', req.user.id]
    );
    await activity.log({
      projectId:  req.params.projectId,
      user:       req.user,
      action:     'add_note',
      entityType: 'wstg_test',
      entityId:   req.params.testId,
      entityName: testName || req.params.testId,
    });
    res.json({ ok:true });
  } catch (err) { next(err); }
});

// PATCH /:testId/items/:itemIdx
router.patch('/:testId/items/:itemIdx', requireEditor, async (req, res, next) => {
  const itemIdx = parseInt(req.params.itemIdx);
  if (isNaN(itemIdx)) return res.status(400).json({ error:'Invalid item index' });
  const { checked } = req.body;
  try {
    await db.query(
      `INSERT INTO wstg_item_checks (project_id, test_id, item_idx, checked, updated_by)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (project_id, test_id, item_idx) DO UPDATE
         SET checked=$4, updated_by=$5, updated_at=NOW()`,
      [req.params.projectId, req.params.testId, itemIdx, !!checked, req.user.id]
    );
    res.json({ ok:true });
  } catch (err) { next(err); }
});

// PATCH /:testId/target  — assign target to a vuln-found test
router.patch('/:testId/target', requireEditor, async (req, res, next) => {
  const { target_id } = req.body;
  try {
    await db.query(
      `INSERT INTO wstg_progress (project_id, test_id, target_id, updated_by)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (project_id, test_id) DO UPDATE
         SET target_id=$3, updated_by=$4, updated_at=NOW()`,
      [req.params.projectId, req.params.testId, target_id||null, req.user.id]
    );
    res.json({ ok:true });
  } catch (err) { next(err); }
});

// PATCH /:testId/link  — link/unlink a custom vuln
router.patch('/:testId/link', requireEditor, async (req, res, next) => {
  const { linked_vuln_id } = req.body;
  try {
    await db.query(
      `INSERT INTO wstg_progress (project_id, test_id, linked_vuln_id, updated_by)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (project_id, test_id) DO UPDATE
         SET linked_vuln_id=$3, updated_by=$4, updated_at=NOW()`,
      [req.params.projectId, req.params.testId, linked_vuln_id||null, req.user.id]
    );
    res.json({ ok:true });
  } catch (err) { next(err); }
});

// PATCH /:testId/report  — save description + remediation for export
router.patch('/:testId/report', requireEditor, async (req, res, next) => {
  const { description, remediation } = req.body;
  try {
    await db.query(
      `INSERT INTO wstg_progress (project_id, test_id, description, remediation, updated_by)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (project_id, test_id) DO UPDATE
         SET description=$3, remediation=$4, updated_by=$5, updated_at=NOW()`,
      [req.params.projectId, req.params.testId, description||'', remediation||'', req.user.id]
    );
    res.json({ ok:true });
  } catch (err) { next(err); }
});

module.exports = router;