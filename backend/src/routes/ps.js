const router   = require('express').Router({ mergeParams: true });
const db       = require('../db');
const activity = require('../services/activity');
const { requireAuth } = require('../middleware/auth');
const { requireProjectAccess, requireWriter, denyClientSessions } = require('../middleware/project');

// Progreso y notas de los labs de PortSwigger: entrenamiento interno del equipo
// que la vista cliente no muestra. Antes el portal lo leía (con las notas) solo
// con show_wstg_progress prendido; ahora portal y viewer reciben 403.
router.use(requireAuth, requireProjectAccess, denyClientSessions);

// GET all progress + notes
router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT cat_id, lab_idx, done, note FROM ps_progress WHERE project_id=$1`,
      [req.params.projectId]
    );
    const progress = {};
    rows.forEach(r => {
      progress[`${r.cat_id}_${r.lab_idx}`] = { done: r.done, note: r.note || '' };
    });
    res.json(progress);
  } catch (err) { next(err); }
});

// PATCH toggle done
router.patch('/:catId/:labIdx', requireWriter, async (req, res, next) => {
  const labIdx = parseInt(req.params.labIdx);
  if (isNaN(labIdx)) return res.status(400).json({ error:'Invalid lab index' });
  const { done, labName } = req.body;
  try {
    await db.query(
      `INSERT INTO ps_progress (project_id, cat_id, lab_idx, done, updated_by)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (project_id, cat_id, lab_idx) DO UPDATE
         SET done=$4, updated_by=$5, updated_at=NOW()`,
      [req.params.projectId, req.params.catId, labIdx, !!done, req.user.id]
    );
    if (done) {
      await activity.log({
        projectId:  req.params.projectId,
        user:       req.user,
        action:     'lab_completed',
        entityType: 'ps_lab',
        entityId:   `${req.params.catId}_${labIdx}`,
        entityName: labName || `Lab ${labIdx}`,
        meta:       { catId: req.params.catId },
      });
    }
    res.json({ ok:true });
  } catch (err) { next(err); }
});

// PATCH note
router.patch('/:catId/:labIdx/note', requireWriter, async (req, res, next) => {
  const labIdx = parseInt(req.params.labIdx);
  if (isNaN(labIdx)) return res.status(400).json({ error:'Invalid lab index' });
  const { note } = req.body;
  try {
    await db.query(
      `INSERT INTO ps_progress (project_id, cat_id, lab_idx, done, note, updated_by)
       VALUES ($1,$2,$3,false,$4,$5)
       ON CONFLICT (project_id, cat_id, lab_idx) DO UPDATE
         SET note=$4, updated_by=$5, updated_at=NOW()`,
      [req.params.projectId, req.params.catId, labIdx, note || '', req.user.id]
    );
    res.json({ ok:true });
  } catch (err) { next(err); }
});

module.exports = router;