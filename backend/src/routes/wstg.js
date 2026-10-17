const router   = require('express').Router({ mergeParams: true });
const db       = require('../db');
const activity = require('../services/activity');
const { requireAuth } = require('../middleware/auth');
const { requireProjectAccess, requireWriter, isClientSession, clientRequiresFlag } = require('../middleware/project');
const { targetBelongsToProject, vulnBelongsToProject } = require('../services/ownership');
const { WSTG_NAMES, wstgCategory } = require('../services/wstgCatalog');

// Portal y cuentas viewer (el cliente) solo ven el progreso WSTG si el dueño
// prendió show_wstg_progress.
router.use(requireAuth, requireProjectAccess, clientRequiresFlag('show_wstg_progress'));

// Lo que el cliente ve de la metodología: proyección FIJA armada desde cero,
// no un SELECT * con campos borrados. Antes el portal recibía la nota interna
// aunque show_wstg_notes estuviera apagado, la descripción/remediación de
// trabajo, el target, quién editó (id, usuario, avatar) y el id del hallazgo
// vinculado aunque fuera un borrador. Ahora: id, nombre, categoría y estado;
// la nota solo con show_wstg_notes; el hallazgo vinculado solo si HOY está
// publicado (mismo criterio que GET /vulns del portal). Solo tests del
// catálogo: un test_id arbitrario guardado por PATCH no llega al cliente.
async function clientProgress(req, res) {
  const showNotes = !!req.project.show_wstg_notes;
  const { rows } = await db.query(
    `SELECT wp.test_id, wp.status, wp.note,
            cv.id AS finding_id, cv.name AS finding_name
     FROM wstg_progress wp
     LEFT JOIN custom_vulns cv
            ON cv.id = wp.linked_vuln_id
           AND cv.project_id = wp.project_id
           AND cv.client_visible = true
     WHERE wp.project_id = $1`,
    [req.params.projectId]
  );
  const progress = {};
  for (const r of rows) {
    if (!WSTG_NAMES[r.test_id]) continue;
    const note = showNotes && r.note ? r.note : null;
    // Una fila sin estado y sin nota visible no le dice nada al cliente.
    if (!r.status && !note && !r.finding_id) continue;
    const entry = {
      test_id:  r.test_id,
      name:     WSTG_NAMES[r.test_id],
      category: wstgCategory(r.test_id),
      status:   r.status || null,
    };
    if (showNotes) entry.note = note;
    entry.linked_finding = r.finding_id ? { id: r.finding_id, name: r.finding_name } : null;
    progress[r.test_id] = entry;
  }
  res.json(progress);
}

// GET all progress + last-editor info
router.get('/', async (req, res, next) => {
  try {
    if (isClientSession(req)) return await clientProgress(req, res);
    const [progressRes, checksRes] = await Promise.all([
      db.query(
        `SELECT wp.test_id, wp.status, wp.note, wp.description, wp.remediation, wp.target_id, wp.linked_vuln_id, wp.updated_at,
                u.id AS editor_id, u.username AS editor_username, u.display_name AS editor_display_name, u.avatar_color AS editor_color, u.avatar_url AS editor_avatar_url
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
          id: r.editor_id, username: r.editor_username, display_name: r.editor_display_name || null, avatar_color: r.editor_color, avatar_url: r.editor_avatar_url || null,
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
router.patch('/:testId/status', requireWriter, async (req, res, next) => {
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

    res.json({ ok:true, editor: { id:req.user.id, username:req.user.username, display_name:req.user.display_name || null, avatar_color:req.user.avatar_color, avatar_url: req.user.avatar_url||null }, updated_at: new Date() });
  } catch (err) { next(err); }
});

// PATCH /:testId/note
router.patch('/:testId/note', requireWriter, async (req, res, next) => {
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
router.patch('/:testId/items/:itemIdx', requireWriter, async (req, res, next) => {
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
router.patch('/:testId/target', requireWriter, async (req, res, next) => {
  const { target_id } = req.body;
  try {
    const validTargetId = await targetBelongsToProject(target_id, req.params.projectId);
    await db.query(
      `INSERT INTO wstg_progress (project_id, test_id, target_id, updated_by)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (project_id, test_id) DO UPDATE
         SET target_id=$3, updated_by=$4, updated_at=NOW()`,
      [req.params.projectId, req.params.testId, validTargetId, req.user.id]
    );
    res.json({ ok:true });
  } catch (err) { next(err); }
});

// PATCH /:testId/link  — link/unlink a custom vuln
router.patch('/:testId/link', requireWriter, async (req, res, next) => {
  const { linked_vuln_id } = req.body;
  try {
    const validVulnId = await vulnBelongsToProject(linked_vuln_id, req.params.projectId);
    await db.query(
      `INSERT INTO wstg_progress (project_id, test_id, linked_vuln_id, updated_by)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (project_id, test_id) DO UPDATE
         SET linked_vuln_id=$3, updated_by=$4, updated_at=NOW()`,
      [req.params.projectId, req.params.testId, validVulnId, req.user.id]
    );
    res.json({ ok:true });
  } catch (err) { next(err); }
});

// PATCH /:testId/report  — save description + remediation for export
router.patch('/:testId/report', requireWriter, async (req, res, next) => {
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