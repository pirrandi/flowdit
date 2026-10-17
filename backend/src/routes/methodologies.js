const router = require('express').Router({ mergeParams: true });
const { body, validationResult } = require('express-validator');
const db       = require('../db');
const { requireAuth, requireUser } = require('../middleware/auth');
const { requireProjectAccess, requireWriter, denyClientSessions } = require('../middleware/project');
const { targetBelongsToProject } = require('../services/ownership');

// Methodologies are internal working material (test status, pentester notes,
// target hosts) — never client-facing. A portal session gets nothing here,
// not even the library list; the client portal only shows WSTG progress,
// gated by its own visibility flags.
router.use(requireAuth, requireUser);

// ── METHODOLOGY LIBRARY (user-scoped, no project needed) ──────────

// GET all methodologies visible to user (own + shared)
router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT m.*, u.username AS owner_username, u.display_name AS owner_display_name
       FROM methodologies m
       JOIN users u ON u.id = m.owner_id
       WHERE m.owner_id = $1 OR m.is_shared = true
       ORDER BY m.created_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// POST create methodology
router.post('/', [
  body('name').trim().isLength({ min:1, max:200 }),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { name, description='', is_shared=false, tests=[] } = req.body;
  try {
    const { rows } = await db.query(
      `INSERT INTO methodologies (owner_id, name, description, is_shared, tests)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [req.user.id, name, description, !!is_shared, JSON.stringify(tests)]
    );
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

// PATCH update methodology (owner only)
router.patch('/:methodId', async (req, res, next) => {
  const allowed = ['name','description','is_shared','tests'];
  const updates = [], values = [];
  allowed.forEach(f => {
    if (req.body[f] !== undefined) {
      updates.push(`${f}=$${values.length+1}`);
      values.push(f === 'tests' ? JSON.stringify(req.body[f]) : req.body[f]);
    }
  });
  if (!updates.length) return res.status(400).json({ error:'Nothing to update' });
  values.push(req.params.methodId, req.user.id);
  try {
    const { rows } = await db.query(
      `UPDATE methodologies SET ${updates.join(',')}, updated_at=NOW()
       WHERE id=$${values.length-1} AND owner_id=$${values.length} RETURNING *`,
      values
    );
    if (!rows.length) return res.status(404).json({ error:'Not found or not owner' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

// DELETE methodology (owner only)
router.delete('/:methodId', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `DELETE FROM methodologies WHERE id=$1 AND owner_id=$2 RETURNING name`,
      [req.params.methodId, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error:'Not found or not owner' });
    res.json({ ok:true });
  } catch (err) { next(err); }
});

// ── PROGRESS (project-scoped) ─────────────────────────────────────

// GET progress for a methodology in a project
// Progreso y notas por proyecto: tampoco para cuentas viewer (el cliente).
router.get('/:methodId/progress/:projectId', requireProjectAccess, denyClientSessions, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT mp.*, t.host AS target_host
       FROM methodology_progress mp
       LEFT JOIN targets t ON t.id = mp.target_id
       WHERE mp.project_id=$1 AND mp.methodology_id=$2`,
      [req.params.projectId, req.params.methodId]
    );
    const progress = {};
    rows.forEach(r => {
      progress[r.test_idx] = {
        status:      r.status,
        note:        r.note,
        target_id:   r.target_id,
        target_host: r.target_host,
        updated_at:  r.updated_at,
      };
    });
    res.json(progress);
  } catch (err) { next(err); }
});

// PATCH set test status in project
router.patch('/:methodId/progress/:projectId/:testIdx', requireProjectAccess, requireWriter, async (req, res, next) => {
  const testIdx = parseInt(req.params.testIdx);
  if (isNaN(testIdx)) return res.status(400).json({ error:'Invalid test index' });
  const { status, note, target_id } = req.body;
  try {
    const fields = ['project_id','methodology_id','test_idx','updated_by'];
    const vals   = [req.params.projectId, req.params.methodId, testIdx, req.user.id];
    const updates = ['updated_by=$4','updated_at=NOW()'];

    if (status !== undefined) { fields.push('status'); vals.push(status||null); updates.push(`status=$${vals.length}`); }
    if (note   !== undefined) { fields.push('note');   vals.push(note);         updates.push(`note=$${vals.length}`); }
    if (target_id !== undefined) {
      const validTargetId = await targetBelongsToProject(target_id, req.params.projectId);
      fields.push('target_id'); vals.push(validTargetId); updates.push(`target_id=$${vals.length}`);
    }

    await db.query(
      `INSERT INTO methodology_progress (${fields.join(',')})
       VALUES (${fields.map((_,i)=>`$${i+1}`).join(',')})
       ON CONFLICT (project_id, methodology_id, test_idx) DO UPDATE
         SET ${updates.join(',')}`,
      vals
    );
    res.json({ ok:true, editor:{ id:req.user.id, username:req.user.username, display_name:req.user.display_name || null, avatar_color:req.user.avatar_color }, updated_at: new Date() });
  } catch (err) { next(err); }
});

// ── PROJECT ACTIVATION ───────────────────────────────────────────
// GET all-progress for project: returns { [methodId]: { done, fail, total, tests:[{status,target_id}] } }
router.get('/project-progress/:projectId', requireProjectAccess, denyClientSessions, async (req, res, next) => {
  try {
    // Get active methodology ids for this project
    const { rows: projRows } = await db.query(
      `SELECT active_methodology_ids FROM projects WHERE id=$1`,
      [req.params.projectId]
    );
    const activeIds = projRows[0]?.active_methodology_ids || [];
    if (!activeIds.length) return res.json({});

    // Get methodology details
    const { rows: methods } = await db.query(
      `SELECT id, name, tests FROM methodologies WHERE id = ANY($1)`,
      [activeIds]
    );

    // Get all progress for this project across active methodologies
    const { rows: progress } = await db.query(
      `SELECT methodology_id, test_idx, status, target_id
       FROM methodology_progress
       WHERE project_id=$1 AND methodology_id = ANY($2)`,
      [req.params.projectId, activeIds]
    );

    // Build result
    const result = {};
    methods.forEach(m => {
      const tests = m.tests || [];
      const prog  = progress.filter(p => p.methodology_id === m.id);
      result[m.id] = {
        name:  m.name,
        total: tests.length,
        done:  prog.filter(p => p.status === 'done').length,
        fail:  prog.filter(p => p.status === 'fail').length,
        tests: tests.map((_, i) => {
          const p = prog.find(x => x.test_idx === i);
          return { status: p?.status || null, target_id: p?.target_id || null };
        }),
      };
    });
    res.json(result);
  } catch (err) { next(err); }
});

// PATCH toggle methodology active for project
router.patch('/:methodId/activate/:projectId', requireProjectAccess, requireWriter, async (req, res, next) => {
  const { active } = req.body; // true or false
  try {
    if (active) {
      await db.query(
        `UPDATE projects SET active_methodology_ids = array_append(
           array_remove(active_methodology_ids, $1::uuid), $1::uuid
         ) WHERE id=$2`,
        [req.params.methodId, req.params.projectId]
      );
    } else {
      await db.query(
        `UPDATE projects SET active_methodology_ids = array_remove(active_methodology_ids, $1::uuid)
         WHERE id=$2`,
        [req.params.methodId, req.params.projectId]
      );
    }
    res.json({ ok:true, active: !!active });
  } catch (err) { next(err); }
});

module.exports = router;