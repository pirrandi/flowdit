const router   = require('express').Router({ mergeParams: true });
const { body, validationResult } = require('express-validator');
const db       = require('../db');
const activity = require('../services/activity');
const { requireAuth } = require('../middleware/auth');
const { requireProjectAccess, requireWriter, isClientSession, clientRequiresFlag } = require('../middleware/project');

// Portal y cuentas viewer (el cliente) solo ven el scope con show_targets.
router.use(requireAuth, requireProjectAccess, clientRequiresFlag('show_targets'));

// GET all targets for a project
router.get('/', async (req, res, next) => {
  try {
    // El cliente recibe una proyección FIJA: lo que la sección "Scope" de la
    // vista cliente dibuja (host, tipo, scope, estado) más el id, que usa para
    // contar los hallazgos publicados de cada target. Antes iba t.* con las
    // notas internas del pentester y added_by / quién lo agregó.
    if (isClientSession(req)) {
      const { rows } = await db.query(
        `SELECT t.id, t.host, t.type, t.scope, t.status
         FROM targets t
         WHERE t.project_id = $1
         ORDER BY t.created_at`,
        [req.params.projectId]
      );
      return res.json(rows);
    }
    const { rows } = await db.query(
      `SELECT t.*, u.username AS added_by_username, u.display_name AS added_by_display_name
       FROM targets t
       LEFT JOIN users u ON u.id = t.added_by
       WHERE t.project_id = $1
       ORDER BY t.created_at`,
      [req.params.projectId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// POST create target
router.post('/', requireWriter, [
  body('host').trim().isLength({ min:1, max:500 }),
  body('type').isIn(['domain','ip','cidr','url','other']),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { host, type='domain', scope='in', notes='' } = req.body;
  try {
    const { rows } = await db.query(
      `INSERT INTO targets (project_id, host, type, scope, notes, added_by)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [req.params.projectId, host, type, scope, notes, req.user.id]
    );
    await activity.log({
      projectId:  req.params.projectId,
      user:       req.user,
      action:     'target_added',
      entityType: 'target',
      entityId:   rows[0].id,
      entityName: host,
      meta:       { type, scope },
    });
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

// PATCH update target
// PATCH update target
router.patch('/:targetId', requireWriter, async (req, res, next) => {
  const allowed = ['host','type','scope','notes','status'];
  const updates = [], values = [];
  
  allowed.forEach(f => {
    if (req.body[f] !== undefined) {
      updates.push(`${f}=$${values.length + 1}`);
      values.push(req.body[f]);
    }
  });

  if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });

  // Añadimos los IDs para el WHERE
  values.push(req.params.targetId, req.params.projectId);

  try {
    const { rows } = await db.query(
      `UPDATE targets SET ${updates.join(',')}
       WHERE id=$${values.length - 1} AND project_id=$${values.length} 
       RETURNING *`, // El RETURNING * es clave para obtener los datos actuales
      values
    );

    if (!rows.length) return res.status(404).json({ error: 'Target not found' });

    // --- INICIO DE LA ACCIÓN DE LOG ---
    await activity.log({
      projectId:  req.params.projectId,
      user:       req.user,
      action:     'target_updated',
      entityType: 'target',
      entityId:   rows[0].id,
      entityName: rows[0].host, // Usamos el host del registro actualizado
      details:    Object.keys(req.body).filter(k => allowed.includes(k)) // Opcional: registrar qué campos cambiaron
    });
    // --- FIN DE LA ACCIÓN DE LOG ---

    res.json(rows[0]);
  } catch (err) { 
    next(err); 
  }
});

// DELETE target
router.delete('/:targetId', requireWriter, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `DELETE FROM targets WHERE id=$1 AND project_id=$2 RETURNING host`,
      [req.params.targetId, req.params.projectId]
    );
    if (rows.length) {
      await activity.log({
        projectId:  req.params.projectId,
        user:       req.user,
        action:     'target_removed',
        entityType: 'target',
        entityName: rows[0].host,
      });
    }
    res.json({ ok:true });
  } catch (err) { next(err); }
});

module.exports = router;