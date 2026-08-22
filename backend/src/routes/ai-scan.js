const router   = require('express').Router({ mergeParams: true });
const { body, validationResult } = require('express-validator');
const db        = require('../db');
const activity  = require('../services/activity');
const { requireAuth } = require('../middleware/auth');
const { requireProjectAccess, requireEditor } = require('../middleware/project');
const { targetBelongsToProject } = require('../services/ownership');
const agentLoop = require('../services/ai/agentLoop');
const ai = require('../services/ai');

router.use(requireAuth, requireProjectAccess);

// Crea una sesión de scan y arranca el loop del agente. Responde apenas se
// crea el registro — NO espera a que el agente haga nada (ver
// AI_PENTEST_AGENT.md § Rutas backend). El progreso real llega por WebSocket.
router.post('/sessions', requireEditor, [
  body('instruction').optional({ nullable: true }).trim().isLength({ max: 4000 }),
  body('lang').optional({ nullable: true }).isIn(['es', 'en']),
  // Config de IA por sesión — opcional, pisa la del proyecto si viene (ver
  // el merge `effective` en agentLoop.js advance()). NULL/omitido = "usá lo
  // del proyecto".
  body('ai_provider').optional({ nullable: true }).isIn(ai.PROVIDERS),
  body('ai_model').optional({ nullable: true }).trim().isLength({ max: 50 }),
  body('ai_tool_mode').optional({ nullable: true }).isIn(['native', 'text']),
  body('ai_autonomous_requests').optional({ nullable: true }).isBoolean(),
  body('ai_single_agent').optional({ nullable: true }).isBoolean(),
  // Qué tipo de engagement es — cambia el enfoque del agente (buildSystemPrompt
  // en agentLoop.js), no la config de IA. NULL/omitido = 'pentest' (default,
  // sin cambio de comportamiento).
  body('ai_profile').optional({ nullable: true }).isIn(['pentest', 'ctf', 'lab']),
  // Tope duro de gasto para esta sesión — ver el chequeo en advance()
  // (agentLoop.js). Mínimo $0.01: un tope de $0 pausaría la sesión antes de
  // la primera llamada, que no es lo que alguien quiere decir con "poné un
  // límite".
  body('ai_max_cost_usd').optional({ nullable: true }).isFloat({ min: 0.01 }),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { target_id = null, instruction = null, lang = 'es' } = req.body;
  const aiOverrides = {
    ai_provider: req.body.ai_provider || null,
    ai_model: req.body.ai_model || null,
    ai_tool_mode: req.body.ai_tool_mode || null,
    ai_autonomous_requests: req.body.ai_autonomous_requests ?? null,
    ai_single_agent: req.body.ai_single_agent ?? null,
    ai_profile: req.body.ai_profile || null,
    ai_max_cost_usd: req.body.ai_max_cost_usd || null,
  };
  try {
    const validTargetId = await targetBelongsToProject(target_id, req.params.projectId);

    // Crea la sesión Y su thread primario (coordinador) en un solo paso —
    // advance() no tiene sentido sin un thread. Ver agentLoop.js.
    const { session, primaryThread } = await agentLoop.createSessionWithPrimaryThread(req.params.projectId, validTargetId, req.user.id, lang, instruction, aiOverrides);

    await db.query(
      `INSERT INTO ai_scan_events (session_id, thread_id, type, payload, created_by) VALUES ($1,$2,'session.started',$3,$4)`,
      [session.id, primaryThread.id, JSON.stringify({ target_id: validTargetId }), req.user.id]
    );
    if (instruction) {
      await db.query(
        `INSERT INTO ai_scan_events (session_id, thread_id, type, payload, created_by) VALUES ($1,$2,'chat.message',$3,$4)`,
        [session.id, primaryThread.id, JSON.stringify({ role: 'user', text: instruction }), req.user.id]
      );
    }

    activity.log({
      projectId: req.params.projectId, user: req.user,
      action: 'ai_scan_started', entityType: 'ai_scan_session', entityId: session.id,
    });

    res.status(201).json({ session });

    // Fire-and-forget: advance() ya maneja sus propios errores de proveedor
    // internamente (persiste session.error, no relanza), pero un fallo de DB
    // antes de ese try/catch interno igual podría quedar como una promesa
    // sin atrapar si no ponemos este .catch() acá.
    agentLoop.advance(session.id, primaryThread.id).catch(err => console.error('agentLoop.advance failed:', err.message));
  } catch (err) { next(err); }
});

// Catch-up: historial completo para quien recién se conecta o se reconecta
// (ver AI_PENTEST_AGENT.md § WebSocket).
router.get('/sessions/:sessionId', async (req, res, next) => {
  try {
    const { rows: sessionRows } = await db.query(
      `SELECT * FROM ai_scan_sessions WHERE id=$1 AND project_id=$2`,
      [req.params.sessionId, req.params.projectId]
    );
    if (!sessionRows.length) return res.status(404).json({ error: 'Session not found' });

    const { rows: threads } = await db.query(
      `SELECT * FROM ai_scan_threads WHERE session_id=$1 ORDER BY created_at`,
      [req.params.sessionId]
    );
    const { rows: events } = await db.query(
      `SELECT id, thread_id, type, payload, created_by, created_at FROM ai_scan_events WHERE session_id=$1 ORDER BY created_at, id`,
      [req.params.sessionId]
    );
    res.json({ session: sessionRows[0], threads, events });
  } catch (err) { next(err); }
});

// Últimas sesiones del proyecto — para saber si hay un scan en curso al
// abrir el panel.
router.get('/sessions', async (req, res, next) => {
  try {
    // total_cost/findings_count: agregados desde ai_usage/custom_vulns vía
    // session_id (ver migrate.js) — para mostrar cuánto costó y cuántos
    // hallazgos produjo cada sesión en el picker (ai-agent.js).
    const { rows } = await db.query(
      `SELECT s.*,
         COALESCE(u.total_cost, 0)     AS total_cost,
         COALESCE(v.findings_count, 0) AS findings_count
       FROM ai_scan_sessions s
       LEFT JOIN (SELECT session_id, SUM(cost_usd) AS total_cost FROM ai_usage
                  WHERE session_id IS NOT NULL GROUP BY session_id) u ON u.session_id = s.id
       LEFT JOIN (SELECT session_id, COUNT(*) AS findings_count FROM custom_vulns
                  WHERE session_id IS NOT NULL GROUP BY session_id) v ON v.session_id = s.id
       WHERE s.project_id=$1
       ORDER BY s.started_at DESC LIMIT 20`,
      [req.params.projectId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// Borra una sesión (y en cascada sus threads/eventos — FKs con ON DELETE
// CASCADE, ver migrate.js). Bloqueada mientras está `running`: en ese
// estado puede haber un advance() realmente en vuelo (llamada al proveedor
// o tool ejecutándose) — borrar la sesión debajo suyo haría que su próximo
// persistEvent() viole la FK contra una fila que ya no existe. `idle`,
// `waiting_approval`, `paused`, `completed` y `error` no tienen nada en
// vuelo, se pueden borrar sin ese riesgo.
router.delete('/sessions/:sessionId', requireEditor, async (req, res, next) => {
  try {
    const { rows: existing } = await db.query(
      `SELECT status FROM ai_scan_sessions WHERE id=$1 AND project_id=$2`,
      [req.params.sessionId, req.params.projectId]
    );
    if (!existing.length) return res.status(404).json({ error: 'Session not found' });
    if (existing[0].status === 'running') {
      return res.status(409).json({ error: 'La sesión está corriendo — pausala o esperá a que termine antes de borrarla' });
    }

    await db.query(`DELETE FROM ai_scan_sessions WHERE id=$1`, [req.params.sessionId]);
    activity.log({
      projectId: req.params.projectId, user: req.user,
      action: 'ai_scan_deleted', entityType: 'ai_scan_session', entityId: req.params.sessionId,
    });
    res.status(204).end();
  } catch (err) { next(err); }
});

// Renombra una sesión (pisa cualquier auto-nombre derivado del primer
// mensaje, ver deriveSessionName en agentLoop.js) y/o sube el tope de gasto
// de una sesión que ya lo alcanzó (ver el chequeo en advance(), agentLoop.js).
// Subir el tope acá NO retoma la sesión sola a propósito — advance() solo
// vuelve a correr cuando el pentester manda un mensaje de chat de verdad
// (sendMessage(), que ya funciona con el input habilitado en estado `idle`).
// Auto-retomar en cuanto se sube el tope resolvería el caso feliz, pero
// también dispararía un turno del agente sin que nadie lo haya pedido en
// sesiones `idle` por cualquier OTRA razón (ej. esperando instrucción) — el
// costo de ese error es exactamente lo que este feature existe para evitar.
router.patch('/sessions/:sessionId', requireEditor, [
  body('name').optional().trim().isLength({ min: 1, max: 200 }),
  body('ai_max_cost_usd').optional({ nullable: true }).isFloat({ min: 0.01 }),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  if (req.body.name === undefined && req.body.ai_max_cost_usd === undefined) {
    return res.status(400).json({ error: 'Nothing to update' });
  }

  const sets = [];
  const values = [];
  if (req.body.name !== undefined) { values.push(req.body.name); sets.push(`name=$${values.length}`); }
  if (req.body.ai_max_cost_usd !== undefined) { values.push(req.body.ai_max_cost_usd); sets.push(`ai_max_cost_usd=$${values.length}`); }
  values.push(req.params.sessionId, req.params.projectId);

  try {
    const { rows } = await db.query(
      `UPDATE ai_scan_sessions SET ${sets.join(', ')} WHERE id=$${values.length - 1} AND project_id=$${values.length} RETURNING *`,
      values
    );
    if (!rows.length) return res.status(404).json({ error: 'Session not found' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

module.exports = router;
