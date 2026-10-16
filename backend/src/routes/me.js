// Cross-project views of the current user's own work.
const router = require('express').Router();
const db = require('../db');
const { requireAuth, requireUser } = require('../middleware/auth');
const { body, param, validationResult } = require('express-validator');
const { projectAccessSql } = require('../services/ownership');
const apiTokens = require('../services/apiTokens');

router.use(requireAuth, requireUser);

// GET /me/tasks?include_done=1 — tasks assigned to me, in every project I can
// still access (an assignment in a project I was removed from is not listed).
router.get('/tasks', async (req, res, next) => {
  const includeDone = req.query.include_done === '1' || req.query.include_done === 'true';
  try {
    const { rows } = await db.query(
      `SELECT t.*, p.name AS project_name,
              c.username AS created_by_username, c.display_name AS created_by_display_name,
              tg.host AS target_host, v.name AS vuln_name,
              (SELECT COUNT(*) FROM task_comments tc WHERE tc.task_id = t.id)::int AS comment_count
       FROM project_tasks t
       JOIN projects p ON p.id = t.project_id
       LEFT JOIN users c ON c.id = t.created_by
       LEFT JOIN targets tg ON tg.id = t.target_id
       LEFT JOIN custom_vulns v ON v.id = t.vuln_id
       WHERE t.assignee_id = $1
         AND ${projectAccessSql('t.project_id', '$1')}
         ${includeDone ? '' : `AND t.status <> 'done'`}
       ORDER BY CASE t.status WHEN 'done' THEN 1 ELSE 0 END,
                t.due_date ASC NULLS LAST,
                CASE t.priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                t.created_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// ── Tokens de Claude Code (MCP) ────────────────────────────────────────
// Se gestionan con la sesión normal (JWT); el token en sí solo sirve para
// /mcp (middleware/apiToken.js). token_hash nunca sale de la API y el token
// en claro se devuelve una única vez, en la respuesta del POST.

// Tope de tokens vivos por usuario: uno por máquina/uso alcanza de sobra.
const MAX_ACTIVE_API_TOKENS = 20;

const API_TOKEN_SELECT = `
  SELECT id, name, token_prefix, scopes, created_at, last_used_at, expires_at, revoked_at,
         CASE WHEN revoked_at IS NOT NULL THEN 'revoked'
              WHEN expires_at IS NOT NULL AND expires_at <= NOW() THEN 'expired'
              ELSE 'active' END AS status
  FROM api_tokens`;

// GET /me/api-tokens
router.get('/api-tokens', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `${API_TOKEN_SELECT} WHERE user_id = $1 ORDER BY created_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// POST /me/api-tokens — { name, scopes: 'read'|'read_propose', expires_in_days? }
router.post('/api-tokens', [
  body('name').isString().trim().isLength({ min: 1, max: 100 }),
  body('scopes').optional().isIn(apiTokens.SCOPES),
  body('expires_in_days').optional({ values: 'null' }).isInt({ min: 1, max: 3650 }).toInt(),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const scopes = req.body.scopes || 'read';
  const days   = req.body.expires_in_days ?? null;
  const token  = apiTokens.generateApiToken();
  try {
    const { rows: active } = await db.query(
      `SELECT COUNT(*)::int AS n FROM api_tokens
       WHERE user_id = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())`,
      [req.user.id]
    );
    if (active[0].n >= MAX_ACTIVE_API_TOKENS)
      return res.status(400).json({ error: `At most ${MAX_ACTIVE_API_TOKENS} active tokens — revoke one before creating another` });

    const { rows: inserted } = await db.query(
      `INSERT INTO api_tokens (user_id, name, token_prefix, token_hash, scopes, expires_at)
       VALUES ($1,$2,$3,$4,$5, CASE WHEN $6::int IS NULL THEN NULL ELSE NOW() + make_interval(days => $6::int) END)
       RETURNING id`,
      [req.user.id, req.body.name, apiTokens.displayPrefix(token), apiTokens.hashApiToken(token), scopes, days]
    );
    const { rows } = await db.query(`${API_TOKEN_SELECT} WHERE id = $1`, [inserted[0].id]);
    res.status(201).json({ ...rows[0], token });
  } catch (err) { next(err); }
});

// POST /me/api-tokens/:tokenId/revoke — idempotente
router.post('/api-tokens/:tokenId/revoke', [
  param('tokenId').isUUID(),
], async (req, res, next) => {
  if (!validationResult(req).isEmpty()) return res.status(404).json({ error: 'Token not found' });
  try {
    await db.query(
      `UPDATE api_tokens SET revoked_at = NOW() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
      [req.params.tokenId, req.user.id]
    );
    const { rows } = await db.query(`${API_TOKEN_SELECT} WHERE id = $1 AND user_id = $2`, [req.params.tokenId, req.user.id]);
    if (!rows.length) return res.status(404).json({ error: 'Token not found' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

module.exports = router;
