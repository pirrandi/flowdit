const router = require('express').Router({ mergeParams: true });
const db     = require('../db');
const { requireAuth, requireUser } = require('../middleware/auth');
const { requireProjectAccess, requireLead, denyClientSessions } = require('../middleware/project');
// Guard against a runaway payload filling the column: the report config is
// text + layout, never binary evidence (that lives on the vuln rows).
const { REPORT_MAX_BYTES: MAX_BYTES } = require('../services/mcp/report');

// The report builder config is the team's working draft of the deliverable,
// not something the client portal reads — portal sessions are refused.
// Las cuentas viewer son el cliente (ver isClientSession): igual que el portal,
// no ven este material interno aunque no puedan escribirlo.
router.use(requireAuth, requireUser, requireProjectAccess, denyClientSessions);

// GET /api/projects/:projectId/report-config
router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT project_id, data, updated_by, updated_at FROM report_config WHERE project_id=$1`,
      [req.params.projectId]
    );
    res.json(rows[0] || { project_id: req.params.projectId, data: null, updated_by: null, updated_at: null });
  } catch (err) { next(err); }
});

// PUT /api/projects/:projectId/report-config
// The report builder shapes the client deliverable — lead only (no pentester).
//
// Optimistic concurrency: the builder sends `base_updated_at`, the updated_at
// of the copy it last pulled or pushed (null = it saw no saved report). If the
// stored row changed since (another tab, or an approved Claude Code
// report_section proposal), the write is refused with 409 and the current
// server copy, so a stale tab cannot silently overwrite it. Without
// base_updated_at the old last-write-wins behavior stays (older clients).
// updated_at is stamped at millisecond precision and strictly increasing, so
// the value the client got back as JSON compares exactly.
const STAMP_SQL = `GREATEST(date_trunc('milliseconds', clock_timestamp()), report_config.updated_at + INTERVAL '1 millisecond')`;

router.put('/', requireLead, async (req, res, next) => {
  const data = req.body.data;
  if (data === null || typeof data !== 'object' || Array.isArray(data)) {
    return res.status(400).json({ error: 'data must be an object' });
  }
  const checkBase = req.body.base_updated_at !== undefined;
  const base = req.body.base_updated_at;
  if (checkBase && base !== null && (typeof base !== 'string' || Number.isNaN(Date.parse(base)))) {
    return res.status(400).json({ error: 'base_updated_at must be a timestamp or null' });
  }
  const serialized = JSON.stringify(data);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_BYTES) {
    return res.status(413).json({ error: 'Report configuration is too large to store' });
  }
  const client = await db.pool.connect().catch(next);
  if (!client) return;
  try {
    await client.query('BEGIN');
    if (checkBase) {
      const { rows } = await client.query(
        `SELECT project_id, data, updated_by, updated_at,
                date_trunc('milliseconds', updated_at) = $2::timestamptz AS same
         FROM report_config WHERE project_id = $1 FOR UPDATE`,
        [req.params.projectId, base]
      );
      const current = rows[0];
      if (current && !current.same) {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: 'The report was changed elsewhere since this copy was loaded',
          current: { project_id: current.project_id, data: current.data, updated_by: current.updated_by, updated_at: current.updated_at },
        });
      }
    }
    const { rows } = await client.query(
      `INSERT INTO report_config (project_id, data, updated_by, updated_at)
       VALUES ($1, $2, $3, date_trunc('milliseconds', clock_timestamp()))
       ON CONFLICT (project_id) DO UPDATE
         SET data=$2, updated_by=$3, updated_at=${STAMP_SQL}
       RETURNING project_id, data, updated_by, updated_at`,
      [req.params.projectId, serialized, req.user.id]
    );
    await client.query('COMMIT');
    res.json(rows[0]);
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    next(err);
  } finally {
    client.release();
  }
});

module.exports = router;
