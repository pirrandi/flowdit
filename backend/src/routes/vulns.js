const router   = require('express').Router({ mergeParams: true });
const { body, validationResult } = require('express-validator');
const db       = require('../db');
const activity = require('../services/activity');
const { requireAuth } = require('../middleware/auth');
const { requireProjectAccess, requireWriter, isLeadRole, isClientSession, clientRequiresFlag } = require('../middleware/project');
const { targetBelongsToProject } = require('../services/ownership');
const agentLoop = require('../services/ai/agentLoop');

// Portal y cuentas viewer (el cliente, ver isClientSession) quedan sujetos a
// show_findings y reciben la misma proyección: antes la cuenta viewer recibía
// todos los hallazgos, borradores incluidos, con notas, payloads, editor y
// ai_generated.
router.use(requireAuth, requireProjectAccess, clientRequiresFlag('show_findings'));

// What a client portal session is allowed to see of a finding — an explicit
// ALLOWLIST, not a blocklist, so a field added later (internal notes, raw
// payloads, the editing pentester's identity/avatar, AI provenance, evidence
// proofs) can never leak to the client by default. Everything else the full
// row carries (notes, payloads, items, checked_items, evidence, editor_*,
// verifier_*, created_by, updated_by, ai_generated) is dropped for the portal.
const PORTAL_FINDING_FIELDS = [
  'id', 'name', 'category', 'severity', 'description', 'remediation',
  'cvss_vector', 'cvss_score', 'cwe', 'compliance_tags', 'target_id',
  'target_host', 'target_type', 'remediation_status', 'retest_date',
  'retest_notes', 'created_at',
];
function toPortalFinding(row) {
  const out = {};
  for (const f of PORTAL_FINDING_FIELDS) out[f] = row[f];
  return out;
}

router.get('/', async (req, res, next) => {
  try {
    // Portal sessions see ONLY findings the pentester has published
    // (client_visible), never drafts or half-triaged ones.
    const client = isClientSession(req);
    const portalFilter = client ? 'AND cv.client_visible = true' : '';
    const { rows } = await db.query(
      `SELECT cv.*, u.username AS editor_username, u.display_name AS editor_display_name, u.avatar_color AS editor_color, u.avatar_url AS editor_avatar_url,
              vu.username AS verifier_username, vu.display_name AS verifier_display_name,
              t.host AS target_host, t.type AS target_type
       FROM custom_vulns cv
       LEFT JOIN users u  ON u.id=cv.updated_by
       LEFT JOIN users vu ON vu.id=cv.verified_by
       LEFT JOIN targets t ON t.id=cv.target_id
       WHERE cv.project_id=$1 ${portalFilter}
       ORDER BY
         CASE cv.severity
           WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
           WHEN 'low' THEN 4 WHEN 'info' THEN 5 ELSE 6 END,
         cv.created_at`,
      [req.params.projectId]
    );
    res.json(client ? rows.map(toPortalFinding) : rows);
  } catch (err) { next(err); }
});

router.post('/', requireWriter, [
  body('name').trim().isLength({ min:1, max:300 }),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const {
    name, category='Custom', severity='medium', items=[], payloads=[], notes='', description='', remediation='', evidence=[], target_id=null, cvss_vector=null, cvss_score=null, cwe=null, compliance_tags=[],
    // Presentes solo cuando este POST viene del flujo "Editar y agregar" de
    // una propuesta del scanner de IA (ver AI_PENTEST_AGENT.md § Nivel 3) —
    // le avisan al loop que esa tool call quedó resuelta, para que no se
    // quede esperando una aprobación que ya pasó por acá.
    resolve_ai_session_id = null, resolve_ai_call_id = null,
  } = req.body;
  try {
    // client_visible is intentionally NOT read from the body: a new finding is
    // always a draft (column default false). Publishing is a separate, lead-only
    // step through PATCH — see below.
    const validTargetId = await targetBelongsToProject(target_id, req.params.projectId);
    // "Editar y agregar" de una propuesta del agente sigue siendo un
    // hallazgo de origen IA (el humano ajustó campos, no lo inventó de
    // cero) — mismo criterio que createFindingFromProposal() en
    // agentLoop.js para el resto de las vías de propose_finding.
    const aiGenerated = !!(resolve_ai_session_id && resolve_ai_call_id);
    const { rows } = await db.query(
      `INSERT INTO custom_vulns (project_id, name, category, severity, items, payloads, notes, description, remediation, evidence, target_id, cvss_vector, cvss_score, cwe, compliance_tags, created_by, updated_by, ai_generated)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$16,$17) RETURNING *`,
      [req.params.projectId, name, category, severity, JSON.stringify(items), JSON.stringify(payloads), notes, description, remediation, JSON.stringify(evidence), validTargetId, cvss_vector||null, cvss_score||null, cwe||null, JSON.stringify(compliance_tags), req.user.id, aiGenerated]
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

    if (resolve_ai_session_id && resolve_ai_call_id) {
      // No await — resolver el gate no debe demorar ni poder hacer fallar
      // la respuesta de creación del hallazgo, que ya está confirmada.
      // sessionBelongsToProject: resolve_ai_session_id lo manda el cliente
      // — sin validarlo, cualquier proyecto podía forzar la resolución de
      // un gate pendiente en OTRO proyecto (encontrado en revisión, ver
      // AI_PENTEST_AGENT.md § Seguridad).
      agentLoop.sessionBelongsToProject(resolve_ai_session_id, req.params.projectId)
        .then(belongs => belongs
          ? agentLoop.resolveGatedCall(resolve_ai_session_id, resolve_ai_call_id, 'accepted', req.user.id, { created_vuln_id: rows[0].id })
          : null)
        .catch(err => console.error('resolveGatedCall (editar y agregar) failed:', err.message));
    }

    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

router.patch('/:vulnId', requireWriter, async (req, res, next) => {
  // Publishing to / hiding from the client portal is a client-facing action:
  // owner/editor only. A pentester may send the field back unchanged (a form
  // that round-trips the whole row), but any actual change is refused.
  if (req.body.client_visible !== undefined && !isLeadRole(req.memberRole)) {
    try {
      const { rows: cur } = await db.query(
        `SELECT client_visible FROM custom_vulns WHERE id=$1 AND project_id=$2`,
        [req.params.vulnId, req.params.projectId]
      );
      if (!cur.length) return res.status(404).json({ error:'Vulnerability not found' });
      const wanted = req.body.client_visible === true || req.body.client_visible === 'true';
      if (cur[0].client_visible !== wanted)
        return res.status(403).json({ error:'Only the project owner or an editor can publish findings to the client' });
    } catch (err) { return next(err); }
  }
  const allowed = ['name','category','severity','items','payloads','notes','description','remediation','evidence','http_proofs','status','checked_items','cvss_vector','cvss_score','cwe','compliance_tags','client_visible'];
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

// PATCH /:vulnId/remediation — remediation/retest lifecycle (open -> remediated -> verified_closed | not_remediated)
router.patch('/:vulnId/remediation', requireWriter, [
  body('remediation_status').isIn(['open', 'remediated', 'not_remediated', 'verified_closed']),
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
        // 'open' or 'not_remediated' — no confirmed fix stands, so the
        // remediated/verified trail from a prior claim no longer applies.
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

router.delete('/:vulnId', requireWriter, async (req, res, next) => {
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