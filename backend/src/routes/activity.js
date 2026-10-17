const router = require('express').Router({ mergeParams: true });
const db = require('../db');
const { requireAuth } = require('../middleware/auth');
const { requireProjectAccess, portalRequiresFlag } = require('../middleware/project');

router.use(requireAuth, requireProjectAccess, portalRequiresFlag('show_activity'));

// Qué eventos del feed puede ver el portal del cliente: ALLOWLIST de pares
// (entity_type, action), no denylist. Antes se ocultaban algunos entity_type
// (task, organization, portal, mcp_proposal) y todo lo demás pasaba, así que
// cada evento nuevo llegaba al cliente por defecto: invitaciones de miembros
// (con el token de invitación en meta), sesiones del AI Agent, recon interno
// (puertos, endpoints), notas de trabajo y hallazgos en borrador. Con la
// allowlist, un evento que se agregue mañana queda oculto hasta que alguien
// decida explícitamente que es para el cliente.
//
// Lista vigente y por qué:
//   - custom_vuln / vuln_created               → hallazgo reportado. Solo si HOY
//     está publicado (client_visible), mismo criterio que GET /vulns del portal.
//   - custom_vuln / remediation_status_changed → remediación y resultado del
//     retest. Solo sobre hallazgos publicados.
//   - wstg_test / set_status                   → avance de la metodología, solo
//     con show_wstg_progress (el portal ya muestra ese progreso).
//   - target / target_added, target_removed    → cambios de alcance, solo con
//     show_targets (el portal ya muestra el scope).
// Quedan afuera a propósito, entre otros: vuln set_status (triage interno),
// vuln_deleted (sin entity_id no se puede saber si estuvo publicado), add_note,
// target_updated, puertos/endpoints, labs, miembros/invitaciones, tareas,
// links del portal, propuestas de Claude Code y todo ai_scan_* (sesiones,
// límites, costos, pausas): el cliente no ve el trabajo interno ni la IA.
// Constantes del código, nunca input del usuario.
const PORTAL_ACTIVITY_ALLOWLIST = [
  { entityType: 'custom_vuln', action: 'vuln_created',               publishedFinding: true },
  { entityType: 'custom_vuln', action: 'remediation_status_changed', publishedFinding: true },
  { entityType: 'wstg_test',   action: 'set_status',                 flag: 'show_wstg_progress' },
  { entityType: 'target',      action: 'target_added',               flag: 'show_targets' },
  { entityType: 'target',      action: 'target_removed',             flag: 'show_targets' },
];

// Claves de meta que puede recibir el portal: solo enums de estado que el
// label del feed necesita. Todo lo demás (ai_generated, via, message, token,
// assignee, scope...) se descarta, así la procedencia IA o un dato interno
// agregado en meta en el futuro nunca llega al cliente.
const PORTAL_META_FIELDS = ['severity', 'status', 'remediation_status'];

function portalMeta(meta) {
  if (!meta || typeof meta !== 'object') return null;
  const out = {};
  for (const k of PORTAL_META_FIELDS) {
    if (typeof meta[k] === 'string') out[k] = meta[k];
  }
  return Object.keys(out).length ? out : null;
}

// Arma el filtro SQL del portal a partir de la allowlist. Los pares van como
// parámetros; los flags del proyecto se resuelven acá porque son por proyecto
// y no cambian dentro del request. Se filtra en SQL (no en JS después) para que
// LIMIT/OFFSET pagine sobre lo que el cliente realmente puede ver.
function portalFilter(project, params) {
  const clauses = [];
  for (const rule of PORTAL_ACTIVITY_ALLOWLIST) {
    if (rule.flag && !project[rule.flag]) continue;
    params.push(rule.entityType, rule.action);
    const et = `$${params.length - 1}`, ac = `$${params.length}`;
    clauses.push(rule.publishedFinding
      ? `(al.entity_type = ${et} AND al.action = ${ac} AND cv.client_visible = true)`
      : `(al.entity_type = ${et} AND al.action = ${ac})`);
  }
  return clauses.length ? `AND (${clauses.join(' OR ')})` : 'AND false';
}

// GET /projects/:projectId/activity?limit=50&offset=0
router.get('/', async (req, res, next) => {
  const limit  = Math.min(parseInt(req.query.limit)  || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const params = [req.params.projectId, limit, offset];
    const filter = req.isPortal ? portalFilter(req.project, params) : '';
    // El JOIN a custom_vulns solo lo usa el portal: decide si el hallazgo está
    // publicado y aporta su nombre actual (el que el cliente ve en Findings).
    const { rows } = await db.query(
      `SELECT al.id, al.action, al.entity_type, al.entity_id, al.entity_name,
              al.meta, al.created_at,
              u.id AS user_id, u.username, u.display_name, u.avatar_color, u.avatar_url,
              cv.name AS finding_name
       FROM activity_log al
       JOIN users u ON u.id = al.user_id
       LEFT JOIN custom_vulns cv
              ON al.entity_type = 'custom_vuln'
             AND cv.id::text = al.entity_id
             AND cv.project_id = al.project_id
       WHERE al.project_id = $1
         ${filter}
       ORDER BY al.created_at DESC
       LIMIT $2 OFFSET $3`,
      params
    );

    // Client portal privacy: strip the internal team's uploaded avatar images
    // and/or the exact log timestamps when the owner enabled those switches.
    // Enforced server-side so the data never leaves the API, not just hidden in
    // the client's DOM. Internal user sessions always get the full rows.
    if (req.isPortal) {
      const hideAvatars = req.project.portal_hide_team_avatars;
      const hideTimes   = req.project.portal_hide_log_times;
      // Proyección explícita (allowlist de campos): meta filtrada y, para
      // hallazgos, el nombre publicado en vez del entity_name logueado, que
      // pudo ser el título del borrador (p. ej. con wording del AI Agent o de
      // Claude Code) antes de que alguien lo editara y lo publicara.
      return res.json(rows.map(r => ({
        id:           r.id,
        action:       r.action,
        entity_type:  r.entity_type,
        entity_id:    r.entity_id,
        entity_name:  r.entity_type === 'custom_vuln' ? r.finding_name : r.entity_name,
        meta:         portalMeta(r.meta),
        created_at:   hideTimes   ? null : r.created_at,
        username:     r.username,
        display_name: r.display_name,
        avatar_color: r.avatar_color,
        avatar_url:   hideAvatars ? null : r.avatar_url,
      })));
    }

    res.json(rows.map(({ finding_name, ...r }) => r));
  } catch (err) { next(err); }
});

module.exports = router;
