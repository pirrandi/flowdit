const db = require('../db');
const ws = require('./ws');
const { userBelongsToProject } = require('./ownership');
const { WRITER_ROLES } = require('../middleware/project');

/**
 * Create one notification per recipient and push each live to its recipient.
 *
 * Generic on purpose (type + entity + payload) so any feature can raise
 * notifications without a schema change. Recipients are deduplicated, the
 * actor is always dropped (nobody gets notified of their own action), and for
 * project-scoped events anyone who no longer has access to the project is
 * dropped too, so a removed member doesn't keep receiving its titles.
 *
 * @param {object}   opts
 * @param {string[]} opts.recipients  - user ids (null/undefined entries ignored)
 * @param {object}   opts.actor       - { id, username, display_name, avatar_color }
 * @param {string}   [opts.projectId]
 * @param {string}   opts.type        - e.g. 'task_assigned'
 * @param {string}   [opts.entityType]
 * @param {string}   [opts.entityId]
 * @param {object}   [opts.payload]   - small display data (title snippet, ...)
 */
async function notify({ recipients, actor, projectId, type, entityType, entityId, payload = {} }) {
  const ids = [...new Set((recipients || []).filter(Boolean))].filter(id => id !== actor?.id);
  const created = [];
  for (const userId of ids) {
    try {
      if (projectId && !(await userBelongsToProject(userId, projectId))) continue;
      const { rows } = await db.query(
        `INSERT INTO notifications (user_id, project_id, type, entity_type, entity_id, actor_id, payload)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
        [userId, projectId || null, type, entityType || null, entityId || null, actor?.id || null, JSON.stringify(payload)]
      );
      const n = {
        ...rows[0],
        actor_username: actor?.username || null,
        actor_display_name: actor?.display_name || null,
        actor_color:    actor?.avatar_color || null,
      };
      created.push(n);
      ws.sendToUser(userId, { type: 'notification', notification: n });
    } catch (err) {
      // A failed notification must never break the action that raised it.
      console.error('Notification error:', err.message);
    }
  }
  return created;
}

// Ids de quienes pueden aprobar trabajo en el proyecto: el mismo rol
// efectivo que calcula findProjectForUser (middleware/project.js) — la
// membership directa gana; si no hay, owner/admin de la organización mapean
// a owner/editor — filtrado por WRITER_ROLES. Las cuentas viewer (el
// cliente) quedan afuera: nunca ven propuestas de IA.
async function projectWriterIds(projectId) {
  const { rows } = await db.query(
    `SELECT pm.user_id AS id
     FROM project_members pm
     WHERE pm.project_id = $1 AND pm.role = ANY($2)
     UNION
     SELECT om.user_id
     FROM projects p
     JOIN organization_members om ON om.organization_id = p.organization_id AND om.role IN ('owner','admin')
     WHERE p.id = $1
       AND NOT EXISTS (SELECT 1 FROM project_members x WHERE x.project_id = p.id AND x.user_id = om.user_id)`,
    [projectId, WRITER_ROLES]
  );
  return rows.map(r => r.id);
}

// Avisos que no los dispara una persona sino la IA (Claude Code, AI Agent):
// van a TODOS los writers, incluido quien inició el trabajo — él también
// tiene que revisar. Por eso no hay actor humano (notify() siempre descarta
// al actor); el origen viaja en payload.source. Fire-and-forget: nunca
// rechaza, así que el caller no puede romperse por un aviso que falló.
async function notifyProjectWriters({ projectId, type, entityType, entityId, payload }) {
  try {
    const recipients = await projectWriterIds(projectId);
    if (!recipients.length) return [];
    // El nombre del proyecto va en el payload como en el resto de los avisos
    // (la campana lo muestra debajo del texto).
    const { rows } = await db.query('SELECT name FROM projects WHERE id = $1', [projectId]);
    return await notify({
      recipients, actor: null, projectId, type, entityType, entityId,
      payload: { ...payload, project_name: rows[0]?.name || null },
    });
  } catch (err) {
    console.error('Notification error:', err.message);
    return [];
  }
}

module.exports = { notify, notifyProjectWriters, projectWriterIds };
