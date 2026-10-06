const db = require('../db');
const ws = require('./ws');
const { userBelongsToProject } = require('./ownership');

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

module.exports = { notify };
