const db  = require('../db');
const ws  = require('./ws');

/**
 * Log an action and broadcast it via WebSocket.
 *
 * @param {object} opts
 * @param {string} opts.projectId
 * @param {object} opts.user        - { id, username, avatar_color }
 * @param {string} opts.action      - e.g. 'set_status', 'add_note', 'invite_created'
 * @param {string} opts.entityType  - 'wstg_test' | 'ps_lab' | 'custom_vuln' | 'member' | 'project'
 * @param {string} [opts.entityId]
 * @param {string} [opts.entityName]
 * @param {object} [opts.meta]      - extra data (old/new values, etc.)
 */
async function log(opts) {
  const { projectId, user, action, entityType, entityId, entityName, meta } = opts;

  try {
    const { rows } = await db.query(
      `INSERT INTO activity_log
         (project_id, user_id, action, entity_type, entity_id, entity_name, meta)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING id, created_at`,
      [projectId, user.id, action, entityType, entityId || null, entityName || null, meta ? JSON.stringify(meta) : null]
    );

    const entry = {
      id:          rows[0].id,
      project_id:  projectId,
      created_at:  rows[0].created_at,
      action,
      entity_type: entityType,
      entity_id:   entityId,
      entity_name: entityName,
      meta,
      user: {
        id:           user.id,
        username:     user.username,
        avatar_color: user.avatar_color || '#7c3aed',
      },
    };

    // Real-time broadcast
    ws.broadcastActivity(projectId, entry);
  } catch (err) {
    // Never let logging break main flows
    console.error('Activity log error:', err.message);
  }
}

module.exports = { log };
