const router = require('express').Router({ mergeParams: true });
const db = require('../db');
const { requireAuth } = require('../middleware/auth');
const { requireProjectAccess, portalRequiresFlag } = require('../middleware/project');

router.use(requireAuth, requireProjectAccess, portalRequiresFlag('show_activity'));

// Internal-only work items that are logged to the team feed but must never
// reach the client portal (even with show_activity on): task assignment and
// progress are the team's internal coordination, not engagement progress.
// Code-defined constants, never user input.
const PORTAL_HIDDEN_ENTITIES = ['task', 'organization', 'portal'];

// GET /projects/:projectId/activity?limit=50&offset=0
router.get('/', async (req, res, next) => {
  const limit  = Math.min(parseInt(req.query.limit)  || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  try {
    const { rows } = await db.query(
      `SELECT al.id, al.action, al.entity_type, al.entity_id, al.entity_name,
              al.meta, al.created_at,
              u.id AS user_id, u.username, u.display_name, u.avatar_color, u.avatar_url
       FROM activity_log al
       JOIN users u ON u.id = al.user_id
       WHERE al.project_id = $1
         ${req.isPortal ? `AND al.entity_type NOT IN (${PORTAL_HIDDEN_ENTITIES.map(e => `'${e}'`).join(',')})` : ''}
       ORDER BY al.created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.params.projectId, limit, offset]
    );

    // Client portal privacy: strip the internal team's uploaded avatar images
    // and/or the exact log timestamps when the owner enabled those switches.
    // Enforced server-side so the data never leaves the API, not just hidden in
    // the client's DOM. Internal user sessions always get the full rows.
    if (req.isPortal) {
      const hideAvatars = req.project.portal_hide_team_avatars;
      const hideTimes   = req.project.portal_hide_log_times;
      return res.json(rows.map(r => ({
        ...r,
        avatar_url: hideAvatars ? null : r.avatar_url,
        created_at: hideTimes   ? null : r.created_at,
      })));
    }

    res.json(rows);
  } catch (err) { next(err); }
});

module.exports = router;
