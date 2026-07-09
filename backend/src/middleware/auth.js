const jwt = require('jsonwebtoken');
const db  = require('../db');

async function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer '))
    return res.status(401).json({ error: 'No token provided' });

  const token = header.slice(7);
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    // Portal token — no user account, project-scoped read-only access
    if (payload.type === 'portal') {
      req.isPortal        = true;
      req.portalProjectId = payload.projectId;
      req.portalTok       = payload.tok;   // bound to a specific portal link
      req.user            = { id: null, username: 'client', role: 'viewer' };
      return next();
    }

    // Regular user token
    const { rows } = await db.query(
      'SELECT id, username, email, avatar_color, avatar_url FROM users WHERE id = $1', [payload.sub]
    );
    if (!rows.length) return res.status(401).json({ error: 'User not found' });
    req.user = rows[0];
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Blocks portal sessions from routes that require a real user account
function requireUser(req, res, next) {
  if (req.isPortal)
    return res.status(403).json({ error: 'Not available in portal sessions' });
  next();
}

// Guards the handful of actions that would leave the public demo instance
// unusable for the next visitor until the periodic reset job runs (project
// delete, org delete, enabling 2FA on the shared login and locking everyone
// else out) — deliberately NOT a blanket "demo is read-only" block, since
// editing findings/targets/tickets is the point of a hands-on demo.
// Only active when DEMO_MODE=true (the demo.flowdit.space deploy), so a real
// user on production choosing the username "demo" is never affected.
function blockDemoDestructive(req, res, next) {
  if (process.env.DEMO_MODE === 'true' && req.user?.username === 'demo') {
    return res.status(403).json({ error: 'Disabled on the public demo — this resets automatically anyway.' });
  }
  next();
}

module.exports = { requireAuth, requireUser, blockDemoDestructive };
