// ── Portal auth — public endpoint, no requireAuth ────────────────────
const router  = require('express').Router();
const jwt     = require('jsonwebtoken');
const bcrypt  = require('bcryptjs');
const db      = require('../db');

// POST /api/portal/auth  { token, password? }
router.post('/auth', async (req, res, next) => {
  const { token, password } = req.body;
  if (!token) return res.status(400).json({ error: 'Token required' });
  try {
    const { rows } = await db.query(
      `SELECT id, name, portal_token, portal_password_hash, portal_require_password, client_view_enabled
       FROM projects WHERE portal_token = $1`,
      [token.trim()]
    );
    if (!rows.length) return res.status(401).json({ error: 'Invalid or expired link' });
    const proj = rows[0];

    // Don't mint a working token at all when the owner has the portal switched off —
    // the frontend gate can be bypassed by reading the accessToken straight off this
    // response, so the check has to happen here, not just client-side on `portalOpen`.
    if (!proj.client_view_enabled) {
      return res.status(403).json({ error: 'Client portal is not enabled for this project', portalOpen: false });
    }

    if (proj.portal_require_password) {
      if (!password) return res.status(401).json({ error: 'Password required', passwordRequired: true });
      const match = proj.portal_password_hash && await bcrypt.compare(password, proj.portal_password_hash);
      if (!match) return res.status(401).json({ error: 'Incorrect password' });
    }

    const accessToken = jwt.sign(
      { sub: 'portal', projectId: proj.id, type: 'portal', tok: proj.portal_token },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      accessToken,
      projectId:   proj.id,
      projectName: proj.name,
      portalOpen:  proj.client_view_enabled,
    });
  } catch (err) { next(err); }
});

module.exports = router;
