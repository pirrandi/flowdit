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
