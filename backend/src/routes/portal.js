// ── Portal auth — public endpoint, no requireAuth ────────────────────
const router  = require('express').Router();
const jwt     = require('jsonwebtoken');
const bcrypt  = require('bcryptjs');
const db      = require('../db');
const { hashToken, ACTIVE_SQL } = require('../services/portalLinks');

// POST /api/portal/auth  { token, password? }
router.post('/auth', async (req, res, next) => {
  const { token, password } = req.body;
  if (!token || typeof token !== 'string') return res.status(400).json({ error: 'Token required' });
  try {
    // Lookup by SHA-256 of the token: the plaintext is never stored or compared.
    // Unknown, revoked and expired links all get the same 401 — no oracle
    // telling a link holder which of the three it is.
    const { rows } = await db.query(
      `SELECT pl.id AS link_id, pl.label, pl.email, pl.is_legacy,
              p.id, p.name, p.portal_password_hash, p.portal_require_password, p.client_view_enabled
       FROM portal_links pl
       JOIN projects p ON p.id = pl.project_id
       WHERE pl.token_hash = $1 AND ${ACTIVE_SQL}`,
      [hashToken(token.trim())]
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

    await db.query(
      `UPDATE portal_links SET last_used_at = NOW(), use_count = use_count + 1 WHERE id = $1`,
      [proj.link_id]
    );

    // Bound to the link, not the project: revoking this one contact's link
    // ends their session on the next request (see requireProjectAccess).
    const accessToken = jwt.sign(
      { sub: 'portal', type: 'portal', projectId: proj.id, linkId: proj.link_id },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      accessToken,
      projectId:    proj.id,
      projectName:  proj.name,
      portalOpen:   proj.client_view_enabled,
      // The shared legacy link has no single contact behind it.
      contactName:  proj.is_legacy ? null : proj.label,
      contactEmail: proj.is_legacy ? null : (proj.email || null),
    });
  } catch (err) { next(err); }
});

module.exports = router;
