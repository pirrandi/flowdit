const jwt = require('jsonwebtoken');
const db  = require('../db');

async function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer '))
    return res.status(401).json({ error: 'No token provided' });

  const token = header.slice(7);
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    // Attach full user (including avatar_color) so activity log can use it
    const { rows } = await db.query(
      'SELECT id, username, email, avatar_color FROM users WHERE id = $1', [payload.sub]
    );
    if (!rows.length) return res.status(401).json({ error: 'User not found' });
    req.user = rows[0];
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = { requireAuth };
