const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const db = require('../db');

// Shared by /auth/login, /auth/register, and /auth/sso/callback — every path
// that establishes a session mints the same first-party HS256 token, so
// middleware/auth.js's requireAuth needs zero changes regardless of how the
// user authenticated.
function signAccess(user) {
  return jwt.sign({ sub: user.id, username: user.username }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  });
}

// Full session mint (access token + persisted refresh token). Used by every
// login path that issues real tokens: /auth/sso/callback and
// /auth/mfa/verify (the two paths that establish a session *after* an
// intermediate step, as opposed to /auth/login and /auth/register which
// inline this same sequence directly).
async function mintSession(user) {
  const accessToken  = signAccess(user);
  const refreshToken = uuidv4() + uuidv4().replace(/-/g, '');
  await db.query(
    `INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1,$2, NOW() + INTERVAL '30 days')`,
    [user.id, refreshToken]
  );
  return {
    accessToken, refreshToken,
    user: { id: user.id, username: user.username, email: user.email, avatar_color: user.avatar_color },
  };
}

module.exports = { signAccess, mintSession };
