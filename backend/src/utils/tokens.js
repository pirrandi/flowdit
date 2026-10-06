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

// JWT_REFRESH_EXPIRES_IN was documented in .env.example but never read — the
// refresh window was hardcoded to 30 days at all four insert sites, so an
// operator tightening it saw no effect. Accepts the same "30d" form as
// JWT_EXPIRES_IN (plain digits are read as days), and falls back to 30 on
// anything it cannot parse rather than producing an invalid interval.
function refreshExpiryDays() {
  const raw = (process.env.JWT_REFRESH_EXPIRES_IN || '30d').trim();
  const m   = /^(\d+)\s*d?$/i.exec(raw);
  return m ? Number(m[1]) : 30;
}

// The parsed day count is bound as a parameter and cast to an interval — never
// interpolated into the statement.
const REFRESH_INSERT =
  `INSERT INTO refresh_tokens (user_id, token, expires_at)
   VALUES ($1, $2, NOW() + ($3 || ' days')::interval)`;

// Full session mint (access token + persisted refresh token). Used by every
// login path that issues real tokens: /auth/sso/callback and
// /auth/mfa/verify (the two paths that establish a session *after* an
// intermediate step, as opposed to /auth/login and /auth/register which
// inline this same sequence directly).
async function mintSession(user) {
  const accessToken  = signAccess(user);
  const refreshToken = uuidv4() + uuidv4().replace(/-/g, '');
  await db.query(REFRESH_INSERT, [user.id, refreshToken, refreshExpiryDays()]);
  return {
    accessToken, refreshToken,
    user: { id: user.id, username: user.username, display_name: user.display_name || null, email: user.email, avatar_color: user.avatar_color },
  };
}

module.exports = { signAccess, mintSession, refreshExpiryDays, REFRESH_INSERT };
