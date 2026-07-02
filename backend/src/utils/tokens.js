const jwt = require('jsonwebtoken');

// Shared by /auth/login, /auth/register, and /auth/sso/callback — every path
// that establishes a session mints the same first-party HS256 token, so
// middleware/auth.js's requireAuth needs zero changes regardless of how the
// user authenticated.
function signAccess(user) {
  return jwt.sign({ sub: user.id, username: user.username }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  });
}

module.exports = { signAccess };
