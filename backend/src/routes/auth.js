const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt    = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { body, validationResult } = require('express-validator');
const db = require('../db');
const { requireAuth } = require('../middleware/auth');
const wsService = require('../services/ws');

// Palette for auto-assigned avatar colors
const COLORS = ['#7c3aed','#2563eb','#059669','#dc2626','#d97706','#0891b2','#7c3aed','#be185d'];

function signAccess(user) {
  return jwt.sign({ sub: user.id, username: user.username }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  });
}

// POST /auth/register
router.post('/register', [
  body('username').trim().isLength({ min:2, max:50 }).matches(/^[a-zA-Z0-9_-]+$/),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min:8, max:128 }),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, email, password } = req.body;
  try {
    const exists = await db.query(
      'SELECT id FROM users WHERE username=$1 OR email=$2', [username, email]
    );
    if (exists.rows.length)
      return res.status(409).json({ error: 'Username or email already taken' });

    const hash  = await bcrypt.hash(password, 12);
    const color = COLORS[Math.floor(Math.random() * COLORS.length)];
    const { rows } = await db.query(
      `INSERT INTO users (username, email, password, avatar_color)
       VALUES ($1,$2,$3,$4) RETURNING id, username, email, avatar_color, created_at`,
      [username, email, hash, color]
    );
    const user = rows[0];

    const accessToken  = signAccess(user);
    const refreshToken = uuidv4() + uuidv4().replace(/-/g,'');
    await db.query(
      `INSERT INTO refresh_tokens (user_id, token, expires_at)
       VALUES ($1,$2, NOW() + INTERVAL '30 days')`,
      [user.id, refreshToken]
    );

    res.status(201).json({ accessToken, refreshToken,
      user: { id:user.id, username:user.username, email:user.email, avatar_color:user.avatar_color } });
  } catch (err) { next(err); }
});

// POST /auth/login
router.post('/login', [
  body('login').trim().notEmpty(),
  body('password').notEmpty(),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { login, password } = req.body;
  try {
    const { rows } = await db.query(
      'SELECT * FROM users WHERE username=$1 OR email=$1', [login]
    );
    const user = rows[0];
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: 'Invalid credentials' });

    const accessToken  = signAccess(user);
    const refreshToken = uuidv4() + uuidv4().replace(/-/g,'');
    await db.query(
      `INSERT INTO refresh_tokens (user_id, token, expires_at)
       VALUES ($1,$2, NOW() + INTERVAL '30 days')`,
      [user.id, refreshToken]
    );

    res.json({ accessToken, refreshToken,
      user: { id:user.id, username:user.username, email:user.email, avatar_color:user.avatar_color } });
  } catch (err) { next(err); }
});

// POST /auth/refresh
router.post('/refresh', async (req, res, next) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });
  try {
    const { rows } = await db.query(
      `SELECT rt.*, u.id as uid, u.username, u.avatar_color
       FROM refresh_tokens rt JOIN users u ON u.id=rt.user_id
       WHERE rt.token=$1 AND rt.expires_at > NOW()`,
      [refreshToken]
    );
    if (!rows.length) return res.status(401).json({ error: 'Invalid or expired refresh token' });
    const row = rows[0];

    await db.query('DELETE FROM refresh_tokens WHERE id=$1', [row.id]);
    const newRefresh = uuidv4() + uuidv4().replace(/-/g,'');
    await db.query(
      `INSERT INTO refresh_tokens (user_id, token, expires_at)
       VALUES ($1,$2, NOW() + INTERVAL '30 days')`,
      [row.uid, newRefresh]
    );

    const accessToken = signAccess({ id:row.uid, username:row.username });
    res.json({ accessToken, refreshToken: newRefresh });
  } catch (err) { next(err); }
});

// POST /auth/logout
router.post('/logout', requireAuth, async (req, res, next) => {
  const { refreshToken } = req.body;
  try {
    if (refreshToken) await db.query('DELETE FROM refresh_tokens WHERE token=$1', [refreshToken]);
    wsService.disconnectUser(req.user.id);
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// GET /auth/me
router.get('/me', requireAuth, async (req, res) => {
  res.json({
    id: req.user.id, username: req.user.username,
    email: req.user.email, avatar_color: req.user.avatar_color,
    avatar_url: req.user.avatar_url || null,
  });
});

// PATCH /auth/me — update display name and/or avatar
router.patch('/me', requireAuth, [
  body('username').optional().trim().isLength({ min:2, max:50 }).matches(/^[a-zA-Z0-9_-]+$/),
  body('avatar_url').optional({ nullable: true }).isString(),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, avatar_url } = req.body;
  const sets = [], vals = [];
  let idx = 1;

  try {
    if (username && username !== req.user.username) {
      const { rows } = await db.query(
        'SELECT id FROM users WHERE username=$1 AND id!=$2', [username, req.user.id]
      );
      if (rows.length) return res.status(409).json({ error: 'Username already taken' });
      sets.push(`username=$${idx++}`); vals.push(username);
    }

    if (avatar_url !== undefined) {
      // avatar_url is a base64 data URL or null; basic size guard (~2MB)
      if (avatar_url && avatar_url.length > 2_100_000)
        return res.status(400).json({ error: 'Avatar image too large (max ~1.5 MB)' });
      sets.push(`avatar_url=$${idx++}`); vals.push(avatar_url || null);
    }

    if (!sets.length) {
      return res.json({
        id: req.user.id, username: req.user.username,
        email: req.user.email, avatar_color: req.user.avatar_color,
        avatar_url: req.user.avatar_url || null,
      });
    }

    vals.push(req.user.id);
    const { rows } = await db.query(
      `UPDATE users SET ${sets.join(',')} WHERE id=$${idx}
       RETURNING id, username, email, avatar_color, avatar_url`,
      vals
    );
    res.json(rows[0]);
  } catch (err) { next(err); }
});

module.exports = router;
