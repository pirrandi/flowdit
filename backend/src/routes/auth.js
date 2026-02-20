const router  = require('express').Router();
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { body, validationResult } = require('express-validator');
const db      = require('../db');
const { requireAuth } = require('../middleware/auth');

function signAccess(user) {
  return jwt.sign(
    { sub: user.id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );
}

function signRefresh() {
  return uuidv4() + '-' + uuidv4();
}

// ── POST /auth/register ─────────────────────────────────────────────
router.post('/register', [
  body('username').trim().isLength({ min: 2, max: 50 }).matches(/^[a-zA-Z0-9_-]+$/),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8, max: 128 }),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, email, password } = req.body;
  try {
    // Check uniqueness
    const exists = await db.query(
      'SELECT id FROM users WHERE username = $1 OR email = $2', [username, email]
    );
    if (exists.rows.length) {
      return res.status(409).json({ error: 'Username or email already taken' });
    }

    const hash = await bcrypt.hash(password, 12);
    const { rows } = await db.query(
      'INSERT INTO users (username, email, password) VALUES ($1,$2,$3) RETURNING id, username, email, created_at',
      [username, email, hash]
    );
    const user = rows[0];

    // Auto-create a "Personal" project for new user
    const projectRes = await db.query(
      `INSERT INTO projects (name, target, description, owner_id)
       VALUES ($1,$2,$3,$4) RETURNING id`,
      ['Personal Workspace', '', 'Your personal pentest checklist', user.id]
    );
    await db.query(
      `INSERT INTO project_members (project_id, user_id, role) VALUES ($1,$2,'owner')`,
      [projectRes.rows[0].id, user.id]
    );

    const accessToken  = signAccess(user);
    const refreshToken = signRefresh();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await db.query(
      'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1,$2,$3)',
      [user.id, refreshToken, expiresAt]
    );

    res.status(201).json({ accessToken, refreshToken, user: { id: user.id, username: user.username, email: user.email } });
  } catch (err) { next(err); }
});

// ── POST /auth/login ────────────────────────────────────────────────
router.post('/login', [
  body('login').trim().notEmpty(),   // username or email
  body('password').notEmpty(),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { login, password } = req.body;
  try {
    const { rows } = await db.query(
      'SELECT * FROM users WHERE username = $1 OR email = $1', [login]
    );
    const user = rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const accessToken  = signAccess(user);
    const refreshToken = signRefresh();
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await db.query(
      'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1,$2,$3)',
      [user.id, refreshToken, expiresAt]
    );

    res.json({ accessToken, refreshToken, user: { id: user.id, username: user.username, email: user.email } });
  } catch (err) { next(err); }
});

// ── POST /auth/refresh ──────────────────────────────────────────────
router.post('/refresh', async (req, res, next) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });
  try {
    const { rows } = await db.query(
      `SELECT rt.*, u.id as uid, u.username FROM refresh_tokens rt
       JOIN users u ON u.id = rt.user_id
       WHERE rt.token = $1 AND rt.expires_at > NOW()`,
      [refreshToken]
    );
    if (!rows.length) return res.status(401).json({ error: 'Invalid or expired refresh token' });

    const row = rows[0];
    // Rotate refresh token
    await db.query('DELETE FROM refresh_tokens WHERE id = $1', [row.id]);
    const newRefresh = signRefresh();
    const expiresAt  = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await db.query(
      'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1,$2,$3)',
      [row.uid, newRefresh, expiresAt]
    );

    const accessToken = signAccess({ id: row.uid, username: row.username });
    res.json({ accessToken, refreshToken: newRefresh });
  } catch (err) { next(err); }
});

// ── POST /auth/logout ───────────────────────────────────────────────
router.post('/logout', requireAuth, async (req, res, next) => {
  const { refreshToken } = req.body;
  try {
    if (refreshToken) {
      await db.query('DELETE FROM refresh_tokens WHERE token = $1', [refreshToken]);
    }
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// ── GET /auth/me ────────────────────────────────────────────────────
router.get('/me', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      'SELECT id, username, email, created_at FROM users WHERE id = $1', [req.user.id]
    );
    res.json(rows[0]);
  } catch (err) { next(err); }
});

module.exports = router;
