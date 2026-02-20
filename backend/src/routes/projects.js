const router = require('express').Router();
const { v4: uuidv4 } = require('uuid');
const { body, validationResult } = require('express-validator');
const db = require('../db');
const { requireAuth } = require('../middleware/auth');
const { requireProjectAccess, requireEditor, requireOwner } = require('../middleware/project');

// All project routes require auth
router.use(requireAuth);

// ── GET /projects ────────────────────────────────────────────────────
// List all projects the user is a member of
router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT p.*, pm.role AS member_role,
              u.username AS owner_username,
              (SELECT COUNT(*) FROM project_members pm2 WHERE pm2.project_id = p.id) AS member_count
       FROM projects p
       JOIN project_members pm ON pm.project_id = p.id AND pm.user_id = $1
       JOIN users u ON u.id = p.owner_id
       ORDER BY p.updated_at DESC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// ── POST /projects ───────────────────────────────────────────────────
router.post('/', [
  body('name').trim().isLength({ min: 1, max: 200 }),
  body('target').optional().trim().isLength({ max: 500 }),
  body('description').optional().trim().isLength({ max: 2000 }),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { name, target = '', description = '' } = req.body;
  try {
    const { rows } = await db.query(
      `INSERT INTO projects (name, target, description, owner_id)
       VALUES ($1,$2,$3,$4) RETURNING *`,
      [name, target, description, req.user.id]
    );
    const project = rows[0];
    await db.query(
      `INSERT INTO project_members (project_id, user_id, role) VALUES ($1,$2,'owner')`,
      [project.id, req.user.id]
    );
    res.status(201).json({ ...project, member_role: 'owner' });
  } catch (err) { next(err); }
});

// ── GET /projects/:projectId ─────────────────────────────────────────
router.get('/:projectId', requireProjectAccess, async (req, res) => {
  res.json(req.project);
});

// ── PATCH /projects/:projectId ───────────────────────────────────────
router.patch('/:projectId', requireProjectAccess, requireOwner, [
  body('name').optional().trim().isLength({ min: 1, max: 200 }),
  body('target').optional().trim(),
  body('description').optional().trim(),
  body('status').optional().isIn(['active','completed','archived']),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const fields = ['name','target','description','status'];
  const updates = [];
  const values = [];
  fields.forEach(f => {
    if (req.body[f] !== undefined) {
      updates.push(`${f} = $${values.length + 1}`);
      values.push(req.body[f]);
    }
  });
  if (!updates.length) return res.json(req.project);
  values.push(req.params.projectId);

  try {
    const { rows } = await db.query(
      `UPDATE projects SET ${updates.join(', ')} WHERE id = $${values.length} RETURNING *`,
      values
    );
    res.json(rows[0]);
  } catch (err) { next(err); }
});

// ── DELETE /projects/:projectId ──────────────────────────────────────
router.delete('/:projectId', requireProjectAccess, requireOwner, async (req, res, next) => {
  try {
    await db.query('DELETE FROM projects WHERE id = $1', [req.params.projectId]);
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// ────────────────────────────────────────────────────────────────────
// MEMBERS
// ────────────────────────────────────────────────────────────────────

// GET /projects/:projectId/members
router.get('/:projectId/members', requireProjectAccess, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT u.id, u.username, u.email, pm.role, pm.joined_at
       FROM project_members pm
       JOIN users u ON u.id = pm.user_id
       WHERE pm.project_id = $1
       ORDER BY pm.joined_at`,
      [req.params.projectId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// PATCH /projects/:projectId/members/:userId — change role
router.patch('/:projectId/members/:userId', requireProjectAccess, requireOwner, async (req, res, next) => {
  const { role } = req.body;
  if (!['editor','viewer'].includes(role)) return res.status(400).json({ error: 'Role must be editor or viewer' });
  if (req.params.userId === req.user.id) return res.status(400).json({ error: 'Cannot change your own role' });
  try {
    await db.query(
      `UPDATE project_members SET role = $1 WHERE project_id = $2 AND user_id = $3`,
      [role, req.params.projectId, req.params.userId]
    );
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// DELETE /projects/:projectId/members/:userId — remove member
router.delete('/:projectId/members/:userId', requireProjectAccess, requireOwner, async (req, res, next) => {
  if (req.params.userId === req.user.id) return res.status(400).json({ error: 'Cannot remove yourself' });
  try {
    await db.query(
      `DELETE FROM project_members WHERE project_id = $1 AND user_id = $2`,
      [req.params.projectId, req.params.userId]
    );
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// ────────────────────────────────────────────────────────────────────
// INVITES
// ────────────────────────────────────────────────────────────────────

// POST /projects/:projectId/invites — invite by username
router.post('/:projectId/invites', requireProjectAccess, requireOwner, [
  body('username').trim().notEmpty(),
  body('role').optional().isIn(['editor','viewer']),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, role = 'editor' } = req.body;
  try {
    // Find user by username
    const userRes = await db.query('SELECT id, email FROM users WHERE username = $1', [username]);
    if (!userRes.rows.length) return res.status(404).json({ error: 'User not found' });
    const invitee = userRes.rows[0];

    // Check not already a member
    const memberCheck = await db.query(
      'SELECT 1 FROM project_members WHERE project_id = $1 AND user_id = $2',
      [req.params.projectId, invitee.id]
    );
    if (memberCheck.rows.length) return res.status(409).json({ error: 'User is already a member' });

    // Create invite token
    const token = uuidv4() + uuidv4().replace(/-/g,'');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await db.query(
      `INSERT INTO project_invites (project_id, invited_by, email, role, token, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [req.params.projectId, req.user.id, invitee.email, role, token, expiresAt]
    );

    // In production you'd send an email here.
    // For now, return the invite token directly so the user can share it.
    res.status(201).json({
      ok: true,
      inviteToken: token,
      message: `Share this token with ${username} so they can join the project`,
    });
  } catch (err) { next(err); }
});

// POST /projects/join — accept invite by token
router.post('/join', async (req, res, next) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token required' });
  try {
    const { rows } = await db.query(
      `SELECT * FROM project_invites WHERE token = $1 AND expires_at > NOW() AND accepted_at IS NULL`,
      [token]
    );
    if (!rows.length) return res.status(404).json({ error: 'Invalid or expired invite' });
    const invite = rows[0];

    // Check user email matches invite (optional security check)
    const userRes = await db.query('SELECT email FROM users WHERE id = $1', [req.user.id]);
    if (userRes.rows[0].email !== invite.email) {
      return res.status(403).json({ error: 'This invite was sent to a different email' });
    }

    // Add member
    await db.query(
      `INSERT INTO project_members (project_id, user_id, role, invited_by)
       VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
      [invite.project_id, req.user.id, invite.role, invite.invited_by]
    );
    await db.query(`UPDATE project_invites SET accepted_at = NOW() WHERE id = $1`, [invite.id]);

    res.json({ ok: true, projectId: invite.project_id });
  } catch (err) { next(err); }
});

// GET /projects/:projectId/invites — list pending invites
router.get('/:projectId/invites', requireProjectAccess, requireOwner, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT pi.id, pi.email, pi.role, pi.token, pi.expires_at, pi.created_at,
              u.username AS invited_by_username
       FROM project_invites pi
       JOIN users u ON u.id = pi.invited_by
       WHERE pi.project_id = $1 AND pi.accepted_at IS NULL AND pi.expires_at > NOW()
       ORDER BY pi.created_at DESC`,
      [req.params.projectId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// DELETE /projects/:projectId/invites/:inviteId — cancel invite
router.delete('/:projectId/invites/:inviteId', requireProjectAccess, requireOwner, async (req, res, next) => {
  try {
    await db.query(
      `DELETE FROM project_invites WHERE id = $1 AND project_id = $2`,
      [req.params.inviteId, req.params.projectId]
    );
    res.json({ ok: true });
  } catch (err) { next(err); }
});

module.exports = router;
