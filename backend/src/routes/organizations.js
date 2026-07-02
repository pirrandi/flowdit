const router = require('express').Router();
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');
const db = require('../db');
const { requireAuth } = require('../middleware/auth');
const { requireOrgAccess, requireOrgAdmin, requireOrgOwner } = require('../middleware/organization');

router.use(requireAuth);

// GET /organizations — orgs the caller directly belongs to
router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT o.*, om.role AS member_role,
              (SELECT COUNT(*) FROM organization_members om2 WHERE om2.organization_id=o.id) AS member_count,
              (SELECT COUNT(*) FROM projects p WHERE p.organization_id=o.id) AS project_count
       FROM organizations o
       JOIN organization_members om ON om.organization_id=o.id AND om.user_id=$1
       ORDER BY o.is_personal DESC, o.created_at ASC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// POST /organizations — create a real (non-personal) org
router.post('/', [
  body('name').trim().isLength({ min:1, max:200 }),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    const { rows } = await db.query(
      `INSERT INTO organizations (name, owner_id, is_personal) VALUES ($1,$2,false) RETURNING *`,
      [req.body.name, req.user.id]
    );
    const org = rows[0];
    await db.query(
      `INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1,$2,'owner')`,
      [org.id, req.user.id]
    );
    res.status(201).json({ ...org, member_role: 'owner' });
  } catch (err) { next(err); }
});

// GET /organizations/:orgId
router.get('/:orgId', requireOrgAccess, (req, res) => res.json(req.organization));

// GET /organizations/:orgId/projects — the admin-panel payoff of the org model:
// every project the company owns, with enough at-a-glance signal (findings by
// severity, member count) to not have to click into each one. Owner/admin only —
// a plain 'member' has no implicit visibility into org projects, so showing them
// this list would leak more than their actual access grants.
router.get('/:orgId/projects', requireOrgAccess, requireOrgAdmin, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT p.id, p.name, p.status, p.updated_at, u.username AS owner_username,
              (SELECT COUNT(*) FROM project_members pm WHERE pm.project_id=p.id) AS member_count,
              COALESCE(v.crit,0)::int AS crit_count, COALESCE(v.high,0)::int AS high_count,
              COALESCE(v.med,0)::int  AS med_count,  COALESCE(v.low,0)::int  AS low_count,
              COALESCE(v.info,0)::int AS info_count
       FROM projects p
       JOIN users u ON u.id = p.owner_id
       LEFT JOIN (
         SELECT project_id,
           COUNT(*) FILTER (WHERE severity='critical') AS crit,
           COUNT(*) FILTER (WHERE severity='high')     AS high,
           COUNT(*) FILTER (WHERE severity='medium')   AS med,
           COUNT(*) FILTER (WHERE severity='low')      AS low,
           COUNT(*) FILTER (WHERE severity='info')     AS info
         FROM custom_vulns GROUP BY project_id
       ) v ON v.project_id = p.id
       WHERE p.organization_id = $1
       ORDER BY p.updated_at DESC`,
      [req.params.orgId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// PATCH /organizations/:orgId — rename
router.patch('/:orgId', requireOrgAccess, requireOrgOwner, [
  body('name').trim().isLength({ min:1, max:200 }),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    const { rows } = await db.query(
      `UPDATE organizations SET name=$1 WHERE id=$2 RETURNING *`,
      [req.body.name, req.params.orgId]
    );
    res.json(rows[0]);
  } catch (err) { next(err); }
});

// DELETE /organizations/:orgId
router.delete('/:orgId', requireOrgAccess, requireOrgOwner, async (req, res, next) => {
  try {
    await db.query(`DELETE FROM organizations WHERE id=$1`, [req.params.orgId]);
    res.json({ ok:true });
  } catch (err) { next(err); }
});

// ── MEMBERS ─────────────────────────────────────────────────────────

router.get('/:orgId/members', requireOrgAccess, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT u.id, u.username, u.email, u.avatar_color, u.avatar_url, om.role, om.joined_at,
              inv.username AS invited_by_username
       FROM organization_members om
       JOIN users u ON u.id=om.user_id
       LEFT JOIN users inv ON inv.id=om.invited_by
       WHERE om.organization_id=$1 ORDER BY om.joined_at`,
      [req.params.orgId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

router.patch('/:orgId/members/:userId', requireOrgAccess, requireOrgOwner, async (req, res, next) => {
  const { role } = req.body;
  if (!['admin','member'].includes(role)) return res.status(400).json({ error:'Role must be admin or member' });
  if (req.params.userId === req.user.id)  return res.status(400).json({ error:'Cannot change your own role' });
  try {
    await db.query(`UPDATE organization_members SET role=$1 WHERE organization_id=$2 AND user_id=$3`, [role, req.params.orgId, req.params.userId]);
    res.json({ ok:true });
  } catch (err) { next(err); }
});

router.delete('/:orgId/members/:userId', requireOrgAccess, requireOrgOwner, async (req, res, next) => {
  if (req.params.userId === req.user.id) return res.status(400).json({ error:'Cannot remove yourself' });
  try {
    await db.query(`DELETE FROM organization_members WHERE organization_id=$1 AND user_id=$2`, [req.params.orgId, req.params.userId]);
    res.json({ ok:true });
  } catch (err) { next(err); }
});

// ── INVITES (token-based, no email) ─────────────────────────────────
// FO- prefix (vs. projects' FD-) so a token pasted into the wrong join
// field is visually obvious, not just functionally rejected. Uses
// crypto.randomBytes for real entropy (project invites still use
// Math.random — a pre-existing pattern not worth touching here).

router.post('/:orgId/invites', requireOrgAccess, requireOrgAdmin, [
  body('role').optional().isIn(['admin','member']),
  body('label').optional().trim().isLength({ max:100 }),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { role='member', label='' } = req.body;
  try {
    const token = `FO-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
    const { rows } = await db.query(
      `INSERT INTO organization_invites (organization_id, invited_by, role, token, label, expires_at)
       VALUES ($1,$2,$3,$4,$5, NOW() + INTERVAL '7 days')
       RETURNING id, token, role, label, expires_at, created_at`,
      [req.params.orgId, req.user.id, role, token, label]
    );
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

router.get('/:orgId/invites', requireOrgAccess, requireOrgAdmin, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT oi.id, oi.token, oi.role, oi.label, oi.expires_at, oi.created_at,
              oi.accepted_at, u.username AS invited_by_username,
              au.username AS accepted_by_username
       FROM organization_invites oi
       JOIN users u ON u.id=oi.invited_by
       LEFT JOIN users au ON au.id=oi.accepted_by
       WHERE oi.organization_id=$1
       ORDER BY oi.created_at DESC`,
      [req.params.orgId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

router.delete('/:orgId/invites/:inviteId', requireOrgAccess, requireOrgAdmin, async (req, res, next) => {
  try {
    await db.query(`DELETE FROM organization_invites WHERE id=$1 AND organization_id=$2`, [req.params.inviteId, req.params.orgId]);
    res.json({ ok:true });
  } catch (err) { next(err); }
});

// POST /organizations/join — anyone with a valid token can join
router.post('/join', async (req, res, next) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error:'Token required' });
  try {
    const { rows } = await db.query(
      `SELECT * FROM organization_invites WHERE token=$1 AND accepted_at IS NULL AND expires_at > NOW()`,
      [token.trim().toUpperCase()]
    );
    if (!rows.length) return res.status(404).json({ error:'Invalid or expired invite code' });
    const invite = rows[0];

    const already = await db.query(
      `SELECT 1 FROM organization_members WHERE organization_id=$1 AND user_id=$2`,
      [invite.organization_id, req.user.id]
    );
    if (already.rows.length) return res.status(409).json({ error:'You are already a member of this organization' });

    await db.query(
      `INSERT INTO organization_members (organization_id, user_id, role, invited_by)
       VALUES ($1,$2,$3,$4)`,
      [invite.organization_id, req.user.id, invite.role, invite.invited_by]
    );
    await db.query(
      `UPDATE organization_invites SET accepted_at=NOW(), accepted_by=$1 WHERE id=$2`,
      [req.user.id, invite.id]
    );

    res.json({ ok:true, organizationId: invite.organization_id, role: invite.role });
  } catch (err) { next(err); }
});

module.exports = router;
