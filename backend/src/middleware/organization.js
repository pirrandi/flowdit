const db = require('../db');

async function requireOrgAccess(req, res, next) {
  const { orgId } = req.params;
  try {
    const { rows } = await db.query(
      `SELECT o.*, om.role AS member_role
       FROM organizations o
       JOIN organization_members om ON om.organization_id = o.id
       WHERE o.id = $1 AND om.user_id = $2`,
      [orgId, req.user.id]
    );
    if (!rows.length)
      return res.status(404).json({ error: 'Organization not found or access denied' });
    req.organization = rows[0];
    req.orgRole       = rows[0].member_role;
    next();
  } catch (err) { next(err); }
}

function requireOrgAdmin(req, res, next) {
  if (req.orgRole !== 'owner' && req.orgRole !== 'admin')
    return res.status(403).json({ error: 'Only org owners/admins can do this' });
  next();
}

function requireOrgOwner(req, res, next) {
  if (req.orgRole !== 'owner')
    return res.status(403).json({ error: 'Only the organization owner can do this' });
  next();
}

module.exports = { requireOrgAccess, requireOrgAdmin, requireOrgOwner };
