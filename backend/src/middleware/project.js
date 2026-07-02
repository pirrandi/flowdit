const db = require('../db');

async function requireProjectAccess(req, res, next) {
  const { projectId } = req.params;

  // Portal token access — validate project matches token scope
  if (req.isPortal) {
    if (req.portalProjectId !== projectId)
      return res.status(403).json({ error: 'Access denied' });
    try {
      const { rows } = await db.query('SELECT * FROM projects WHERE id = $1', [projectId]);
      if (!rows.length) return res.status(404).json({ error: 'Project not found' });
      // Verify the link hasn't been regenerated since this session was issued
      if (!rows[0].portal_token || req.portalTok !== rows[0].portal_token)
        return res.status(401).json({ error: 'Portal link has changed. Please use the new link.' });
      // Revoke immediately if the owner turns the portal off mid-session — a JWT already
      // issued shouldn't keep working just because it hasn't expired yet.
      if (!rows[0].client_view_enabled)
        return res.status(403).json({ error: 'Client portal is not enabled for this project' });
      req.project    = rows[0];
      req.memberRole = 'viewer';
      return next();
    } catch (err) { return next(err); }
  }

  // Regular user access
  try {
    const { rows } = await db.query(
      `SELECT p.*, pm.role AS member_role
       FROM projects p
       JOIN project_members pm ON pm.project_id = p.id
       WHERE p.id = $1 AND pm.user_id = $2`,
      [projectId, req.user.id]
    );
    if (!rows.length)
      return res.status(404).json({ error: 'Project not found or access denied' });
    req.project    = rows[0];
    req.memberRole = rows[0].member_role;
    next();
  } catch (err) { next(err); }
}

// Ports/endpoints are nested under :targetId — requireProjectAccess only proves the
// caller belongs to :projectId, not that :targetId is actually one of that project's
// targets. Without this, a member of any project could read/write another project's
// target_ports/target_endpoints by guessing/knowing a foreign targetId.
async function requireTargetAccess(req, res, next) {
  try {
    const { rows } = await db.query(
      `SELECT * FROM targets WHERE id = $1 AND project_id = $2`,
      [req.params.targetId, req.params.projectId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Target not found' });
    req.target = rows[0];
    next();
  } catch (err) { next(err); }
}

function requireEditor(req, res, next) {
  if (req.memberRole === 'viewer')
    return res.status(403).json({ error: 'Viewers cannot modify data' });
  next();
}

function requireOwner(req, res, next) {
  if (req.memberRole !== 'owner')
    return res.status(403).json({ error: 'Only the project owner can do this' });
  next();
}

module.exports = { requireProjectAccess, requireEditor, requireOwner, requireTargetAccess };
