const db = require('../db');
const { ACTIVE_SQL } = require('../services/portalLinks');

async function requireProjectAccess(req, res, next) {
  const { projectId } = req.params;

  // Portal token access — validate project matches token scope
  if (req.isPortal) {
    if (req.portalProjectId !== projectId)
      return res.status(403).json({ error: 'Access denied' });
    // Sessions minted before per-contact links carry no linkId — they were
    // bound to the old shared token and can't be tied to a link, so they end.
    if (!req.portalLinkId)
      return res.status(401).json({ error: 'Portal link has changed. Please use the new link.' });
    try {
      const { rows } = await db.query('SELECT * FROM projects WHERE id = $1', [projectId]);
      if (!rows.length) return res.status(404).json({ error: 'Project not found' });
      // The session's link must still exist in THIS project and be active: a
      // revoked or expired link ends its session on the next request, without
      // touching other contacts' sessions.
      const { rows: links } = await db.query(
        `SELECT pl.id, pl.label, pl.email, pl.is_legacy FROM portal_links pl
         WHERE pl.id = $1 AND pl.project_id = $2 AND ${ACTIVE_SQL}`,
        [req.portalLinkId, projectId]
      );
      if (!links.length)
        return res.status(401).json({ error: 'Portal link has changed. Please use the new link.' });
      // Revoke immediately if the owner turns the portal off mid-session — a JWT already
      // issued shouldn't keep working just because it hasn't expired yet.
      if (!rows[0].client_view_enabled)
        return res.status(403).json({ error: 'Client portal is not enabled for this project' });
      req.project    = rows[0];
      req.portalLink = links[0];
      req.memberRole = 'viewer';
      return next();
    } catch (err) { return next(err); }
  }

  // Regular user access — direct project membership, OR implicit access via
  // being an owner/admin of the project's organization (the enterprise case:
  // a company account holder can see/manage every project the company owns
  // without being manually invited to each one). Direct membership always
  // wins if both exist (COALESCE prefers pm.role). Org owner maps to project
  // 'owner' — a strong, intentional grant (can rename/delete/manage members/
  // manage the client portal links) for the literal company-account
  // owner. Org admin maps to project 'editor' (can edit data, not delete
  // or touch membership).
  try {
    const project = await findProjectForUser(projectId, req.user.id);
    if (!project)
      return res.status(404).json({ error: 'Project not found or access denied' });
    req.project    = project;
    req.memberRole = project.member_role;
    req.viaOrg     = project.via_org;
    next();
  } catch (err) { next(err); }
}

// The project row plus the caller's effective role (member_role), or null when
// they have no access. Shared with routes that take the project id from the
// body instead of the URL (export).
async function findProjectForUser(projectId, userId) {
  const { rows } = await db.query(
    `SELECT p.*,
            COALESCE(pm.role, CASE om.role WHEN 'owner' THEN 'owner' WHEN 'admin' THEN 'editor' END) AS member_role,
            (pm.user_id IS NULL) AS via_org
     FROM projects p
     LEFT JOIN project_members pm ON pm.project_id = p.id AND pm.user_id = $2
     LEFT JOIN organization_members om ON om.organization_id = p.organization_id AND om.user_id = $2 AND om.role IN ('owner','admin')
     WHERE p.id = $1 AND (pm.user_id IS NOT NULL OR om.user_id IS NOT NULL)`,
    [projectId, userId]
  );
  return rows[0] || null;
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

// Server-side enforcement of a client-portal visibility flag. The project
// settings already carry per-project switches (show_findings, show_targets,
// show_activity, …) but historically they were only honored by the client
// frontend — a portal JWT could still hit the API directly and read data the
// owner had switched OFF. This closes that gap: for a portal session, the
// matching project flag must be truthy or the whole route is refused. A real
// user account is never affected. Must run AFTER requireProjectAccess (needs
// req.project / req.isPortal).
function portalRequiresFlag(flag) {
  return (req, res, next) => {
    if (req.isPortal && !req.project?.[flag])
      return res.status(403).json({ error: 'Not available in this client portal' });
    next();
  };
}

// Role tiers: owner > editor (the engagement lead) > pentester > viewer.
// "Writer" = can do technical work on the project data (findings, WSTG,
// targets, recon, AI agent...). Pentesters pass; viewers and portal sessions
// (memberRole 'viewer') don't.
const WRITER_ROLES = ['owner', 'editor', 'pentester'];
// "Lead" = can additionally take CLIENT-FACING actions: publish findings to
// the portal, answer/triage client tickets, export the report and edit the
// report builder. Pentesters are deliberately excluded.
const LEAD_ROLES = ['owner', 'editor'];

function isLeadRole(role) { return LEAD_ROLES.includes(role); }

function requireWriter(req, res, next) {
  if (!WRITER_ROLES.includes(req.memberRole))
    return res.status(403).json({ error: 'Viewers cannot modify data' });
  next();
}

function requireLead(req, res, next) {
  if (!isLeadRole(req.memberRole))
    return res.status(403).json({ error: 'Only the project owner or an editor can do this' });
  next();
}

function requireOwner(req, res, next) {
  if (req.memberRole !== 'owner')
    return res.status(403).json({ error: 'Only the project owner can do this' });
  next();
}

module.exports = { requireProjectAccess, findProjectForUser, WRITER_ROLES, requireWriter, requireLead, isLeadRole, requireOwner, requireTargetAccess, portalRequiresFlag };
