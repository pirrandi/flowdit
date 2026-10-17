const router = require('express').Router();
const { body, param, validationResult } = require('express-validator');
const bcrypt   = require('bcryptjs');
const db       = require('../db');
const activity = require('../services/activity');
const { requireAuth, requireUser, blockDemoDestructive } = require('../middleware/auth');
const { requireProjectAccess, requireOwner, isClientSession } = require('../middleware/project');
const { encrypt } = require('../utils/crypto');
const portalLinks = require('../services/portalLinks');
const { PROVIDERS: ALL_AI_PROVIDERS } = require('../services/ai');

router.use(requireAuth);

// 'custom' queda afuera a propósito — su base_url es host-level únicamente
// (ver services/ai/custom.js), no hay key por-proyecto que tenga sentido.
// Derivado de services/ai/index.js en vez de una lista hardcodeada acá para
// que sumar un proveedor nuevo no requiera acordarse de tocar este archivo
// también.
const AI_KEY_PROVIDERS = ALL_AI_PROVIDERS.filter(p => p !== 'custom');

// Strip secrets from project objects — frontend only needs boolean flags.
// portal_token is the pre-portal_links shared client link: no longer used by
// anything, never returned to anyone (owners manage links via /portal/links).
function sanitizeProject(p) {
  const out = { ...p };
  delete out.portal_token;
  out.has_portal_password = !!out.portal_password_hash;
  out.has_github_pat = !!out.github_pat_enc;
  out.ai_api_keys_set = Object.fromEntries(AI_KEY_PROVIDERS.map(k => [k, !!out.ai_api_keys_enc?.[k]]));
  delete out.portal_password_hash;
  delete out.github_pat_enc;
  delete out.ai_api_keys_enc;
  return out;
}

// A client portal session gets an ALLOWLIST projection of the project — only
// the presentation + visibility flags the client view needs. Internal config
// (ai_provider/ai_model/ai_tool_mode, github_repo, portal_token, member_count,
// organization_id, created_by, …) never reaches the client, even though the
// generic sanitizeProject would pass it through. Allowlist, not blocklist, so a
// field added later does not leak by default.
const PORTAL_PROJECT_FIELDS = [
  'id', 'name', 'status', 'created_at',
  'client_view_enabled', 'tickets_enabled',
  'show_findings', 'show_wstg_progress', 'show_wstg_notes', 'show_targets', 'show_activity',
  'portal_hide_team_avatars', 'portal_hide_log_times',
  'logo_url', 'logo_bg', 'date_start', 'date_end', 'date_report',
];
function sanitizeProjectForPortal(p) {
  const out = {};
  for (const f of PORTAL_PROJECT_FIELDS) out[f] = p[f];
  return out;
}

// Una cuenta viewer es el cliente (ver isClientSession): recibe la misma
// proyección que el portal más su rol, que el frontend usa para mandarla a la
// vista cliente. Antes recibía sanitizeProject (config de IA, repo de GitHub,
// descripción interna, owner...). En el listado, los contadores crit/high
// cuentan solo hallazgos publicados y solo si show_findings está prendido:
// contar borradores le anticipaba al cliente hallazgos no publicados.
function sanitizeProjectForViewer(p) {
  const out = sanitizeProjectForPortal(p);
  out.member_role = p.member_role;
  if ('crit_count' in p) {
    out.crit_count = p.show_findings ? p.pub_crit_count : 0;
    out.high_count = p.show_findings ? p.pub_high_count : 0;
  }
  return out;
}

function projectFor(p) {
  return p.member_role === 'viewer' ? sanitizeProjectForViewer(p) : sanitizeProject(p);
}

// GET /projects — direct membership OR implicit access via being an
// owner/admin of the project's organization (same fallback shape as
// requireProjectAccess). Without the org-fallback join here, an org
// admin would have no way to *discover* projects they weren't directly
// invited to — this is what actually makes "the company can see
// everything" true, not just authorizable-if-you-know-the-URL.
router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT p.*,
              COALESCE(pm.role, CASE om.role WHEN 'owner' THEN 'owner' WHEN 'admin' THEN 'editor' END) AS member_role,
              u.username AS owner_username, u.display_name AS owner_display_name, o.name AS organization_name,
              (pm.user_id IS NULL) AS via_org,
              (SELECT COUNT(*) FROM project_members pm2 WHERE pm2.project_id = p.id) AS member_count,
              COALESCE(v.crit,0)::int AS crit_count, COALESCE(v.high,0)::int AS high_count,
              COALESCE(v.pub_crit,0)::int AS pub_crit_count, COALESCE(v.pub_high,0)::int AS pub_high_count
       FROM projects p
       LEFT JOIN project_members pm ON pm.project_id=p.id AND pm.user_id=$1
       LEFT JOIN organization_members om ON om.organization_id=p.organization_id AND om.user_id=$1 AND om.role IN ('owner','admin')
       JOIN users u ON u.id=p.owner_id
       LEFT JOIN organizations o ON o.id=p.organization_id
       LEFT JOIN (
         SELECT project_id,
           COUNT(*) FILTER (WHERE severity='critical') AS crit,
           COUNT(*) FILTER (WHERE severity='high')     AS high,
           COUNT(*) FILTER (WHERE severity='critical' AND client_visible) AS pub_crit,
           COUNT(*) FILTER (WHERE severity='high'     AND client_visible) AS pub_high
         FROM custom_vulns GROUP BY project_id
       ) v ON v.project_id = p.id
       WHERE pm.user_id IS NOT NULL OR om.user_id IS NOT NULL
       ORDER BY p.updated_at DESC`,
      [req.user.id]
    );
    res.json(rows.map(projectFor));
  } catch (err) { next(err); }
});

// POST /projects — every project belongs to an organization now; the
// caller must be a member (any role) of the org they're creating it under.
router.post('/', [
  body('name').trim().isLength({ min:1, max:200 }),
  body('target').optional().trim(),
  body('description').optional().trim(),
  body('organization_id').isUUID(),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { name, target='', description='', organization_id } = req.body;
  try {
    const orgMember = await db.query(
      `SELECT 1 FROM organization_members WHERE organization_id=$1 AND user_id=$2`,
      [organization_id, req.user.id]
    );
    if (!orgMember.rows.length) return res.status(403).json({ error: 'You are not a member of that organization' });

    const { rows } = await db.query(
      `INSERT INTO projects (name, target, description, owner_id, organization_id)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [name, target, description, req.user.id, organization_id]
    );
    const project = rows[0];
    await db.query(
      `INSERT INTO project_members (project_id, user_id, role) VALUES ($1,$2,'owner')`,
      [project.id, req.user.id]
    );
    res.status(201).json(sanitizeProject({ ...project, member_role:'owner' }));
  } catch (err) { next(err); }
});

// GET /projects/:projectId
router.get('/:projectId', requireProjectAccess, (req, res) =>
  res.json(req.isPortal ? sanitizeProjectForPortal(req.project) : projectFor(req.project)));

// PATCH /projects/:projectId
router.patch('/:projectId', requireProjectAccess, requireOwner, async (req, res, next) => {
  const fields = ['name','target','description','status','client_view_enabled','tickets_enabled','show_findings','show_wstg_progress','show_wstg_notes','show_targets','show_activity','portal_hide_team_avatars','portal_hide_log_times','logo_url','logo_bg','date_start','date_end','date_report','portal_require_password','ai_provider','ai_model','ai_tool_mode','ai_autonomous_requests','ai_single_agent','github_repo','claude_code_enabled'];
  const updates = [], values = [];
  fields.forEach(f => { if (req.body[f] !== undefined) { updates.push(`${f}=$${values.length+1}`); values.push(req.body[f]); } });

  // Hashing/encryption below can throw (e.g. SSO_ENCRYPTION_KEY unset): Express 4
  // doesn't catch async rejections, so without this the request would hang.
  try {
    // portal_password — hash before storing, empty string clears it
    if (req.body.portal_password !== undefined) {
      if (req.body.portal_password) {
        const hash = await bcrypt.hash(req.body.portal_password, 10);
        updates.push(`portal_password_hash=$${values.length+1}`); values.push(hash);
      } else {
        updates.push(`portal_password_hash=NULL`);
      }
    }

    // github_pat — encrypted at rest, same as portal_password's hash-not-store
    // pattern: omitted = untouched, empty string = cleared, non-empty = set.
    if (req.body.github_pat !== undefined) {
      updates.push(`github_pat_enc=$${values.length+1}`);
      values.push(req.body.github_pat ? encrypt(req.body.github_pat) : null);
    }

    // ai_api_keys — per-project override of a hosted AI provider's API key
    // (Groq/DeepSeek/Anthropic/Kimi only; 'custom' stays host-level, see
    // services/ai/custom.js). Same omitted/cleared/set semantics as
    // github_pat above, but jsonb-keyed so one PATCH can touch several
    // providers at once without clobbering the ones it doesn't mention.
    // Composed as a single atomic read-modify-write expression (remove the
    // cleared keys, then overlay the newly-set ones) rather than a
    // SELECT-then-UPDATE round trip.
    if (req.body.ai_api_keys && typeof req.body.ai_api_keys === 'object') {
      const removeKeys = [];
      const setPairs   = [];
      AI_KEY_PROVIDERS.forEach(provider => {
        if (!(provider in req.body.ai_api_keys)) return;
        const raw = req.body.ai_api_keys[provider];
        const val = typeof raw === 'string' ? raw.trim() : raw;
        if (val) {
          values.push(encrypt(val));
          setPairs.push([provider, values.length]);
        } else {
          removeKeys.push(provider);
        }
      });
      if (removeKeys.length || setPairs.length) {
        let expr = 'ai_api_keys_enc';
        removeKeys.forEach(k => { expr += ` - '${k}'`; });
        if (setPairs.length) {
          expr += ` || jsonb_build_object(${setPairs.map(([k, idx]) => `'${k}', $${idx}::text`).join(', ')})`;
        }
        updates.push(`ai_api_keys_enc = ${expr}`);
      }
    }
  } catch (err) { return next(err); }

  if (!updates.length) return res.json(sanitizeProject(req.project));
  values.push(req.params.projectId);
  try {
    const { rows } = await db.query(`UPDATE projects SET ${updates.join(',')} WHERE id=$${values.length} RETURNING *`, values);
    res.json(sanitizeProject(rows[0]));
  } catch (err) { next(err); }
});

// ── CLIENT PORTAL LINKS (one per client contact) ────────────────────
// Owner-only. requireUser first, so a portal session is refused before it
// even reaches the project lookup.

const LINK_SELECT = `
  SELECT pl.id, pl.label, pl.email, pl.is_legacy, pl.created_at, pl.expires_at,
         pl.revoked_at, pl.last_used_at, pl.use_count, pl.token_enc,
         ${portalLinks.STATUS_SQL} AS status,
         COALESCE(u.display_name, u.username) AS created_by_name
  FROM portal_links pl
  LEFT JOIN users u ON u.id = pl.created_by`;

// token_enc/token_hash never leave the API; the url-ready token is only
// handed out while the link still works.
function presentLink(row, token) {
  const { token_enc: _enc, token_hash: _hash, ...out } = row;
  out.token = out.status === 'active' ? (token || portalLinks.tokenOf(row)) : null;
  return out;
}

// GET /projects/:projectId/portal/links
router.get('/:projectId/portal/links', requireUser, requireProjectAccess, requireOwner, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `${LINK_SELECT} WHERE pl.project_id = $1 ORDER BY pl.created_at DESC`,
      [req.params.projectId]
    );
    res.json(rows.map(r => presentLink(r)));
  } catch (err) { next(err); }
});

// POST /projects/:projectId/portal/links  { label, email?, expires_in_days? }
router.post('/:projectId/portal/links', requireUser, requireProjectAccess, requireOwner, [
  body('label').isString().trim().isLength({ min: 1, max: 200 }),
  body('email').optional({ values: 'falsy' }).isString().trim().isEmail().isLength({ max: 320 }),
  body('expires_in_days').optional({ values: 'null' }).isInt({ min: 1, max: 3650 }).toInt(),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { label } = req.body;
  const email = req.body.email || null;
  const days  = req.body.expires_in_days ?? null;
  const token = portalLinks.generateToken();
  try {
    const { rows: inserted } = await db.query(
      `INSERT INTO portal_links (project_id, label, email, token_hash, token_enc, created_by, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6, CASE WHEN $7::int IS NULL THEN NULL ELSE NOW() + make_interval(days => $7::int) END)
       RETURNING id`,
      [req.params.projectId, label, email, portalLinks.hashToken(token), encrypt(token), req.user.id, days]
    );
    const { rows } = await db.query(`${LINK_SELECT} WHERE pl.id = $1`, [inserted[0].id]);
    await activity.log({
      projectId:  req.params.projectId,
      user:       req.user,
      action:     'portal_link_created',
      entityType: 'portal',
      entityId:   rows[0].id,
      entityName: label,
      meta:       { expires_at: rows[0].expires_at },
    });
    res.status(201).json(presentLink(rows[0], token));
  } catch (err) { next(err); }
});

// POST /projects/:projectId/portal/links/:linkId/revoke — idempotent
router.post('/:projectId/portal/links/:linkId/revoke', requireUser, requireProjectAccess, requireOwner, [
  param('linkId').isUUID(),
], async (req, res, next) => {
  if (!validationResult(req).isEmpty()) return res.status(404).json({ error: 'Portal link not found' });
  try {
    const { rows: revoked } = await db.query(
      `UPDATE portal_links SET revoked_at = NOW()
       WHERE id = $1 AND project_id = $2 AND revoked_at IS NULL
       RETURNING id`,
      [req.params.linkId, req.params.projectId]
    );
    const { rows } = await db.query(
      `${LINK_SELECT} WHERE pl.id = $1 AND pl.project_id = $2`,
      [req.params.linkId, req.params.projectId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Portal link not found' });
    // Only the first revoke is an event; repeating it is a no-op.
    if (revoked.length) {
      await activity.log({
        projectId:  req.params.projectId,
        user:       req.user,
        action:     'portal_link_revoked',
        entityType: 'portal',
        entityId:   rows[0].id,
        entityName: rows[0].label,
      });
    }
    res.json(presentLink(rows[0]));
  } catch (err) { next(err); }
});

// POST /projects/:projectId/move — move the project to another organization.
// Requires project owner (direct, or via owning the current org) AND owner/admin
// of the destination org: nobody can push a project into an org they don't
// manage, nor take it away from its owner. Direct project members keep their
// access; implicit org-level access switches from the old org to the new one.
router.post('/:projectId/move', requireProjectAccess, requireOwner, blockDemoDestructive, [
  body('organization_id').isUUID(),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { organization_id } = req.body;
  if (organization_id === req.project.organization_id)
    return res.status(400).json({ error: 'The project already belongs to that organization' });
  try {
    const { rows: dest } = await db.query(
      `SELECT o.name FROM organizations o
       JOIN organization_members om ON om.organization_id=o.id AND om.user_id=$2 AND om.role IN ('owner','admin')
       WHERE o.id=$1`,
      [organization_id, req.user.id]
    );
    if (!dest.length)
      return res.status(403).json({ error: 'You must be an owner or admin of the destination organization' });

    const { rows: src } = await db.query('SELECT name FROM organizations WHERE id=$1', [req.project.organization_id]);
    await db.query('UPDATE projects SET organization_id=$1 WHERE id=$2', [organization_id, req.params.projectId]);
    await activity.log({
      projectId:  req.params.projectId,
      user:       req.user,
      action:     'project_moved',
      entityType: 'organization',
      entityId:   organization_id,
      entityName: dest[0].name,
      meta:       { from: src[0]?.name || null, to: dest[0].name },
    });
    res.json({ ok: true, organization_id, organization_name: dest[0].name });
  } catch (err) { next(err); }
});

// DELETE /projects/:projectId
router.delete('/:projectId', requireProjectAccess, requireOwner, blockDemoDestructive, async (req, res, next) => {
  try {
    await db.query('DELETE FROM projects WHERE id=$1', [req.params.projectId]);
    res.json({ ok:true });
  } catch (err) { next(err); }
});

// ── MEMBERS ─────────────────────────────────────────────────────────

// Roles an owner can hand out (owner itself is never assigned, only held).
const ASSIGNABLE_ROLES = ['editor', 'pentester', 'viewer'];

router.get('/:projectId/members', requireProjectAccess, requireUser, async (req, res, next) => {
  try {
    // La vista cliente pide los miembros solo para color de rol y avatar en el
    // feed. A una cuenta viewer (el cliente) no le van emails, ids, etiquetas
    // internas ni quién invitó a quién; el avatar respeta
    // portal_hide_team_avatars igual que el feed.
    if (isClientSession(req)) {
      const { rows } = await db.query(
        `SELECT u.username, u.display_name, u.avatar_color, u.avatar_url, pm.role
         FROM project_members pm
         JOIN users u ON u.id=pm.user_id
         WHERE pm.project_id=$1 ORDER BY pm.joined_at`,
        [req.params.projectId]
      );
      const hideAvatars = req.project.portal_hide_team_avatars;
      return res.json(rows.map(r => ({ ...r, avatar_url: hideAvatars ? null : r.avatar_url })));
    }
    const { rows } = await db.query(
      `SELECT u.id, u.username, u.display_name, u.email, u.avatar_color, u.avatar_url, pm.role, pm.joined_at,
              pm.label, inv.username AS invited_by_username, inv.display_name AS invited_by_display_name
       FROM project_members pm
       JOIN users u ON u.id=pm.user_id
       LEFT JOIN users inv ON inv.id=pm.invited_by
       WHERE pm.project_id=$1 ORDER BY pm.joined_at`,
      [req.params.projectId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

router.patch('/:projectId/members/:userId', requireProjectAccess, requireOwner, async (req, res, next) => {
  const { role } = req.body;
  if (!ASSIGNABLE_ROLES.includes(role)) return res.status(400).json({ error:'Role must be editor, pentester or viewer' });
  if (req.params.userId === req.user.id)   return res.status(400).json({ error:'Cannot change your own role' });
  try {
    await db.query(`UPDATE project_members SET role=$1 WHERE project_id=$2 AND user_id=$3`, [role, req.params.projectId, req.params.userId]);
    res.json({ ok:true });
  } catch (err) { next(err); }
});

router.delete('/:projectId/members/:userId', requireProjectAccess, requireOwner, async (req, res, next) => {
  if (req.params.userId === req.user.id) return res.status(400).json({ error:'Cannot remove yourself' });
  try {
    await db.query(`DELETE FROM project_members WHERE project_id=$1 AND user_id=$2`, [req.params.projectId, req.params.userId]);
    res.json({ ok:true });
  } catch (err) { next(err); }
});

// ── INVITES (token-based, no email) ─────────────────────────────────

// POST /projects/:projectId/invites  — create a link/token
router.post('/:projectId/invites', requireProjectAccess, requireOwner, [
  body('role').optional().isIn(ASSIGNABLE_ROLES),
  body('label').optional().trim().isLength({ max:100 }),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { role='editor', label='' } = req.body;
  try {
    // Generate a short human-readable token: FLOWDIT-XXXXXXXXXXXX
    const rand  = Math.random().toString(36).slice(2,8).toUpperCase() + Math.random().toString(36).slice(2,8).toUpperCase();
    const token = `FD-${rand}`;

    const { rows } = await db.query(
      `INSERT INTO project_invites (project_id, invited_by, role, token, label, expires_at)
       VALUES ($1,$2,$3,$4,$5, NOW() + INTERVAL '7 days')
       RETURNING id, token, role, label, expires_at, created_at`,
      [req.params.projectId, req.user.id, role, token, label]
    );

    await activity.log({
      projectId:  req.params.projectId,
      user:       req.user,
      action:     'invite_created',
      entityType: 'member',
      entityName: label || `${role} invite`,
      meta:       { role, token },
    });

    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

// GET /projects/:projectId/invites — list active invites
router.get('/:projectId/invites', requireProjectAccess, requireOwner, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT pi.id, pi.token, pi.role, pi.label, pi.expires_at, pi.created_at,
              pi.accepted_at, u.username AS invited_by_username, u.display_name AS invited_by_display_name,
              au.username AS accepted_by_username, au.display_name AS accepted_by_display_name
       FROM project_invites pi
       JOIN users u ON u.id=pi.invited_by
       LEFT JOIN users au ON au.id=pi.accepted_by
       WHERE pi.project_id=$1
       ORDER BY pi.created_at DESC`,
      [req.params.projectId]
    );
    res.json(rows);
  } catch (err) { next(err); }
});

// DELETE /projects/:projectId/invites/:inviteId — revoke
router.delete('/:projectId/invites/:inviteId', requireProjectAccess, requireOwner, async (req, res, next) => {
  try {
    await db.query(`DELETE FROM project_invites WHERE id=$1 AND project_id=$2`, [req.params.inviteId, req.params.projectId]);
    res.json({ ok:true });
  } catch (err) { next(err); }
});

// POST /projects/join — anyone with a valid token can join
router.post('/join', async (req, res, next) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error:'Token required' });
  try {
    const { rows } = await db.query(
      `SELECT * FROM project_invites WHERE token=$1 AND accepted_at IS NULL AND expires_at > NOW()`,
      [token.trim().toUpperCase()]
    );
    if (!rows.length) return res.status(404).json({ error:'Invalid or expired invite code' });
    const invite = rows[0];

    // Check not already a member
    const already = await db.query(
      `SELECT 1 FROM project_members WHERE project_id=$1 AND user_id=$2`,
      [invite.project_id, req.user.id]
    );
    if (already.rows.length) return res.status(409).json({ error:'You are already a member of this project' });

    await db.query(
      `INSERT INTO project_members (project_id, user_id, role, invited_by, label)
       VALUES ($1,$2,$3,$4,$5)`,
      [invite.project_id, req.user.id, invite.role, invite.invited_by, invite.label || null]
    );
    await db.query(
      `UPDATE project_invites SET accepted_at=NOW(), accepted_by=$1 WHERE id=$2`,
      [req.user.id, invite.id]
    );

    await activity.log({
      projectId:  invite.project_id,
      user:       req.user,
      action:     'member_joined',
      entityType: 'member',
      entityName: req.user.display_name || req.user.username,
      meta:       { role: invite.role },
    });

    res.json({ ok:true, projectId: invite.project_id, role: invite.role });
  } catch (err) { next(err); }
});

module.exports = router;
