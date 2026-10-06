const router   = require('express').Router({ mergeParams: true });
const { body, validationResult } = require('express-validator');
const db       = require('../db');
const mailer   = require('../services/mailer');
const { requireAuth } = require('../middleware/auth');
const { requireProjectAccess, requireLead, requireOwner, isLeadRole, portalRequiresFlag } = require('../middleware/project');
const { vulnBelongsToProject } = require('../services/ownership');
const { decrypt } = require('../utils/crypto');
const github    = require('../services/github');

// Portal clients may read and open tickets, but only when the owner enabled the
// tickets channel for this project. Internal users are unaffected.
router.use(requireAuth, requireProjectAccess, portalRequiresFlag('tickets_enabled'));

// Free-text cap for ticket descriptions and replies (applies to everyone).
const MAX_TEXT = 10000;

// A portal session gets an ALLOWLIST projection of tickets and replies, same
// idea as sanitizeProjectForPortal: no internal identity (user ids, usernames,
// avatar colors), no GitHub issue link, only a display name plus an is_team
// marker so the client view can still tell team and client messages apart.
// Timestamps are nulled when the owner switched portal_hide_log_times on.
// Avatar colors are never sent, so portal_hide_team_avatars needs no branch.
function portalTime(project, value) {
  return project.portal_hide_log_times ? null : value;
}

function portalTicket(t, project) {
  return {
    id:             t.id,
    project_id:     t.project_id,
    // vuln_name is already nulled in SQL for unpublished findings; drop the id too
    vuln_id:        t.vuln_name != null ? t.vuln_id : null,
    vuln_name:      t.vuln_name ?? null,
    title:          t.title,
    description:    t.description,
    status:         t.status,
    client_name:    t.client_name,
    client_email:   t.client_email,
    opened_by_name: t.opened_by ? (t.opened_by_display_name || t.opened_by_username) : (t.client_name || 'Client'),
    is_team:        !!t.opened_by,
    reply_count:    t.reply_count,
    created_at:     portalTime(project, t.created_at),
    updated_at:     portalTime(project, t.updated_at),
  };
}

function portalReply(r, project) {
  return {
    id:          r.id,
    ticket_id:   r.ticket_id,
    body:        r.body,
    author_name: r.author_id ? (r.author_display_name || r.author_username) : (r.client_name || 'Client'),
    is_team:     !!r.author_id,
    created_at:  portalTime(project, r.created_at),
  };
}

// ── TICKETS ───────────────────────────────────────────────────────

// GET all tickets for a project
router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT t.*,
              u.username AS opened_by_username, u.display_name AS opened_by_display_name, u.avatar_color AS opened_by_color,
              CASE WHEN $2::boolean OR v.client_visible THEN v.name END AS vuln_name,
              gi.external_url AS github_url,
              (SELECT COUNT(*) FROM ticket_replies r WHERE r.ticket_id = t.id)::int AS reply_count
       FROM tickets t
       LEFT JOIN users u ON u.id = t.opened_by
       LEFT JOIN custom_vulns v ON v.id = t.vuln_id
       LEFT JOIN ticket_integrations gi ON gi.ticket_id = t.id AND gi.provider = 'github'
       WHERE t.project_id = $1
       ORDER BY t.updated_at DESC`,
      // Team members see every linked finding; the portal only published ones.
      [req.params.projectId, !req.isPortal]
    );
    res.json(req.isPortal ? rows.map(t => portalTicket(t, req.project)) : rows);
  } catch (err) { next(err); }
});

// GET single ticket with replies
router.get('/:ticketId', async (req, res, next) => {
  try {
    const { rows: tickets } = await db.query(
      `SELECT t.*,
              u.username AS opened_by_username, u.display_name AS opened_by_display_name, u.avatar_color AS opened_by_color,
              CASE WHEN $3::boolean OR v.client_visible THEN v.name END AS vuln_name,
              gi.external_url AS github_url
       FROM tickets t
       LEFT JOIN users u ON u.id = t.opened_by
       LEFT JOIN custom_vulns v ON v.id = t.vuln_id
       LEFT JOIN ticket_integrations gi ON gi.ticket_id = t.id AND gi.provider = 'github'
       WHERE t.id = $1 AND t.project_id = $2`,
      [req.params.ticketId, req.params.projectId, !req.isPortal]
    );
    if (!tickets.length) return res.status(404).json({ error: 'Ticket not found' });

    const { rows: replies } = await db.query(
      `SELECT r.*, u.username AS author_username, u.display_name AS author_display_name, u.avatar_color AS author_color
       FROM ticket_replies r
       LEFT JOIN users u ON u.id = r.author_id
       WHERE r.ticket_id = $1
       ORDER BY r.created_at ASC`,
      [req.params.ticketId]
    );
    if (req.isPortal) {
      return res.json({
        ...portalTicket(tickets[0], req.project),
        replies: replies.map(r => portalReply(r, req.project)),
      });
    }
    res.json({ ...tickets[0], replies });
  } catch (err) { next(err); }
});

// POST create ticket — team members or portal users
router.post('/', [
  body('title').trim().isLength({ min: 1, max: 300 }),
  body('description').optional().trim().isLength({ max: MAX_TEXT }),
  // Linking a finding is optional. The client form sends null for "not linked",
  // and optional() alone only skips undefined, so accept null and '' explicitly.
  body('vuln_id').optional({ values: 'falsy' }).isUUID(),
  body('client_name').optional().trim().isLength({ max: 200 }),
  body('client_email').optional().trim().isEmail().normalizeEmail(),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { rows: proj } = await db.query(
    `SELECT tickets_enabled FROM projects WHERE id=$1`, [req.params.projectId]
  );
  if (!proj[0]?.tickets_enabled) {
    return res.status(403).json({ error: 'Tickets are not enabled for this project' });
  }

  const { title, description = '' } = req.body;
  const validVulnId = await vulnBelongsToProject(req.body.vuln_id, req.params.projectId);

  if (req.isPortal) {
    // A client can only link a finding they can actually see in the portal —
    // otherwise the ticket would reveal (and confirm) an unpublished finding.
    // Checked on the raw id (not validVulnId) so a foreign or unknown id gets the
    // same 400 as an unpublished one — no existence oracle.
    let vulnName = null;
    if (req.body.vuln_id) {
      const { rows: pub } = await db.query(
        `SELECT name FROM custom_vulns WHERE id=$1 AND project_id=$2 AND client_visible`,
        [req.body.vuln_id, req.params.projectId]
      );
      if (!pub.length) return res.status(400).json({ error: 'Finding not available' });
      vulnName = pub[0].name;
    }
    // Portal user — no user account, store client_name/email instead
    const clientName  = req.body.client_name?.trim()  || 'Client';
    const clientEmail = req.body.client_email?.trim()  || null;
    try {
      const { rows } = await db.query(
        `INSERT INTO tickets (project_id, vuln_id, title, description, client_name, client_email)
         VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
        [req.params.projectId, validVulnId, title, description, clientName, clientEmail]
      );
      return res.status(201).json(portalTicket({ ...rows[0], vuln_name: vulnName }, req.project));
    } catch (err) { return next(err); }
  }

  // Team member
  if (!req.user) return res.status(403).json({ error: 'Authentication required' });
  try {
    const { rows } = await db.query(
      `INSERT INTO tickets (project_id, vuln_id, title, description, opened_by)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [req.params.projectId, validVulnId, title, description, req.user.id]
    );
    res.status(201).json(rows[0]);
  } catch (err) { next(err); }
});

// Answering/triaging a client query is client-facing: owner/editor (the lead)
// only. Pentesters can still read tickets.

// PATCH update ticket status (editors/owner only)
router.patch('/:ticketId', requireLead, [
  body('status').optional().isIn(['open', 'in_review', 'closed']),
  body('title').optional().trim().isLength({ min: 1, max: 300 }),
  body('description').optional().trim().isLength({ max: MAX_TEXT }),
], async (req, res, next) => {
  const allowed = ['status', 'title', 'description'];
  const updates = [], values = [];
  allowed.forEach(f => {
    if (req.body[f] !== undefined) {
      updates.push(`${f}=$${values.length + 1}`);
      values.push(req.body[f]);
    }
  });
  if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });
  updates.push(`updated_at=NOW()`);
  values.push(req.params.ticketId, req.params.projectId);
  try {
    const { rows } = await db.query(
      `UPDATE tickets SET ${updates.join(',')}
       WHERE id=$${values.length - 1} AND project_id=$${values.length} RETURNING *`,
      values
    );
    if (!rows.length) return res.status(404).json({ error: 'Ticket not found' });
    res.json(rows[0]);
  } catch (err) { next(err); }
});

// DELETE ticket (owner only): it erases the whole client conversation.
router.delete('/:ticketId', requireOwner, async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `DELETE FROM tickets WHERE id=$1 AND project_id=$2 RETURNING title`,
      [req.params.ticketId, req.params.projectId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Ticket not found' });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// ── GITHUB INTEGRATION (v1 — one-way push) ──────────────────────────
// See GITHUB_INTEGRATION.md for the design and the path to bidirectional
// sync. requireLead matches the bar for every other ticket mutation.
router.post('/:ticketId/github', requireLead, async (req, res, next) => {
  try {
    const { rows: proj } = await db.query(
      `SELECT github_repo, github_pat_enc FROM projects WHERE id=$1`, [req.params.projectId]
    );
    if (!proj[0]?.github_repo || !proj[0]?.github_pat_enc) {
      return res.status(400).json({ error: 'GitHub is not configured for this project (Settings → GitHub Integration)' });
    }

    const existing = await db.query(
      `SELECT external_url FROM ticket_integrations WHERE ticket_id=$1 AND provider='github'`,
      [req.params.ticketId]
    );
    if (existing.rows.length) {
      return res.status(409).json({ error: 'Already linked to GitHub', external_url: existing.rows[0].external_url });
    }

    const { rows: tickets } = await db.query(
      `SELECT t.title, t.description, v.name AS vuln_name, v.severity, v.description AS vuln_description, v.remediation
       FROM tickets t
       LEFT JOIN custom_vulns v ON v.id = t.vuln_id
       WHERE t.id=$1 AND t.project_id=$2`,
      [req.params.ticketId, req.params.projectId]
    );
    if (!tickets.length) return res.status(404).json({ error: 'Ticket not found' });
    const ticket = tickets[0];

    const bodyParts = [];
    if (ticket.description) bodyParts.push(ticket.description);
    if (ticket.vuln_name) {
      bodyParts.push(`\n---\n**Linked finding:** ${ticket.vuln_name}${ticket.severity ? ` (${ticket.severity})` : ''}`);
      if (ticket.vuln_description) bodyParts.push(`\n${ticket.vuln_description}`);
      if (ticket.remediation) bodyParts.push(`\n**Remediation:** ${ticket.remediation}`);
    }
    bodyParts.push(`\n\n_Pushed from Flowdit — this issue is not synced back; status changes here don't reflect in Flowdit._`);

    const pat = decrypt(proj[0].github_pat_enc);
    const issue = await github.createIssue(proj[0].github_repo, pat, {
      title: ticket.title,
      body: bodyParts.join('\n'),
    });

    const { rows: inserted } = await db.query(
      `INSERT INTO ticket_integrations (ticket_id, provider, external_id, external_url, created_by)
       VALUES ($1,'github',$2,$3,$4) RETURNING external_id, external_url`,
      [req.params.ticketId, issue.id, issue.url, req.user.id]
    );
    res.status(201).json(inserted[0]);
  } catch (err) {
    if (err.message?.startsWith('GitHub')) return res.status(502).json({ error: err.message });
    next(err);
  }
});

// ── REPLIES ───────────────────────────────────────────────────────

// POST add reply — team members or portal users
router.post('/:ticketId/replies', [
  body('body').trim().isLength({ min: 1, max: MAX_TEXT }),
  body('client_name').optional().trim().isLength({ max: 200 }),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  // Portal: require a session (already enforced by requireProjectAccess)
  // Team: require a real user
  if (!req.isPortal && !req.user) return res.status(403).json({ error: 'Authentication required' });
  // A team reply goes to the client (and emails them), so a pentester can't
  // send one — that's the lead's job. Viewers stay allowed: a viewer account
  // IS the client (they land on the client view), replying on their own query.
  if (!req.isPortal && req.memberRole === 'pentester')
    return res.status(403).json({ error: 'Only the project owner or an editor can reply to client queries' });

  try {
    const { rows: ticket } = await db.query(
      `SELECT id, title, status, client_email, client_name, project_id FROM tickets WHERE id=$1 AND project_id=$2`,
      [req.params.ticketId, req.params.projectId]
    );
    if (!ticket.length) return res.status(404).json({ error: 'Ticket not found' });
    // A closed query is closed for the client; the team can still add a note
    // (and reopening it is a lead action via PATCH status).
    if (req.isPortal && ticket[0].status === 'closed')
      return res.status(409).json({ error: 'This query is closed' });

    let newReply;

    if (req.isPortal) {
      const clientName = req.body.client_name?.trim() || 'Client';
      const { rows } = await db.query(
        `INSERT INTO ticket_replies (ticket_id, body, client_name) VALUES ($1,$2,$3) RETURNING *`,
        [req.params.ticketId, req.body.body, clientName]
      );
      newReply = portalReply(rows[0], req.project);
    } else {
      const { rows } = await db.query(
        `INSERT INTO ticket_replies (ticket_id, body, author_id) VALUES ($1,$2,$3) RETURNING *`,
        [req.params.ticketId, req.body.body, req.user.id]
      );
      // Bump ticket updated_at
      await db.query(`UPDATE tickets SET updated_at=NOW() WHERE id=$1`, [req.params.ticketId]);

      const { rows: full } = await db.query(
        `SELECT r.*, u.username AS author_username, u.display_name AS author_display_name, u.avatar_color AS author_color
         FROM ticket_replies r JOIN users u ON u.id = r.author_id
         WHERE r.id=$1`,
        [rows[0].id]
      );
      newReply = full[0];

      // Email notification to client if ticket has client_email
      if (ticket[0].client_email) {
        const { rows: projRows } = await db.query(
          `SELECT name, portal_token FROM projects WHERE id=$1`, [req.params.projectId]
        );
        const proj       = projRows[0];
        const portalUrl  = proj?.portal_token
          ? `${process.env.FRONTEND_URL || ''}/client-login#token=${proj.portal_token}`
          : null;
        mailer.sendTicketReplyNotification({
          toEmail:     ticket[0].client_email,
          toName:      ticket[0].client_name,
          projectName: proj?.name || 'Your project',
          ticketTitle: ticket[0].title,
          replyBody:   req.body.body,
          replyAuthor: req.user.display_name || req.user.username,
          portalUrl,
        }).catch(err => console.error('Email notification failed:', err.message));
      }
    }

    await db.query(`UPDATE tickets SET updated_at=NOW() WHERE id=$1`, [req.params.ticketId]);
    res.status(201).json(newReply);
  } catch (err) { next(err); }
});

// DELETE reply (author or editor)
router.delete('/:ticketId/replies/:replyId', async (req, res, next) => {
  try {
    const { rows: ticket } = await db.query(
      `SELECT id FROM tickets WHERE id=$1 AND project_id=$2`,
      [req.params.ticketId, req.params.projectId]
    );
    if (!ticket.length) return res.status(404).json({ error: 'Ticket not found' });

    const isEditor = isLeadRole(req.memberRole);
    const { rows } = await db.query(
      `DELETE FROM ticket_replies
       WHERE id=$1 AND ticket_id=$2 ${isEditor ? '' : 'AND author_id=$3'}
       RETURNING id`,
      isEditor
        ? [req.params.replyId, req.params.ticketId]
        : [req.params.replyId, req.params.ticketId, req.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Reply not found or not authorized' });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

module.exports = router;
